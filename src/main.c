#include "proto.h"
#include "peers.h"
#include "log.h"
#include "metrics.h"
#include "base64.h"
#include "api.h"

#include <time.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>

#include <stdint.h>
#include <stdlib.h>

static volatile bool killed = false;
void sigint_handler(int sig) {
	killed = true;
}

#define CONF_ENO 1

void save_config() {
	FILE* config = fopen("conf.dmp.tmp", "w");
	if(config == NULL)
		fatal("Couldn't open config for writing");

	if(fwrite(&myID, sizeof(struct nodeid), 1, config) != 1)
		fatal("Couldn't write state");
	if(fwrite(table, sizeof(struct entry), table_size, config) != table_size)
		fatal("Couldn't write state");

	if(fwrite(&peer_table_size, sizeof(peer_table_size), 1, config) != 1)
		fatal("Couldn't write peer table size");
	if(fwrite(&peer_table_load, sizeof(peer_table_load), 1, config) != 1)
		fatal("Couldn't write peer table load");
	if(fwrite(peer_table, sizeof(struct peer_entry), peer_table_size, config) != peer_table_size)
		fatal("Couldn't write peer table");

	fflush(config);
	if(fclose(config) != 0)
		fatal("Couldn't close config file");

	rename("conf.dmp.tmp", "conf.dmp");
}

int read_config() {
	FILE* config = fopen("conf.dmp", "r");
	if(config == NULL)
		return CONF_ENO;

	if(fread(&myID, sizeof(struct nodeid), 1, config) != 1)
		fatal("Couldn't read routing table");
	if(fread(table, sizeof(struct entry), table_size, config) != table_size)
		fatal("Couldn't read routing table");

	if(fread(&peer_table_size, sizeof(peer_table_size), 1, config) != 1)
		fatal("Couldn't read peer table");
	if(fread(&peer_table_load, sizeof(peer_table_load), 1, config) != 1)
		fatal("Couldn't read peer table");

	peer_table = malloc(sizeof(struct peer_entry) * peer_table_size);
	assert(peer_table != NULL);

	if(fread(peer_table, sizeof(struct peer_entry), peer_table_size, config) != peer_table_size)
		fatal("Couldn't read peer table");

	long pos = ftell(config);
	fseek(config, 0, SEEK_END);
	if(pos != ftell(config))
		fatal("The config file was too long?");

	if(fclose(config) != 0)
		fatal("Couldn't close config file");

	return 0;
}

void flush_messages(int sfd, struct message* cursor, const struct message* const end) {
	prom_counter_add(requests, end - cursor, NULL);
	for(; cursor < end; cursor++) {
		//now reply the client with the same data
		int rc = sendto(sfd, cursor->payload, cursor->payload_len, 0, (const struct sockaddr*)&cursor->dest, cursor->dest_len);
		if (rc < 0) {
			dbg("dest_len %d", cursor->dest_len);
			fatal("Failed to send message %d %m: %d", errno, cursor->dest_len);
		}
		prom_counter_add(bytesSent, cursor->payload_len, NULL);
	}
}

#define OUTBOX_SIZE 32
int main(int argc, char** argv) {
	srand(time(NULL));
	struct message outbuff[OUTBOX_SIZE] = {0};

	struct sigaction sa;
	sa.sa_handler = sigint_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	if(sigaction(SIGINT, &sa, NULL) == -1)
		fatal("Couldn't set signal handler");

	if(sigaction(SIGTERM, &sa, NULL) == -1)
		fatal("Couldn't set signal handler");

	struct dht dht = {0};
	pthread_mutexattr_t mutexattr;
	pthread_mutexattr_init(&mutexattr);
	pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_ERRORCHECK);
	pthread_mutex_init(&dht.mutex, &mutexattr);
	pthread_mutex_lock(&dht.mutex);
	{
		routing_init(NULL);
		int rc = read_config();
		if(rc == CONF_ENO) {
			for(uint16_t i = 0; i < sizeof(myID.inner_b); i++) {
				myID.inner_b[i] = rand();
			}
			routing_init(&myID);
			allocate_hashtable();
		} else {
			routing_setid(&myID);
			routing_reset_expire(time(NULL) + PROTO_UNCTM);
		}

		dht.self = myID;
	}

	metric_init();
	api_init(&dht);
	routing_update_metrics();
	peer_update_metrics();

	size_t outLen;
	const char *id = base64_encode((unsigned char*)myID.inner_b, 20, &outLen);
	prom_counter_inc(meta, (const char *[]){id});
	free((char*)id);

	struct message* message_cursor = outbuff;
	proto_begin(&dht, time(NULL), &message_cursor, outbuff+32);
	flush_messages(dht.sfd, outbuff, message_cursor);

#define RECV_BUFF_SIZE 4096
	char buff_storage[RECV_BUFF_SIZE+1];
	int rc = 0;
	while(rc == 0 && !killed) {
		char* buff = buff_storage;

		bool timedout = false;
		time_t next = dht.wake;
		if(next != 0) {
			time_t sleepfor = next - time(NULL);
			struct timeval tv = {
				.tv_sec = sleepfor,
				.tv_usec = 0,
			};
			if(tv.tv_sec <= 0) {
				timedout = true;
			} else {
				setsockopt(dht.sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
			}
		}

		// Try to receive some data, this is a blocking call
		struct sockaddr_storage remote;
		socklen_t remote_len = sizeof(remote);
		ssize_t recv_len;
		if(!timedout) {
			pthread_mutex_unlock(&dht.mutex);
			recv_len = recvfrom(dht.sfd, buff, RECV_BUFF_SIZE, 0, (struct sockaddr *)&remote, &remote_len);
			pthread_mutex_lock(&dht.mutex);
			if(recv_len == -1) {
				// This is really strange. The man pages say we should be getting
				// an ETIMEDOUT here, but instead linux gives us this.
				if(errno == EAGAIN) {
					buff = NULL;
					recv_len = 0;
				} else if(errno == EINTR) {
					continue;
				} else {
					fatal("RECV failed %d %m", errno);
				}
			} else if(recv_len >= RECV_BUFF_SIZE) {
				dbg("Receive buffer too small");
				continue;
			}
			prom_counter_add(bytesRecv, recv_len, NULL);
			// Null terminate the packet
			if(buff != NULL) {
				buff[recv_len] = '\0';
			}
		} else {
			buff = NULL;
			recv_len = 0;
		}

		struct message* message_cursor = outbuff;
		time_t now = time(NULL);
		rc = proto_run(&dht, buff, recv_len, (struct sockaddr_in*)&remote, remote_len, now, &message_cursor, outbuff+OUTBOX_SIZE);
		flush_messages(dht.sfd, outbuff, message_cursor);

		if(dht.dirtyconf) {
			save_config();
			dht.dirtyconf = false;
		}
	}

	proto_end(&dht);
	api_end();
	metric_end();
	save_config();

	return rc;
}

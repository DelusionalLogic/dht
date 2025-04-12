#include "proto.h"
#include "peers.h"
#include "log.h"
#include "metrics.h"

#include <time.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>

#include <stdint.h>
#include <stdlib.h>

static char encoding_table[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/'
};
static int mod_table[] = {0, 2, 1};


char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
	*output_length = 4 * ((input_length + 2) / 3);

	char *encoded_data = malloc(*output_length + 1);
	assert(encoded_data != NULL);

	for (int i = 0, j = 0; i < input_length;) {
		uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
		uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for (int i = 0; i < mod_table[input_length % 3]; i++) {
		encoded_data[*output_length - 1 - i] = '=';
	}

	encoded_data[*output_length] = 0;

	return encoded_data;
}

static volatile bool killed = false;
void sigint_handler(int sig) {
	killed = true;
}

#define CONF_ENO 1

void save_config() {
	FILE* config = fopen("conf.dmp", "w");
	if(config == NULL)
		fatal("Couldn't open config for writing");

	if(fwrite(&myID, sizeof(struct nodeid), 1, config) != 1)
		fatal("Couldn't write state");
	if(fwrite(table, sizeof(struct entry), table_size, config) != table_size)
		fatal("Couldn't write state");

	long pos = ftell(config);
	dbg("Routing stops at 0x%04lX", pos);

	if(fwrite(&peer_table_size, sizeof(peer_table_size), 1, config) != 1)
		fatal("Couldn't write peer table size");
	if(fwrite(&peer_table_load, sizeof(peer_table_load), 1, config) != 1)
		fatal("Couldn't write peer table load");
	if(fwrite(peer_table, sizeof(struct peer_entry), peer_table_size, config) != peer_table_size)
		fatal("Couldn't write peer table");

	if(fclose(config) != 0)
		fatal("Couldn't close config file");
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
	dbg("Flushing %ld pending messages", end - cursor);
	prom_counter_add(requests, end - cursor, NULL);
	for(; cursor < end; cursor++) {
		//now reply the client with the same data
		int rc = sendto(sfd, cursor->payload, cursor->payload_len, 0, (const struct sockaddr*)&cursor->dest, cursor->dest_len);
		if (rc < 0) {
			fatal("Failed to send message %m");
		}
		prom_counter_add(bytesSent, cursor->payload_len, NULL);
	}
}

struct lookup {
	struct nodeid target;

	struct nodeid closest[8];
	struct addr closest_addr[8];
	bool closest_valid[8]; // @SLOP: This could be a single word

	uint64_t outstanding;

	time_t wake;
};

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
	{
		int rc = read_config();
		if(rc == CONF_ENO) {
			for(uint16_t i = 0; i < sizeof(myID.inner_b); i++) {
				myID.inner_b[i] = rand();
			}
			/* myID = (struct nodeid){.inner={0xebe9bbf1, 0x3cdba6b3, 0x993e0c87, 0x900d5e25, 0x00000000}}; */
			routing_flush();
			allocate_hashtable();
		}

		dht.self = myID;
	}

	metric_init();

	size_t outLen;
	const char *id = base64_encode((unsigned char*)myID.inner_b, 20, &outLen);
	prom_counter_inc(meta, (const char *[]){id});

	struct message* message_cursor = outbuff;
	proto_begin(&dht, time(NULL), &message_cursor, outbuff+32);
	flush_messages(dht.sfd, outbuff, message_cursor);

	/* struct lookup lookup; */
	/* // Init the lookup */
	/* { */
	/* 	lookup.wake = 0; */
	/* 	lookup.target = (struct nodeid){.inner={0x19b8a941, 0x38fa0191, 0x1403fac2, 0x581000ab, 0x19583cda}}; */

	/* 	struct entry* entry[8]; */
	/* 	int found = routing_closest(&lookup.target, 8, entry); */
	/* 	for(size_t i = 0; i < found; i++) { */
	/* 		lookup.closest[i] = entry[i]->id; */
	/* 		lookup.closest_addr[i] = entry[i]->addr; */
	/* 		lookup.closest_valid[i] = true; */
	/* 	} */
	/* } */

#define RECV_BUFF_SIZE 4096
	char buff_storage[RECV_BUFF_SIZE+1];
	int rc = 0;
	while(rc == 0 && !killed) {
		char* buff = buff_storage;

		bool timedout = false;
		time_t next = dht.wake;

		if(next != 0) {
			time_t sleepfor = next - time(NULL);
			dbg("Set timeout to %ld", sleepfor);
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
			recv_len = recvfrom(dht.sfd, buff, RECV_BUFF_SIZE, 0, (struct sockaddr *)&remote, &remote_len);
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
	}

	proto_end(&dht);
	metric_end();
	dbg("Writing out config");
	save_config();

	return rc;
}

#include "proto.h"
#include "log.h"

#include <time.h>
#include <assert.h>
#include <errno.h>

void flush_messages(int sfd, struct message* cursor, const struct message* const end) {
	dbg("Flushing %ld pending messages", end - cursor);
	for(; cursor < end; cursor++) {
		//now reply the client with the same data
		int rc = sendto(sfd, cursor->payload, cursor->payload_len, 0, (const struct sockaddr*)&cursor->dest, cursor->dest_len);
		if (rc < 0) {
			fatal("Failed to send message");
		}
	}
}

int main(int argc, char** argv) {
	struct message outbuff[10] = {0};

	struct dht dht;
	dht.self = (struct nodeid){.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, 0x0ab00521}};
	struct message* message_cursor = outbuff;
	proto_begin(&dht, time(NULL), &message_cursor, outbuff+10);
	flush_messages(dht.sfd, outbuff, message_cursor);


	char buff_storage[2049];
	int rc = 0;
	while(rc == 0) {
		char* buff = buff_storage;
		printf("Waiting for data...");
		fflush(stdout);

		bool timedout = false;
		if(!dht.pause){
			struct entry* oldest;
			routing_oldest(&oldest);
			if(oldest != NULL) {
				dbg("Set timeout to %ld", oldest->expire - time(NULL));
				struct timeval tv = {
					.tv_sec = oldest->expire - time(NULL),
					.tv_usec = 0,
				};
				if(tv.tv_sec <= 0) {
					timedout = true;
				} else {
					setsockopt(dht.sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
				}
			}
		} else {
			printf("DHT timeout is paused");
		}
		// Try to receive some data, this is a blocking call
		struct sockaddr_storage remote;
		socklen_t remote_len = sizeof(remote);
		ssize_t recv_len;
		if(!timedout) {
			recv_len = recvfrom(dht.sfd, buff, 2048, 0, (struct sockaddr *)&remote, &remote_len);
			if(recv_len == -1) {
				// This is really strange. The man pages say we should be getting
				// an ETIMEDOUT here, but instead linux gives us this.
				if(errno == EAGAIN) {
					buff = NULL;
					recv_len = 0;
				} else {
					fatal("RECV failed %d %m", errno, errno);
				}
			} else if(recv_len >= 2048) {
				fatal("Receive buffer too small");
			}
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
		rc = proto_run(&dht, buff, recv_len, (struct sockaddr_in*)&remote, remote_len, now, &message_cursor, outbuff+10);
		flush_messages(dht.sfd, outbuff, message_cursor);
	}

	proto_end(&dht);

	return rc;
}

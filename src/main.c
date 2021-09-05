#include "routing.h"
#include "benc.h"
#include "query.h"
#include "log.h"

#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <stdio.h>

#define MAX(a, b)                 \
	 ({                           \
		 __typeof__ (a) _a = (a); \
		 __typeof__ (b) _b = (b); \
		 _a > _b ? _a : _b;       \
	 })

#define MIN(a, b)                 \
	 ({                           \
		 __typeof__ (a) _a = (a); \
		 __typeof__ (b) _b = (b); \
		 _a < _b ? _a : _b;       \
	 })


void dbgl_id(struct nodeid* id) {
	for(uint8_t i = 0; i < 5; i++) {
		fprintf(stderr, "0x%08x ", id->inner[i]);
	}
	fprintf(stderr, "\n");
	fflush(stderr);
}

struct discovery {
	uint16_t port;
	struct nodeid expected_id;
};

int sockaddr_cmp(struct sockaddr* x, struct sockaddr* y) {
#define CMP(a, b) \
	do { \
		typeof(a) cmp = a - b; \
		if(cmp != 0) return cmp; \
	} while(0)
	if (x->sa_family == AF_INET) {
		struct sockaddr_in *xin = (void*)x;
		struct sockaddr_in *yin = (void*)y;

		CMP(ntohl(xin->sin_addr.s_addr), ntohl(yin->sin_addr.s_addr));
		CMP(ntohs(xin->sin_port), ntohs(yin->sin_port));
	} else if (x->sa_family == AF_INET6) {
		struct sockaddr_in6 *xin6 = (void*)x, *yin6 = (void*)y;
		int r = memcmp(xin6->sin6_addr.s6_addr, yin6->sin6_addr.s6_addr, sizeof(xin6->sin6_addr.s6_addr));
		if (r != 0)
			return r;
		CMP(ntohs(xin6->sin6_port), ntohs(yin6->sin6_port));
		CMP(xin6->sin6_flowinfo, yin6->sin6_flowinfo);
		CMP(xin6->sin6_scope_id, yin6->sin6_scope_id);
	} else {
		err("Unsupported sa_family");
		abort();
	}

	return 0;
};

#define UNDEF_ADDR (struct in_addr){0xC0000200}
#define MAX_DISC 32
struct in_addr addrs[MAX_DISC];
struct discovery pending_discover[MAX_DISC];

typedef void (*cont)(struct nodeid* self, char* packet, size_t packet_len, int socket, struct sockaddr_in* remote, socklen_t remote_len);

#define MAX_INFLIGHT 32
bool reqalloc[MAX_INFLIGHT] = { false };
struct {
	struct sockaddr addr;
	cont fun;
} requestdata[MAX_INFLIGHT];

bool alloc_req(uint16_t* reqId) {
	for(size_t i = 0; i < MAX_INFLIGHT; i++) {
		if(!reqalloc[i]) {
			reqalloc[i] = true;
			*reqId = i;
			return true;
		}
	}
	return false;
}

bool find_req(uint32_t transId, uint16_t* reqId) {
	*reqId = transId;
	return reqalloc[transId];
}

void getclient_response(struct nodeid* self, char* packet, size_t packet_len, int socket, struct sockaddr_in* remote, socklen_t remote_len);

uint8_t rand_byte() {
	int limit = RAND_MAX - (RAND_MAX % UINT8_MAX);
	int val;
	while((val = rand()) > limit);

	return val;
}

int send_ping(struct nodeid* self, const int sfd, const struct sockaddr* dest_addr, socklen_t dest_len) {
	// Generate a random target
	struct nodeid target;
	for(uint8_t *target_byte = (uint8_t*)&target; target_byte < ((uint8_t*)&target)+sizeof(target); target_byte++) {
		*target_byte = rand_byte();
	}

	uint16_t reqId;
	if(!alloc_req(&reqId)) {
		return ENOBUFS;
	}
	char buff[128];
	size_t i = 0;

	dbg("Allocating request %d", reqId);
	requestdata[reqId].fun = &getclient_response;
	requestdata[reqId].addr = *dest_addr;

	int rc = snprintf(buff+i, 128-i, "d1:ad2:id20:");
	if(rc < 0)
		return EPERM;
	i += rc;
	memcpy(buff+i, self, sizeof(struct nodeid));
	i += sizeof(struct nodeid);
	rc = snprintf(buff+i, 128-i, "6:target20:");
	if(rc < 0)
		return EPERM;
	i += rc;
	memcpy(buff+i, &target, sizeof(struct nodeid));
	i += sizeof(struct nodeid);
	rc = snprintf(buff+i, 128-i, "e1:q9:find_node1:t%d:%d1:y1:qe", (reqId/10)+1, reqId);
	if(rc < 0)
		return EPERM;
	i += rc;

	//now reply the client with the same data
	rc = sendto(sfd, buff, i, 0, dest_addr, dest_len);
	if (rc == -1) {
		return EPERM; // Operation not permitted is used as the default "generic" error
	}

	return 0;
}

void getclient_response(struct nodeid* self, char* packet, size_t packet_len, int socket, struct sockaddr_in* remote, socklen_t remote_len) {
	struct benc_node stream[256];
	struct bcursor bcursor;
	bcur_open(&bcursor, packet, packet+packet_len, stream, 256);

	if(bcursor.end - bcursor.readhead <= 0) {
		err("Reponse too short");
		exit(EXIT_FAILURE);
	}

	struct nodeid id;
	uint8_t nodes_len;
	struct nodeid nodes[8];
	struct in_addr ips[8];
	uint16_t ports[8];


	// Read the payload
	{
		// Check that we have a dict
		if(bcursor.readhead->type != BNT_DICT) {
			err("Response is not a dict");
			exit(EXIT_FAILURE);
		}
		bcur_next(&bcursor, 1);

		bcur_find_key(&bcursor, (const enum benc_nodetype[]){BNT_STRING}, (const char*[]){"r"}, (const size_t[]){1}, 1);
		// Skip the key
		bcur_next(&bcursor, 1);

		if(bcursor.readhead->type != BNT_DICT) {
			err("Wrong value type for response");
			exit(EXIT_FAILURE);
		}

		// Skip the dict element
		bcur_next(&bcursor, 1);

		while(bcursor.readhead->type != BNT_END) {
			switch(bcur_find_key(&bcursor, (const enum benc_nodetype[]){BNT_STRING, BNT_STRING}, (const char*[]){"nodes", "id"}, (const size_t[]){5, 2}, 2)) {
				case 0:
					// Skip the key
					bcur_next(&bcursor, 1);

					if(bcursor.readhead->type != BNT_STRING) {
						err("Wrong value type for response");
						exit(EXIT_FAILURE);
					}

					if((bcursor.readhead->size % 26) != 0) {
						err("get_nodes call returned an incorrect nodes array");
						exit(EXIT_FAILURE);
					}

					nodes_len = MIN(bcursor.readhead->size/26, 8);
					dbg("We have %d (%d/26) nodes", nodes_len, bcursor.readhead->size);
					for(int i = 0; i < nodes_len; i++) {
						memcpy(nodes+i, bcursor.readhead->loc+(26*i), 20);
						memcpy(ips+i, bcursor.readhead->loc+(26*i)+20, 4);
						memcpy(ports+i, bcursor.readhead->loc+(26*i)+24, 2);
					}

					// Skip the value
					bcur_next(&bcursor, 1);
					break;
				case 1:
					// Skip the key
					bcur_next(&bcursor, 1);

					if(bcursor.readhead->type != BNT_STRING) {
						err("Wrong value type for response");
						exit(EXIT_FAILURE);
					}

					if(bcursor.readhead->size != 20) {
						err("remote node id was not 20 bytes long");
						exit(EXIT_FAILURE);
					}

					memcpy(&id, bcursor.readhead->loc, 20);

					// Skip the value
					bcur_next(&bcursor, 1);
					break;
			}
		}
	}

	// Print the candidates
	for(uint8_t i = 0; i < nodes_len; i++) {
		dbgl_id(&nodes[i]);
		printf("Candidate %s:%d\n", inet_ntoa(ips[i]), ntohs(ports[i]));

		struct sockaddr_in dest = {
			.sin_family = AF_INET,
			.sin_addr = ips[i],
			.sin_port = ports[i],
		};

		if(routing_interested(&nodes[i])) {
			int rc = send_ping(self, socket, (struct sockaddr*)&dest, sizeof(struct sockaddr_in));
			if(rc != 0) {
				err("send_ping failed %d", rc);
			}
		} else {
			dbg("Not interested in node");
		}
	}

	struct entry* entry;
	routing_offer(&id, &entry);
}

enum commandType {
	CT_QUERY,
	CT_RESPONSE,
	CT_ERROR,
};

int main(int argc, char** argv) {
	for(int i = 0; i < MAX_DISC; i++) {
		// 192.0.2.0
		addrs[i] = UNDEF_ADDR;
	}

	struct nodeid self = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, 0x0ab00521}};
	routing_init(&self);
	dbgl_id(&self);

	int sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sfd == -1) {
		err("Failed creating socket");
		exit(1);
	}
	struct sockaddr_in bindAddr = {0};
	bindAddr.sin_family = AF_INET;
	bindAddr.sin_port = htons(6881);
	bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	bind(sfd, (struct sockaddr*)&bindAddr, sizeof(struct sockaddr_in));

	struct addrinfo hints = {0};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_NUMERICSERV;

	struct addrinfo* res;
	int rc = getaddrinfo("router.bittorrent.com", "6881", &hints, &res);
	if(rc != 0) {
		err("Failed getting the bootstrap ip: %s", gai_strerror(rc));
		exit(EXIT_FAILURE);
	}

	for(struct addrinfo* cur = res; cur != NULL; cur = cur->ai_next) {
		char buff[128];
		inet_ntop(cur->ai_family, &((struct sockaddr_in*)cur->ai_addr)->sin_addr, buff, 128);
		dbg("IP %s", buff);

		/* size_t i = 0; */
		/* int rc = snprintf(buff+i, 128-i, "d1:ad2:id20:"); */
		/* i += rc; */
		/* memcpy(buff+i, &self, sizeof(struct nodeid)); */
		/* i += sizeof(struct nodeid); */
		/* rc = snprintf(buff+i, 128-i, "e1:q4:ping1:t2:ab1:y1:qe"); */
		/* i += rc; */

		send_ping(&self, sfd, cur->ai_addr, cur->ai_addrlen);
	}

	freeaddrinfo(res);

	//keep listening for data
	while(1) {
		char buff[2049];
		printf("Waiting for data...");
		fflush(stdout);
		
		//try to receive some data, this is a blocking call
		ssize_t recv_len;
		struct sockaddr_in remote;
		socklen_t remote_len = sizeof(remote);
		if ((recv_len = recvfrom(sfd, buff, 2048, 0, (struct sockaddr *)&remote, &remote_len)) == -1) {
			fatal("recvfrom failed");
		}
		if(recv_len >= 2048) {
			fatal("Recv buffer too small");
		}
		// Null terminate the packet
		buff[recv_len] = '\0';

		printf("Received packet from %s:%d\n", inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
		
		struct bcursor bcursor;
		struct benc_node stream[256];
		bcur_open(&bcursor, buff, buff+recv_len, stream, 256);
		benc_print(bcursor.readhead, bcursor.end - bcursor.readhead);

		if(bcursor.readhead->type != BNT_DICT) {
			fatal("First value is not a dict");
		}
		bcur_next(&bcursor, 1);

		bool discard = false;
		enum commandType type;
		bool transaction_set = false;
		char transaction[64];
		size_t transaction_len;
		bool query_set = false;
		char query[64];
		size_t query_len;
		while(bcursor.readhead->type != BNT_END) {
			switch(bcur_find_key(&bcursor, (const enum benc_nodetype[]){BNT_STRING, BNT_STRING, BNT_STRING}, (const char*[]){"y", "t", "q"}, (const size_t[]){1, 1, 1}, 3)) {
				case 0:
					// Skip the key
					bcur_next(&bcursor, 1);
					if(*bcursor.readhead->loc == 'r') {
						type = CT_RESPONSE;
					} else if(*bcursor.readhead->loc == 'q') {
						type = CT_QUERY;
					} else if(*bcursor.readhead->loc == 'e') {
						type = CT_ERROR;
					} else {
						fatal("Unknown command type %c", *bcursor.readhead->loc);
					}
					// Skip the value
					bcur_next(&bcursor, 1);
					break;
				case 1: {
					// Skip the key
					bcur_next(&bcursor, 1);
					if(bcursor.readhead->size > 64-1)
						fatal("Transaction string too long");

					transaction_set = true;
					transaction_len = bcursor.readhead->size;
					memcpy(transaction, bcursor.readhead->loc, transaction_len);
					transaction[transaction_len] = '\0';

					// Skip the value
					bcur_next(&bcursor, 1);
					break;
				}
				case 2: {
					bcur_next(&bcursor, 1);
					query_set = true;
					query_len = bcursor.readhead->size;
					memcpy(query, bcursor.readhead->loc, query_len);
					query[query_len] = '\0';
					bcur_next(&bcursor, 1);
				}
			}
		}

		if(discard)
			continue;

		if(type == CT_RESPONSE) {
			uint32_t transaction_number;

			if(!transaction_set)
				fatal("No transaction in response");

			// Temporary null terminate the string to parse the number without a copy
			char* end;
			transaction_number = strtol(transaction, &end, 10);

			if(end != transaction+transaction_len) {
				fatal("DISCARD: Transaction id is not a number %.*s", transaction_len, transaction);
			}

			uint16_t reqId;
			if(!find_req(transaction_number, &reqId)) {
				dbg("DISCARD: unknown transaction id %d", transaction);
				continue;
			}
			dbg("Transaction id matches request %d", reqId);

			if(sockaddr_cmp(&requestdata[reqId].addr, (struct sockaddr*)&remote) != 0) {
				fatal("Unexpected IP for valid transaction");
			}

			requestdata[reqId].fun(&self, buff, recv_len, sfd, &remote, remote_len);

			reqalloc[reqId] = false;
		} else if(type == CT_QUERY) { // Must be a query
			if(!query_set)
				fatal("No query function in query request");
			if(!transaction_set)
				fatal("No transaction in request");

			assert(strlen(query) == query_len);

			char response[1024];
			char* end = response+sizeof(response)-1;
			char* cursor = response;

			int rc = snprintf(cursor, end-cursor , "d1:t%ld:", transaction_len);
			if(rc < 0)
				return EPERM;
			cursor += rc;
			memcpy(cursor, transaction, transaction_len);
			cursor += transaction_len;
			rc = snprintf(cursor, end-cursor, "1:y1:r1:r");
			if(rc < 0)
				return EPERM;
			cursor += rc;

			rc = handle_request(&self, query, buff, recv_len, &cursor, end-cursor-1);
			if(rc != 0) fatal("Error handling request");

			rc = snprintf(cursor, end-cursor, "e");
			if(rc < 0)
				return EPERM;
			cursor += rc;

			//now reply the client with the same data
			rc = sendto(sfd, buff, cursor-response, 0, (const struct sockaddr*)&remote, remote_len);
			if (rc == -1) {
				return EPERM; // Operation not permitted is used as the default "generic" error
			}

		}
	}

	close(sfd);

	return 0;
}

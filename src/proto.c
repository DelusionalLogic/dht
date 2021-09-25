#include "proto.h"

#include "benc.h"
#include "query.h"
#include "log.h"

#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <netdb.h>
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

bool alloc_req(struct dht* dht, uint16_t* reqId) {
	for(size_t i = 0; i < MAX_INFLIGHT; i++) {
		if(!dht->reqalloc[i]) {
			dht->reqalloc[i] = true;
			*reqId = i;
			return true;
		}
	}
	return false;
}

bool find_req(struct dht* dht, uint32_t transId, uint16_t* reqId) {
	*reqId = transId;
	return dht->reqalloc[transId];
}

struct msgbuff {
	struct message** messages;
	const struct message* const messages_end;
};

#define PROTO_EDISC 1
#define PROTO_ENOREQ 2

PROCESS_REPONSE(getclient_response);

uint8_t rand_byte() {
	int limit = RAND_MAX - (RAND_MAX % UINT8_MAX);
	int val;
	while((val = rand()) > limit);

	return val;
}

int send_ping(struct dht* dht, struct nodeid* self, time_t now, const int sfd, const struct sockaddr* dest_addr, socklen_t dest_len, struct msgbuff* msgbuff) {
	// Generate a random target
	struct nodeid target;
	for(uint8_t *target_byte = (uint8_t*)&target; target_byte < ((uint8_t*)&target)+sizeof(target); target_byte++) {
		*target_byte = rand_byte();
	}

	uint16_t reqId;
	if(!alloc_req(dht, &reqId)) {
		return PROTO_ENOREQ;
	}

	if(*msgbuff->messages >= msgbuff->messages_end)
		return PROTO_ENOREQ;
	struct message* message = *msgbuff->messages;

	memcpy(&message->dest, dest_addr, dest_len);
	message->dest_len = dest_len;
	char* buff = message->payload;
	size_t i = 0;

	dbg("Allocating request %d", reqId);
	dht->requestdata[reqId].fun = &getclient_response;
	dht->requestdata[reqId].timeout = now + PROTO_TMOUT;
	dht->requestdata[reqId].timeout_fun = NULL;
	memcpy(&dht->requestdata[reqId].addr, dest_addr, dest_len);

	int rc = snprintf(buff+i, 128-i, "d1:ad2:id20:");
	if(rc < 0)
		fatal("Failed to write packet");
	i += rc;
	memcpy(buff+i, self, sizeof(struct nodeid));
	i += sizeof(struct nodeid);
	rc = snprintf(buff+i, 128-i, "6:target20:");
	if(rc < 0)
		fatal("Failed to write packet");
	i += rc;
	memcpy(buff+i, &target, sizeof(struct nodeid));
	i += sizeof(struct nodeid);
	rc = snprintf(buff+i, 128-i, "e1:q9:find_node1:t%d:%d1:y1:qe", (int)(log10(reqId+1)+1), reqId);
	if(rc < 0)
		fatal("Failed to write packet");
	i += rc;

	message->payload_len = i;
	(*msgbuff->messages)++;

	return 0;
}

PROCESS_REPONSE(getclient_response) {
	struct benc_node stream[256];
	struct bcursor bcursor;
	bcur_open(&bcursor, packet, packet+packet_len, stream, 256);

	if(bcursor.end - bcursor.readhead <= 0) {
		fatal("Response too short");
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
			fatal("Response is not a dict");
		}
		bcur_next(&bcursor, 1);

		bcur_find_key(&bcursor, (const enum benc_nodetype[]){BNT_STRING}, (const char*[]){"r"}, (const size_t[]){1}, 1);
		// Skip the key
		bcur_next(&bcursor, 1);

		if(bcursor.readhead->type != BNT_DICT) {
			fatal("Wrong value type for response");
		}

		// Skip the dict element
		bcur_next(&bcursor, 1);

		uint8_t parts = 0;
		while(bcursor.readhead->type != BNT_END) {
			switch(bcur_find_key(&bcursor, (const enum benc_nodetype[]){BNT_STRING, BNT_STRING}, (const char*[]){"nodes", "id"}, (const size_t[]){5, 2}, 2)) {
				case 0:
					// Skip the key
					bcur_next(&bcursor, 1);

					if(bcursor.readhead->type != BNT_STRING) {
						fatal("Nodes must be a string");
					}

					if((bcursor.readhead->size % 26) != 0) {
						fatal("Nodes string value must be a multiple of 26");
					}

					nodes_len = MIN(bcursor.readhead->size/26, 8);
					dbg("Remote gave us %d new candidates", nodes_len);
					for(int i = 0; i < nodes_len; i++) {
						memcpy(nodes+i, bcursor.readhead->loc+(26*i), 20);
						memcpy(ips+i, bcursor.readhead->loc+(26*i)+20, 4);
						memcpy(ports+i, bcursor.readhead->loc+(26*i)+24, 2);
					}

					parts++;

					// Skip the value
					bcur_next(&bcursor, 1);
					break;
				case 1:
					// Skip the key
					bcur_next(&bcursor, 1);

					if(bcursor.readhead->type != BNT_STRING) {
						fatal("Wrong value type for response");
					}

					if(bcursor.readhead->size != 20) {
						fatal("remote node id was not 20 bytes long");
					}

					memcpy(&id, bcursor.readhead->loc, 20);

					parts++;

					// Skip the value
					bcur_next(&bcursor, 1);
					break;
			}
		}

		if(parts < 2) {
			err("Response didn't contain nodes and id");
			return PROTO_EDISC;
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
			int rc = send_ping(dht, &dht->self, now, socket, (struct sockaddr*)&dest, sizeof(struct sockaddr_in), msgbuff);
			if(rc != 0) {
				err("send_ping failed %d", rc);
			}
		} else {
			dbg("Not interested in node");
		}
	}

	struct entry* entry;
	if(!routing_offer(&id, &entry)) {
		dbg("We are no longer interested");
		return 0;
	}

	struct sockaddr_in* ipv4 = (struct sockaddr_in*)remote;
	entry->addr.ip = ipv4->sin_addr.s_addr;
	entry->addr.port = ipv4->sin_port;
	entry->expire = now + UNCERTAIN_TIME;

	return 0;
}

enum commandType {
	CT_QUERY,
	CT_RESPONSE,
	CT_ERROR,
};

void proto_begin(struct dht* dht, time_t now, struct message** output, const struct message* const output_end) {
	routing_flush();
	struct msgbuff msgbuff = {
		output,
		output_end,
	};
	dht->pause = false;

	for(int i = 0; i < MAX_INFLIGHT; i++) {
		dht->reqalloc[i] = false;
	}

	routing_init(&dht->self);
	dbgl_id(&dht->self);

	dht->sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(dht->sfd == -1) {
		err("Failed creating socket");
		exit(1);
	}
	struct sockaddr_in bindAddr = {0};
	bindAddr.sin_family = AF_INET;
	bindAddr.sin_port = htons(6881);
	bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	bind(dht->sfd, (struct sockaddr*)&bindAddr, sizeof(struct sockaddr_in));

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

		send_ping(dht, &dht->self, now, dht->sfd, cur->ai_addr, cur->ai_addrlen, &msgbuff);
	}

	freeaddrinfo(res);
}

void proto_end(struct dht* dht) {
	close(dht->sfd);
}

int proto_run(struct dht* dht, char* buff, size_t recv_len, struct sockaddr_in* remote, socklen_t remote_len, time_t now, struct message** output, const struct message* const output_end) {
	struct msgbuff msgbuff = {
		output,
		output_end,
	};

	if(recv_len == 0 && buff == NULL) {
		for(int i = 0; i < MAX_INFLIGHT; i++) {
			if(!dht->reqalloc[i])
				continue;
			if(difftime(now, dht->requestdata[i].timeout) < 0)
				continue;

			if(dht->requestdata[i].timeout_fun != NULL)
				dht->requestdata[i].timeout_fun(dht, &dht->self, now, &msgbuff);

			dht->requestdata[i].fun = NULL;
			dht->requestdata[i].timeout_fun = NULL;
			dht->requestdata[i].timeout = 0;
			dht->reqalloc[i] = false;

			dht->pause = false;
		}

		struct entry* oldest = NULL;
		routing_oldest(&oldest);
		while(oldest != NULL) {
			if(difftime(now, oldest->expire) < 0)
				break;
			dbg("============ Ping uncertain node");

			struct sockaddr_in dest = {0};
			dest.sin_family = AF_INET;
			dest.sin_addr.s_addr = oldest->addr.ip;
			dest.sin_port = oldest->addr.port;
			int rc = send_ping(dht, &dht->self, now, dht->sfd, (const struct sockaddr*)&dest, sizeof(dest), &msgbuff);
			if(rc == PROTO_ENOREQ) {
				dht->pause = true;
				return 0;
			} else if(rc != 0) {
				fatal("NOPE %d", rc);
				return 0;
			}

			oldest->expire = now + 30;
			routing_oldest(&oldest);
		}

		return 0;
	}
	printf("Received packet from %s:%d\n", inet_ntoa(remote->sin_addr), ntohs(remote->sin_port));
	
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

	if(discard){
		return 0;
	}

	if(type == CT_RESPONSE) {
		uint32_t transaction_number;

		if(!transaction_set) {
			err("DISCARD: No transaction in response");
			return 0;
		}

		// Temporary null terminate the string to parse the number without a copy
		char* end;
		dbg("Transaction %s", transaction);
		transaction_number = strtol(transaction, &end, 10);

		if(end != transaction+transaction_len) {
			err("DISCARD: Transaction id is not a number %.*s", (int)transaction_len, transaction);
			return 0;
		}

		uint16_t reqId;
		if(!find_req(dht, transaction_number, &reqId)) {
			err("DISCARD: unknown transaction id %d", transaction_number);
			return 0;
		}
		dbg("Transaction id matches request %d", reqId);

		if(sockaddr_cmp((struct sockaddr*)&dht->requestdata[reqId].addr, (struct sockaddr*)remote) != 0) {
			err("DISCARD: Unexpected IP for valid transaction");
			return 0;
		}

		int rc = dht->requestdata[reqId].fun(dht, now, buff, recv_len, dht->sfd, (struct sockaddr*)remote, remote_len, &msgbuff);
		if(rc == PROTO_EDISC) {
			dht->pause = true;
			return 0;
		}

		dht->requestdata[reqId].fun = NULL;
		dht->requestdata[reqId].timeout_fun = NULL;
		dht->requestdata[reqId].timeout = 0;
		dht->reqalloc[reqId] = false;
		dht->pause = false;
	} else if(type == CT_QUERY) { // Must be a query
		if(!query_set)
			fatal("No query function in query request");
		if(!transaction_set)
			fatal("No transaction in request");

		assert(strlen(query) == query_len);

		assert(*msgbuff.messages < msgbuff.messages_end);
		struct message* message = *msgbuff.messages;

		char* end = message->payload+128;
		char* cursor = message->payload;

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

		rc = handle_request(&dht->self, query, buff, recv_len, &cursor, end-cursor-1);
		if(rc == QUERY_EUNK) {
			dbg("DISCARD: Unknown query method");
			return 0;
		} else if(rc != 0) fatal("Error handling request");

		rc = snprintf(cursor, end-cursor, "e");
		if(rc < 0)
			return EPERM;
		cursor += rc;
		assert(cursor < end);

		message->payload_len = cursor - message->payload;

		memcpy(&message->dest, remote, remote_len);
		message->dest_len = remote_len;
		(*msgbuff.messages)++;
	}

	return 0;
}

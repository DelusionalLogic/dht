#include "proto.h"

#include "benc.h"
#include "query.h"
#include "log.h"
#include "metrics.h"
#include "peers.h"

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
#include <arpa/inet.h>

#if UINT8_MAX > RAND_MAX
#error UINT8_MAX is larger than RAND_MAX
#endif
uint8_t rand_byte() {
	int limit = (RAND_MAX / UINT8_MAX)*UINT8_MAX;
	int val;
	while((val = rand()) >= limit);

	return val % UINT8_MAX;
}

void token_create(struct tokens* tokens, time_t now, struct addr* remote, char* token) {
	assert(tokens->head < TOKEN_KNUM);
	if(difftime(now, tokens->issued[tokens->head]) >= TOKEN_ITMO) {
		// We can no longer issue for this ticket
		tokens->head = (tokens->head + 1) % TOKEN_KNUM;

		// The ticket we are going to overwrite should be ineligible for validation
		assert(difftime(now, tokens->issued[tokens->head]) >= TOKEN_VTMO);

		tokens->issued[tokens->head] = now;
		for(size_t i = 0; i < TOKEN_TLEN; i++) {
			tokens->ticket[tokens->head][i] = rand_byte();
		}
	}

	sha256_init(&tokens->ctx);
	sha256_update(&tokens->ctx, (unsigned char*)&remote->ip, sizeof(uint32_t));
	sha256_update(&tokens->ctx, (unsigned char*)&remote->port, sizeof(uint16_t));
	sha256_update(&tokens->ctx, (unsigned char*)tokens->ticket[tokens->head], TOKEN_TLEN);
	sha256_final(&tokens->ctx, (unsigned char*)token);
}

int token_validate(struct tokens* tokens, time_t now, struct addr* remote, char* token) {
	assert(tokens->head < TOKEN_KNUM);
	size_t i = tokens->head;
	char buf[SHA256_BLOCK_SIZE];
	while(true) {
		if(difftime(now, tokens->issued[i]) >= TOKEN_VTMO) {
			// If we are outside the validation timeout, we know that all the ones before us were too
			break;
		}

		sha256_init(&tokens->ctx);
		sha256_update(&tokens->ctx, (unsigned char*)&remote->ip, sizeof(uint32_t));
		sha256_update(&tokens->ctx, (unsigned char*)&remote->port, sizeof(uint16_t));
		sha256_update(&tokens->ctx, (unsigned char*)tokens->ticket[i], TOKEN_TLEN);
		sha256_final(&tokens->ctx, (unsigned char*)buf);

		if(memcmp(buf, token, SHA256_BLOCK_SIZE) == 0) {
			return TOK_VALI;
		}

		i = (i + TOKEN_KNUM - 1) % TOKEN_KNUM;
		if(i == tokens->head) {
			// We've gone through all the tickets
			break;
		}
	}
	return TOK_INVA;
}

#define MAX(a, b)                \
	({                           \
		__typeof__ (a) _a = (a); \
		__typeof__ (b) _b = (b); \
		_a > _b ? _a : _b;       \
	})

#define MIN(a, b)                \
	({                           \
		__typeof__ (a) _a = (a); \
		__typeof__ (b) _b = (b); \
		_a < _b ? _a : _b;       \
	})

#define CLAMP(a, b, c)           \
	MAX(MIN(a, c), b)


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
PROCESS_TIMEOUT(getclient_timeout);

// Number of nodeid bits
#define IDBITS 160
#if IDBITS > RAND_MAX
#error IDBITS is larger than RAND_MAX
#endif
uint8_t rand_bucket() {
	int limit = (RAND_MAX / IDBITS)*IDBITS;
	int val;
	while((val = rand()) >= limit);

	return val % IDBITS;
}

int write_find_node(char* buff, size_t* buff_len, struct nodeid* self, struct nodeid* target, uint16_t tid) {
	char* buff_end = buff + *buff_len;

	int rc = snprintf(buff, buff_end - buff, "d1:ad2:id20:");
	if(rc < 0)
		fatal("Failed to write packet");
	buff += rc;
	memcpy(buff, self, sizeof(struct nodeid));
	buff += sizeof(struct nodeid);
	rc = snprintf(buff, buff_end - buff, "6:target20:");
	if(rc < 0)
		fatal("Failed to write packet");
	buff += rc;
	memcpy(buff, target, sizeof(struct nodeid));
	buff += sizeof(struct nodeid);
	rc = snprintf(buff, buff_end - buff, "e1:q9:find_node1:t%d:%d1:y1:qe", tid == 0 ? 1 : (int)(log10(tid)+1), tid);
	if(rc < 0)
		fatal("Failed to write packet");
	buff += rc;

	*buff_len = buff - (buff_end - *buff_len);
	return 0;
}

int send_ping(struct dht* dht, struct nodeid* expected, time_t now, bool node_is_new, const struct sockaddr* dest_addr, socklen_t dest_len, struct msgbuff* msgbuff) {
	if(*msgbuff->messages >= msgbuff->messages_end)
		return PROTO_ENOREQ;
	struct message* message = *msgbuff->messages;

	uint16_t reqId;
	if(!alloc_req(dht, &reqId)) {
		return PROTO_ENOREQ;
	}

	memcpy(&message->dest, dest_addr, dest_len);
	message->dest_len = dest_len;

	struct ping* data = &dht->requestdata[reqId].cont.ping;
	if(!node_is_new) {
		data->remote_id = *expected;
	} else {
		expected = &dht->self;
	}
	data->is_new = node_is_new;
	data->attempt = 0;

	dht->requestdata[reqId].fun = &getclient_response;
	dht->requestdata[reqId].timeout = now + PROTO_TMOUT;
	dht->requestdata[reqId].timeout_fun = &getclient_timeout;
	memcpy(&dht->requestdata[reqId].addr, dest_addr, dest_len);
	dht->requestdata[reqId].addr_len = dest_len;

	struct nodeid target = rand_nodeid_in_bucket(&dht->self, expected);

	message->payload_len = sizeof(message->payload);
	int rc = write_find_node(message->payload, &message->payload_len, &dht->self, &target, reqId);
	if(rc != 0) {
		return rc;
	}
	(*msgbuff->messages)++;

	return 0;
}

int send_announce(struct dht* dht, struct nodeid* expected, time_t now, bool node_is_new, const struct sockaddr* dest_addr, socklen_t dest_len, struct msgbuff* msgbuff) {
	if(*msgbuff->messages >= msgbuff->messages_end)
		return PROTO_ENOREQ;
	struct message* message = *msgbuff->messages;

	uint16_t reqId;
	if(!alloc_req(dht, &reqId)) {
		return PROTO_ENOREQ;
	}

	memcpy(&message->dest, dest_addr, dest_len);
	message->dest_len = dest_len;

	struct ping* data = &dht->requestdata[reqId].cont.ping;
	if(!node_is_new) {
		data->remote_id = *expected;
	} else {
		expected = &dht->self;
	}
	data->is_new = node_is_new;
	data->attempt = 0;

	dht->requestdata[reqId].fun = &getclient_response;
	dht->requestdata[reqId].timeout = now + PROTO_TMOUT;
	dht->requestdata[reqId].timeout_fun = &getclient_timeout;
	memcpy(&dht->requestdata[reqId].addr, dest_addr, dest_len);
	dht->requestdata[reqId].addr_len = dest_len;

	struct nodeid target = rand_nodeid_in_bucket(&dht->self, expected);

	message->payload_len = sizeof(message->payload);
	int rc = write_find_node(message->payload, &message->payload_len, &dht->self, &target, reqId);
	if(rc != 0) {
		return rc;
	}
	(*msgbuff->messages)++;

	return 0;
}

PROCESS_TIMEOUT(getclient_timeout) {
	// @HACK: This really sucks. maybe we should just pass in the request id
	size_t reqId = (typeof(dht->requestdata[0])*)((void*)cont - offsetof(typeof(dht->requestdata[0]), cont)) - dht->requestdata;

	if(cont->ping.attempt >= 2) {
		dbg("Timing out request %ld after %d attempts", reqId, cont->ping.attempt);
		if(cont->ping.is_new)
			return 0;

		routing_remove(&cont->ping.remote_id);
		return 0;
	}

	dbg("Retrying request %ld", reqId);

	if(*msgbuff->messages >= msgbuff->messages_end)
		return PROTO_ENOREQ;
	struct message* message = *msgbuff->messages;

	memcpy(&message->dest, &dht->requestdata[reqId].addr, dht->requestdata[reqId].addr_len);
	message->dest_len = dht->requestdata[reqId].addr_len;

	struct nodeid *remote;
	if(!cont->ping.is_new) {
		remote = &dht->requestdata[reqId].cont.ping.remote_id;
	} else {
		remote = &dht->self;
	}
	struct nodeid target = rand_nodeid_in_bucket(&dht->self, remote);

	message->payload_len = sizeof(message->payload);
	int rc = write_find_node(message->payload, &message->payload_len, &dht->self, &target, reqId);
	if(rc != 0) {
		fatal("Can't create ping");
	}
	(*msgbuff->messages)++;

	dht->requestdata[reqId].timeout = now + PROTO_TMOUT;
	cont->ping.attempt++;
	return PROTO_EDISC;
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
				case -BENC_EBADP:
					fatal("Bad dict");
			}
		}

		if(parts < 2) {
			err("Response didn't contain nodes and id");
			return PROTO_EDISC;
		}
	}

	// The response was good, so save the node
	if(cont->ping.is_new) {
		struct entry* entry;
		if(routing_offer(&id, &entry)) {
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)remote;
			entry->addr.ip = ipv4->sin_addr.s_addr;
			entry->addr.port = ipv4->sin_port;
			entry->expire = now + PROTO_UNCTM;
		} else {
			dbg("We are no longer interested");
		}

	} else {
		struct entry* entry = routing_get(&id);
		// @CLEANUP: Figure out why this can be null. Is the node getting
		// removed while we are waiting for a response?
		if(entry != NULL) {
			entry->expire = now + PROTO_UNCTM;
		}
	}

	uint8_t accepted = 0;
	// Fan out the search if the results were interesting
	for(uint8_t i = 0; i < nodes_len; i++) {
		// @ROBUST: Some nodes report a bunch of nodes in the same ip. Maybe we
		// could check for that here

		struct sockaddr_in dest = {
			.sin_family = AF_INET,
			.sin_addr = ips[i],
			.sin_port = ports[i],
		};

		if(routing_interested(&nodes[i])) {
			accepted++;
			int rc = send_ping(dht, &nodes[i], now, true, (struct sockaddr*)&dest, sizeof(struct sockaddr_in), msgbuff);
			if(rc == PROTO_ENOREQ) {
				return rc;
			} else if(rc != 0) {
				fatal("send_ping failed %d", rc);
			}
		}
	}

	dbg("Node provided %d nodes. %d of them were useful", nodes_len, accepted);

	return 0;
}

enum commandType {
	CT_UNK,
	CT_QUERY,
	CT_RESPONSE,
	CT_ERROR,
};

void proto_begin(struct dht* dht, time_t now, struct message** output, const struct message* const output_end) {
	struct msgbuff msgbuff = {
		output,
		output_end,
	};
	dht->pause = false;

	for(int i = 0; i < MAX_INFLIGHT; i++) {
		dht->reqalloc[i] = false;
	}

	dbgl_id(&dht->self);

	dht->sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(dht->sfd == -1) {
		err("Failed creating socket");
		exit(1);
	}
	struct sockaddr_in bindAddr = {0};
	bindAddr.sin_family = AF_INET;
	bindAddr.sin_port = htons(6886);
	bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(dht->sfd, (struct sockaddr*)&bindAddr, sizeof(struct sockaddr_in)) != 0) {
		err("Bind failed");
		// We should bail here, but the tests need this to be unhandled
	}

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
		send_ping(dht, NULL, now, true, cur->ai_addr, cur->ai_addrlen, &msgbuff);
	}

	freeaddrinfo(res);
}

void proto_end(struct dht* dht) {
	close(dht->sfd);
}

int handle_packet(struct dht* dht, time_t now, enum commandType type, char* transaction, size_t transaction_len, char* query, size_t query_len, char* packet, size_t packet_len, struct sockaddr_in* remote, socklen_t remote_len, struct msgbuff* msgbuff) {
	if(type == CT_RESPONSE) {
		uint32_t transaction_number;

		if(transaction == NULL) {
			err("DISCARD: No transaction in response");
			return 0;
		}

		// Temporary null terminate the string to parse the number without a copy
		char* end;
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
		dbg("Request %d gets a response", reqId);

		if(sockaddr_cmp((struct sockaddr*)&dht->requestdata[reqId].addr, (struct sockaddr*)remote) != 0) {
			err("DISCARD: Unexpected IP for valid transaction");
			return 0;
		}

		dht->pause = false;
		int rc = dht->requestdata[reqId].fun(dht, now, &dht->requestdata[reqId].cont, packet, packet_len, dht->sfd, (struct sockaddr*)remote, remote_len, msgbuff);
		if(rc == PROTO_ENOREQ) {
			dht->pause = true;
		} else if(rc == PROTO_EDISC) {
			return 0;
		}

		dht->requestdata[reqId].fun = NULL;
		dht->requestdata[reqId].timeout_fun = NULL;
		dht->requestdata[reqId].timeout = 0;
		dht->reqalloc[reqId] = false;
	} else if(type == CT_QUERY) { // Must be a query
		if(transaction == NULL)
			fatal("No transaction in request");
		if(transaction_len > 16) {
			prom_counter_inc(queries, (const char *[]){"discard"});
			err("DISCARD: Transaction ID is too long");
			return 0;
		}

		assert(*msgbuff->messages < msgbuff->messages_end);
		struct message* message = *msgbuff->messages;

		char* end = message->payload+sizeof(message->payload);
		char* cursor = message->payload;

		int rc;

		rc = snprintf(cursor, end-cursor , "d1:r");
		if(rc < 0)
			fatal("No space for response");
		cursor += rc;

		char respType = 'r';
		rc = handle_request(&dht->self, &dht->tokens, now, query, (const struct sockaddr*)remote, remote_len, packet, packet_len, &cursor, end-cursor-1);
		if(rc == QUERY_EUNK) {
			prom_counter_inc(queries, (const char *[]){"unknown"});
			// @FRAGILE: @HACK: Static offsets to fiddle with already written
			// out packet data. Acceptable because this is the uncommon error
			// case.
			respType = 'e';
			// The r key is called e for errors
			*(cursor-1) = 'e';

			// Now create the payload
			rc = snprintf(cursor, end-cursor, "li204e14:Unknown Methode");
			if(rc < 0)
				fatal("No space for response");
			cursor += rc;
			assert(cursor < end);

			// Use the normal finalize flow
		} else if(rc == QUERY_EBADQ) {
			prom_counter_inc(queries, (const char *[]){"badquery"});
			// @FRAGILE: @HACK: Static offsets to fiddle with already written
			// out packet data. Acceptable because this is the uncommon error
			// case.
			respType = 'e';
			// The r key is called e for errors
			*(cursor-1) = 'e';

			// Now create the payload
			rc = snprintf(cursor, end-cursor, "li204e11:Bad Requeste");
			if(rc < 0)
				fatal("No space for response");
			cursor += rc;
			assert(cursor < end);

			// Use the normal finalize flow
		} else if(rc == 0) prom_counter_inc(queries, (const char *[]){"ok"});
		else fatal("Error handling request");

		rc = snprintf(cursor, end-cursor , "1:t%ld:", transaction_len);
		if(rc < 0)
			fatal("No space for response");
		cursor += rc;
		memcpy(cursor, transaction, transaction_len);
		cursor += transaction_len;
		rc = snprintf(cursor, end-cursor, "1:y1:%ce", respType);
		if(rc < 0)
			fatal("No space for response");
		cursor += rc;

		assert(cursor < end);
		message->payload_len = cursor - message->payload;

		memcpy(&message->dest, remote, remote_len);
		message->dest_len = remote_len;
		(*msgbuff->messages)++;
	} else if(type == CT_ERROR) {
		dbg("Unhandled error");
	} else {
		dbg("Unknown request type");
	}

	return 0;
}

static void recalulate_waketime(struct dht *dht) {
	dht->wake = 0;
	if(!dht->pause){
		struct entry* oldest;
		routing_oldest(&oldest);
		if(oldest != NULL)
			dht->wake = oldest->expire;
	}

	for(int i = 0; i < MAX_INFLIGHT; i++) {
		if(!dht->reqalloc[i])
			continue;

		time_t timeout = dht->requestdata[i].timeout;
		if(dht->wake == 0 || (timeout != 0 && difftime(timeout, dht->wake) < 0))
			dht->wake = timeout;
	}
}

int proto_run(struct dht* dht, char* buff, size_t recv_len, struct sockaddr_in* remote, socklen_t remote_len, time_t now, struct message** output, const struct message* const output_end) {
	struct msgbuff msgbuff = {
		output,
		output_end,
	};

	if(recv_len == 0 && buff == NULL) {
		uint8_t timedout = 0;
		for(int i = 0; i < MAX_INFLIGHT; i++) {
			if(!dht->reqalloc[i])
				continue;
			if(dht->requestdata[i].timeout == 0)
				continue;
			if(difftime(now, dht->requestdata[i].timeout) < 0)
				continue;

			prom_counter_inc(retries, NULL);
			int rc = dht->requestdata[i].timeout_fun(dht, &dht->self, now, &dht->requestdata[i].cont, &msgbuff);

			if(rc == PROTO_ENOREQ) {
				dht->pause = true;
				recalulate_waketime(dht);
				return 0;
			}
			if(rc != PROTO_EDISC) {
				dht->requestdata[i].fun = NULL;
				dht->requestdata[i].timeout_fun = NULL;
				dht->requestdata[i].timeout = 0;
				dht->reqalloc[i] = false;

				dht->pause = false;
			}
		}
		if(timedout != 0) {
			dbg("processed %d requests that timed out", timedout);
		}

		struct entry* oldest = NULL;
		routing_oldest(&oldest);
		while(oldest != NULL) {
			if(difftime(now, oldest->expire) < 0)
				break;

			struct sockaddr_in dest = {0};
			dest.sin_family = AF_INET;
			dest.sin_addr.s_addr = oldest->addr.ip;
			dest.sin_port = oldest->addr.port;
			int rc = send_ping(dht, &oldest->id, now, false, (const struct sockaddr*)&dest, sizeof(dest), &msgbuff);
			if(rc == PROTO_ENOREQ) {
				dht->pause = true;
				recalulate_waketime(dht);
				return 0;
			} else if(rc != 0) {
				fatal("NOPE %d", rc);
			}

			oldest->expire = 0;
			routing_oldest(&oldest);
		}

		// @HACK 0 means unitialized, only happens in tests
		if(peer_table_size != 0) {
			expire_hashes(now);
		}

		recalulate_waketime(dht);
		return 0;
	}

	struct bcursor bcursor;
	struct benc_node stream[256];
	bcur_open(&bcursor, buff, buff+recv_len, stream, 256);

	if(bcursor.readhead->type != BNT_DICT) {
		fatal("First value is not a dict");
	}
	bcur_next(&bcursor, 1);

	enum commandType type = CT_UNK;
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
				break;
			}
			case -BENC_EBADP:
				fatal("Bad dict");
		}
	}

	recalulate_waketime(dht);

	int rc = handle_packet(dht, now, type, transaction_set ? transaction : NULL, transaction_len, query_set ? query : NULL, query_len, buff, recv_len, remote, remote_len, &msgbuff);
	assert(rc == 0);

	// Debug output

	{
		printf("In flight |");
		uint16_t inflight = 0;
		for(int i = 0; i < MAX_INFLIGHT; i++) {
			if(dht->reqalloc[i]) {
				printf("#");
				inflight++;
			} else {
				printf(" ");
			}
		}
		printf("|\n");
		prom_gauge_set(requestsInFlight, inflight, NULL);
	}
	{
		int filled;
		int total;
#define LFACLEN 64
		double load_factor[LFACLEN] = {0};
		routing_status(&filled, &total, load_factor, LFACLEN);
		prom_gauge_set(activeNodes, filled, NULL);
		dbg("%d/%d nodes in routing table", filled, total);

#define GRAPHY 5
		// @HACK @CLEANUP: I'm pretty zooted right now. I have zero confidence
		// that this is correct. It looks allright though.
		for(int y = 0; y < GRAPHY; y++) {
			printf("|");
			for(int x = 0; x < LFACLEN; x++) {
				double cell_load = CLAMP((load_factor[x] - ((1.0/GRAPHY) * (GRAPHY-y-1))) * GRAPHY, 0, 1);
				if(cell_load == 0.0) {
					printf(" ");
				} else if (cell_load > 1.0 - 1.0/GRAPHY) {
					printf("#");
				} else {
					printf("%d", (int)(cell_load*10));
				}
			}
			printf("|\n");
		}
#undef GRAPHY
#undef LFACLEN
	}

	return 0;
}

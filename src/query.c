#include "query.h"
#include "benc.h"
#include "log.h"
#include "peers.h"
#include "sha256.h"

#include <string.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>

int handle_request(struct nodeid* self, struct tokens *tokens, time_t now, const char* method, const struct sockaddr* src, socklen_t src_len, const char* packet, size_t packet_len, char** response, size_t response_len) {
	if(method == NULL) {
		return QUERY_EBADQ;
	}

	if(strcmp(method, "ping") == 0) {
		struct bcursor bcursor;
		struct benc_node stream[256];
		bcur_open(&bcursor, packet, packet+packet_len, stream, 256);

		if(bcursor.readhead->type != BNT_DICT) {
			err("Bad query: Packet is not a dict");
			return QUERY_EBADQ;
		}
		if(bcur_next(&bcursor, 1) < 0) {
			err("Bad query: No token after outer dict start");
			return QUERY_EBADQ;
		}

		if(bcur_find_key(&bcursor, (const enum benc_nodetype[]){BNT_STRING}, (const char*[]){"a"}, (const size_t[]){1}, 1) != 0) {
			err("Bad query: No arguments to request");
			return QUERY_EBADQ;
		}
		bcur_next(&bcursor, 1);
		if(bcursor.readhead->type != BNT_DICT) {
			err("Bad query: Wrong value type for request");
			return QUERY_EBADQ;
		}
		// Skip the dict element
		bcur_next(&bcursor, 1);
		bool source_set = false;
		struct nodeid source_id;
		while(bcursor.readhead->type != BNT_END) {
			switch(bcur_find_key(&bcursor, (const enum benc_nodetype[]){BNT_STRING}, (const char*[]){"id"}, (const size_t[]){6}, 1)) {
				case 0:
					// Skip the key
					bcur_next(&bcursor, 1);

					if(bcursor.readhead->type != BNT_STRING) {
						err("Bad query: Wrong value type for id");
						return QUERY_EBADQ;
					}

					if(bcursor.readhead->size != 20) {
						err("Bad query: Incorrect id length");
						return QUERY_EBADQ;
					}

					source_set = true;
					memcpy(&source_id, bcursor.readhead->loc, 20);

					// Skip the value
					bcur_next(&bcursor, 1);
					break;
				case -BENC_EBADP:
					fatal("Bad dict");
			}
		}

		if(!source_set) {
			err("Id argument not set");
			return QUERY_EBADQ;
		}

		char* end = (*response) + response_len;

		int rc = snprintf(*response, end-*response, "d2:id20:");
		if(rc < 0)
			return QUERY_EBADQ;
		*response += rc;
		memcpy(*response, self, sizeof(struct nodeid));
		*response += sizeof(struct nodeid);
		rc = snprintf(*response, end-*response, "e");
		if(rc < 0)
			return QUERY_EBADQ;
		*response += rc;
	} else if(strcmp(method, "find_node") == 0) {
		struct bcursor bcursor;
		struct benc_node stream[256];
		bcur_open(&bcursor, packet, packet+packet_len, stream, 256);

		if(bcursor.readhead->type != BNT_DICT) {
			err("Bad query: Packet is not a dict");
			return QUERY_EBADQ;
		}
		if(bcur_next(&bcursor, 1) < 0) {
			err("Bad query: No token after outer dict start");
			return QUERY_EBADQ;
		}

		if(bcur_find_key(&bcursor, (const enum benc_nodetype[]){BNT_STRING}, (const char*[]){"a"}, (const size_t[]){1}, 1) != 0) {
			err("Bad query: No arguments to request");
			return QUERY_EBADQ;
		}
		bcur_next(&bcursor, 1);
		if(bcursor.readhead->type != BNT_DICT) {
			err("Bad query: Wrong value type for request");
			return QUERY_EBADQ;
		}
		// Skip the dict element
		bcur_next(&bcursor, 1);
		bool target_set = false;
		struct nodeid target;
		while(bcursor.readhead->type != BNT_END) {
			switch(bcur_find_key(&bcursor, (const enum benc_nodetype[]){BNT_STRING}, (const char*[]){"target"}, (const size_t[]){6}, 1)) {
				case 0:
					// Skip the key
					bcur_next(&bcursor, 1);

					if(bcursor.readhead->type != BNT_STRING) {
						err("Bad query: Wrong value type for id");
						return QUERY_EBADQ;
					}

					if(bcursor.readhead->size != 20) {
						err("Bad query: Incorrect target length");
						return QUERY_EBADQ;
					}

					target_set = true;
					memcpy(&target, bcursor.readhead->loc, 20);

					// Skip the value
					bcur_next(&bcursor, 1);
					break;
				case -BENC_EBADP:
					fatal("Bad dict");
			}
		}

		if(!target_set) {
			err("Target argument not set");
			return QUERY_EBADQ;
		}

		// Actually do the handling
		struct entry* closest[8];
		int found = routing_closest(&target, 8, closest);

		char* end = (*response) + response_len;

		int rc = snprintf(*response, end-*response, "d2:id20:");
		if(rc < 0)
			return QUERY_EBADQ;
		*response += rc;
		assert(*response < end);

		memcpy(*response, self, sizeof(struct nodeid));
		*response += sizeof(struct nodeid);
		assert(*response < end);

		rc = snprintf(*response, end-*response, "5:nodes%d:", found*26);
		if(rc < 0)
			return QUERY_EBADQ;
		*response += rc;
		assert(*response < end);

		for(int i = 0; i < found; i++) {
			memcpy(*response, &closest[i]->id, sizeof(struct nodeid));
			*response += sizeof(struct nodeid); // 20
			assert(*response < end);
			memcpy(*response, &closest[i]->addr.ip, sizeof(uint32_t));
			*response += sizeof(uint32_t); // 4
			assert(*response < end);
			memcpy(*response, &closest[i]->addr.port, sizeof(uint16_t));
			*response += sizeof(uint16_t); // 2
			assert(*response < end);
		}

		rc = snprintf(*response, end-*response, "e");
		if(rc < 0)
			return QUERY_EBADQ;
		*response += rc;
		assert(*response < end);
	} else if(strcmp(method, "get_peers") == 0) {
		struct bcursor bcursor;
		struct benc_node stream[256];
		bcur_open(&bcursor, packet, packet+packet_len, stream, 256);

		if(bcursor.readhead->type != BNT_DICT) {
			err("Bad query: Packet is not a dict");
			return QUERY_EBADQ;
		}
		if(bcur_next(&bcursor, 1) < 0) {
			err("Bad query: No token after outer dict start");
			return QUERY_EBADQ;
		}

		if(bcur_find_key(&bcursor, (const enum benc_nodetype[]){BNT_STRING}, (const char*[]){"a"}, (const size_t[]){1}, 1) != 0) {
			err("Bad query: No arguments to request");
			return QUERY_EBADQ;
		}
		bcur_next(&bcursor, 1);
		if(bcursor.readhead->type != BNT_DICT) {
			err("Bad query: Wrong value type for request");
			return QUERY_EBADQ;
		}
		// Skip the dict element
		bcur_next(&bcursor, 1);
		bool infohash_set = false;
		struct infohash infohash;
		while(bcursor.readhead->type != BNT_END) {
			switch(bcur_find_key(&bcursor, (const enum benc_nodetype[]){BNT_STRING}, (const char*[]){"info_hash"}, (const size_t[]){9}, 1)) {
				case 0:
					// Skip the key
					bcur_next(&bcursor, 1);

					if(bcursor.readhead->type != BNT_STRING) {
						err("Bad query: Wrong value type for info_hash");
						return QUERY_EBADQ;
					}

					if(bcursor.readhead->size != 20) {
						err("Bad query: Incorrect target length");
						return QUERY_EBADQ;
					}

					infohash_set = true;
					memcpy(&infohash, bcursor.readhead->loc, 20);

					// Skip the value
					bcur_next(&bcursor, 1);
					break;
				case -BENC_EBADP:
					fatal("Bad dict");
			}
		}

		if(!infohash_set) {
			err("info_hash argument not provided");
			return QUERY_EBADQ;
		}

		struct addr src_addr;
		{
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)src;
			src_addr.ip = ipv4->sin_addr.s_addr;
			src_addr.port = ipv4->sin_port;
		}

		char* end = (*response) + response_len;

		int rc = snprintf(*response, end-*response, "d2:id20:");
		if(rc < 0)
			return QUERY_EBADQ;
		*response += rc;
		assert(*response < end);

		memcpy(*response, self, sizeof(struct nodeid));
		*response += sizeof(struct nodeid);
		assert(*response < end);

		struct addr* peers;
		size_t peers_len;
		get_peers(&infohash, &peers, &peers_len);

		char token[SHA256_BLOCK_SIZE];
		token_create(tokens, now, &src_addr, token);

		if(peers != NULL) {
			rc = snprintf(*response, end-*response, "5:token%ld:%.*s", sizeof(token), (int)sizeof(token), token);
			if(rc < 0)
				return QUERY_EBADQ;
			*response += rc;
			assert(*response < end);

			rc = snprintf(*response, end-*response, "6:valuesl");
			if(rc < 0)
				return QUERY_EBADQ;
			*response += rc;
			assert(*response < end);

			for(int i = 0; i < peers_len; i++) {
				*(*response) = '6';
				*(*response+1) = ':';
				(*response) += 2;
				memcpy(*response, &peers[i].ip, sizeof(uint32_t));
				*response += sizeof(uint32_t); // 4
				assert(*response < end);
				memcpy(*response, &peers[i].port, sizeof(uint16_t));
				*response += sizeof(uint16_t); // 2
				assert(*response < end);
			}

			(**response) = 'e';
			(*response)++;
			assert(*response < end);
		} else {
			// If we didn't get any peers we send back the closest nodes
			struct entry* closest[8];
			int found = routing_closest((struct nodeid*)&infohash, 8, closest);

			rc = snprintf(*response, end-*response, "5:nodes%d:", found*26);
			if(rc < 0)
				return QUERY_EBADQ;
			*response += rc;
			assert(*response < end);

			for(int i = 0; i < found; i++) {
				memcpy(*response, &closest[i]->id, sizeof(struct nodeid));
				*response += sizeof(struct nodeid); // 20
				assert(*response < end);
				memcpy(*response, &closest[i]->addr.ip, sizeof(uint32_t));
				*response += sizeof(uint32_t); // 4
				assert(*response < end);
				memcpy(*response, &closest[i]->addr.port, sizeof(uint16_t));
				*response += sizeof(uint16_t); // 2
				assert(*response < end);
			}

			int pos;
			rc = snprintf(*response, end-*response, "5:token%ld:%n%*s", sizeof(token), &pos, (int)sizeof(token), " ");
			memcpy((*response) + pos, token, sizeof(token));
			if(rc < 0)
				return QUERY_EBADQ;
			*response += rc;
			assert(*response < end);
		}

		rc = snprintf(*response, end-*response, "e");
		if(rc < 0)
			return QUERY_EBADQ;
		*response += rc;
		assert(*response < end);
	} else if(strcmp(method, "announce_peer") == 0) {
		struct bcursor bcursor;
		struct benc_node stream[256];
		bcur_open(&bcursor, packet, packet+packet_len, stream, 256);

		if(bcursor.readhead->type != BNT_DICT) {
			err("Bad query: Packet is not a dict");
			return QUERY_EBADQ;
		}
		if(bcur_next(&bcursor, 1) < 0) {
			err("Bad query: No token after outer dict start");
			return QUERY_EBADQ;
		}

		if(bcur_find_key(&bcursor, (const enum benc_nodetype[]){BNT_STRING}, (const char*[]){"a"}, (const size_t[]){1}, 1) != 0) {
			err("Bad query: No arguments to request");
			return QUERY_EBADQ;
		}
		bcur_next(&bcursor, 1);
		if(bcursor.readhead->type != BNT_DICT) {
			err("Bad query: Wrong value type for request");
			return QUERY_EBADQ;
		}
		// Skip the dict element
		bcur_next(&bcursor, 1);

		bool implied_port = false;

		bool infohash_set = false;
		struct infohash infohash;

		bool port_set = false;
		uint16_t port;

		bool token_set = false;
		char token[SHA256_BLOCK_SIZE];

		while(bcursor.readhead->type != BNT_END) {
			switch(bcur_find_key(&bcursor, (const enum benc_nodetype[]){BNT_STRING, BNT_STRING, BNT_STRING, BNT_STRING}, (const char*[]){"implied_port", "info_hash", "port", "token"}, (const size_t[]){12, 9, 4, 5}, 4)) {
				case 0:
					// Skip the key
					bcur_next(&bcursor, 1);

					if(bcursor.readhead->type != BNT_INT) {
						err("Bad query: Wrong value type for implied_port");
						return QUERY_EBADQ;
					}

					if(*bcursor.readhead->loc == '0') {
						implied_port = false;
					} else {
						implied_port = true;
					}

					// Skip the value
					bcur_next(&bcursor, 1);
					break;
				case 1:
					// Skip the key
					bcur_next(&bcursor, 1);

					if(bcursor.readhead->type != BNT_STRING) {
						err("Bad query: Wrong value type for info_hash");
						return QUERY_EBADQ;
					}

					if(bcursor.readhead->size != 20) {
						err("Bad query: Incorrect info_hash length");
						return QUERY_EBADQ;
					}

					infohash_set = true;
					memcpy(&infohash, bcursor.readhead->loc, 20);

					bcur_next(&bcursor, 1);
					break;
				case 2:
					// Skip the key
					bcur_next(&bcursor, 1);

					if(bcursor.readhead->type != BNT_INT) {
						err("Bad query: Wrong value type for port");
						return QUERY_EBADQ;
					}

					port_set = true;
					port = strtol(bcursor.readhead->loc, NULL, 10);

					bcur_next(&bcursor, 1);
					break;
				case 3:
					// Skip the key
					bcur_next(&bcursor, 1);

					if(bcursor.readhead->type != BNT_STRING) {
						err("Bad query: Wrong value type for token");
						return QUERY_EBADQ;
					}

					if(bcursor.readhead->size != SHA256_BLOCK_SIZE) {
						err("Bad query: Incorrect token length");
						return QUERY_EBADQ;
					}

					token_set = true;
					memcpy(&token, bcursor.readhead->loc, SHA256_BLOCK_SIZE);

					bcur_next(&bcursor, 1);
					break;
				case -BENC_EBADP:
					fatal("Bad dict");
			}
		}

		if(!infohash_set || (!implied_port && !port_set) || !token_set) {
			err("Missing argument to query");
			return QUERY_EBADQ;
		}

		{
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)src;
			struct addr src_addr;
			src_addr.ip = ipv4->sin_addr.s_addr;

			src_addr.port = ipv4->sin_port;

			if(token_validate(tokens, now, &src_addr, token) != TOK_VALI) {
				err("Invalid token");
				return QUERY_EBADQ;
			}

			if(!implied_port) {
				src_addr.port = htons(port);
			}
			int rc = add_peer(&infohash, &src_addr, now);
			if(rc == PEER_EFULL) {
			} else if(rc != 0) {
				fatal("Could not add peer (%d)", rc);
			}
		}

		// Write out the response
		char* end = (*response) + response_len;

		int rc = snprintf(*response, end-*response, "d2:id20:");
		if(rc < 0)
			return QUERY_EBADQ;
		*response += rc;
		assert(*response < end);

		memcpy(*response, self, sizeof(struct nodeid));
		*response += sizeof(struct nodeid);
		assert(*response < end);

		(**response) = 'e';
		(*response)++;
		assert(*response < end);

		return 0;
	} else {
		return QUERY_EUNK;
	}

	return 0;
}


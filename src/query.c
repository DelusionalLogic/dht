#include "query.h"
#include "benc.h"
#include "log.h"

#include <string.h>
#include <errno.h>
#include <assert.h>

int handle_request(struct nodeid* self, const char* method, const char* packet, size_t packet_len, char** response, size_t response_len) {
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
	} else {
		return QUERY_EUNK;
	}

	return 0;
}


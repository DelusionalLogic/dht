#pragma once

#include "routing.h"

#define PEER_ENOMEM 1
#define PEER_EFULL 1

struct infohash {
	union {
		uint32_t inner[5];
		char inner_b[20];
	};
};

#define PEERS_PER_HASH 8
struct peer_entry {
	struct infohash key;
	struct addr value[PEERS_PER_HASH];
	size_t value_len;
	bool set;
};

extern struct peer_status {
	size_t peers;
	size_t hashes;
} peer_status;

extern struct peer_entry* peer_table;
extern size_t peer_table_size;
extern size_t peer_table_load;

int allocate_hashtable();
int add_peer(struct infohash* key, struct addr* peer);
void get_peers(struct infohash* infohash, struct addr *peers[PEERS_PER_HASH], size_t *peers_len);

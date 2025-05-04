#pragma once

#include "routing.h"

#define PEER_ENOMEM 1
#define PEER_EFULL 1

#define HASH_TIMEOUT (12 * 60 * 60)

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
	time_t last_seen;
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
int add_peer(struct infohash* infohash, struct addr* peer, time_t now);
void get_peers(struct infohash* infohash, struct addr **peers, size_t *peers_len);

void expire_hashes(time_t now);
void peer_update_metrics();

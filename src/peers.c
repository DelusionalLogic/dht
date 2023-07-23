#include "peers.h"

#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

struct peer_entry* peer_table;
size_t peer_table_size;
size_t peer_table_load;

int allocate_hashtable() {
	peer_table_load = 0;
	peer_table_size = 16;
	peer_table = calloc(peer_table_size, sizeof(struct peer_entry));
	if(peer_table == NULL)
		return PEER_ENOMEM;

	return 0;
}

static uint64_t hash(struct infohash* key, size_t size) {
	uint64_t hash = (key->inner[4] << 4) | key->inner[3];
	return hash % size;
}

static void find(struct peer_entry* table, size_t size, struct infohash* infohash, struct peer_entry** entry) {
	uint64_t key = hash(infohash, size);
	do {
		*entry = &table[key++];
		key %= size;
	} while((*entry)->set && memcmp(&(*entry)->key, infohash, sizeof(struct infohash)) != 0);
}

static int resize(size_t new_size) {
	assert((new_size & (new_size - 1)) == 0); // Power of two
	assert(new_size >= peer_table_load);

	struct peer_entry* new_table = calloc(new_size, sizeof(struct peer_entry));
	if(peer_table == NULL)
		return PEER_ENOMEM;

	for(size_t i = 0; i < peer_table_size; i++) {
		struct peer_entry* entry = &peer_table[i];

		struct peer_entry* new_entry = NULL;
		find(new_table, new_size, &entry->key, &new_entry);

		assert(!new_entry->set);
		*new_entry = *entry;
	}

	free(peer_table);

	peer_table = new_table;
	peer_table_size = new_size;
	return 0;
};

static double load_factor(size_t size, size_t load) {
	return (double)load / (double)size;
}

uint64_t next_pow2(uint64_t x) {
	if(x == 1) return 1;
	uint16_t leading = __builtin_clzl(x-1);
	return 1 << (64 - leading);
}

int add_peer(struct infohash* infohash, struct addr* peer) {
	assert(peer_table_load < peer_table_size);

	if(load_factor(peer_table_size, peer_table_load + 1) > 0.75) {
		int rc = resize(peer_table_size * 2);
		if(rc != 0) return rc;
	}

	struct peer_entry* entry = NULL;
	find(peer_table, peer_table_size, infohash, &entry);

	if(!entry->set) {
		entry->set = true;
		entry->key = *infohash;
		peer_table_load++;
	}

	size_t peern = entry->value_len;
	if(peern == PEERS_PER_HASH)
		return PEER_EFULL;
	assert(peern < PEERS_PER_HASH);
	entry->value[peern] = *peer;
	entry->value_len++;

	return 0;
}

void get_peers(struct infohash* infohash, struct addr *peers[PEERS_PER_HASH], size_t *peers_len) {
	struct peer_entry* entry;
	find(peer_table, peer_table_size, infohash, &entry);

	if(!entry->set) {
		*peers = NULL;
		*peers_len = 0;
		return;
	}

	*peers = entry->value;
	*peers_len = entry->value_len;
}

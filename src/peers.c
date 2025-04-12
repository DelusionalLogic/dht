#include "peers.h"

#include "log.h"
#include "metrics.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

struct peer_status peer_status;
struct peer_entry* peer_table;
size_t peer_table_size;
size_t peer_table_load;

int allocate_hashtable() {
	memset(&peer_status, 0, sizeof(struct peer_status));

	peer_table_load = 0;
	peer_table_size = 16;
	peer_table = calloc(peer_table_size, sizeof(struct peer_entry));
	if(peer_table == NULL)
		return PEER_ENOMEM;

	return 0;
}

static uint64_t hash(struct infohash* key, size_t size) {
	uint64_t x = 5381;
	for(uint8_t i = 0; i < sizeof(key->inner_b); i++) {
		x = ((x << 5) + x) + key->inner_b[i];
	}
	return x % size;
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

int add_peer(struct infohash* infohash, struct addr* peer, time_t now) {
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
		entry->last_seen = now;
		peer_table_load++;
		peer_status.hashes++;
		prom_counter_inc(hashes, NULL);
	}

	entry->last_seen = now;
	size_t peern = entry->value_len;
	if(peern == PEERS_PER_HASH)
		return PEER_EFULL;
	assert(peern < PEERS_PER_HASH);
	entry->value[peern] = *peer;
	entry->value_len++;
	peer_status.peers++;
	prom_counter_inc(peers, NULL);

	return 0;
}

void get_peers(struct infohash* infohash, struct addr **peers, size_t *peers_len) {
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

void expire_hashes(time_t now) {
	assert(peer_table_load < peer_table_size);
	for(size_t i = 0; i < peer_table_size; i++) {
		struct peer_entry *entry = &peer_table[i];
		if(!entry->set) continue;

		if(difftime(now, entry->last_seen + HASH_TIMEOUT) < 0.0) continue;

		// Find the last hash that collides with us
		uint64_t entry_hash = hash(&entry->key, peer_table_size);
		size_t last_in_slot = i;
		while(true) {
			size_t next = (last_in_slot + 1) % peer_table_size;
			assert(next != i);

			// There can't be holes in the chain
			if(!peer_table[next].set) break;

			// If the two hashes are different we've reached the end of the probe chain
			uint64_t next_hash = hash(&peer_table[next].key, peer_table_size);
			if(next_hash != entry_hash) break;

			last_in_slot = next;
		}

		// If some hashes were chained on us, we copy the last one into our slot
		if(last_in_slot != i) {
			*entry = peer_table[last_in_slot];
			entry = &peer_table[last_in_slot];
		}

		// Remove the slot
		entry->set = false;
		prom_counter_inc(hash_expired, NULL);
	}
}

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

static void dbgl_id(struct infohash* id) {
	for(uint8_t i = 0; i < 5; i++) {
		dbgl("0x%08x ", id->inner[i]);
	}
}

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

int infohash_compar(const void* ar, const void* br) {
	return memcmp(ar, br, sizeof(struct infohash));
}

static void check_duplicates() {
	struct infohash *keys = calloc(peer_table_size, sizeof(struct infohash));
	size_t keyi = 0;
	for(size_t i = 0; i < peer_table_size; i++) {
		if(!peer_table[i].set) continue;
		keys[keyi++] = peer_table[i].key;
	}

	qsort(keys, keyi, sizeof(struct infohash), infohash_compar);
	for(size_t i = 1; i < keyi; i++) {
		if(memcmp(&keys[i], &keys[i-1], sizeof(struct infohash)) == 0) {
			fatal("Duplicate key found");
		}
	}
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
	if(new_table == NULL)
		return PEER_ENOMEM;

	for(size_t i = 0; i < peer_table_size; i++) {
		struct peer_entry* entry = &peer_table[i];
		if(!entry->set) continue;

		struct peer_entry* new_entry = NULL;
		find(new_table, new_size, &entry->key, &new_entry);

		// If this new entry is already set, this infohash is already present
		// somehow
		if(new_entry->set) {
			dbgl("Collision detected: ");
			dbgl_id(&new_entry->key);
			dbgl(" and ");
			dbgl_id(&entry->key);
			dbg();
			abort();
		}
		*new_entry = *entry;
	}

	free(peer_table);

	peer_table = new_table;
	peer_table_size = new_size;

	check_duplicates();
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

	if(load_factor(peer_table_size, peer_table_load + 1) > 0.60) {
		int rc = resize(peer_table_size * 2);
		if(rc != 0) return rc;
	}

	struct peer_entry* entry = NULL;
	find(peer_table, peer_table_size, infohash, &entry);

	if(!entry->set) {
		entry->set = true;
		entry->key = *infohash;
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

	peer_update_metrics();
	check_duplicates();
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

	assert(entry->value_len != 0);

	*peers = entry->value;
	*peers_len = entry->value_len;
	prom_counter_add(peers_fetched, entry->value_len, NULL);
}

void expire_hashes(time_t now) {
	assert(peer_table_load < peer_table_size);
	for(size_t i = 0; i < peer_table_size; i++) {
		struct peer_entry *entry = &peer_table[i];
		if(!entry->set) continue;

		if(difftime(now, entry->last_seen + HASH_TIMEOUT) < 0.0) continue;

		// The entry is expired, remove it from the table
		// This is a standard linear probing hashtable removal. current_slot is
		// the "hole" we are currently trying to fill in with something. in
		// doing so we have to find the next connected slot that can go here
		// (has a hash value smaller than the slot index) and copy it in. That
		// leaves us with a new "hole" we then have to fill in.
		// @PERF This is a little naive. In chains with a long series of
		// matching hashes, we will end up copying each. We could probably
		// speed that up a little by allowing reordering.
		size_t current_hole = i;
		size_t head = current_hole;
		while(true) {
			head = (head + 1) % peer_table_size;
			assert(head != i);

			// If there's nothing in the chain that can be copied into the
			// "hole" then we're done. Everything we skipped can stay.
			if(!peer_table[head].set) break;

			// Check if the head slot could have been placed here
			uint64_t next_hash = hash(&peer_table[head].key, peer_table_size);
			if(next_hash <= current_hole) {
				// Then copy it over
				peer_table[current_hole] = peer_table[head];
				// And try to fill in this new "hole"
				current_hole = head;
			}
		}

		peer_table[current_hole].set = false;
		peer_table_load--;
		prom_counter_inc(hash_expired, NULL);
	}

	peer_update_metrics();
	check_duplicates();
}

void peer_update_metrics() {
	time_t now = time(NULL);
	time_t next_expire = -1;
	size_t computed_load = 0;
	for(size_t i = 0; i < peer_table_size; i++) {
		if(!peer_table[i].set) continue;
		computed_load++;
		if(now < peer_table[i].last_seen) dbg("%d was seen after now? (%ld < %ld)", i, now, peer_table[i].last_seen);

		time_t entry_expire = peer_table[i].last_seen + HASH_TIMEOUT;
		next_expire = (next_expire == -1 || entry_expire < next_expire) ? entry_expire : next_expire;
	}
	prom_gauge_set(hash_next_expire, next_expire, NULL);
	assert(computed_load == peer_table_load);

	prom_gauge_set(hashes_size, peer_table_size, NULL);
	prom_gauge_set(current_hashes, (double)peer_table_load, NULL);
}

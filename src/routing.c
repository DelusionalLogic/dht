#include "routing.h"

#include "log.h"

#include <assert.h>
#include <limits.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

// The DHT routing table has a keyspace of 0 -- 2^160 split into buckets of 8.
// When a bucket becomes full, we split it in half. As we further expand the
// routing table we only continue to split the buckets on the side we fall on.
//
// Initially, this may sound like a binary tree (because we split it in two),
// but looking at it as a flat array leads to some interesting intuitions.
// Since we only expand one half of the "tree", the total size is bounded by
// the depth of the tree log2(2^160) == 160.
//
// As a flat array we notice the intrinsic properties of the routing table.
// With a bucket size of 8, the routing table contains 160 * 8 == 1280 nodes.
// As the node ids get less similar to our own our grouping of them becomes
// less detailed. While the bucket we are in contains node very close to us,
// the nodes furthest away from us are grouped in buckets with nodes they
// barely resemble.
//
// +----------------------------+
// | n1 | n2 | n3 | ... | n1280 |
// +----------------------------+
//   More                  Less
//  <--------Similarity-------->
//  <----------Detail---------->
//

struct table {
	struct nodeid myID;
	struct entry table[RT_SIZE];
};

struct table* pTable;

void routing_init(struct nodeid* myid) {
	pTable = malloc(sizeof(struct table));
	pTable->myID = *myid;
	routing_flush();
}

void routing_flush() {
	memset(pTable->table, 0, sizeof(pTable->table));
}

// Calculate the common bit prefix between two node ids.
static uint8_t prefix(struct nodeid* a, struct nodeid* b) {
	uint8_t c = 0;
	for(uint8_t i = 0; i < 5; i++) {
		uint32_t word = a->inner[i] ^ b->inner[i];

		// This word is different, find the location of the difference
		if(word != 0)
			return c + __builtin_clz(word);

		// This word is completely the same
		c += sizeof(word) * CHAR_BIT;
	}

	return c;
}

static int8_t scan(uint16_t baseIndex, struct nodeid* id) {
	assert(baseIndex < RT_SIZE - RT_BSIZE);
	int8_t index = -2;

	for(size_t i = baseIndex; i < baseIndex + RT_BSIZE; i++) {
		if(!pTable->table[i].set) {
			index = index == -2 ? i - baseIndex : index;
			continue;
		}

		if(memcmp(&pTable->table[i].id, id, sizeof(struct nodeid)) == 0) {
			return -1;
		}
	}
	
	return index;
}

static uint16_t base_bucket(struct nodeid* id) {
	uint16_t bucketIndex = prefix(&pTable->myID, id);
	assert(bucketIndex != RT_IDBITS);

	// If they are sufficiently similar they end up in the final bucket. Clamp the index to ensure.
	bucketIndex = bucketIndex > (RT_IDBITS - RT_BBITS) ? (RT_IDBITS - RT_BBITS) : bucketIndex;
	assert(bucketIndex <= RT_IDBITS - RT_BBITS);

	return bucketIndex * RT_BSIZE;
}

struct entry* routing_get(struct nodeid* id) {
	uint16_t baseIndex = base_bucket(id);
	for(size_t i = baseIndex; i < baseIndex + RT_BSIZE; i++) {
		if(!pTable->table[i].set) continue;

		if(memcmp(&pTable->table[i].id, id, sizeof(struct nodeid)) == 0) {
			return &pTable->table[i];
		}
	}

	return NULL;
}

void routing_remove(struct nodeid* id) {
	struct entry* entry = routing_get(id);

	entry->set = false;
}

bool routing_interested(struct nodeid* id) {
	uint16_t bucketIndex = prefix(&pTable->myID, id);
	// The nodeid is the same as our own
	if(bucketIndex == RT_IDBITS) {
		return false;
	}

	uint16_t baseIndex = base_bucket(id);
	int8_t inBucketIndex = scan(baseIndex, id);

	if(inBucketIndex < 0) {
		// The bucket either already contains the node, or it has no more space
		return false;
	}

	return true;
}

// Offer the routing table a new node
bool routing_offer(struct nodeid* id, struct entry **dest) {
	uint16_t bucketIndex = prefix(&pTable->myID, id);
	// The nodeid is the same as our own
	if(bucketIndex == RT_IDBITS) {
		return false;
	}

	uint16_t baseIndex = base_bucket(id);
	int8_t inBucketIndex = scan(baseIndex, id);

	if(inBucketIndex < 0) {
		// The bucket either already contains the node, or it has no more space
		return false;
	}

	struct entry* entry = &pTable->table[baseIndex + inBucketIndex];
	entry->set = true;
	entry->id = *id;

	*dest = entry;
	return true;
}

struct item {
	struct nodeid distance;
	bool set;
	uint16_t index;
};
int compareItem(const void* a_v, const void* b_v) {
	struct item* a = (struct item*)a_v;
	struct item* b = (struct item*)b_v;

	// If either of the two are not set, the one that is set comes before the
	// one that isn't.
	if(!a->set || !b->set) return b->set - a->set;

	return memcmp(&a->distance, &b->distance, sizeof(struct nodeid));
}

size_t routing_closest(struct nodeid* needle, size_t n, struct entry** res) {
	assert(n <= RT_SIZE);
	static struct item items[RT_SIZE] = {0};
	for(uint16_t i = 0; i < RT_SIZE; i++) {
		items[i].index = i;
	}

	{
		struct item* item;
		struct entry* entry;
		for(item = &items[0], entry = &pTable->table[0]; item < &items[RT_SIZE] && entry < &pTable->table[RT_SIZE]; item++, entry++){
			item->set = entry->set;
			for(uint8_t j = 0; j < 5; j++) {
				item->distance.inner[j] = entry->id.inner[j] ^ needle->inner[j];
			}
		}
	}

	// @PERFORMANCE: There's an algorithm known as quickselect which can select
	// the top k elements from a list while only doing a partial sort.
	// I imagine that would be more efficient than this full sort.
	qsort(items, RT_SIZE, sizeof(struct item), compareItem);

	size_t read;
	for(read = 0; read < n; read++) {
		if(!items[read].set)
			break;
		res[read] = &pTable->table[items[read].index];
	}

	return read;
}

void routing_oldest(struct entry** dest) {
	*dest = NULL;

	for(struct entry* entry = pTable->table; entry < pTable->table+RT_SIZE; entry++){
		if(!entry->set)
			continue;

		if(entry->expire == 0)
			continue;

		if(*dest == NULL) {
			*dest = entry;
			continue;
		}

		if(difftime((*dest)->expire, entry->expire) > 0.0) {
			*dest = entry;
		}
	}
}

void routing_status(int* filled, int* size, double* load_factor, size_t load_factor_len) {
	*size = RT_SIZE;

	*filled = 0;
	for(size_t i = 0; i < RT_SIZE; i++) {
		if(pTable->table[i].set)
			(*filled)++;
	}

	int per_bucket = RT_SIZE / load_factor_len;
	int overflow = RT_SIZE % load_factor_len;
	struct entry* table_cursor = pTable->table;
	for(int i = 0; i < load_factor_len; i++) {
		int is_overflow = i < overflow;
		for(int j = 0; j < per_bucket + is_overflow; j++) {
			load_factor[i] += table_cursor->set;
			table_cursor++;
		}
		load_factor[i] /= per_bucket + is_overflow;
	}
}

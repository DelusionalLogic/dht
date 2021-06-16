#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#define dbg(format, ...) \
	dbgl(format "\n", ##  __VA_ARGS__)

#define dbgl(format, ...) \
	printf(format, ## __VA_ARGS__); \
	fflush(stderr)

#define err(format, ...) \
	printf(format "\n", ## __VA_ARGS__); \
	fflush(stderr)

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

struct addr {
	uint32_t ip;
	uint16_t port;
};

struct nodeid {
	uint32_t inner[5];
};

struct entry {
	bool set;
	struct nodeid id;
	time_t last;
	struct addr addr;
};

#define IDBITS 160
#define BUCKETSIZE 8
// The 3 here is log2(BUCKETSIZE), since the final bucket will contain all those combinations
#define BUCKETBITS 3
#define ROUTINGSIZE (IDBITS * BUCKETSIZE)

struct nodeid myID;
struct entry table[ROUTINGSIZE];

void routing_init(struct nodeid* myid) {
	myID = *myid;
}

// Calculate the common bit prefix between two node ids.
uint8_t prefix(struct nodeid* a, struct nodeid* b) {
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

int8_t scan(uint16_t baseIndex, struct nodeid* id) {
	assert(baseIndex < ROUTINGSIZE - BUCKETSIZE);
	int8_t index = -1;

	for(size_t i = baseIndex; i < baseIndex + BUCKETSIZE; i++) {
		if(!table[i].set) {
			index = index == -1 ? i - baseIndex : index;
			continue;
		}

		if(memcmp(&table[i].id, id, sizeof(struct nodeid)) == 0) {
			return -1;
		}
	}
	
	return index;
}

// Offer the routing table a new node
bool routing_offer(struct nodeid* id, struct entry **dest) {
	uint16_t bucketIndex = prefix(&myID, id);
	// The nodeid is the same as our own
	assert(bucketIndex != IDBITS);

	// If they are sufficiently similar they end up in the final bucket. Clamp the index to ensure.
	bucketIndex = bucketIndex > (IDBITS - BUCKETBITS) ? (IDBITS - BUCKETBITS) : bucketIndex;
	assert(bucketIndex <= IDBITS - BUCKETBITS);

	uint16_t baseIndex = bucketIndex * BUCKETSIZE;
	int8_t inBucketIndex = scan(baseIndex, id);

	if(inBucketIndex == -1) {
		// The bucket either already contains the node, or it has no more space
		dbg("discarding node");
		return false;
	}

	struct entry* entry = &table[baseIndex + inBucketIndex];
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

size_t rounting_closest(struct nodeid* needle, size_t n, struct entry** res) {
	assert(n <= ROUTINGSIZE);
	static struct item items[ROUTINGSIZE] = {0};
	for(uint16_t i = 0; i < ROUTINGSIZE; i++) {
		items[i].index = i;
	}

	{
		struct item* item;
		struct entry* entry;
		for(item = &items[0], entry = &table[0]; item < &items[ROUTINGSIZE] && entry < &table[ROUTINGSIZE]; item++, entry++){
			item->set = entry->set;
			for(uint8_t j = 0; j < 5; j++) {
				item->distance.inner[j] = entry->id.inner[j] ^ needle->inner[j];
			}
		}
	}

	qsort(items, ROUTINGSIZE, sizeof(struct item), compareItem);

	size_t read;
	for(read = 0; read < n; read++) {
		if(!items[read].set)
			break;
		res[read] = &table[items[read].index];
	}

	return read;
}

void dbgl_id(struct nodeid* id) {
	for(uint8_t i = 0; i < 5; i++) {
		fprintf(stderr, "0x%08x ", id->inner[i]);
	}
	fprintf(stderr, "\n");
	fflush(stderr);
}

int main(int argc, char** argv) {

	struct nodeid a = {0};
	a.inner[1] = 0xFFFFFFFF;
	routing_init(&a);


	struct nodeid b = {0};
	b.inner[1] = 0xFFFFFFFF;
	b.inner[4] = 0x00000001;
	struct entry *entry;
	if(routing_offer(&b, &entry)) {
		entry->addr.ip = 0;
		entry->addr.port = 0;
	}

	b.inner[1] = 0xFFFFFFFF;
	b.inner[4] = 0x00000002;
	if(routing_offer(&b, &entry)) {
		entry->addr.ip = 0;
		entry->addr.port = 0;
	}

	struct entry *found[10];
	size_t nfound = rounting_closest(&b, 10, found);

	for(size_t i = 0; i < nfound; i++) {
		dbgl_id(&found[i]->id);
	}
	dbg("%d", prefix(&a, &b));

	return 0;
}

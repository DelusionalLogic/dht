#include "routing.h"

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

	return 0;
}

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
	size_t nfound = routing_closest(&b, 10, found);

	for(size_t i = 0; i < nfound; i++) {
		dbgl_id(&found[i]->id);
	}

	return 0;
}

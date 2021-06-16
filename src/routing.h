#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>

#define dbg(format, ...) \
	dbgl(format "\n", ##  __VA_ARGS__)

#define dbgl(format, ...) \
	printf(format, ## __VA_ARGS__); \
	fflush(stderr)

#define err(format, ...) \
	printf(format "\n", ## __VA_ARGS__); \
	fflush(stderr)


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

void routing_init(struct nodeid* myid);
bool routing_offer(struct nodeid* id, struct entry **dest);
size_t rounting_closest(struct nodeid* needle, size_t n, struct entry** res);

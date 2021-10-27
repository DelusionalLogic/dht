#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>

#define RT_IDBITS 160
#define RT_BSIZE 8
// The 3 here is log2(BUCKETSIZE), since the final bucket will contain all those combinations
#define RT_BBITS 3
#define RT_SIZE (RT_IDBITS * RT_BSIZE)

struct addr {
	uint32_t ip;
	uint16_t port;
};

struct nodeid {
	union {
		uint32_t inner[5];
		char inner_b[20];
	};
};

struct entry {
	bool set;
	struct nodeid id;
	time_t expire;
	struct addr addr;
};

void routing_init(struct nodeid* myid);
void routing_flush();
bool routing_interested(struct nodeid* id);
bool routing_offer(struct nodeid* id, struct entry **dest);
void routing_oldest(struct entry** dest);
size_t routing_closest(struct nodeid* needle, size_t n, struct entry** res);
void routing_status(int* filled, int* size, double* load_factor, size_t load_factor_len);

struct entry* routing_get(struct nodeid* id);
void routing_remove(struct nodeid* self);

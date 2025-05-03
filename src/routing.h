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
	struct addr addr;

	time_t expire;
};

extern struct nodeid myID;
extern struct entry *table;
extern int table_size;

void routing_init(struct nodeid* myid);
void routing_update_metrics();
void routing_flush();
bool routing_interested(struct nodeid* id);
bool routing_offer(struct nodeid* id, struct entry **dest);
void routing_oldest(struct entry** dest);
size_t routing_closest(struct nodeid* needle, size_t n, struct entry** res);
void routing_status(int* filled, int* size, double* load_factor, size_t load_factor_len);

struct entry* routing_get(struct nodeid* id);
void routing_remove(struct nodeid* self);

struct nodeid rand_nodeid_in_bucket(struct nodeid *self, struct nodeid *other);
uint8_t prefix(struct nodeid* a, struct nodeid* b);

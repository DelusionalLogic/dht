#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>

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

struct entry* routing_get(struct nodeid* id);
void routing_remove(struct nodeid* self);

#include "unity.h"
#include "routing.h"

#define IP(a, b, c, d) (a << 24 | b << 16 | c << 8 | d)

struct nodeid self;

void setUp() {
	self = (struct nodeid){{ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 }};
	routing_init(&self);
}

void test_deny_self_add() {
	routing_flush();
	struct entry* entry;
	if(!routing_offer(&self, &entry))
		TEST_PASS();

	TEST_FAIL();
}

void test_can_find_added() {
	routing_flush();

	// The address we are going to store
	struct addr addr = (struct addr){.ip = IP(128,0,0,1), .port = 0};

	// Make a nodeid that is one bit different
	struct nodeid new = self;

	new.inner[4] += 1;
	struct entry* entry;
	TEST_ASSERT_TRUE_MESSAGE(routing_offer(&new, &entry), "Did not accept new entry");
	new.inner[4] += 1;
	TEST_ASSERT_TRUE_MESSAGE(routing_offer(&new, &entry), "Did not accept new entry");

	// Set the entries
	entry->addr = addr;
	entry->last = time(NULL);

	// Ask for 3 nodes
	struct entry *out[3] = {0};
	size_t n = routing_closest(&new, 3, out);
	// Since we only put 2 in, we should get 2 out
	TEST_ASSERT_EQUAL_INT(2, n);

	TEST_ASSERT_EQUAL_MEMORY(&addr, &out[0]->addr, sizeof(struct addr));
	TEST_ASSERT_EQUAL_MEMORY(&new, &out[0]->id, sizeof(struct nodeid));
}

void test_discard_offer_when_bucket_full() {
	routing_flush();

	// The address we are going to store
	struct addr addr = (struct addr){.ip = IP(128,0,0,1), .port = 0};

	struct nodeid new = self;
	// Flip the top bit of the id to go into the low resolution bucket
	new.inner[0] ^= 0x80000000;

	// Fill up the bucket with entries
	for(uint8_t i = 0; i < 8; i++) {
		struct entry* entry;
		TEST_ASSERT_TRUE_MESSAGE(routing_offer(&new, &entry), "Did not accept new entry");

		// Set the entries
		entry->addr = addr;
		entry->last = time(NULL);

		new.inner[4] += 1;
	}

	struct entry* entry;
	TEST_ASSERT_FALSE_MESSAGE(routing_offer(&new, &entry), "Accepted entry when bucket was full");
}

void test_discard_offer_when_nodeid_added_twice() {
	routing_flush();

	// The address we are going to store
	struct addr addr = (struct addr){.ip = IP(128,0,0,1), .port = 0};

	struct nodeid new = self;
	new.inner[4] ^= 0x00000001;

	struct entry* entry;
	TEST_ASSERT_TRUE(routing_offer(&new, &entry));
	entry->addr = addr;
	entry->last = time(NULL);

	bool accept = routing_offer(&new, &entry);
	TEST_ASSERT_FALSE_MESSAGE(accept, "Accepted entry when bucket was full");
}

void test_interested_when_space_in_bucket() {
	routing_flush();

	struct nodeid new = self;
	new.inner[4] ^= 0x00000001;

	bool interest = routing_interested(&new);

	TEST_ASSERT_TRUE_MESSAGE(interest, "Was not interested in node");
}

void test_not_interested_when_nodeid_in_table() {
	routing_flush();

	struct nodeid new = self;
	new.inner[4] ^= 0x00000001;

	struct entry* entry;
	TEST_ASSERT_TRUE(routing_offer(&new, &entry));
	entry->addr = (struct addr){.ip = IP(128,0,0,1), .port = 0};
	entry->last = time(NULL);

	bool interest = routing_interested(&new);
	TEST_ASSERT_FALSE_MESSAGE(interest, "Was interested in node");
}

void test_not_interested_when_bucket_is_full() {
	routing_flush();

	// The address we are going to store
	struct addr addr = (struct addr){.ip = IP(128,0,0,1), .port = 0};

	struct nodeid new = self;
	// Flip the top bit of the id to go into the low resolution bucket
	new.inner[0] ^= 0x80000000;

	// Fill up the bucket with entries
	for(uint8_t i = 0; i < 8; i++) {
		struct entry* entry;
		TEST_ASSERT_TRUE_MESSAGE(routing_offer(&new, &entry), "Did not accept new entry");

		// Set the entries
		entry->addr = addr;
		entry->last = time(NULL);

		new.inner[4] += 1;
	}

	TEST_ASSERT_FALSE_MESSAGE(routing_interested(&new), "Still interested when bucket was full");
}

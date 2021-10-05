#include "unity.h"
#include "routing.h"

#define IP(a, b, c, d) (a << 24 | b << 16 | c << 8 | d)

struct nodeid self;

void setUp() {
	self = (struct nodeid){.inner={ 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 }};
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
	entry->expire = time(NULL);

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
		entry->expire = time(NULL);

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
	entry->expire = time(NULL);

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
	entry->expire = time(NULL);

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
		entry->expire = time(NULL);

		new.inner[4] += 1;
	}

	TEST_ASSERT_FALSE_MESSAGE(routing_interested(&new), "Still interested when bucket was full");
}

void test_lowest_ts_is_oldest() {
	routing_flush();

	// The address we are going to store
	struct addr addr = (struct addr){.ip = IP(128,0,0,1), .port = 0};

	struct nodeid new = self;
	// Flip the top bit of the id to go into the low resolution bucket
	new.inner_b[0] ^= 0x80;

	// Fill up the bucket with entries
	for(uint8_t i = 0; i < 2; i++) {
		struct entry* entry;
		TEST_ASSERT_TRUE_MESSAGE(routing_offer(&new, &entry), "Did not accept new entry");

		// Set the entries
		entry->id = new;
		entry->addr = addr;
		// Invert the timestamps to make the last one have lowest timestamp
		entry->expire = 2-i;

		new.inner_b[19] += 1;
	}

	struct entry* dest = NULL;
	routing_oldest(&dest);

	TEST_ASSERT_NOT_NULL(dest);
	TEST_ASSERT_EQUAL(1, dest->id.inner_b[19]);
}

void test_get_after_offer() {
	routing_flush();

	// The address we are going to store
	struct addr addr = (struct addr){.ip = IP(128,0,0,1), .port = 0};

	// Make a nodeid that is one bit different
	struct nodeid new = self;

	new.inner[4] += 1;
	struct entry* entry;
	TEST_ASSERT_TRUE_MESSAGE(routing_offer(&new, &entry), "Did not accept new entry");

	// Set the entry
	entry->addr = addr;
	entry->expire = 10;

	struct entry* e = routing_get(&new);

	TEST_ASSERT_NOT_NULL(e);
	TEST_ASSERT_EQUAL_MEMORY(&addr, &e->addr, sizeof(struct addr));
}

void test_get_after_offer_and_remove() {
	routing_flush();

	// The address we are going to store
	struct addr addr = (struct addr){.ip = IP(128,0,0,1), .port = 0};

	// Make a nodeid that is one bit different
	struct nodeid new = self;

	new.inner[4] += 1;
	struct entry* entry;
	TEST_ASSERT_TRUE_MESSAGE(routing_offer(&new, &entry), "Did not accept new entry");

	// Set the entry
	entry->addr = addr;
	entry->expire = 10;

	routing_remove(&new);
	struct entry* e = routing_get(&new);

	TEST_ASSERT_NULL(e);
}

void test_close_to_self_load_factor() {
	routing_flush();

	// The address we are going to store
	struct addr addr = (struct addr){.ip = IP(128,0,0,1), .port = 0};

	// Make a nodeid that is one bit different
	struct nodeid new = self;

	new.inner[4] += 1;
	struct entry* entry;
	TEST_ASSERT_TRUE_MESSAGE(routing_offer(&new, &entry), "Did not accept new entry");

	// Set the entries
	entry->addr = addr;
	entry->expire = time(NULL);

	int filled;
	int total;
	double load_factor[8] = {0};
	routing_status(&filled, &total, load_factor, 8);

	TEST_ASSERT_EQUAL(1, filled);
	TEST_ASSERT_EQUAL(1280, total);
	// First bucket should have none
	TEST_ASSERT_EQUAL_DOUBLE(0.0, load_factor[0]);
	// The final bucket should have the one node
	TEST_ASSERT_EQUAL_DOUBLE(1.0/(1280/8), load_factor[7]);
}

void test_far_from_self_load_factor() {
	routing_flush();

	// The address we are going to store
	struct addr addr = (struct addr){.ip = IP(128,0,0,1), .port = 0};

	// Make a nodeid that is one bit different
	struct nodeid new = self;

	// Flip top bit to make it very dissimilar
	new.inner[0] ^= 0x80000000;
	struct entry* entry;
	TEST_ASSERT_TRUE_MESSAGE(routing_offer(&new, &entry), "Did not accept new entry");

	// Set the entries
	entry->addr = addr;
	entry->expire = time(NULL);

	int filled;
	int total;
	double load_factor[8] = {0};
	routing_status(&filled, &total, load_factor, 8);

	TEST_ASSERT_EQUAL(1, filled);
	TEST_ASSERT_EQUAL(1280, total);
	// First bucket should have the one node
	TEST_ASSERT_EQUAL_DOUBLE(1.0/(1280/8), load_factor[0]);
	// The final bucket should have none
	TEST_ASSERT_EQUAL_DOUBLE(0.0, load_factor[7]);
}

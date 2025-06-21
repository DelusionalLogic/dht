#include "unity.h"
#include "peers.h"
#include "log.h"

#include <string.h>
#include <arpa/inet.h>

#define IP(a, b, c, d) htonl(a << 24 | b << 16 | c << 8 | d)

void test_add_single_peer() {
	allocate_hashtable();

	struct infohash sometorrent = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, 0x0ab00521}};
	struct addr addr = (struct addr){.ip = IP(128,0,0,1), .port = 0};

	int rc = add_peer(&sometorrent, &addr, 0);
	TEST_ASSERT_EQUAL(0, rc);
}

void test_add_9_peers_same_torrent() {
	allocate_hashtable();

	struct infohash sometorrent = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, 0x0ab00521}};
	struct addr addr = (struct addr){.ip = IP(128,0,0,1), .port = 0};

	int rc = add_peer(&sometorrent, &addr, 0);
	TEST_ASSERT_EQUAL(0, rc);
	rc = add_peer(&sometorrent, &addr, 0);
	TEST_ASSERT_EQUAL(0, rc);
	rc = add_peer(&sometorrent, &addr, 0);
	TEST_ASSERT_EQUAL(0, rc);
	rc = add_peer(&sometorrent, &addr, 0);
	TEST_ASSERT_EQUAL(0, rc);
	rc = add_peer(&sometorrent, &addr, 0);
	TEST_ASSERT_EQUAL(0, rc);
	rc = add_peer(&sometorrent, &addr, 0);
	TEST_ASSERT_EQUAL(0, rc);
	rc = add_peer(&sometorrent, &addr, 0);
	TEST_ASSERT_EQUAL(0, rc);
	rc = add_peer(&sometorrent, &addr, 0);
	TEST_ASSERT_EQUAL(0, rc);
	// There's room for 8 peers per infohash
	rc = add_peer(&sometorrent, &addr, 0);
	TEST_ASSERT_EQUAL(PEER_EFULL, rc);
}

void test_peers_for_only_torrent() {
	allocate_hashtable();

	struct infohash sometorrent  = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, 0x0ab00521}};
	struct infohash othertorrent = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, 0x0ab00522}};
	struct addr someaddr = (struct addr){.ip = IP(128,0,0,1), .port = 0};
	struct addr otheraddr = (struct addr){.ip = IP(128,0,0,1), .port = 1};

	int rc = add_peer(&sometorrent, &someaddr, 0);
	TEST_ASSERT_EQUAL(0, rc);
	rc = add_peer(&othertorrent, &otheraddr, 0);
	TEST_ASSERT_EQUAL(0, rc);

	struct addr* found;
	size_t found_len;

	get_peers(&sometorrent, &found, &found_len);
	TEST_ASSERT_EQUAL(1, found_len);
	TEST_ASSERT_EQUAL_MEMORY(&someaddr, &found[0], sizeof(struct addr));

	get_peers(&othertorrent, &found, &found_len);
	TEST_ASSERT_EQUAL(1, found_len);
	TEST_ASSERT_EQUAL_MEMORY(&otheraddr, &found[0], sizeof(struct addr));
}

void test_have_no_peers() {
	allocate_hashtable();

	struct infohash sometorrent = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, 0x0ab00521}};

	struct addr* found;
	size_t found_len;
	get_peers(&sometorrent, &found, &found_len);
	TEST_ASSERT_NULL(found);
	TEST_ASSERT_EQUAL(0, found_len);
}

void test_grows() {
	allocate_hashtable();

	struct addr addr = (struct addr){.ip = IP(128,0,0,1), .port = 0};

	for(int i = 0; i < 17; i++) { // Peer table size + 1 to make sure it HAS to grow
		struct infohash sometorrent = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, i}};
		int rc = add_peer(&sometorrent, &addr, 0);
		TEST_ASSERT_EQUAL(0, rc);
	}

	{
		// We can find a peer after the resize again
		struct infohash sometorrent = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, 0x00000001}};
		struct addr* found;
		size_t found_len;
		get_peers(&sometorrent, &found, &found_len);
		TEST_ASSERT_NOT_NULL(found);
		TEST_ASSERT_EQUAL(1, found_len);
	}
}

void test_expired() {
	allocate_hashtable();

	// @FRAGILE Theres a complication with linear probing where earlier
	// displacements cause later slots to also displace. We are forcing that
	// case here while making sure that the one we want to retain is the one
	// displaced from the slot right after the ones that expire. That means the
	// values of these infohashes are tightly coupled to the hash function.
	// I don't have any way to assert that.

	struct infohash sometorrent = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, 0x0ab00521}};
	struct infohash samehash = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008470, 0x0ab00521}};
	struct infohash nexthash = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008470, 0x0ab00522}};
	struct addr addr = (struct addr){.ip = IP(128,0,0,1), .port = 0};
	struct addr other_addr = (struct addr){.ip = IP(128,0,0,1), .port = 1};

	int rc = add_peer(&sometorrent, &addr, 0);
	TEST_ASSERT_EQUAL(0, rc);
	rc = add_peer(&samehash, &addr, 0);
	TEST_ASSERT_EQUAL(0, rc);
	rc = add_peer(&nexthash, &addr, 0);
	TEST_ASSERT_EQUAL(0, rc);

	// Add a peer later, should refresh the hash
	rc = add_peer(&nexthash, &other_addr, 2);
	TEST_ASSERT_EQUAL(0, rc);

	expire_hashes(HASH_TIMEOUT + 1);

	{
		struct addr* found;
		size_t found_len;
		get_peers(&sometorrent, &found, &found_len);
		TEST_ASSERT_NULL(found);
		TEST_ASSERT_EQUAL(0, found_len);
	}

	{
		struct addr* found;
		size_t found_len;
		get_peers(&nexthash, &found, &found_len);
		TEST_ASSERT_NOT_NULL(found);
		TEST_ASSERT_EQUAL(2, found_len);
	}
}

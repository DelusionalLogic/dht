#include "unity.h"
#include "proto.h"
#include "peers.h"

#include "log.h"

#include <string.h>

#define IP(a, b, c, d) htonl(a << 24 | b << 16 | c << 8 | d)

void test_create_first_ticket() {
	time_t now = TOKEN_VTMO;
	struct tokens tokens = {0};
	char hash[SHA256_BLOCK_SIZE] = {0};
	struct addr addr  = (struct addr){.ip = IP(128,0,0,1), .port = 6881};
	struct addr addr2 = (struct addr){.ip = IP(128,0,0,2), .port = 6881};
	int rc;

	// First token create should create a new ticket
	token_create(&tokens, now, &addr, hash);

	// It should be valid for the address it was issued for
	rc = token_validate(&tokens, now, &addr, hash);
	TEST_ASSERT_EQUAL(TOK_VALI, rc);

	// But not for some other addr
	rc = token_validate(&tokens, now, &addr2, hash);
	TEST_ASSERT_EQUAL(TOK_INVA, rc);

	// Time passes and our ticket becomes invalid for issuance
	now += TOKEN_ITMO;

	char hash2[SHA256_BLOCK_SIZE];
	token_create(&tokens, now, &addr, hash2);

	// We should get a different token, since we have a new ticket
	if(memcmp(hash, hash2, SHA256_BLOCK_SIZE) == 0) {
		TEST_FAIL();
	}

	// Which should be valid
	rc = token_validate(&tokens, now, &addr, hash2);
	TEST_ASSERT_EQUAL(TOK_VALI, rc);

	// And so should the old one (since it's not timed out for validation)
	rc = token_validate(&tokens, now, &addr, hash);
	TEST_ASSERT_EQUAL(TOK_VALI, rc);

	// More time passes and the original token becomes invalid for validation
	now += TOKEN_VTMO - TOKEN_ITMO;

	// Old token should now no longer be validated
	rc = token_validate(&tokens, now, &addr, hash);
	TEST_ASSERT_EQUAL(TOK_INVA, rc);

	// New token should
	rc = token_validate(&tokens, now, &addr, hash2);
	TEST_ASSERT_EQUAL(TOK_VALI, rc);
}

void test_begin_pings_bootstrap_node() {
	struct message outbuff[10] = {0};

	struct dht dht;
	dht.self = (struct nodeid){.inner={0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
	routing_init(&dht.self);

	struct message* message_cursor = outbuff;
	proto_begin(&dht, time(NULL), &message_cursor, outbuff+10);

	TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+1);
	TEST_ASSERT_EQUAL(91, outbuff[0].payload_len);
	TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:ad2:id20:BBBBBBBBBBBBBBBBBBBB6:target20:", outbuff[0].payload, 43);
	TEST_ASSERT_EQUAL_CHAR_ARRAY("e1:q9:find_node1:t1:01:y1:qe", outbuff[0].payload+63, 28);

	proto_end(&dht);
}

void test_response_from_initial_probe() {
	struct message outbuff[2] = {0};

	struct sockaddr_storage remote;
	socklen_t remote_len;

	struct dht dht;
	dht.self = (struct nodeid){.inner={0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
	routing_init(&dht.self);

	{
		struct message* message_cursor = outbuff;
		proto_begin(&dht, time(NULL), &message_cursor, outbuff+2);
		remote_len = outbuff[0].dest_len;
		memcpy(&remote, &outbuff[0].dest, remote_len);
	}

	char buff[] = "d1:y1:r1:t1:01:rd2:id20:aaaaaaaaaaaaaaaaaaaa5:nodes26:bbbbbbbbbbbbbbbbbbbb\xFF\xFF\xFF\xFF\x00\x00""ee";
	struct message* message_cursor = outbuff;
	proto_run(&dht, buff, sizeof(buff), (struct sockaddr_in*)&remote, remote_len, 10, &message_cursor, outbuff+2);

	TEST_ASSERT_EQUAL_PTR_MESSAGE(message_cursor, outbuff+1, "Sends one packet");
	TEST_ASSERT_EQUAL(91, outbuff[0].payload_len);
	TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:ad2:id20:BBBBBBBBBBBBBBBBBBBB6:target20:", outbuff[0].payload, 43);

	struct nodeid target;
	memcpy(&target, outbuff[0].payload+43, sizeof(struct nodeid));
	TEST_ASSERT_EQUAL_MEMORY_MESSAGE(&dht.self, &target, sizeof(struct nodeid), "Target should be our own id");

	TEST_ASSERT_EQUAL_CHAR_ARRAY("e1:q9:find_node1:t1:11:y1:qe", outbuff[0].payload+63, 28);

	// The queried node gets added to the routing table
	struct nodeid other = (struct nodeid){.inner={0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161}};
	struct entry* entry = routing_get(&other);
	TEST_ASSERT_NOT_NULL(entry);
	TEST_ASSERT_EQUAL(((struct sockaddr_in*)&remote)->sin_addr.s_addr, entry->addr.ip);
	TEST_ASSERT_EQUAL(((struct sockaddr_in*)&remote)->sin_port, entry->addr.port);
	TEST_ASSERT_EQUAL(PROTO_UNCTM+10, entry->expire);

	proto_end(&dht);
}

void test_reponse_from_wrong_ip() {
	struct message outbuff[2] = {0};

	struct dht dht;
	dht.self = (struct nodeid){.inner={0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
	routing_init(&dht.self);
	{
		struct message* message_cursor = outbuff;
		proto_begin(&dht, time(NULL), &message_cursor, outbuff+2);
	}

	// This is fragile, since the ip of the bootstrap node could change, and we
	// look it up from DNS. Although it pretty unlikely that it would change to
	// this ip
	struct sockaddr_in remote;
	remote.sin_family = AF_INET;
	inet_pton(AF_INET, "255.255.255.255", &remote.sin_addr.s_addr);
	remote.sin_port = htons(6881);

	char buff[] = "d1:y1:r1:t1:01:rd2:id20:aaaaaaaaaaaaaaaaaaaa5:nodes26:bbbbbbbbbbbbbbbbbbbb\xFF\xFF\xFF\xFF\x00\x00""ee";
	struct message* message_cursor = outbuff;
	proto_run(&dht, buff, sizeof(buff), &remote, sizeof(remote), 0, &message_cursor, outbuff+2);

	// We shouldn't send any packets, since the response is rejected
	TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff);

	// Since the ip was wrong we should not have accepted the node into the
	// rounting table
	struct nodeid other = (struct nodeid){.inner={0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161}};
	struct entry* entry = routing_get(&other);
	TEST_ASSERT_NULL(entry);

	proto_end(&dht);
}

void test_ping() {
	struct message outbuff[2] = {0};

	struct dht dht;
	dht.self = (struct nodeid){.inner={0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
	routing_init(&dht.self);
	{
		struct message* message_cursor = outbuff;
		proto_begin(&dht, time(NULL), &message_cursor, outbuff+2);
	}

	struct sockaddr_in remote;
	remote.sin_family = AF_INET;
	inet_pton(AF_INET, "255.255.255.255", &remote.sin_addr.s_addr);
	remote.sin_port = htons(6881);

	char buff[] = "d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
	struct message* message_cursor = outbuff;
	proto_run(&dht, buff, sizeof(buff), &remote, sizeof(remote), 0, &message_cursor, outbuff+2);

	// We should have sent a response
	TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+1);

	TEST_ASSERT_EQUAL(47, outbuff[0].payload_len);
	TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:rd2:id20:BBBBBBBBBBBBBBBBBBBBe1:t2:aa1:y1:re", outbuff[0].payload, 47);

	proto_end(&dht);
}

void test_unknown_method() {
	struct message outbuff[2] = {0};

	struct dht dht;
	dht.self = (struct nodeid){.inner={0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
	routing_init(&dht.self);
	{
		struct message* message_cursor = outbuff;
		proto_begin(&dht, time(NULL), &message_cursor, outbuff+2);
	}

	struct sockaddr_in remote;
	remote.sin_family = AF_INET;
	inet_pton(AF_INET, "255.255.255.255", &remote.sin_addr.s_addr);
	remote.sin_port = htons(6881);

	char buff[] = "d1:q4:fake1:t2:aa1:y1:qe";
	struct message* message_cursor = outbuff;
	proto_run(&dht, buff, sizeof(buff), &remote, sizeof(remote), 0, &message_cursor, outbuff+2);

	// We should have sent a response
	TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+1);

	TEST_ASSERT_EQUAL(42, outbuff[0].payload_len);
	TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:eli204e14:Unknown Methode1:t2:aa1:y1:ee", outbuff[0].payload, 42);

	proto_end(&dht);
}

void test_note_times_out() {
	struct message outbuff[2] = {0};

	struct sockaddr_storage remote;
	socklen_t remote_len;

	struct dht dht;
	dht.self = (struct nodeid){.inner={0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
	routing_init(&dht.self);
	{
		struct message* message_cursor = outbuff;
		proto_begin(&dht, 0, &message_cursor, outbuff+2);
		remote_len = outbuff[0].dest_len;
		memcpy(&remote, &outbuff[0].dest, remote_len);
	}

	// The node responds to the ping at t=5
	{
		char buff[] = "d1:y1:r1:t1:01:rd2:id20:BB\x5F""aaaaaaaaaaaaaaaaa5:nodes26:bbbbbbbbbbbbbbbbbbbb\xFF\xFF\xFF\xFF\x00\x00""ee";
		struct message* message_cursor = outbuff;
		proto_run(&dht, buff, sizeof(buff), (struct sockaddr_in*)&remote, remote_len, 5, &message_cursor, outbuff+2);
	}

	// later a timeout is fired
	struct message* message_cursor = outbuff;
	proto_run(&dht, NULL, 0, (struct sockaddr_in*)&remote, remote_len, 1205, &message_cursor, outbuff+2);

	// Which should create a retry ping and a ping for the (now) uncertain node
	TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+2);
	TEST_ASSERT_EQUAL(91, outbuff[1].payload_len);
	TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:ad2:id20:BBBBBBBBBBBBBBBBBBBB6:target20:", outbuff[1].payload, 43);

	// The target should be in the same bucket as the queried node
	struct nodeid target;
	memcpy(&target, outbuff[1].payload+43, sizeof(struct nodeid));
	TEST_ASSERT_GREATER_THAN(19, prefix(&dht.self, &target));

	TEST_ASSERT_EQUAL_CHAR_ARRAY("e1:q9:find_node1:t1:01:y1:qe", outbuff[1].payload+63, 28);

	proto_end(&dht);
}

void test_response_after_retry() {
	struct message outbuff[10] = {0};

	struct dht dht;
	dht.self = (struct nodeid){.inner={0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
	routing_init(&dht.self);

	{
		struct message* message_cursor = outbuff;
		proto_begin(&dht, 0, &message_cursor, outbuff+2);
	}

	// After TMOUT seconds we retry the ping
	struct message* message_cursor = outbuff;
	proto_run(&dht, NULL, 0, (struct sockaddr_in*)NULL, 0, PROTO_TMOUT, &message_cursor, outbuff+2);

	TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+1);
	TEST_ASSERT_EQUAL(91, outbuff[0].payload_len);
	TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:ad2:id20:BBBBBBBBBBBBBBBBBBBB6:target20:", outbuff[0].payload, 43);

	struct nodeid target;
	memcpy(&target, outbuff[0].payload+43, sizeof(struct nodeid));
	TEST_ASSERT_EQUAL_MEMORY_MESSAGE(&dht.self, &target, sizeof(struct nodeid), "Target should be our own id");

	TEST_ASSERT_EQUAL_CHAR_ARRAY("e1:q9:find_node1:t1:01:y1:qe", outbuff[0].payload+63, 28);

	proto_end(&dht);
}

void test_remove_from_routing_after_3_retries() {
	struct message outbuff[10] = {0};
	time_t now = 0;

	struct sockaddr_storage remote;
	socklen_t remote_len;

	struct dht dht;
	dht.self = (struct nodeid){.inner={0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
	routing_init(&dht.self);
	struct nodeid other = (struct nodeid){.inner={0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161}};

	{
		struct message* message_cursor = outbuff;
		proto_begin(&dht, 0, &message_cursor, outbuff+2);
		remote_len = outbuff[0].dest_len;
		memcpy(&remote, &outbuff[0].dest, remote_len);
	}
	now += 10;

	{
		// The node responds
		// We return no new nodes to stop any new pings from going out
		char buff[] = "d1:y1:r1:t1:01:rd2:id20:aaaaaaaaaaaaaaaaaaaa5:nodes0:ee";
		struct message* message_cursor = outbuff;
		proto_run(&dht, buff, sizeof(buff), (struct sockaddr_in*)&remote, remote_len, now, &message_cursor, outbuff+2);
	}
	struct entry* entry = routing_get(&other);
	TEST_ASSERT_NOT_NULL(entry);

	now += PROTO_UNCTM;
	{
		// The node becomes uncertain
		struct message* message_cursor = outbuff;
		proto_run(&dht, NULL, 0, (struct sockaddr_in*)NULL, 0, now, &message_cursor, outbuff+2);
		TEST_ASSERT_EQUAL_PTR_MESSAGE(message_cursor, outbuff+1, "Ping was not sent");
	}

	now += PROTO_TMOUT;
	{
		// 1st retry
		struct message* message_cursor = outbuff;
		proto_run(&dht, NULL, 0, (struct sockaddr_in*)NULL, 0, now, &message_cursor, outbuff+2);
		TEST_ASSERT_EQUAL_PTR_MESSAGE(message_cursor, outbuff+1, "Ping was not sent");
	}

	now += PROTO_TMOUT;
	{
		// 2nd retry
		struct message* message_cursor = outbuff;
		proto_run(&dht, NULL, 0, (struct sockaddr_in*)NULL, 0, now, &message_cursor, outbuff+2);
		TEST_ASSERT_EQUAL_PTR_MESSAGE(message_cursor, outbuff+1, "Ping was not sent");
	}

	now += PROTO_TMOUT;
	// Drop the node
	struct message* message_cursor = outbuff;
	proto_run(&dht, NULL, 0, (struct sockaddr_in*)NULL, 0, now, &message_cursor, outbuff+2);

	TEST_ASSERT_EQUAL_PTR_MESSAGE(message_cursor, outbuff, "The timeout should send not a message");
	entry = routing_get(&other);
	TEST_ASSERT_NULL(entry);

	proto_end(&dht);
}

void test_ping_node_when_uncertain() {
	struct message outbuff[10] = {0};
	time_t now = 0;

	struct sockaddr_storage remote;
	socklen_t remote_len;

	struct dht dht;
	dht.self = (struct nodeid){.inner={0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
	routing_init(&dht.self);
	struct nodeid other = (struct nodeid){.inner={0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161}};

	{
		struct message* message_cursor = outbuff;
		proto_begin(&dht, 0, &message_cursor, outbuff+2);
		remote_len = outbuff[0].dest_len;
		memcpy(&remote, &outbuff[0].dest, remote_len);
	}
	now += 10;

	{
		// The node responds
		// We return no new nodes to stop any new pings from going out
		char buff[] = "d1:y1:r1:t1:01:rd2:id20:aaaaaaaaaaaaaaaaaaaa5:nodes0:ee";
		struct message* message_cursor = outbuff;
		proto_run(&dht, buff, sizeof(buff), (struct sockaddr_in*)&remote, remote_len, now, &message_cursor, outbuff+2);
	}
	struct entry* entry = routing_get(&other);
	TEST_ASSERT_NOT_NULL(entry);

	now += PROTO_UNCTM;
	{
		// The node becomes uncertain
		struct message* message_cursor = outbuff;
		proto_run(&dht, NULL, 0, (struct sockaddr_in*)NULL, 0, now, &message_cursor, outbuff+2);

		// Which should create a ping
		TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+1);
		TEST_ASSERT_EQUAL(91, outbuff[0].payload_len);
		TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:ad2:id20:BBBBBBBBBBBBBBBBBBBB6:target20:", outbuff[0].payload, 43);
		TEST_ASSERT_EQUAL_CHAR_ARRAY("e1:q9:find_node1:t1:01:y1:qe", outbuff[0].payload+63, 28);
	}

	now += 5;
	{
		// The node responds
		char buff[] = "d1:y1:r1:t1:01:rd2:id20:aaaaaaaaaaaaaaaaaaaa5:nodes0:ee";
		struct message* message_cursor = outbuff;
		proto_run(&dht, buff, sizeof(buff), (struct sockaddr_in*)&remote, remote_len, now, &message_cursor, outbuff+2);

		// The routing table entry should have its expiry time updated
		struct entry* entry = routing_get(&other);
		TEST_ASSERT_NOT_NULL(entry);
		TEST_ASSERT_GREATER_THAN(now, entry->expire);
	}

	proto_end(&dht);
}

void test_query_find_node() {
	struct message outbuff[10] = {0};
	time_t now = 0;

	struct sockaddr_storage remote;
	socklen_t remote_len;

	struct dht dht;
	dht.self = (struct nodeid){.inner={0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
	routing_init(&dht.self);
	struct nodeid other = (struct nodeid){.inner={0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161}};

	{
		struct message* message_cursor = outbuff;
		proto_begin(&dht, 0, &message_cursor, outbuff+2);
		remote_len = outbuff[0].dest_len;
		memcpy(&remote, &outbuff[0].dest, remote_len);
	}
	now += 10;

	{
		// The node responds
		// We return no new nodes to stop any new pings from going out
		char buff[] = "d1:y1:r1:t1:01:rd2:id20:aaaaaaaaaaaaaaaaaaaa5:nodes0:ee";
		struct message* message_cursor = outbuff;
		proto_run(&dht, buff, sizeof(buff), (struct sockaddr_in*)&remote, remote_len, now, &message_cursor, outbuff+2);
	}
	struct entry* entry = routing_get(&other);
	TEST_ASSERT_NOT_NULL(entry);

	{
		struct sockaddr_in other;
		other.sin_family = AF_INET;
		inet_pton(AF_INET, "255.255.255.255", &other.sin_addr.s_addr);
		other.sin_port = htons(6881);

		char buff[] = "d1:ad2:id20:abcdefghij01234567896:target20:aaaaaaaaaaaaaaaaaaaae1:q9:find_node1:t2:aa1:y1:qe";
		struct message* message_cursor = outbuff;
		proto_run(&dht, buff, sizeof(buff), &other, sizeof(other), 0, &message_cursor, outbuff+2);

		// We should have sent a response
		TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+1);

		TEST_ASSERT_EQUAL(83, outbuff[0].payload_len);
		TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:rd2:id20:BBBBBBBBBBBBBBBBBBBB5:nodes26:aaaaaaaaaaaaaaaaaaaa", outbuff[0].payload, 62);
		TEST_ASSERT_EQUAL_MEMORY(&((struct sockaddr_in*)&remote)->sin_addr.s_addr, outbuff[0].payload+62, 4);
		TEST_ASSERT_EQUAL_MEMORY(&((struct sockaddr_in*)&remote)->sin_port, outbuff[0].payload+66, 2);
		TEST_ASSERT_EQUAL_CHAR_ARRAY("e1:t2:aa1:y1:re", outbuff[0].payload+68, 15);
	}

	proto_end(&dht);
}

void test_query_get_peers_have_one() {
	struct message outbuff[10] = {0};
	time_t now = 0;

	struct sockaddr_storage remote;
	socklen_t remote_len;

	allocate_hashtable();

	struct dht dht = {0};
	dht.self = (struct nodeid){.inner={0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
	routing_init(&dht.self);

	{
		struct message* message_cursor = outbuff;
		proto_begin(&dht, 0, &message_cursor, outbuff+2);
		remote_len = outbuff[0].dest_len;
		memcpy(&remote, &outbuff[0].dest, remote_len);
	}
	now += 10;

	{
		// The node responds
		// We return no new nodes to stop any new pings from going out
		char buff[] = "d1:y1:r1:t1:01:rd2:id20:aaaaaaaaaaaaaaaaaaaa5:nodes0:ee";
		struct message* message_cursor = outbuff;
		proto_run(&dht, buff, sizeof(buff), (struct sockaddr_in*)&remote, remote_len, now, &message_cursor, outbuff+2);
	}
	now += 1;

	// Some other node then asks for peers
	char token[SHA256_BLOCK_SIZE];
	{
		struct sockaddr_in other;
		other.sin_family = AF_INET;
		inet_pton(AF_INET, "128.0.0.1", &other.sin_addr.s_addr);
		other.sin_port = htons(9090);

		// Node asks for peers to get token
		char buff[] = "d1:ad2:id20:abcdefghij01234567899:info_hash20:aaaaaaaaaaaaaaaaaaaae1:q9:get_peers1:t2:aa1:y1:qe";
		struct message* message_cursor = outbuff;
		proto_run(&dht, buff, sizeof(buff), &other, sizeof(other), 0, &message_cursor, outbuff+2);

		// We should have sent a response
		TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+1);

		TEST_ASSERT_EQUAL(125, outbuff[0].payload_len);
		char* cursor = outbuff[0].payload;
		TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:rd2:id20:BBBBBBBBBBBBBBBBBBBB5:nodes26:aaaaaaaaaaaaaaaaaaaa", cursor, 62);
		cursor+=62;
		TEST_ASSERT_EQUAL_MEMORY(&((struct sockaddr_in*)&remote)->sin_addr.s_addr, cursor, 4);
		cursor+=4;
		TEST_ASSERT_EQUAL_MEMORY(&((struct sockaddr_in*)&remote)->sin_port, cursor, 2);
		cursor+=2;
		TEST_ASSERT_EQUAL_CHAR_ARRAY("5:token32:", cursor, 10);
		cursor+=10;
		memcpy(token, cursor, SHA256_BLOCK_SIZE);
		cursor+=SHA256_BLOCK_SIZE;
		TEST_ASSERT_EQUAL_CHAR_ARRAY("e1:t2:aa1:y1:re", cursor, 15);
		cursor+=15;
	}
	now += 1;

	// Using the token from before that node then announces that it's a peer
	{
		struct sockaddr_in other;
		other.sin_family = AF_INET;
		inet_pton(AF_INET, "128.0.0.1", &other.sin_addr.s_addr);
		other.sin_port = htons(9090);

		// Node announces that it's a peer for that torrent
		char buff[] = "d1:ad2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:aaaaaaaaaaaaaaaaaaaa4:porti1337e5:token32:                                e1:q13:announce_peer1:t2:aa1:y1:qe";
		memcpy(buff+106, token, SHA256_BLOCK_SIZE);
		struct message* message_cursor = outbuff;
		proto_run(&dht, buff, sizeof(buff), (struct sockaddr_in*)&other, sizeof(other), now, &message_cursor, outbuff+2);
		TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+1);

		TEST_ASSERT_EQUAL(47, outbuff[0].payload_len);
		char* cursor = outbuff[0].payload;
		TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:rd2:id20:BBBBBBBBBBBBBBBBBBBBe1:t2:aa1:y1:re", cursor, 47);
		cursor+=47;
	}
	now += 1;

	// A third node should now get that peer when asking
	{
		struct sockaddr_in other;
		other.sin_family = AF_INET;
		inet_pton(AF_INET, "255.255.255.255", &other.sin_addr.s_addr);
		other.sin_port = htons(6881);

		char buff[] = "d1:ad2:id20:abcdefghij01234567899:info_hash20:aaaaaaaaaaaaaaaaaaaae1:q9:get_peers1:t2:aa1:y1:qe";
		struct message* message_cursor = outbuff;
		proto_run(&dht, buff, sizeof(buff), &other, sizeof(other), 0, &message_cursor, outbuff+2);

		// We should have sent a response
		TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+1);

		TEST_ASSERT_EQUAL(107, outbuff[0].payload_len);
		char* cursor = outbuff[0].payload;
		TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:rd2:id20:BBBBBBBBBBBBBBBBBBBB5:token32:", cursor, 42);
		cursor+=42;
		// Don't care what the token is
		cursor+=32;
		TEST_ASSERT_EQUAL_CHAR_ARRAY("6:valuesl6:\x80\x00\x00\x01\x23\x82""ee1:t2:aa1:y1:re", cursor, 33);
		cursor+=33;
	}

	proto_end(&dht);
}

void test_node_closer_to_infohash_is_discovered() {
	struct message outbuff[10] = {0};
	time_t now = 0;

	struct sockaddr_storage remote;
	socklen_t remote_len;

	allocate_hashtable();

	struct dht dht;
	dht.self = (struct nodeid){.inner={0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
	routing_init(&dht.self);
	struct nodeid other = (struct nodeid){.inner={0x30303030, 0x30303030, 0x30303030, 0x30303030, 0x3030303}};

	{
		struct message* message_cursor = outbuff;
		proto_begin(&dht, 0, &message_cursor, outbuff+2);
		remote_len = outbuff[0].dest_len;
		memcpy(&remote, &outbuff[0].dest, remote_len);
	}
	now += 10;

	// Some other then asks for peers
	char token[SHA256_BLOCK_SIZE];
	{
		struct sockaddr_in other;
		other.sin_family = AF_INET;
		inet_pton(AF_INET, "128.0.0.1", &other.sin_addr.s_addr);
		other.sin_port = htons(3);

		// Node asks for peers to get token
		char buff[] = "d1:ad2:id20:000000000000000000009:info_hash20:00000000000000000002e1:q9:get_peers1:t2:aa1:y1:qe";
		struct message* message_cursor = outbuff;
		proto_run(&dht, buff, sizeof(buff), &other, sizeof(other), 0, &message_cursor, outbuff+2);

		// We should have sent a response
		TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+1);

		TEST_ASSERT_EQUAL(98, outbuff[0].payload_len);
		char* cursor = outbuff[0].payload;
		TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:rd2:id20:BBBBBBBBBBBBBBBBBBBB5:nodes0:", cursor, 41);
		cursor+=41;
		TEST_ASSERT_EQUAL_CHAR_ARRAY("5:token32:", cursor, 10);
		cursor+=10;
		memcpy(token, cursor, SHA256_BLOCK_SIZE);
		cursor+=SHA256_BLOCK_SIZE;
		TEST_ASSERT_EQUAL_CHAR_ARRAY("e1:t2:aa1:y1:re", cursor, 15);
		cursor+=15;
	}
	now += 1;

	// Using the token from before that node then announces that it's a peer
	{
		struct sockaddr_in other;
		other.sin_family = AF_INET;
		inet_pton(AF_INET, "128.0.0.1", &other.sin_addr.s_addr);
		other.sin_port = htons(3);

		// Node announces that it's a peer for that torrent
		char buff[] = "d1:ad2:id20:0000000000000000000012:implied_porti1e9:info_hash20:000000000000000000024:porti1337e5:token32:                                e1:q13:announce_peer1:t2:aa1:y1:qe";
		memcpy(buff+106, token, SHA256_BLOCK_SIZE);
		struct message* message_cursor = outbuff;
		proto_run(&dht, buff, sizeof(buff), (struct sockaddr_in*)&other, sizeof(other), now, &message_cursor, outbuff+2);
		TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+1);

		TEST_ASSERT_EQUAL(47, outbuff[0].payload_len);
		char* cursor = outbuff[0].payload;
		TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:rd2:id20:BBBBBBBBBBBBBBBBBBBBe1:t2:aa1:y1:re", cursor, 47);
		cursor+=47;
	}
	now += 1;

	// The initial node responds with an id that happens to be closer to the
	// announced infohash than we are. We should reannounce that infohash to
	// it.
	{
		char buff[] = "d1:y1:r1:t1:01:rd2:id20:000000000000000000015:nodes0:ee";
		struct message* message_cursor = outbuff;
		proto_run(&dht, buff, sizeof(buff), (struct sockaddr_in*)&remote, remote_len, now, &message_cursor, outbuff+2);


// Disable this part since we don't currently implementing this functionality.
// It's technically part of the Kademlia spec, but I don't see how you can
// implement it in DHT
#if 0
		TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+1);
		TEST_ASSERT_EQUAL(94, outbuff[0].payload_len);
		TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:ad2:id20:BBBBBBBBBBBBBBBBBBBB9:info_hash20:00000000000000000002e1:q9:get_peers1:t2:aa1:y:qe", outbuff[0].payload, 94);
#else
		TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff);
#endif
	}

#if 0
	struct entry* entry = routing_get(&other);
	TEST_ASSERT_NOT_NULL(entry);
	{
		struct sockaddr_in other;
		other.sin_family = AF_INET;
		inet_pton(AF_INET, "255.255.255.255", &other.sin_addr.s_addr);
		other.sin_port = htons(6881);

		char buff[] = "d1:ad2:id20:abcdefghij01234567896:target20:aaaaaaaaaaaaaaaaaaaae1:q9:find_node1:t2:aa1:y1:qe";
		struct message* message_cursor = outbuff;
		proto_run(&dht, buff, sizeof(buff), &other, sizeof(other), 0, &message_cursor, outbuff+2);

		// We should have sent a response
		TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+1);

		TEST_ASSERT_EQUAL(83, outbuff[0].payload_len);
		TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:rd2:id20:BBBBBBBBBBBBBBBBBBBB5:nodes26:aaaaaaaaaaaaaaaaaaaa", outbuff[0].payload, 62);
		TEST_ASSERT_EQUAL_MEMORY(&((struct sockaddr_in*)&remote)->sin_addr.s_addr, outbuff[0].payload+62, 4);
		TEST_ASSERT_EQUAL_MEMORY(&((struct sockaddr_in*)&remote)->sin_port, outbuff[0].payload+66, 2);
		TEST_ASSERT_EQUAL_CHAR_ARRAY("e1:t2:aa1:y1:re", outbuff[0].payload+68, 15);
	}
#endif

	proto_end(&dht);
}

void test_lookup_response() {
	struct message outbuff[10] = {0};
	time_t now = 0;

	struct sockaddr_in remote;

	struct dht dht;
	dht.self = (struct nodeid){.inner={0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
	routing_init(&dht.self);

	{
		// The initial round of requests for the lookup looks in the routing table.
		// We could do a whole song and dance of getting stuff in there, or just
		// assume that that part works. We just assume.
		struct nodeid other = {.inner={0x43424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
		struct entry *entry;
		TEST_ASSERT_TRUE(routing_offer(&other, &entry));
		entry->addr = (struct addr){
			.ip = 0xFFFFFFFF,
			.port = 1,
		};
		entry->expire = now + PROTO_UNCTM;
	}

	{
		struct message* message_cursor = outbuff;
		proto_begin(&dht, 0, &message_cursor, outbuff+2);
		// We just ignore the first ping. The bootstrap node never responds.
	}
	now += 10;
	
	{
		// We start the lookup by filling in the struct and setting the state
		struct lookup *lookup = &dht.lookup;
		lookup->target = (struct nodeid){.inner={0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161}};
		lookup->state = OP_PENDING;

		struct message* message_cursor = outbuff;
		int rc = proto_run(&dht, NULL, 0, (struct sockaddr_in*)&remote, sizeof(remote), now, &message_cursor, outbuff+2);

		TEST_ASSERT_EQUAL(rc, 0);
		TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+1);
		TEST_ASSERT_EQUAL(91, outbuff[0].payload_len);
		TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:ad2:id20:BBBBBBBBBBBBBBBBBBBB6:target20:aaaaaaaaaaaaaaaaaaaae1:q9:find_node1:t1:11:y1:qe", outbuff[0].payload, 91);
		TEST_ASSERT_EQUAL(1, dht.lookup.outstanding);

		memcpy(&remote, &outbuff[0].dest, sizeof(remote));
	}
	now += 1;

	{
		// The node responds. This should add it to our frontier since it's
		// empty. It should also fan out the search into what it returns since
		// we still have empty spots after adding this one.
		char buff[] = "d1:y1:r1:t1:11:rd2:id20:CBBBBBBBBBBBBBBBBBBB5:nodes52:aBBBBBBBBBBBBBBBBBBB\xFF\xFF\xFF\xFF\x00\x01""aaaaBBBBBBBBBBBBBBBB\xFF\xFF\xFF\xFF\x00\x01""ee";
		struct message* message_cursor = outbuff;
		int rc = proto_run(&dht, buff, sizeof(buff), (struct sockaddr_in*)&remote, sizeof(remote), now, &message_cursor, outbuff+2);

		TEST_ASSERT_EQUAL(rc, 0);
		TEST_ASSERT_EQUAL_CHAR_ARRAY("CBBBBBBBBBBBBBBBBBBB", &dht.lookup.closest[0], 20);

		TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+2);
		TEST_ASSERT_EQUAL(91, outbuff[0].payload_len);
		TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:ad2:id20:BBBBBBBBBBBBBBBBBBBB6:target20:aaaaaaaaaaaaaaaaaaaae1:q9:find_node1:t1:21:y1:qe", outbuff[0].payload, 91);
		TEST_ASSERT_EQUAL(91, outbuff[1].payload_len);
		TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:ad2:id20:BBBBBBBBBBBBBBBBBBBB6:target20:aaaaaaaaaaaaaaaaaaaae1:q9:find_node1:t1:31:y1:qe", outbuff[1].payload, 91);
		TEST_ASSERT_EQUAL(2, dht.lookup.outstanding); // Resolve 1, add 2

		memcpy(&remote, &outbuff[0].dest, sizeof(remote));
	}

	// In actual use, we would have a lot more network/public api traffic here
	// that would respond to some more pings. I don't want to write that code,
	// so instead I'll just fill out some of the internal structures myself.
	//
	// What we are emulating is that a bunch of nodes responded before the one
	// we just asserted above. Those nodes happened to be closer to the final
	// target than the outstanding request we have going on.
	{
		for(size_t i = 0; i < 8; i++) {
			dht.lookup.closest[i] = (struct nodeid){.inner={0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
			// The first two bytes match
			dht.lookup.closest[i].inner_b[0] = 'a';
			dht.lookup.closest[i].inner_b[1] = 'a';
			dht.lookup.closest[i].inner_b[2] = 'a' + i;

			dht.lookup.closest_addr[i].ip = 0;
			dht.lookup.closest_addr[i].port = 1;
		}
	}
	now += 1;

	{
		// The node now finally responds, but woops only the first byte of its
		// ID matches. That's worse than the frontier and shouldn't cause any
		// addtional adjustment to the frontier.
		// It also includes a new node that's better than some nodes in the
		// current frontier, but is also already included.
		char buff[] = "d1:y1:r1:t1:21:rd2:id20:aBBBBBBBBBBBBBBBBBBB5:nodes52:aaaBBBBBBBBBBBBBBBBB\xFF\xFF\xFF\xFF\x00\x01""aaBBBBBBBBBBBBBBBBBB\xFF\xFF\xFF\xFE\x00\x01""ee";
		struct message* message_cursor = outbuff;
		int rc = proto_run(&dht, buff, sizeof(buff), (struct sockaddr_in*)&remote, sizeof(remote), now, &message_cursor, outbuff+2);

		TEST_ASSERT_EQUAL(rc, 0);
		// We only need to check this once since we always pick the first slot
		// with a given score. It's a little implementation dependant, but it
		// beats having 8 asserts.
		TEST_ASSERT_EQUAL_CHAR_ARRAY(&dht.lookup.closest[0], "aaaBBBBBBBBBBBBBBBBB", 20);

		// And we didn't fan out to the new node since it's already part of the current frontier
		TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff);

		TEST_ASSERT_EQUAL(1, dht.lookup.outstanding); // Resolve 1
	}

	// No other packets arrive for this lookup command and it should time out
	now += 119;

	{
		// 15 minutes later a timeout is fired
		struct message* message_cursor = outbuff;
		proto_run(&dht, NULL, 0, (struct sockaddr_in*)&remote, sizeof(remote), now, &message_cursor, outbuff+2);

		TEST_ASSERT_EQUAL(OP_COMPLETED, dht.lookup.state);
		TEST_ASSERT_EQUAL(0, dht.lookup.outstanding);
	}

	now += 10;

	{
		// The slow node from before now _finally_ responds. At this point we
		// have ended the lookup and shouldn't update it anymore, even if this
		// is a really good match
		char buff[] = "d1:y1:r1:t1:31:rd2:id20:aaaaBBBBBBBBBBBBBBBB5:nodes26:aaaaaaaaaaaaaaaaaaaB\xFF\xFF\xFF\xFF\x00\x01""ee";
		struct message* message_cursor = outbuff;
		int rc = proto_run(&dht, buff, sizeof(buff), (struct sockaddr_in*)&remote, sizeof(remote), now, &message_cursor, outbuff+2);

		TEST_ASSERT_EQUAL(rc, 0);
		// We only need to check this once since we always pick the first slot
		// with a given score. It's a little implementation dependant, but it
		// beats having 8 asserts.
		TEST_ASSERT_EQUAL_CHAR_ARRAY(&dht.lookup.closest[0], "aaaBBBBBBBBBBBBBBBBB", 20);

		// And we didn't fan out to the new node since the lookup is done.
		TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff);

		TEST_ASSERT_EQUAL(0, dht.lookup.outstanding);
	}

	proto_end(&dht);
}

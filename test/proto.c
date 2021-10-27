#include "unity.h"
#include "proto.h"

#include "log.h"

#include <string.h>

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
	TEST_ASSERT_EQUAL_CHAR_ARRAY("e1:q9:find_node1:t1:11:y1:qe", outbuff[0].payload+63, 28);

	// The queried node gets added to the routing table
	struct nodeid other = (struct nodeid){.inner={0x61616161, 0x61616161, 0x61616161, 0x61616161, 0x61616161}};
	struct entry* entry = routing_get(&other);
	TEST_ASSERT_NOT_NULL(entry);
	TEST_ASSERT_EQUAL(((struct sockaddr_in*)&remote)->sin_addr.s_addr, entry->addr.ip);
	TEST_ASSERT_EQUAL(((struct sockaddr_in*)&remote)->sin_port, entry->addr.port);
	TEST_ASSERT_EQUAL(PROTO_UNCTM+10, entry->expire);
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
	TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:t2:aa1:y1:r1:rd2:id20:BBBBBBBBBBBBBBBBBBBBee", outbuff[0].payload, 47);
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
	TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:t2:aa1:y1:e1:eli204e14:Unknown Methodee", outbuff[0].payload, 42);
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
		char buff[] = "d1:y1:r1:t1:01:rd2:id20:aaaaaaaaaaaaaaaaaaaa5:nodes26:bbbbbbbbbbbbbbbbbbbb\xFF\xFF\xFF\xFF\x00\x00""ee";
		struct message* message_cursor = outbuff;
		proto_run(&dht, buff, sizeof(buff), (struct sockaddr_in*)&remote, remote_len, 5, &message_cursor, outbuff+2);
	}

	// 15 minutes later a timeout is fired
	struct message* message_cursor = outbuff;
	proto_run(&dht, NULL, 0, (struct sockaddr_in*)&remote, remote_len, 905, &message_cursor, outbuff+2);

	// Which should create a retry ping and a ping for the (now) uncertain node
	TEST_ASSERT_EQUAL_PTR(message_cursor, outbuff+2);
	TEST_ASSERT_EQUAL(91, outbuff[1].payload_len);
	TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:ad2:id20:BBBBBBBBBBBBBBBBBBBB6:target20:", outbuff[1].payload, 43);
	TEST_ASSERT_EQUAL_CHAR_ARRAY("e1:q9:find_node1:t1:01:y1:qe", outbuff[1].payload+63, 28);
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
	TEST_ASSERT_EQUAL_CHAR_ARRAY("e1:q9:find_node1:t1:01:y1:qe", outbuff[0].payload+63, 28);
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
		char buff[] = "d1:y1:r1:t1:01:rd2:id20:aaaaaaaaaaaaaaaaaaaa5:nodes0:""ee";
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

	TEST_ASSERT_EQUAL_PTR_MESSAGE(message_cursor, outbuff, "The timeout should send a message");
	entry = routing_get(&other);
	TEST_ASSERT_NULL(entry);
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
		char buff[] = "d1:y1:r1:t1:01:rd2:id20:aaaaaaaaaaaaaaaaaaaa5:nodes0:""ee";
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
		char buff[] = "d1:y1:r1:t1:01:rd2:id20:aaaaaaaaaaaaaaaaaaaa5:nodes0:""ee";
		struct message* message_cursor = outbuff;
		proto_run(&dht, buff, sizeof(buff), (struct sockaddr_in*)&remote, remote_len, now, &message_cursor, outbuff+2);

		// The routing table entry should have its expiry time updated
		struct entry* entry = routing_get(&other);
		TEST_ASSERT_NOT_NULL(entry);
		TEST_ASSERT_GREATER_THAN(now, entry->expire);
	}
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
		char buff[] = "d1:y1:r1:t1:01:rd2:id20:aaaaaaaaaaaaaaaaaaaa5:nodes0:""ee";
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
		TEST_ASSERT_EQUAL_CHAR_ARRAY("d1:t2:aa1:y1:r1:rd2:id20:BBBBBBBBBBBBBBBBBBBB5:nodes26:aaaaaaaaaaaaaaaaaaaa", outbuff[0].payload, 75);
		TEST_ASSERT_EQUAL_MEMORY(&((struct sockaddr_in*)&remote)->sin_addr.s_addr, outbuff[0].payload+75, 4);
		TEST_ASSERT_EQUAL_MEMORY(&((struct sockaddr_in*)&remote)->sin_port, outbuff[0].payload+79, 2);
		TEST_ASSERT_EQUAL_CHAR_ARRAY("ee", outbuff[0].payload+81, 2);
	}
}

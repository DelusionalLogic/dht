#include <unity.h>

#include "proto.h"
#include "query.h"

#include <string.h>
#include <arpa/inet.h>

#define IP(a, b, c, d) htonl(a << 24 | b << 16 | c << 8 | d)

void test_malformed_empty() {
	time_t now = 120;
	struct tokens tokens = {0};
	struct sockaddr_in src = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = IP(255, 0, 0, 1),
		.sin_port = 6881,
	};

	struct nodeid self = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, 0x0ab00521}};
	char* packet = "";
	size_t packet_len = 0;

	char response[1024];
	char* response_cursor = response;
	char* response_end = response + sizeof(response);

	int rc = handle_request(&self, &tokens, now, "ping", (struct sockaddr*)&src, sizeof(src), packet, packet_len, &response_cursor, response_end-response_cursor);

	TEST_ASSERT_EQUAL(QUERY_EBADQ, rc);
}

void test_malformed_only_dict_start() {
	time_t now = 120;
	struct tokens tokens = {0};
	struct sockaddr_in src = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = IP(255, 0, 0, 1),
		.sin_port = 6881,
	};

	struct nodeid self = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, 0x0ab00521}};
	char* packet = "d";
	size_t packet_len = 1;

	char response[1024];
	char* response_cursor = response;
	char* response_end = response + sizeof(response);

	int rc = handle_request(&self, &tokens, now, "ping", (struct sockaddr*)&src, sizeof(src), packet, packet_len, &response_cursor, response_end-response_cursor);

	TEST_ASSERT_EQUAL(QUERY_EBADQ, rc);
}

void test_malformed_empty_args_key() {
	time_t now = 120;
	struct tokens tokens = {0};
	struct sockaddr_in src = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = IP(255, 0, 0, 1),
		.sin_port = 6881,
	};

	struct nodeid self = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, 0x0ab00521}};
	char* packet = "d1:ae";
	size_t packet_len = strlen(packet);

	char response[1024];
	char* response_cursor = response;
	char* response_end = response + sizeof(response);

	int rc = handle_request(&self, &tokens, now, "ping", (struct sockaddr*)&src, sizeof(src), packet, packet_len, &response_cursor, response_end-response_cursor);

	TEST_ASSERT_EQUAL(QUERY_EBADQ, rc);
}

void test_malformed_wrong_args_type() {
	time_t now = 120;
	struct tokens tokens = {0};
	struct sockaddr_in src = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = IP(255, 0, 0, 1),
		.sin_port = 6881,
	};

	struct nodeid self = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, 0x0ab00521}};
	char* packet = "d1:a1:re";
	size_t packet_len = strlen(packet);

	char response[1024];
	char* response_cursor = response;
	char* response_end = response + sizeof(response);

	int rc = handle_request(&self, &tokens, now, "ping", (struct sockaddr*)&src, sizeof(src), packet, packet_len, &response_cursor, response_end-response_cursor);

	TEST_ASSERT_EQUAL(QUERY_EBADQ, rc);
}

void test_malformed_empty_args() {
	time_t now = 120;
	struct tokens tokens = {0};
	struct sockaddr_in src = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = IP(255, 0, 0, 1),
		.sin_port = 6881,
	};

	struct nodeid self = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, 0x0ab00521}};
	char* packet = "d1:adee";
	size_t packet_len = strlen(packet);

	char response[1024];
	char* response_cursor = response;
	char* response_end = response + sizeof(response);

	int rc = handle_request(&self, &tokens, now, "ping", (struct sockaddr*)&src, sizeof(src), packet, packet_len, &response_cursor, response_end-response_cursor);

	TEST_ASSERT_EQUAL(QUERY_EBADQ, rc);
}

void test_malformed_wrong_id_arg_type() {
	time_t now = 120;
	struct tokens tokens = {0};
	struct sockaddr_in src = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = IP(255, 0, 0, 1),
		.sin_port = 6881,
	};

	struct nodeid self = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, 0x0ab00521}};
	char* packet = "d1:ad2:idi1eee";
	size_t packet_len = strlen(packet);

	char response[1024];
	char* response_cursor = response;
	char* response_end = response + sizeof(response);

	int rc = handle_request(&self, &tokens, now, "ping", (struct sockaddr*)&src, sizeof(src), packet, packet_len, &response_cursor, response_end-response_cursor);

	TEST_ASSERT_EQUAL(QUERY_EBADQ, rc);
}

void test_malformed_wrong_id_length() {
	time_t now = 120;
	struct tokens tokens = {0};
	struct sockaddr_in src = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = IP(255, 0, 0, 1),
		.sin_port = 6881,
	};

	struct nodeid self = {.inner={0x0034048f, 0x08000020, 0x00888880, 0x02008460, 0x0ab00521}};
	char* packet = "d1:ad2:id19:aaaaaaaaaaaaaaaaaaaee";
	size_t packet_len = strlen(packet);

	char response[1024];
	char* response_cursor = response;
	char* response_end = response + sizeof(response);

	int rc = handle_request(&self, &tokens, now, "ping", (struct sockaddr*)&src, sizeof(src), packet, packet_len, &response_cursor, response_end-response_cursor);

	TEST_ASSERT_EQUAL(QUERY_EBADQ, rc);
}

void test_ping() {
	time_t now = 120;
	struct tokens tokens = {0};
	struct sockaddr_in src = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = IP(255, 0, 0, 1),
		.sin_port = 6881,
	};

	struct nodeid self = {.inner_b={"aaaaaaaaaaaaaaaaaaab"}};
	char* packet = "d1:ad2:id20:aaaaaaaaaaaaaaaaaaaaee";
	size_t packet_len = strlen(packet);

	char response[1024];
	char* response_cursor = response;
	char* response_end = response + sizeof(response);

	int rc = handle_request(&self, &tokens, now, "ping", (struct sockaddr*)&src, sizeof(src), packet, packet_len, &response_cursor, response_end-response_cursor);

	TEST_ASSERT_EQUAL(0, rc);
	TEST_ASSERT_EQUAL(29, response_cursor - response);
	TEST_ASSERT_EQUAL_CHAR_ARRAY("d2:id20:aaaaaaaaaaaaaaaaaaabe", response, 30);
}

void test_bad_method() {
	time_t now = 120;
	struct tokens tokens = {0};
	struct sockaddr_in src = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = IP(255, 0, 0, 1),
		.sin_port = 6881,
	};

	struct nodeid self = {.inner_b={"aaaaaaaaaaaaaaaaaaab"}};
	char* packet = "de";
	size_t packet_len = strlen(packet);

	char response[1024];
	char* response_cursor = response;
	char* response_end = response + sizeof(response);

	int rc = handle_request(&self, &tokens, now, "someWrongMethod", (struct sockaddr*)&src, sizeof(src), packet, packet_len, &response_cursor, response_end-response_cursor);

	TEST_ASSERT_EQUAL(QUERY_EUNK, rc);
}

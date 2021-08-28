#include "unity.h"
#include "benc.h"

#include <string.h>

void test_string() {
	struct benc_node stream[1];
	char* packet = "3:abc";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 1);

	TEST_ASSERT_EQUAL(1, len);
	TEST_ASSERT_EQUAL(BNT_STRING, stream[0].type);
	TEST_ASSERT_EQUAL(3, stream[0].size);
	TEST_ASSERT_EQUAL_PTR(packet + 2, stream[0].loc);
}

void test_unfinished_string() {
	struct benc_node stream[1];
	// There only 3 chars available
	char* packet = "4:abc";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 1);

	TEST_ASSERT_EQUAL(0, len);
	TEST_ASSERT_EQUAL(BNT_STRING, stream[0].type);
	TEST_ASSERT_EQUAL(4, stream[0].size);
	TEST_ASSERT_EQUAL_PTR(packet + 2, stream[0].loc);
}

void test_positive_int() {
	struct benc_node stream[1];
	char* packet = "i3e";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 1);

	TEST_ASSERT_EQUAL(1, len);
	TEST_ASSERT_EQUAL(BNT_INT, stream[0].type);
	TEST_ASSERT_EQUAL(1, stream[0].size);
	TEST_ASSERT_EQUAL_PTR(packet + 1, stream[0].loc);
}

void test_multiple_int() {
	struct benc_node stream[2];
	char* packet = "i3ei3e";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 2);

	// Stop after the first int
	TEST_ASSERT_EQUAL(packet + 3, cursor);
	TEST_ASSERT_EQUAL(1, len);
	TEST_ASSERT_EQUAL(BNT_INT, stream[0].type);
	TEST_ASSERT_EQUAL(1, stream[0].size);
	TEST_ASSERT_EQUAL_PTR(packet + 1, stream[0].loc);
}

void test_unfinished_int() {
	struct benc_node stream[1];
	char* packet = "i3";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 1);

	TEST_ASSERT_EQUAL(0, len);
	TEST_ASSERT_EQUAL(BNT_INT, stream[0].type);
	TEST_ASSERT_EQUAL_PTR(packet + 1, stream[0].loc);
}

void test_negative_int() {
	struct benc_node stream[1];
	char* packet = "i-3e";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 1);

	TEST_ASSERT_EQUAL(1, len);
	TEST_ASSERT_EQUAL(BNT_INT, stream[0].type);
	TEST_ASSERT_EQUAL(2, stream[0].size);
	TEST_ASSERT_EQUAL_PTR(packet + 1, stream[0].loc);
}

void test_incorrect_int_char() {
	struct benc_node stream[1];
	char* packet = "i-a3e";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 1);

	TEST_ASSERT_EQUAL(packet + 2, cursor);
	TEST_ASSERT_EQUAL(0, len);
	TEST_ASSERT_EQUAL(BNT_INT, stream[0].type);
	TEST_ASSERT_EQUAL_PTR(packet + 1, stream[0].loc);
}

void test_list() {
	struct benc_node stream[3];
	char* packet = "li1ee";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 3);

	TEST_ASSERT_EQUAL(3, len);
	size_t nodeCursor = 0;
	TEST_ASSERT_EQUAL(BNT_LIST, stream[nodeCursor].type);
	TEST_ASSERT_EQUAL(0, stream[nodeCursor].depth);
	TEST_ASSERT_EQUAL_PTR(packet + 0, stream[nodeCursor].loc);
	nodeCursor++;
	TEST_ASSERT_EQUAL(BNT_INT, stream[nodeCursor].type);
	nodeCursor++;
	TEST_ASSERT_EQUAL(BNT_END, stream[nodeCursor].type);
	TEST_ASSERT_EQUAL(0, stream[nodeCursor].depth);
	TEST_ASSERT_EQUAL_PTR(packet + 4, stream[nodeCursor].loc);
	nodeCursor++;
}

void test_dict() {
	struct benc_node stream[4];
	char* packet = "d1:a1:be";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 4);

	TEST_ASSERT_EQUAL(4, len);
	size_t nodeCursor = 0;
	TEST_ASSERT_EQUAL(BNT_DICT, stream[nodeCursor].type);
	TEST_ASSERT_EQUAL(0, stream[nodeCursor].depth);
	TEST_ASSERT_EQUAL_PTR(packet + 0, stream[nodeCursor].loc);
	nodeCursor++;
	TEST_ASSERT_EQUAL(BNT_STRING, stream[nodeCursor].type);
	nodeCursor++;
	TEST_ASSERT_EQUAL(BNT_STRING, stream[nodeCursor].type);
	nodeCursor++;
	TEST_ASSERT_EQUAL(BNT_END, stream[nodeCursor].type);
	TEST_ASSERT_EQUAL(0, stream[nodeCursor].depth);
	TEST_ASSERT_EQUAL_PTR(packet + 7, stream[nodeCursor].loc);
	nodeCursor++;
}

void test_nested_list() {
	struct benc_node stream[5];
	char* packet = "lli1eee";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 5);

	TEST_ASSERT_EQUAL(5, len);
	size_t nodeCursor = 0;
	TEST_ASSERT_EQUAL(BNT_LIST, stream[nodeCursor].type);
	TEST_ASSERT_EQUAL(0, stream[nodeCursor].depth);
	TEST_ASSERT_EQUAL_PTR(packet + 0, stream[nodeCursor].loc);
	nodeCursor++;
	TEST_ASSERT_EQUAL(BNT_LIST, stream[nodeCursor].type);
	TEST_ASSERT_EQUAL(1, stream[nodeCursor].depth);
	TEST_ASSERT_EQUAL_PTR(packet + 1, stream[nodeCursor].loc);
	nodeCursor++;
	TEST_ASSERT_EQUAL(BNT_INT, stream[nodeCursor].type);
	nodeCursor++;
	TEST_ASSERT_EQUAL(BNT_END, stream[nodeCursor].type);
	TEST_ASSERT_EQUAL(1, stream[nodeCursor].depth);
	TEST_ASSERT_EQUAL_PTR(packet + 5, stream[nodeCursor].loc);
	nodeCursor++;
	TEST_ASSERT_EQUAL(BNT_END, stream[nodeCursor].type);
	TEST_ASSERT_EQUAL(0, stream[nodeCursor].depth);
	TEST_ASSERT_EQUAL_PTR(packet + 6, stream[nodeCursor].loc);
	nodeCursor++;
}

void test_parse_int() {
	char* packet = "100";

	const char* cursor = packet;
	int64_t val;
	bool rc = readint(&cursor, &val);

	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_EQUAL(100, val);
	TEST_ASSERT_EQUAL_PTR(packet + 3, cursor);
}

void test_parse_negative_int() {
	char* packet = "-100";

	const char* cursor = packet;
	int64_t val;
	bool rc = readint(&cursor, &val);

	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_EQUAL(-100, val);
	TEST_ASSERT_EQUAL_PTR(packet + 4, cursor);
}

void test_stop_at_non_digit() {
	char* packet = "10a1";

	const char* cursor = packet;
	int64_t val;
	bool rc = readint(&cursor, &val);

	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_EQUAL(10, val);
	TEST_ASSERT_EQUAL_PTR(packet + 2, cursor);
}

void test_stop_embedded_minus() {
	char* packet = "10-1";

	const char* cursor = packet;
	int64_t val;
	bool rc = readint(&cursor, &val);

	TEST_ASSERT_EQUAL(true, rc);
	TEST_ASSERT_EQUAL(10, val);
	TEST_ASSERT_EQUAL_PTR(packet + 2, cursor);
}

void test_find_key_under_cursor() {
	struct benc_node stream[4];
	char* packet = "d1:ri1ee";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 4);


	const struct benc_node* stream_cursor = stream;
	stream_cursor++; // Skip the dict
	ssize_t found = skip_to_key(&stream_cursor, stream+len, (const enum benc_nodetype[]){BNT_STRING}, (const char*[]){"r"}, (const size_t[]){1}, 1);

	TEST_ASSERT_EQUAL(0, found);
	TEST_ASSERT_EQUAL_PTR(stream+1, stream_cursor);
}

void test_key_not_found() {
	struct benc_node stream[4];
	char* packet = "d1:ri1ee";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 4);


	const struct benc_node* stream_cursor = stream;
	stream_cursor++; // Skip the dict
	ssize_t found = skip_to_key(&stream_cursor, stream+len, (const enum benc_nodetype[]){BNT_STRING}, (const char*[]){"a"}, (const size_t[]){1}, 1);

	TEST_ASSERT_EQUAL(-1, found);
	TEST_ASSERT_EQUAL_PTR(stream+3, stream_cursor);
}

void test_skip_nested_list_value() {
	struct benc_node stream[8];
	char* packet = "d1:al1:re1:ri1ee";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 8);


	const struct benc_node* stream_cursor = stream;
	stream_cursor++; // We know the first is a dict
	ssize_t found = skip_to_key(&stream_cursor, stream+len, (const enum benc_nodetype[]){BNT_STRING}, (const char*[]){"r"}, (const size_t[]){1}, 1);

	TEST_ASSERT_EQUAL(0, found);
	TEST_ASSERT_EQUAL_PTR(stream+5, stream_cursor);
}

void test_skip_nested_dict_value() {
	struct benc_node stream[9];
	char* packet = "d1:adi2e1:re1:ri1ee";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 9);

	const struct benc_node* stream_cursor = stream;
	stream_cursor++; // We know the first is a dict
	ssize_t found = skip_to_key(&stream_cursor, stream+len, (const enum benc_nodetype[]){BNT_STRING}, (const char*[]){"r"}, (const size_t[]){1}, 1);

	TEST_ASSERT_EQUAL(0, found);
	TEST_ASSERT_EQUAL_PTR(stream+6, stream_cursor);
}

void test_skip_nested_dict_key() {
	struct benc_node stream[9];
	char* packet = "d1:ad1:ri2ee1:ri1ee";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 9);

	const struct benc_node* stream_cursor = stream;
	stream_cursor++; // We know the first is a dict
	ssize_t found = skip_to_key(&stream_cursor, stream+len, (const enum benc_nodetype[]){BNT_STRING}, (const char*[]){"r"}, (const size_t[]){1}, 1);

	TEST_ASSERT_EQUAL(0, found);
	TEST_ASSERT_EQUAL_PTR(stream+6, stream_cursor);
}

void test_skip_multilevel_list() {
	struct benc_node stream[9];
	char* packet = "d1:all1:ree1:ri1ee";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 9);

	const struct benc_node* stream_cursor = stream;
	stream_cursor++; // We know the first is a dict
	ssize_t found = skip_to_key(&stream_cursor, stream+len, (const enum benc_nodetype[]){BNT_STRING}, (const char*[]){"r"}, (const size_t[]){1}, 1);

	TEST_ASSERT_EQUAL(0, found);
	TEST_ASSERT_EQUAL_PTR(stream+7, stream_cursor);
}

void test_find_any_semantics() {
	struct benc_node stream[9];
	char* packet = "d1:a1:a1:b1:be";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 9);

	const struct benc_node* stream_cursor = stream;
	stream_cursor++; // We know the first is a dict
	ssize_t found = skip_to_key(&stream_cursor, stream+len, (const enum benc_nodetype[]){BNT_STRING, BNT_STRING}, (const char*[]){"b", "a"}, (const size_t[]){1, 1}, 2);

	TEST_ASSERT_EQUAL(1, found);
	TEST_ASSERT_EQUAL_PTR(stream+1, stream_cursor);

	stream_cursor+=2; // Skip the key and value
	found = skip_to_key(&stream_cursor, stream+len, (const enum benc_nodetype[]){BNT_STRING, BNT_STRING}, (const char*[]){"b", "a"}, (const size_t[]){1, 1}, 2);
	TEST_ASSERT_EQUAL(0, found);
	TEST_ASSERT_EQUAL_PTR(stream+3, stream_cursor);
}

void test_stop_at_end() {
	struct benc_node stream[9];
	char* packet = "ld1:a1:aee";

	const char* cursor = packet;
	int depth = 0;
	int64_t len = benc_decode(&cursor, cursor + strlen(packet), &depth, stream, 9);

	const struct benc_node* stream_cursor = stream;
	stream_cursor++; // We know the first is a list
	stream_cursor++; // We know the second is a dict
	// X does not exist in the packet
	ssize_t found = skip_to_key(&stream_cursor, stream+len, (const enum benc_nodetype[]){BNT_STRING}, (const char*[]){"x"}, (const size_t[]){1}, 1);

	TEST_ASSERT_EQUAL_MESSAGE(-1, found, "Found something");
	TEST_ASSERT_EQUAL_PTR_MESSAGE(stream+4, stream_cursor, "Didn't stop at dict end");
}

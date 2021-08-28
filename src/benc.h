#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>

enum benc_nodetype {
	BNT_INT,
	BNT_STRING,
	BNT_LIST,
	BNT_DICT,
	BNT_END,
};

struct benc_node {
	enum benc_nodetype type;
	const char* loc;
	union {
		size_t size;
		uint32_t depth;
	};
};

bool readint(const char** loc, int64_t* val);

void benc_print(const struct benc_node* stream, size_t stream_len, int* depth);
int64_t benc_decode(const char** cursor, const char* end, int* depth, struct benc_node* stream, size_t stream_len);

void skip_sibling(const struct benc_node** cursor, const struct benc_node* end);
ssize_t skip_to_key(const struct benc_node** cursor, const struct benc_node* end, const enum benc_nodetype* keyTypes, const char** keyValues, const size_t* keyLengths, const size_t keys);

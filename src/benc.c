#include "benc.h"
#include "log.h"

#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>


#define MAX(a, b)                 \
	 ({                           \
		 __typeof__ (a) _a = (a); \
		 __typeof__ (b) _b = (b); \
		 _a > _b ? _a : _b;       \
	 })

#define MIN(a, b)                 \
	 ({                           \
		 __typeof__ (a) _a = (a); \
		 __typeof__ (b) _b = (b); \
		 _a < _b ? _a : _b;       \
	 })

bool readint(const char** loc, int64_t* val) {
	char* end = NULL;
	errno = 0;
	*val = strtol(*loc, &end, 10);
	*loc = end;

	return errno == 0;
}

bool digit(const char c) {
	return c >= '0' && c <= '9';
}

char* nodenames[] = {
	"INT",
	"STR",
	"LIST",
	"DICT",
	"END",
};

void indent(int depth) {
	for(int i = 0; i < depth; i++) {
		printf("    ");
	}
}

void benc_print(const struct benc_node* stream, size_t stream_len, int* depth) {
	const struct benc_node* cursor = stream;
	for(; cursor < stream + stream_len; cursor++) {
		switch(cursor->type) {
			case BNT_INT:
				indent(*depth);
				printf("INT %.*s\n", cursor->size, cursor->loc);
				break;
			case BNT_STRING:
				indent(*depth);
				bool allprint = true;
				for (const char* c = cursor->loc; c < cursor->loc + cursor->size; c++) {
					if(!isalnum(*c)) {
						allprint = false;
						break;
					}
				}
				printf("STR ");
				if(allprint) {
					printf("%.*s", cursor->size, cursor->loc);
				} else {
					for (const unsigned char* c = (const unsigned char*)cursor->loc; c < (unsigned char*)(cursor->loc + cursor->size); c++) {
						printf("\\x%02X", *c);
					}
				}
				printf("\n");
				break;
			case BNT_LIST:
				indent(*depth);
				printf("LIST\n");
				*depth = cursor->depth + 1;
				break;
			case BNT_DICT:
				indent(*depth);
				printf("DICT\n");
				*depth = cursor->depth + 1;
				break;
			case BNT_END:
				*depth = cursor->depth;
				indent(*depth);
				printf("END\n");
				break;
		}
	}
}

int64_t benc_decode(const char** cursor, const char* end, int* depth, struct benc_node* stream, size_t stream_len) {
	size_t cursor_out = 0;

	while(cursor_out < stream_len) {
		struct benc_node* node = &stream[cursor_out];

		if(**cursor == 'i') {
			node->type = BNT_INT;
			(*cursor)++;
			if(*cursor >= end) {
				return -cursor_out;
			}
			node->loc = *cursor;
			while(**cursor != 'e') {
				if(**cursor != '-' && !digit(**cursor)) {
					return -cursor_out;
				}
				(*cursor)++;
				if(*cursor >= end) {
					return -cursor_out;
				}
			}
			node->size = *cursor - node->loc;
			(*cursor)++;
		} else if(**cursor == 'l') {
			node->type = BNT_LIST;
			node->depth = *depth;
			(*depth)++;
			node->loc = *cursor;
			(*cursor)++;
			if(*cursor >= end) {
				return -cursor_out;
			}
		} else if(**cursor == 'd') {
			node->type = BNT_DICT;
			node->depth = *depth;
			(*depth)++;
			node->loc = *cursor;
			(*cursor)++;
			if(*cursor >= end) {
				return -cursor_out;
			}
		} else if(**cursor == 'e') {
			node->type = BNT_END;
			(*depth)--;
			node->depth = *depth;
			node->loc = *cursor;
			(*cursor)++;
		} else if(digit(**cursor)) {
			node->type = BNT_STRING;
			int64_t val;
			bool rc = readint(cursor, &val);
			node->size = val;
			if(*cursor >= end) {
				return -cursor_out;
			}
			assert(rc);
			if(**cursor != ':') {
				return -cursor_out;
			}
			(*cursor)++;
			if(*cursor >= end) {
				return -cursor_out;
			}
			node->loc = *cursor;
			(*cursor) += node->size;
			if(*cursor > end) {
				return -cursor_out;
			}
		} else {
			return -cursor_out;
			dbg("Failing on char \"%c\"", **cursor);
			assert(false);
		}
		cursor_out++;
		if(*depth == 0) break;
	}
	return cursor_out;
}

int bcur_fill(struct bcursor* cursor) {
	if(cursor->source == cursor->source_end) {
		return EOF;
	}

	int read = benc_decode(&cursor->source, cursor->source_end, &cursor->source_depth, cursor->base, cursor->base_len);
	cursor->end = cursor->base + read;

	return 0;
}

int bcur_open(struct bcursor* cursor, const char* source, const char* source_end, struct benc_node* buffer, size_t buffer_len) {
	cursor->source = source;
	(*((const char**)&cursor->source_end)) = source_end;
	cursor->source_depth = 0;

	*((struct benc_node**)&cursor->base) = buffer;
	*((size_t*)&cursor->base_len) = buffer_len;
	cursor->readhead = buffer;

	return bcur_fill(cursor);
}

int bcur_next(struct bcursor* cursor, uint32_t steps) {
	cursor->readhead+=steps;

	// Check if we need to read more
	if(cursor->readhead >= cursor->end) {
		return bcur_fill(cursor);
	}
	return 0;
}

int bcur_next_sibling(struct bcursor* cursor) {
	assert(cursor->readhead->type == BNT_LIST || cursor->readhead->type == BNT_DICT);

	if(cursor->readhead->type == BNT_LIST || cursor->readhead->type == BNT_DICT) {
		uint32_t tdepth = cursor->readhead->depth;
		cursor->readhead++;
		while(cursor->readhead->type != BNT_END || cursor->readhead->depth != tdepth) {
			if(bcur_next(cursor, 1) != 0) {
				fatal("Invalid dict/list");
			}
		}
	}

	return bcur_next(cursor, 1);
}

// All the arrays should be equal length
ssize_t bcur_find_key(struct bcursor* cursor, const enum benc_nodetype* keyTypes, const char** keyValues, const size_t* keyLengths, const size_t keys) {
	// @ROBUSTNESS: Check if keytypes are anything but strings and ints because that is not supported
	int rc;

	while(true) {
		// Skip lists
		if(cursor->readhead->type == BNT_LIST || cursor->readhead->type == BNT_DICT) {
			rc = bcur_next_sibling(cursor);
			if(rc != 0) {
				fatal("Invalid dict");
			}
		} else {
			// Check if the key one of the ones we are looking for
			for(size_t i = 0; i < keys; i++) {
				if(cursor->readhead->type == keyTypes[i] && memcmp(cursor->readhead->loc, keyValues[i], MIN(cursor->readhead->size, keyLengths[i])) == 0) {
					return i;
				}
			}
		}

		// Skip the key part
		rc = bcur_next(cursor, 1);
		if(rc != 0) {
			fatal("Invalid dict");
		}

		if(cursor->readhead->type == BNT_LIST || cursor->readhead->type == BNT_DICT) {
			// Skip a multitoken element
			rc = bcur_next_sibling(cursor);
			if(rc != 0) {
				fatal("Invalid dict");
			}
		} else {
			// Skip a single token element
			rc = bcur_next(cursor, 1);
			if(rc != 0) {
				fatal("Invalid dict");
			}
		}

		if(cursor->readhead->type == BNT_END) {
			return -1;
		}
	}
}

void skip_sibling(const struct benc_node** cursor, const struct benc_node* end) {
	assert((*cursor)->type == BNT_LIST || (*cursor)->type == BNT_DICT);

	if((*cursor)->type == BNT_LIST || (*cursor)->type == BNT_DICT) {
		uint32_t tdepth = (*cursor)->depth;
		(*cursor)++;
		while(true) {
			if(*cursor == end) {
				fatal("Invalid dict");
			}

			if((*cursor)->type == BNT_END && (*cursor)->depth == tdepth) {
				break;
			}

			(*cursor)++;
		}
		(*cursor)++;
	} else {
		(*cursor)++;
	}
}

// All the arrays should be equal length
ssize_t skip_to_key(const struct benc_node** cursor, const struct benc_node* end, const enum benc_nodetype* keyTypes, const char** keyValues, const size_t* keyLengths, const size_t keys) {
	// @ROBUSTNESS: Check if keytypes are anything but strings and ints because that is not supported

	while(true) {
		if(*cursor > end-1) {
			return -1;
		}

		// Skip lists
		if((*cursor)->type == BNT_LIST || (*cursor)->type == BNT_DICT) {
			skip_sibling(cursor, end);
		} else {
			for(size_t i = 0; i < keys; i++) {
				if((*cursor)->type == keyTypes[i] && memcmp((*cursor)->loc, keyValues[i], MIN((*cursor)->size, keyLengths[i])) == 0) {
					return i;
				}
			}
		}

		(*cursor) += 2;

		if((*cursor-1)->type == BNT_LIST || (*cursor-1)->type == BNT_DICT) {
			(*cursor)--;
			skip_sibling(cursor, end);
		}

		if((*cursor)->type == BNT_END) {
			return -1;
		}
	}
}

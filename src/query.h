#pragma once

#include "routing.h"

#include <stdint.h>
#include <sys/socket.h>

#define QUERY_EBADQ 1
#define QUERY_EUNK  2

// @PASTE: This is taken from proto.h, we should move it elsewhere
#define TOK_VALI 1
struct tokens;
void token_create(struct tokens* tokens, time_t now, struct addr* remote, char* token);
int token_validate(struct tokens* tokens, time_t now, struct addr* remote, char* token);

int handle_request(struct nodeid* self, struct tokens* tokens, bool *dirtyconf, time_t now, const char* method, const struct sockaddr* src, socklen_t src_len, const char* packet, size_t packet_len, char** response, size_t response_len);

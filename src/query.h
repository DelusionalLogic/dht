#pragma once

#include "routing.h"

#include <stdint.h>
#include <sys/socket.h>

#define QUERY_EBADQ 1
#define QUERY_EUNK  2

int handle_request(struct nodeid* self, const char* method, const struct sockaddr* src, socklen_t src_len, const char* packet, size_t packet_len, char** response, size_t response_len);

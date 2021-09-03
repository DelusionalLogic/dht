#pragma once

#include "routing.h"

#include <stdint.h>

#define QUERY_EBADQ 1
#define QUERY_EUNK  2

int handle_request(struct nodeid* self, const char* method, const char* packet, size_t packet_len, char** response, size_t response_len);

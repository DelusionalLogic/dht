#pragma once

#include <stdio.h>

#define dbg(format, ...) \
	dbgl(format "\n", ##  __VA_ARGS__)

#define dbgl(format, ...) \
	printf(format, ## __VA_ARGS__); \
	fflush(stderr)

#define err(format, ...) \
	printf(format "\n", ## __VA_ARGS__); \
	fflush(stderr)

#define fatal(format, ...) do{\
		printf(format "\n", ## __VA_ARGS__); \
		fflush(stderr); \
		abort(); \
	} while(0)


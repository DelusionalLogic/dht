#pragma once

#include <stdio.h>
#include <stdlib.h>

#define dbg(format, ...) \
	dbgl(format "\n", ##  __VA_ARGS__)

#define dbgl(format, ...) do{\
		printf(format, ## __VA_ARGS__); \
		fflush(stderr); \
	} while(0)

#define err(format, ...) do{\
		printf(format "\n", ## __VA_ARGS__); \
		fflush(stderr); \
	} while(0)

#define fatal(format, ...) do{\
		printf(format "\n", ## __VA_ARGS__); \
		fflush(stderr); \
		abort(); \
	} while(0)


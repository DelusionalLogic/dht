#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>

ssize_t base64_encode_inplace(const uint8_t *data, size_t data_len, char* buf, size_t buf_len);
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);

ssize_t base64_decode_incr(const unsigned char *data, size_t data_len, uint8_t *buf, size_t buf_len);
ssize_t base64_decode(const unsigned char *data, size_t data_len, uint8_t *buf, size_t buf_len);

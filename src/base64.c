#include "base64.h"
#include "log.h"

#include <stdbool.h>

static char encoding_table[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/'
};
static int mod_table[] = {0, 2, 1};
ssize_t base64_encode_inplace(const uint8_t *data, size_t data_len, char* buf, size_t buf_len) {
	size_t output_len = 4 * ((data_len + 2) / 3);

	if(output_len > buf_len) return output_len;

	for (int i = 0, j = 0; i < data_len;) {
		uint32_t octet_a = i < data_len ? (unsigned char)data[i++] : 0;
		uint32_t octet_b = i < data_len ? (unsigned char)data[i++] : 0;
		uint32_t octet_c = i < data_len ? (unsigned char)data[i++] : 0;

		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		buf[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		buf[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		buf[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		buf[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for (int i = 0; i < mod_table[data_len % 3]; i++) {
		buf[output_len - 1 - i] = '=';
	}

	buf[output_len] = '\0';

	return output_len;
}
// @CLEANUP This really should exist, but I've kept it around as an adapter for
// the code that uses it. Remove it at some point
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
	*output_length = base64_encode_inplace(data, input_length, NULL, 0);

	char *encoded_data = malloc(*output_length + 1);
	assert(encoded_data != NULL);

	base64_encode_inplace(data, input_length, encoded_data, *output_length+1);
	return encoded_data;
}

static int8_t decoding_table[] = {
	62, -1, -1, -1, 63, 52, 53, 54,
	55, 56, 57, 58, 59, 60, 61, -1,
	-1, -1, -1, -1, -1, -1,  0,  1,
	 2,  3,  4,  5,  6,  7,  8,  9,
	10, 11, 12, 13, 14, 15, 16, 17,
	18, 19, 20, 21, 22, 23, 24, 25,
	-1, -1, -1, -1, -1, -1, 26, 27,
	28, 29, 30, 31, 32, 33, 34, 35,
	36, 37, 38, 39, 40, 41, 42, 43,
	44, 45, 46, 47, 48, 49, 50, 51
};

ssize_t base64_decode_incr(const unsigned char *data, size_t data_len, uint8_t *buf, size_t buf_len) {
	size_t i = 0;
	size_t j = 0;
	uint8_t runoff = 0;
	while(runoff == 0 && i < data_len) {
		uint32_t triple = 0;
		for(uint8_t k = 0; k < 4; k++) {
			int8_t sextent = 0;
			char cp = data[i];
			if(cp < 43 || cp > 122) {
				// NULL byte string terminator ends here
				return k == 0 ? j : -1;
			} else if(cp == '=' && k < 2) {
				return -1;
			} else if(cp == '=') {
				sextent = 0;
				runoff = 4-k;
				break;
			} else {
				sextent = decoding_table[cp - 43];
				if(sextent < 0) return k == 0 ? j : -1;
				i++;
			}

			triple |= (sextent << (3-k) * 6);
		}

		if (j+runoff >= buf_len) return -1;
		if(runoff <= 2) buf[j++] = (triple >> 2 * 8) & 0xFF;
		if(runoff <= 1) buf[j++] = (triple >> 1 * 8) & 0xFF;
		if(runoff <= 0) buf[j++] = (triple >> 0 * 8) & 0xFF;
	}

	return j;
}

ssize_t base64_decode(const unsigned char *data, size_t data_len, uint8_t *buf, size_t buf_len) {
	if (data_len % 4 != 0) return -1;

	size_t dest_len = data_len / 4 * 3;
	if (data[data_len - 1] == '=') dest_len--;
	if (data[data_len - 2] == '=') dest_len--;

	if(buf_len < dest_len) return -1;

	return base64_decode_incr(data, data_len, buf, buf_len);
}


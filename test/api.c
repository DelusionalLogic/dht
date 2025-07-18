#include "log.h"
#include "unity.h"

#include "api.h"
#include "base64.h"

#include <assert.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

// @PASTE Stolen from libcurl documentation
struct memory {
	char *body;
	size_t size;
};

static size_t write_to_memory(char *data, size_t size, size_t nmemb, void *clientp) {
	size_t realsize = size * nmemb;
	struct memory *mem = (struct memory *)clientp;

	char *ptr = realloc(mem->body, mem->size + realsize + 1);
	if(!ptr) return 0;  /* out of memory */

	mem->body = ptr;
	memcpy(&(mem->body[mem->size]), data, realsize);
	mem->size += realsize;
	mem->body[mem->size] = 0;

	return realsize;
}

static size_t read_from_memory(char *data, size_t size, size_t nmemb, void *clientp) {
	size_t realsize = size * nmemb;
	struct memory *mem = (struct memory *)clientp;

	realsize = realsize > mem->size ? mem->size : realsize;

	memcpy(data, mem->body, realsize);
	mem->size -= realsize;
	mem->body += realsize;

	return realsize;
}

void test_base64_decode() {
	size_t res = 0;
	uint8_t buf[256];

	res = base64_decode((unsigned char*)"AAAA", 4, buf, 256);
	TEST_ASSERT_EQUAL(3, res);
	TEST_ASSERT_EQUAL_MEMORY("\0\0\0", buf, 3);

	res = base64_decode((unsigned char*)"AA==", 4, buf, 256);
	TEST_ASSERT_EQUAL(1, res);
	TEST_ASSERT_EQUAL_MEMORY("\0", buf, 1);

	res = base64_decode((unsigned char*)"MQ==", 4, buf, 256);
	TEST_ASSERT_EQUAL(1, res);
	TEST_ASSERT_EQUAL_MEMORY("1", buf, 1);

	res = base64_decode((unsigned char*)"AAA=", 4, buf, 256);
	TEST_ASSERT_EQUAL(2, res);
	TEST_ASSERT_EQUAL_MEMORY("\0\0", buf, 2);

	// Too short of an input string
	res = base64_decode((unsigned char*)"AA=", 3, buf, 256);
	TEST_ASSERT_EQUAL(-1, res);

	// Too little space in the output buffer
	res = base64_decode((unsigned char*)"AAA=", 4, buf, 1);
	TEST_ASSERT_EQUAL(-1, res);

	// Too little space in the output buffer
	res = base64_decode((unsigned char*)"dGVzdA==", 8, buf, 256);
	TEST_ASSERT_EQUAL(4, res);
	TEST_ASSERT_EQUAL_MEMORY("test", buf, 4);

	// A null byte in the middle of the input
	res = base64_decode((unsigned char*)"AA\0=", 4, buf, 256);
	TEST_ASSERT_EQUAL(-1, res);

	// It should stop at the first equals
	res = base64_decode_incr((unsigned char*)"AA==W", 5, buf, 256);
	TEST_ASSERT_EQUAL(1, res);
	TEST_ASSERT_EQUAL_MEMORY("\0", buf, 1);

	res = base64_decode_incr((unsigned char*)"AAAA\"", 5, buf, 256);
	TEST_ASSERT_EQUAL(3, res);
	TEST_ASSERT_EQUAL_MEMORY("\0\0\0", buf, 3);

	res = base64_decode_incr((unsigned char*)"AAAA}", 5, buf, 256);
	TEST_ASSERT_EQUAL(3, res);
	TEST_ASSERT_EQUAL_MEMORY("\0\0\0", buf, 3);

	// We are a little overpermissive when it comes to the padding equals. This
	// isn't technically valid, but due to some implementation details we still
	// accept it. I think that's fine
	res = base64_decode_incr((unsigned char*)"AA=W", 4, buf, 256);
	TEST_ASSERT_EQUAL(1, res);
	TEST_ASSERT_EQUAL_MEMORY("\0", buf, 1);
}

void test_root_get() {
	CURLcode curlRes;
	CURL *curl = curl_easy_init();
	TEST_ASSERT_NOT_NULL(curl);

	struct dht dht = {0};
	dht.self = (struct nodeid){.inner={0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
	api_init(&dht);

	curlRes = curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:6982/");
	TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

	curlRes = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_memory);
	TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

	struct memory body = {0};
	curlRes = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
	TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

	curlRes = curl_easy_perform(curl);
	TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

	char *ct;
	curlRes = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);
	TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

	TEST_ASSERT_EQUAL_STRING("application/json", ct);

	TEST_ASSERT_EQUAL_STRING("{ \"id\": \"QkJCQkJCQkJCQkJCQkJCQkJCQkI=\" }", body.body);
	body = (struct memory){0};

	free(body.body);
	curl_easy_cleanup(curl);
	api_end();
}

void test_lookup_get() {
	curl_global_init(CURL_GLOBAL_ALL);
	CURLcode curlRes;
	CURL *curl = curl_easy_init();
	TEST_ASSERT_NOT_NULL(curl);

	struct dht dht = {0};
	dht.self = (struct nodeid){.inner={0x42424242, 0x42424242, 0x42424242, 0x42424242, 0x42424242}};
	api_init(&dht);

	curlRes = curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:6982/lookup");
	TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

	curlRes = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_memory);
	TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

	struct memory body = {0};
	curlRes = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
	TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

	curlRes = curl_easy_perform(curl);
	TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

	char *ct;
	curlRes = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);
	TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

	TEST_ASSERT_EQUAL_STRING("application/json", ct);

	TEST_ASSERT_EQUAL_STRING(
		"{ "
			"\"state\": \"empty\" "
		"}", 
		body.body
	);
	body = (struct memory){0};

	{
		curlRes = curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
		TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

		curlRes = curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_from_memory);
		TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

		struct memory req_body = {
			.body = "{\"target\": \"BAAAAAAAAAAAAAAAAAAAAAAAAAA=\", \"state\": \"pending\"}",
			.size = strlen(req_body.body),
		};
		curlRes = curl_easy_setopt(curl, CURLOPT_READDATA, &req_body);
		TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

		curlRes = curl_easy_perform(curl);
		TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

		curlRes = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);
		TEST_ASSERT_EQUAL(CURLE_OK, curlRes);
		TEST_ASSERT_EQUAL_STRING("application/json", ct);

		TEST_ASSERT_EQUAL_STRING(
			"{ "
				"\"state\": \"pending\", "
				"\"outstanding\": 0, "
				"\"target\": \"BAAAAAAAAAAAAAAAAAAAAAAAAAA=\" "
			"}", 
			body.body
		);
		body = (struct memory){0};
	}

	// The protocol does whatever and complete the lookup
	dht.lookup.state = OP_COMPLETED;

	{
		curlRes = curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
		TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

		curlRes = curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_from_memory);
		TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

		struct memory req_body = {
			.body = "{\"state\": \"empty\"}",
			.size = strlen(req_body.body),
		};
		curlRes = curl_easy_setopt(curl, CURLOPT_READDATA, &req_body);
		TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

		curlRes = curl_easy_perform(curl);
		TEST_ASSERT_EQUAL(CURLE_OK, curlRes);

		curlRes = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);
		TEST_ASSERT_EQUAL(CURLE_OK, curlRes);
		TEST_ASSERT_EQUAL_STRING("application/json", ct);

		TEST_ASSERT_EQUAL_STRING(
			"{ "
				"\"state\": \"empty\" "
			"}", 
			body.body
		);
		body = (struct memory){0};
	}

	free(body.body);
	curl_easy_cleanup(curl);
	curl_global_cleanup();
	api_end();
}

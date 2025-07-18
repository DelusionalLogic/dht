#include "api.h"
#include "log.h"
#include "base64.h"
#include "metrics.h"

#include <arpa/inet.h>
#include <assert.h>
#include <microhttpd.h>
#include <string.h>

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

const char *lookupStateStr[OP_LEN] = {
	[OP_EMPTY] = "empty",
	[OP_PENDING] = "pending",
	[OP_ACTIVE] = "active",
	[OP_COMPLETED] = "completed",
};

struct api {
	struct dht *dht;
};

enum ReqType {
	REQ_PUT_LOOKUP,
};

enum JsonState {
	JSTATE_STR,
};

struct request {
	enum ReqType type;

	bool target_set;
	struct nodeid target;
	enum Operation state;
};

static enum MHD_Result queue_lookup_response(struct api *api, struct MHD_Connection *connection, struct MHD_Response **response, bool locked) {
	enum MHD_Result ret;

	// All states are named
	BUILD_BUG_ON((sizeof(lookupStateStr) / sizeof(lookupStateStr[0])) != OP_LEN);

	char buf[1024];
	char *cursor = buf;
	char *buf_end = buf + sizeof(buf);
	size_t len;

	if(!locked) pthread_mutex_lock(&api->dht->mutex);
	len = snprintf(cursor, buf_end-cursor, "{ \"state\": \"%s\"", lookupStateStr[api->dht->lookup.state]);
	if(len < 0) fatal("printf failed\n");
	cursor += len;
	if(cursor >= buf_end) fatal("buffer to short");

	if(api->dht->lookup.state == OP_ACTIVE || api->dht->lookup.state == OP_COMPLETED || api->dht->lookup.state == OP_PENDING) {
		len = snprintf(cursor, buf_end-cursor, ", \"outstanding\": %ld, \"target\": \"", api->dht->lookup.outstanding);
		if(len < 0) fatal("printf failed\n");
		cursor += len;
		if(cursor >= buf_end) fatal("buffer to short");

		len = base64_encode_inplace((void*)&api->dht->lookup.target, sizeof(struct nodeid), cursor, buf_end - cursor);
		if(len < 0) fatal("base64 failed\n");
		cursor += len;
		if(cursor >= buf_end) fatal("buffer to short");

		len = snprintf(cursor, buf_end-cursor, "\"");
		if(len < 0) fatal("printf failed\n");
		cursor += len;
		if(cursor >= buf_end) fatal("buffer to short");
	}

	if(api->dht->lookup.state == OP_COMPLETED || api->dht->lookup.state == OP_ACTIVE) {
		len = snprintf(cursor, buf_end-cursor, ", \"result\": [");
		if(len < 0) fatal("printf failed\n");
		cursor += len;
		if(cursor >= buf_end) fatal("buffer to short");

		char *lead = "";
		for(size_t i = 0; i < 8; i++) {
			len = snprintf(cursor, buf_end-cursor, "%s{\"id\": \"", lead);
			if(len < 0) fatal("printf failed\n");
			cursor += len;
			if(cursor >= buf_end) fatal("buffer to short");

			len = base64_encode_inplace((void*)&api->dht->lookup.closest[i], sizeof(struct nodeid), cursor, buf_end - cursor);
			if(len < 0) fatal("base64 failed\n");
			cursor += len;
			if(cursor >= buf_end) fatal("buffer to short");

			len = snprintf(cursor, buf_end-cursor, "\"}");
			if(len < 0) fatal("printf failed\n");
			cursor += len;
			if(cursor >= buf_end) fatal("buffer to short");

			lead = ", ";
		}

		len = snprintf(cursor, buf_end-cursor, "]");
		if(len < 0) fatal("printf failed\n");
		cursor += len;
		if(cursor >= buf_end) fatal("buffer to short");
	}


	len = snprintf(cursor, buf_end-cursor, " }");
	if(len < 0) fatal("printf failed\n");
	cursor += len;
	if(cursor >= buf_end) fatal("buffer to short");
	pthread_mutex_unlock(&api->dht->mutex);

	*response = MHD_create_response_from_buffer_copy(cursor - buf, (void *)buf);
	ret = MHD_add_response_header(*response, "Content-Type", "application/json");
	if(ret != MHD_YES) return ret;

	ret = MHD_queue_response(connection, MHD_HTTP_OK, *response);
	return ret;
}

static enum MHD_Result handler(
	void *cls,
	struct MHD_Connection *connection,
	const char *url,
	const char *method,
	const char *version,
	const char *upload_data,
	size_t *upload_data_size,
	void **con_cls
) {
	struct api *api = (struct api*)cls;
	struct request * conn = *con_cls;
	enum MHD_Result ret = MHD_NO;
	struct MHD_Response *response = NULL;

	if(conn != NULL) {
		if(*upload_data_size > 0) {
			const char* cursor = upload_data;

			if(memcmp(cursor, "{", 1) != 0) return MHD_NO;
			cursor += 1;

			while(true) {
				if(memcmp(cursor, "\"target\": \"", 11) == 0) {
					cursor += 11;

					conn->target_set = true;
					size_t read = base64_decode_incr((unsigned char*)cursor, *upload_data_size - (cursor - upload_data), (void*)&conn->target, sizeof(struct nodeid));
					if(read < 0) return MHD_NO;
					// @CLEANUP This isn't necessarily correct since we also accept
					// base64's with invalid final padding. Hopefully that will just
					// lead to a bad error message to the user, but we have to look at
					// that more carefully when this code is done.
					cursor += 4 * ((read + 2) / 3);

					if(memcmp(cursor, "\"", 1) != 0) return MHD_NO;
					cursor += 1;
				} else if(memcmp(cursor, "\"state\": \"", 10) == 0) {
					cursor += 10;

					for(size_t i = 0; i < OP_LEN; i++) {
						size_t lookupLen = strlen(lookupStateStr[i]);
						if(memcmp(cursor, lookupStateStr[i], lookupLen) == 0) {
							cursor += lookupLen;
							conn->state = i;
							break;
						}
					}

					if(memcmp(cursor, "\"", 1) != 0) return MHD_NO;
					cursor += 1;
				} else {
					return MHD_NO;
				}

				if(memcmp(cursor, ", ", 2) != 0) break;
				cursor += 2;
			}

			if(memcmp(cursor, "}", 1) != 0) return MHD_NO;
			cursor += 1;

			*upload_data_size = (*upload_data_size - (cursor - upload_data));

			return MHD_YES;
		} else {

			pthread_mutex_lock(&api->dht->mutex);

			if(conn->state == OP_PENDING) {
				if(!conn->target_set) {
					pthread_mutex_unlock(&api->dht->mutex);
					return MHD_NO;
				}

				if(api->dht->lookup.state != OP_EMPTY) {
					pthread_mutex_unlock(&api->dht->mutex);
					// @COMPL We should return some nice error message to the user
					// here about how they lost a race
					return MHD_NO;
				}

				// Start a lookup
				memcpy(&api->dht->lookup.target, &conn->target, sizeof(struct nodeid));
				api->dht->lookup.state = OP_PENDING;
				prom_gauge_set(lookup_state, api->dht->lookup.state, NULL);
			} else if(conn->state == OP_EMPTY) {
				if(conn->target_set) {
					pthread_mutex_unlock(&api->dht->mutex);
					return MHD_NO;
				}

				if(api->dht->lookup.state != OP_COMPLETED) {
					pthread_mutex_unlock(&api->dht->mutex);
					// @COMPL We should return some nice error message to the user
					// here about how they lost a race
					return MHD_NO;
				}

				api->dht->lookup.state = OP_EMPTY;
				prom_gauge_set(lookup_state, api->dht->lookup.state, NULL);
			} else {
				pthread_mutex_unlock(&api->dht->mutex);
				return MHD_NO;
			}

			ret = queue_lookup_response(api, connection, &response, true);
			goto end;
		}
	}

	if(strcmp(url, "/") == 0) {
		if(strcmp(method, "GET") != 0) {
			response = MHD_create_response_from_buffer_static(0, NULL);
			ret = MHD_queue_response(connection, MHD_HTTP_METHOD_NOT_ALLOWED, response);
			goto end;
		}

		char buf[1024];
		char *cursor = buf;
		char *buf_end = buf + sizeof(buf);
		size_t len;

		pthread_mutex_lock(&api->dht->mutex);
		len = snprintf(cursor, buf_end-cursor, "{ \"id\": \"");
		if(len < 0) fatal("printf failed\n");
		cursor += len;
		if(cursor >= buf_end) fatal("buffer too short");

		len = base64_encode_inplace((void*)&api->dht->self, sizeof(struct nodeid), cursor, buf_end - cursor);
		if(len < 0) fatal("base64 failed\n");
		cursor += len;
		if(cursor >= buf_end) fatal("buffer to short");

		len = snprintf(cursor, buf_end-cursor, "\" }");
		if(len < 0) fatal("printf failed\n");
		cursor += len;
		if(cursor >= buf_end) fatal("buffer too short");
		pthread_mutex_unlock(&api->dht->mutex);

		response = MHD_create_response_from_buffer_copy(cursor - buf, (void *)buf);
		ret = MHD_add_response_header(response, "Content-Type", "application/json");
		if(ret != MHD_YES) goto end;
		ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
		goto end;
	}

	if(strcmp(url, "/lookup") == 0) {
		if(strcmp(method, "GET") == 0) {
			ret = queue_lookup_response(api, connection, &response, false);
			goto end;
		} else if(strcmp(method, "PUT") == 0) {
			conn = calloc(1, sizeof(struct request));

			conn->type = REQ_PUT_LOOKUP;

			*con_cls = conn;
			return MHD_YES;
		}

		response = MHD_create_response_from_buffer_static(0, NULL);
		ret = MHD_queue_response(connection, MHD_HTTP_METHOD_NOT_ALLOWED, response);
		goto end;
	}

	response = MHD_create_response_from_buffer_static(0, NULL);
	ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
end:
	assert(response == NULL || ret == MHD_YES);
	if(response != NULL) MHD_destroy_response(response);
	return ret;
}

#define PORT 6982
static struct MHD_Daemon *mDaemon;
static struct api api;

void api_init(struct dht *dht) {
	api.dht = dht;

	mDaemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION, PORT, NULL, NULL, &handler, &api, MHD_OPTION_END);
	if(mDaemon == NULL) {
		fatal("Failed to start http server");
	}
	dbg("API server started on port %d", PORT);
}

void api_end() {
	MHD_stop_daemon(mDaemon);
	dbg("API server stopped");
}

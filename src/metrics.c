#include "metrics.h"
#include "log.h"

#include "microhttpd.h"

prom_counter_t *bytesRecv = NULL;
prom_counter_t *bytesSent = NULL;

prom_counter_t *meta = NULL;
prom_counter_t *peers = NULL;
prom_gauge_t *current_hashes = NULL;
prom_counter_t *hashes = NULL;
prom_counter_t *hash_expired = NULL;
prom_counter_t *queries = NULL;
prom_counter_t *requests = NULL;
prom_histogram_t *offered = NULL;
prom_gauge_t *activeNodes = NULL;
prom_gauge_t *requestsInFlight = NULL;
prom_counter_t *retries = NULL;

enum MHD_Result promhttp_handler(
	void *cls,
	struct MHD_Connection *connection,
	const char *url,
	const char *method,
	const char *version,
	const char *upload_data,
	size_t *upload_data_size,
	void **con_cls
) {
	if (strcmp(method, "GET") != 0) {
		char *buf = "Invalid HTTP Method\n";
		struct MHD_Response *response = MHD_create_response_from_buffer(strlen(buf), (void *)buf, MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
		MHD_destroy_response(response);
		return ret;
	}

	if (strcmp(url, "/") == 0) {
		char *buf = "OK\n";
		struct MHD_Response *response = MHD_create_response_from_buffer(strlen(buf), (void *)buf, MHD_RESPMEM_PERSISTENT);
		int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
		return ret;
	}

	if (strcmp(url, "/metrics") == 0) {
		const char *buf = prom_collector_registry_bridge(PROM_COLLECTOR_REGISTRY_DEFAULT);
		struct MHD_Response *response = MHD_create_response_from_buffer(strlen(buf), (void *)buf, MHD_RESPMEM_MUST_FREE);
		int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
		MHD_destroy_response(response);
		return ret;
	}

	char *buf = "Bad Request\n";
	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(buf), (void *)buf, MHD_RESPMEM_PERSISTENT);
	int ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
	MHD_destroy_response(response);
	return ret;
}

#define PORT 6981

struct MHD_Daemon *mDaemon;

// @CLEAN: We should call this begin
void metric_init() {
	if(prom_collector_registry_default_init() != 0) {
		fatal("Failed to initialize prometheus registry");
	}

	mDaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL, &promhttp_handler, NULL, MHD_OPTION_END);
	if(mDaemon == NULL) {
		fatal("Failed to start http server");
	}
	dbg("Metrics server started on port %d", PORT);

	bytesRecv = prom_collector_registry_must_register_metric(
		prom_counter_new(
			"dht_bytes_received_total",
			"Number of bytes received",
			0,
			NULL
		)
	);

	bytesSent = prom_collector_registry_must_register_metric(
		prom_counter_new(
			"dht_bytes_sent_total",
			"Number of bytes sent",
			0,
			NULL
		)
	);

	meta = prom_collector_registry_must_register_metric(
		prom_counter_new(
			"dht_meta_info",
			"Meta information value is always 1",
			1,
			(const char *[]){ "nodeid" }
		)
	);

	peers = prom_collector_registry_must_register_metric(
		prom_counter_new(
			"dht_peers_total",
			"Number of total peers",
			0,
			NULL
		)
	);

	current_hashes = prom_collector_registry_must_register_metric(
		prom_gauge_new(
			"dht_live_hashes_total",
			"Number of hashes with active peers",
			0,
			NULL
		)
	);

	hashes = prom_collector_registry_must_register_metric(
		prom_counter_new(
			"dht_hashes_total",
			"Number of hashes currently stored",
			0,
			NULL
		)
	);

	hash_expired = prom_collector_registry_must_register_metric(
		prom_counter_new(
			"dht_hashes_expired_total",
			"Number of hashes expired due to inactivity",
			0,
			NULL
		)
	);

	queries = prom_collector_registry_must_register_metric(
		prom_counter_new(
			"dht_queries_total",
			"Amount of queries handled",
			2,
			(const char *[]){"type", "outcome"}
		)
	);

	requests = prom_collector_registry_must_register_metric(
		prom_counter_new(
			"dht_requests_total",
			"Number of requests sent by us",
			0,
			NULL
		)
	);

	requestsInFlight = prom_collector_registry_must_register_metric(
		prom_gauge_new(
			"dht_requests_in_flight",
			"Requests currently in flight",
			0,
			NULL
		)
	);

	retries = prom_collector_registry_must_register_metric(
		prom_counter_new(
			"dht_retries_total",
			"Retries sent for unanswered requests",
			0,
			NULL
		)
	);

	offered = prom_collector_registry_must_register_metric(
		prom_histogram_new(
			"dht_offered",
			"Nodes seen and considered for the routing table",
			prom_histogram_buckets_linear(0, 1, 157),
			0,
			NULL
		)
	);

	activeNodes = prom_collector_registry_must_register_metric(
		prom_gauge_new(
			"dht_active_nodes",
			"Nodes active in the routing table",
			0,
			NULL
		)
	);
}

void metric_end() {
	MHD_stop_daemon(mDaemon);
	if(prom_collector_registry_destroy(PROM_COLLECTOR_REGISTRY_DEFAULT) != 0) {
		fatal("Failed to destroy the registry");
	}
	dbg("Metric server stopped");
}

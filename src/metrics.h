#pragma once

#include <stdint.h>

#include "prom.h"

extern prom_counter_t *bytesRecv;
extern prom_counter_t *bytesSent;

extern prom_counter_t *meta;

extern prom_counter_t *peers;
extern prom_counter_t *hashes;
extern prom_counter_t *hash_expired;
extern prom_counter_t *queries;
extern prom_counter_t *requests;
extern prom_histogram_t *offered;
extern prom_gauge_t *activeNodes;
extern prom_gauge_t *requestsInFlight;
extern prom_counter_t *retries;

extern prom_counter_t *requestsProcessed;

void metric_init();
void metric_end();

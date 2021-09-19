#pragma once 

#include "routing.h"
#include <sys/socket.h>
#include <arpa/inet.h>

// 192.0.2.0
#define UNDEF_ADDR (struct in_addr){0xC0000200}
#define MAX_DISC 32
#define MAX_INFLIGHT 32

struct dht;
struct msgbuff;
typedef void (*cont)(struct dht* dht, struct nodeid* self, char* packet, size_t packet_len, int socket, struct sockaddr* remote, socklen_t remote_len, struct msgbuff* msgbuff);

struct discovery {
	uint16_t port;
	struct nodeid expected_id;
};

struct dht {
	struct nodeid self;
	int sfd;

	struct in_addr addrs[MAX_DISC];
	struct discovery pending_discover[MAX_DISC];

	bool reqalloc[MAX_INFLIGHT];
	struct {
		struct sockaddr_storage addr;
		cont fun;
	} requestdata[MAX_INFLIGHT];
};

struct message {
	char payload[128];
	size_t payload_len;
	struct sockaddr_storage dest;
	socklen_t dest_len;
};

void proto_begin(struct dht* dht, struct message** output, const struct message* const output_end);
int proto_run(struct dht* dht, char* buffer, size_t buffer_len, struct sockaddr_in* remote, socklen_t remote_len, struct message** output, const struct message* const output_end);
void proto_end(struct dht* dht);

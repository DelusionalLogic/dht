#pragma once 

#include "routing.h"
#include <sys/socket.h>
#include <arpa/inet.h>

// 192.0.2.0
#define UNDEF_ADDR (struct in_addr){0xC0000200}
#define MAX_DISC 32
#define MAX_INFLIGHT 32

#define PROTO_UNCTM 60
#define PROTO_TMOUT 5

struct ping {
	struct nodeid remote_id;
	int attempt;
	bool is_new;
};

union message_cont {
	struct ping ping;
};

struct dht;
struct msgbuff;

#define PROCESS_REPONSE(NAME) int (NAME)(struct dht* dht, time_t now, union message_cont* cont, char* packet, size_t packet_len, int socket, struct sockaddr* remote, socklen_t remote_len, struct msgbuff* msgbuff)
typedef PROCESS_REPONSE(cont);

#define PROCESS_TIMEOUT(NAME) int (NAME)(struct dht* dht, struct nodeid* self, time_t now, union message_cont* cont, struct msgbuff* msgbuff)
typedef PROCESS_TIMEOUT(tmout);

struct dht {
	struct nodeid self;
	int sfd;

	bool pause;

	bool reqalloc[MAX_INFLIGHT];
	struct {
		struct sockaddr_storage addr;
		socklen_t addr_len;
		cont* fun;
		time_t timeout;
		tmout* timeout_fun;
		union message_cont cont;
	} requestdata[MAX_INFLIGHT];
};

struct message {
	char payload[1024];
	size_t payload_len;
	struct sockaddr_storage dest;
	socklen_t dest_len;
};

void proto_begin(struct dht* dht, time_t now, struct message** output, const struct message* const output_end);
int proto_run(struct dht* dht, char* buffer, size_t buffer_len, struct sockaddr_in* remote, socklen_t remote_len, time_t now, struct message** output, const struct message* const output_end);
void proto_end(struct dht* dht);

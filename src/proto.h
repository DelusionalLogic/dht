#pragma once 

#include "routing.h"
#include "sha256.h"
#include <sys/socket.h>
#include <arpa/inet.h>

#define TOKEN_ITMO 20
#define TOKEN_VTMO 60
#define TOKEN_TLEN 32
#define TOKEN_KNUM (TOKEN_VTMO/TOKEN_ITMO)

#define TOK_VALI 1
#define TOK_INVA 0

struct tokens {
	SHA256_CTX ctx;

	char ticket[TOKEN_KNUM][TOKEN_TLEN];
	time_t issued[TOKEN_KNUM];
	size_t head;
};

enum Operation {
	OP_EMPTY,
	OP_PENDING,
	OP_ACTIVE,
	OP_COMPLETED,
};

struct lookup {
	enum Operation state;
	struct nodeid target;

	struct nodeid closest[8];
	struct addr closest_addr[8];

	uint64_t outstanding;
};

void token_create(struct tokens* tokens, time_t now, struct addr* remote, char* token);
int token_validate(struct tokens* tokens, time_t now, struct addr* remote, char* token);

// 192.0.2.0
#define UNDEF_ADDR (struct in_addr){0xC0000200}
#define MAX_DISC 32
#define MAX_INFLIGHT 128

#define PROTO_UNCTM 60*20
#define PROTO_TMOUT 30

struct ping {
	struct nodeid remote_id;
	int attempt;
	bool is_new;
};

union message_cont {
	struct ping ping;
	struct lookup *lookup;
};

struct dht;
struct msgbuff {
	struct message** messages;
	const struct message* const messages_end;
};


#define PROCESS_REPONSE(NAME) int (NAME)(struct dht* dht, time_t now, union message_cont* cont, char* packet, size_t packet_len, int socket, struct sockaddr* remote, socklen_t remote_len, struct msgbuff* msgbuff)
typedef PROCESS_REPONSE(resp);

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
		resp* fun;
		time_t timeout;
		tmout* timeout_fun;
		union message_cont cont;
	} requestdata[MAX_INFLIGHT];

	struct lookup lookup;

	time_t wake;
	struct tokens tokens;
};

struct message {
	char payload[1024];
	size_t payload_len;
	struct sockaddr_storage dest;
	socklen_t dest_len;
};

int send_lookup(struct dht* dht, struct nodeid* target, time_t now, const struct sockaddr* dest_addr, socklen_t dest_len, struct msgbuff* msgbuff);

void proto_begin(struct dht* dht, time_t now, struct message** output, const struct message* const output_end);
int proto_run(struct dht* dht, char* buffer, size_t buffer_len, struct sockaddr_in* remote, socklen_t remote_len, time_t now, struct message** output, const struct message* const output_end);
void proto_end(struct dht* dht);

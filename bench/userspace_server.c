#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../include/protocol.h"
#include "../bench/userspace_hash.h"

static volatile int running = 1;
static void sig_handler(int sig) {
    running = 0;
}

int main(int argc, char **argv) {
    int port = KV_PORT;
    int entries = 10000;

    struct userspace_table *tbl = userspace_table_create(KV_TABLE_CAPACITY);
    if (!tbl) {
        perror("userspace_table_create");
        return 1;
    }

    for (int i = 1; i <= entries; i++) {
        userspace_table_insert(tbl, i, i * 10);
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    srv_addr.sin_port = htons(port);

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(sock, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    printf("[Userspace UDP Server] Listening on 0.0.0.0:%d with %d entries...\n", port, entries);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (running) {
        struct kv_request req;
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        ssize_t n = recvfrom(sock, &req, sizeof(req), 0, (struct sockaddr *)&client_addr, &addr_len);
        if (n <= 0) break;

        if (n >= (ssize_t)sizeof(struct kv_request) && req.opcode == KV_OP_GET) {
            __u64 key = __builtin_bswap64(req.key);
            __u64 val = 0;
            int found = userspace_table_lookup(tbl, key, &val);

            if (found) {
                struct kv_response resp = {
                    .status = KV_STATUS_HIT,
                    .reserved = {0, 0, 0},
                    .key = __builtin_bswap64(key),
                    .value = __builtin_bswap64(val),
                };
                sendto(sock, &resp, sizeof(resp), 0, (struct sockaddr *)&client_addr, addr_len);
            }
        }
    }

    close(sock);
    userspace_table_free(tbl);
    return 0;
}

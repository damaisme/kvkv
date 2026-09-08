#define _GNU_SOURCE
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

#define VLEN 64 /* Batch size for recvmmsg/sendmmsg */

static volatile int running = 1;
static void sig_handler(int sig) {
    running = 0;
}

int main(int argc, char **argv) {
    int port = KV_PORT;
    int entries = 10000;

    struct userspace_table *tbl = userspace_table_create(KV_TABLE_CAPACITY);
    if (!tbl) return 1;

    for (int i = 1; i <= entries; i++) {
        userspace_table_insert(tbl, i, i * 10);
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    /* 1. Best Practice: SO_REUSEADDR & Socket Buffers */
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    int buf_size = 8 * 1024 * 1024; /* 8MB buffer */
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));

    /* 2. Best Practice: SO_BUSY_POLL (low latency kernel polling) */
    int busy_poll_us = 50;
    setsockopt(sock, SOL_SOCKET, SO_BUSY_POLL, &busy_poll_us, sizeof(busy_poll_us));

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    srv_addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    printf("[Optimized Userspace UDP Server (recvmmsg/sendmmsg)] Listening on port %d...\n", port);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Allocate batch structures */
    struct mmsghdr msgs_in[VLEN];
    struct iovec iovecs_in[VLEN];
    struct kv_request req_bufs[VLEN];
    struct sockaddr_in client_addrs[VLEN];

    struct mmsghdr msgs_out[VLEN];
    struct iovec iovecs_out[VLEN];
    struct kv_response resp_bufs[VLEN];

    memset(msgs_in, 0, sizeof(msgs_in));
    memset(msgs_out, 0, sizeof(msgs_out));

    for (int i = 0; i < VLEN; i++) {
        iovecs_in[i].iov_base = &req_bufs[i];
        iovecs_in[i].iov_len = sizeof(struct kv_request);
        msgs_in[i].msg_hdr.msg_iov = &iovecs_in[i];
        msgs_in[i].msg_hdr.msg_iovlen = 1;
        msgs_in[i].msg_hdr.msg_name = &client_addrs[i];
        msgs_in[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);

        iovecs_out[i].iov_base = &resp_bufs[i];
        iovecs_out[i].iov_len = sizeof(struct kv_response);
        msgs_out[i].msg_hdr.msg_iov = &iovecs_out[i];
        msgs_out[i].msg_hdr.msg_iovlen = 1;
    }

    while (running) {
        /* Batch receive up to VLEN packets in 1 syscall */
        int num_received = recvmmsg(sock, msgs_in, VLEN, MSG_WAITFORONE, NULL);
        if (num_received <= 0) break;

        int out_count = 0;
        for (int i = 0; i < num_received; i++) {
            if (msgs_in[i].msg_len >= sizeof(struct kv_request) && req_bufs[i].opcode == KV_OP_GET) {
                __u64 key = __builtin_bswap64(req_bufs[i].key);
                __u64 val = 0;
                if (userspace_table_lookup(tbl, key, &val)) {
                    resp_bufs[out_count].status = KV_STATUS_HIT;
                    resp_bufs[out_count].reserved[0] = 0;
                    resp_bufs[out_count].reserved[1] = 0;
                    resp_bufs[out_count].reserved[2] = 0;
                    resp_bufs[out_count].key = __builtin_bswap64(key);
                    resp_bufs[out_count].value = __builtin_bswap64(val);

                    msgs_out[out_count].msg_hdr.msg_name = &client_addrs[i];
                    msgs_out[out_count].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
                    out_count++;
                }
            }
        }

        if (out_count > 0) {
            /* Batch send replies in 1 syscall */
            sendmmsg(sock, msgs_out, out_count, 0);
        }
    }

    close(sock);
    userspace_table_free(tbl);
    return 0;
}

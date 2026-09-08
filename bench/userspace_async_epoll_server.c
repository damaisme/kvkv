#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../include/protocol.h"
#include "../bench/userspace_hash.h"

#define MAX_EVENTS 64
#define BATCH_SIZE 64

static volatile int running = 1;
static void sig_handler(int sig) {
    running = 0;
}

static int make_socket_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main(int argc, char **argv) {
    int port = KV_PORT;
    int entries = 10000;

    struct userspace_table *tbl = userspace_table_create(KV_TABLE_CAPACITY);
    if (!tbl) return 1;

    for (int i = 1; i <= entries; i++) {
        userspace_table_insert(tbl, i, i * 10);
    }

    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    /* 1. Best Practice: SO_REUSEADDR & SO_REUSEPORT */
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    /* 2. Socket Buffers */
    int buf_size = 8 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));

    /* 3. SO_BUSY_POLL */
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

    /* 4. Setup Epoll instance with Edge-Triggered mode */
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        close(sock);
        return 1;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET; /* Edge-Triggered */
    ev.data.fd = sock;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
        perror("epoll_ctl");
        close(sock);
        close(epoll_fd);
        return 1;
    }

    printf("[Async Epoll Server (Non-blocking + EPOLLET + recvmmsg)] Listening on port %d...\n", port);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct epoll_event events[MAX_EVENTS];

    /* Allocate batch buffers */
    struct mmsghdr msgs_in[BATCH_SIZE];
    struct iovec iovecs_in[BATCH_SIZE];
    struct kv_request req_bufs[BATCH_SIZE];
    struct sockaddr_in client_addrs[BATCH_SIZE];

    struct mmsghdr msgs_out[BATCH_SIZE];
    struct iovec iovecs_out[BATCH_SIZE];
    struct kv_response resp_bufs[BATCH_SIZE];

    memset(msgs_in, 0, sizeof(msgs_in));
    memset(msgs_out, 0, sizeof(msgs_out));

    for (int i = 0; i < BATCH_SIZE; i++) {
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
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 500);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int n = 0; n < nfds; n++) {
            if (events[n].data.fd == sock) {
                /* Drain socket in Edge-Triggered mode using recvmmsg batching */
                while (1) {
                    int num_recvd = recvmmsg(sock, msgs_in, BATCH_SIZE, MSG_DONTWAIT, NULL);
                    if (num_recvd <= 0) {
                        if (num_recvd < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                            break; /* Socket drained */
                        }
                        break;
                    }

                    int out_count = 0;
                    for (int i = 0; i < num_recvd; i++) {
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
                        sendmmsg(sock, msgs_out, out_count, 0);
                    }
                }
            }
        }
    }

    close(sock);
    close(epoll_fd);
    userspace_table_free(tbl);
    return 0;
}

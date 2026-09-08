#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <getopt.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../include/protocol.h"

struct worker_arg {
    char server_ip[64];
    int port;
    int count;
    double hit_ratio;
    unsigned int seed;
    int timeout_ms;
    
    /* Output metrics */
    __u64 requests_sent;
    __u64 responses_recvd;
    __u64 hits;
    __u64 misses;
    __u64 timeouts;
    __u64 elapsed_ns;
};

static inline __u64 get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static void *worker_thread(void *arg) {
    struct worker_arg *w = (struct worker_arg *)arg;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return NULL;
    }

    struct timeval tv;
    tv.tv_sec = w->timeout_ms / 1000;
    tv.tv_usec = (w->timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(w->port);
    inet_pton(AF_INET, w->server_ip, &srv_addr.sin_addr);

    __u64 *keys = malloc(sizeof(__u64) * w->count);
    if (!keys) {
        close(sock);
        return NULL;
    }

    srand(w->seed);
    for (int i = 0; i < w->count; i++) {
        double r = (double)rand() / (double)RAND_MAX;
        if (r < w->hit_ratio) {
            keys[i] = (rand() % 10000) + 1;
        } else {
            keys[i] = 100000000ULL + (rand() % 1000000);
        }
    }

    __u64 t0 = get_time_ns();

    for (int i = 0; i < w->count; i++) {
        struct kv_request req = {
            .opcode = KV_OP_GET,
            .reserved = {0, 0, 0},
            .key = __builtin_bswap64(keys[i]),
        };

        ssize_t sent = sendto(sock, &req, sizeof(req), 0,
                              (struct sockaddr *)&srv_addr, sizeof(srv_addr));
        if (sent == sizeof(req)) {
            w->requests_sent++;
        }

        struct kv_response resp;
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t recvd = recvfrom(sock, &resp, sizeof(resp), 0,
                                 (struct sockaddr *)&from, &fromlen);

        if (recvd >= (ssize_t)sizeof(resp)) {
            w->responses_recvd++;
            __u64 resp_key = __builtin_bswap64(resp.key);
            if (resp.status == KV_STATUS_HIT && resp_key == keys[i]) {
                w->hits++;
            } else {
                w->misses++;
            }
        } else {
            w->timeouts++;
            w->misses++;
        }
    }

    __u64 t1 = get_time_ns();
    w->elapsed_ns = t1 - t0;

    free(keys);
    close(sock);
    return NULL;
}

int main(int argc, char **argv) {
    char server_ip[64] = "192.168.100.1";
    int port = KV_PORT;
    int total_count = 100000;
    int threads = 4;
    double hit_ratio = 1.0;
    unsigned int base_seed = 12345;
    int timeout_ms = 50;

    static struct option long_options[] = {
        {"server", required_argument, 0, 's'},
        {"port", required_argument, 0, 'p'},
        {"count", required_argument, 0, 'c'},
        {"threads", required_argument, 0, 't'},
        {"hit-ratio", required_argument, 0, 'r'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "s:p:c:t:r:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 's': strncpy(server_ip, optarg, sizeof(server_ip) - 1); break;
        case 'p': port = atoi(optarg); break;
        case 'c': total_count = atoi(optarg); break;
        case 't': threads = atoi(optarg); break;
        case 'r': hit_ratio = atof(optarg); break;
        case 'h':
        default:
            printf("Usage: %s [--server IP] [--port PORT] [--count TOTAL] [--threads NUM]\n", argv[0]);
            return 0;
        }
    }

    pthread_t *tids = malloc(sizeof(pthread_t) * threads);
    struct worker_arg *wargs = calloc(threads, sizeof(struct worker_arg));
    int count_per_thread = total_count / threads;

    __u64 global_t0 = get_time_ns();

    for (int i = 0; i < threads; i++) {
        strncpy(wargs[i].server_ip, server_ip, sizeof(wargs[i].server_ip));
        wargs[i].port = port;
        wargs[i].count = count_per_thread;
        wargs[i].hit_ratio = hit_ratio;
        wargs[i].seed = base_seed + i * 100;
        wargs[i].timeout_ms = timeout_ms;
        pthread_create(&tids[i], NULL, worker_thread, &wargs[i]);
    }

    __u64 total_sent = 0, total_recvd = 0, total_hits = 0, total_misses = 0, total_timeouts = 0;
    for (int i = 0; i < threads; i++) {
        pthread_join(tids[i], NULL);
        total_sent += wargs[i].requests_sent;
        total_recvd += wargs[i].responses_recvd;
        total_hits += wargs[i].hits;
        total_misses += wargs[i].misses;
        total_timeouts += wargs[i].timeouts;
    }

    __u64 global_t1 = get_time_ns();
    double elapsed_sec = (double)(global_t1 - global_t0) / 1e9;
    double rps = elapsed_sec > 0 ? (double)total_recvd / elapsed_sec : 0;

    printf("\n===================================================\n");
    printf("     Multi-Threaded Concurrent UDP Benchmark      \n");
    printf("===================================================\n");
    printf("Server:           %s:%d\n", server_ip, port);
    printf("Concurrency:      %d worker threads\n", threads);
    printf("Requests Sent:    %llu\n", total_sent);
    printf("Responses Recvd:  %llu\n", total_recvd);
    printf("Hits:             %llu\n", total_hits);
    printf("Misses:           %llu\n", total_misses);
    printf("Timeouts/Loss:    %llu\n", total_timeouts);
    printf("Elapsed Time:     %.4f s\n", elapsed_sec);
    printf("Throughput:       %.2f req/s (%.2f kops/s)\n", rps, rps / 1000.0);
    printf("===================================================\n\n");

    free(tids);
    free(wargs);
    return 0;
}

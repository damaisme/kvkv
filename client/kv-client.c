#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../include/protocol.h"

static inline __u64 get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static inline __u64 hton64(__u64 val) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(val);
#else
    return val;
#endif
}

static inline __u64 ntoh64(__u64 val) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(val);
#else
    return val;
#endif
}

static int compare_u64(const void *a, const void *b) {
    __u64 arg1 = *(__u64 *)a;
    __u64 arg2 = *(__u64 *)b;
    if (arg1 < arg2) return -1;
    if (arg1 > arg2) return 1;
    return 0;
}

static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("Options:\n");
    printf("  --server, -s <ip>       Server IPv4 address (default: 127.0.0.1)\n");
    printf("  --port, -p <port>       Server UDP port (default: %d)\n", KV_PORT);
    printf("  --key, -k <key>         Key to query (single query mode)\n");
    printf("  --count, -c <num>       Number of requests in benchmark (default: 100000)\n");
    printf("  --hit-ratio, -r <ratio> Expected hit ratio 0.0 - 1.0 (default: 1.0)\n");
    printf("  --seed, -S <seed>       Deterministic workload random seed (default: 12345)\n");
    printf("  --timeout, -t <ms>      Socket receive timeout in ms (default: 50)\n");
    printf("  --benchmark, -b         Run in benchmark mode\n");
    printf("  --csv                   Output benchmark result in CSV format\n");
    printf("  --help, -h              Show this help message\n");
}

int main(int argc, char **argv) {
    char server_ip[64] = "127.0.0.1";
    int port = KV_PORT;
    __u64 single_key = 0;
    int key_specified = 0;
    int count = 100000;
    double hit_ratio = 1.0;
    unsigned int seed = 12345;
    int timeout_ms = 50;
    int benchmark_mode = 0;
    int csv_output = 0;

    static struct option long_options[] = {
        {"server", required_argument, 0, 's'},
        {"port", required_argument, 0, 'p'},
        {"key", required_argument, 0, 'k'},
        {"count", required_argument, 0, 'c'},
        {"hit-ratio", required_argument, 0, 'r'},
        {"seed", required_argument, 0, 'S'},
        {"timeout", required_argument, 0, 't'},
        {"benchmark", no_argument, 0, 'b'},
        {"csv", no_argument, 0, 'C'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "s:p:k:c:r:S:t:bCh", long_options, NULL)) != -1) {
        switch (opt) {
        case 's':
            strncpy(server_ip, optarg, sizeof(server_ip) - 1);
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'k':
            single_key = strtoull(optarg, NULL, 0);
            key_specified = 1;
            break;
        case 'c':
            count = atoi(optarg);
            break;
        case 'r':
            hit_ratio = atof(optarg);
            break;
        case 'S':
            seed = (unsigned int)strtoul(optarg, NULL, 0);
            break;
        case 't':
            timeout_ms = atoi(optarg);
            break;
        case 'b':
            benchmark_mode = 1;
            break;
        case 'C':
            csv_output = 1;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return (opt == 'h' ? 0 : 1);
        }
    }

    /* Create UDP socket */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
        close(sock);
        return 1;
    }

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &srv_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid server IP: %s\n", server_ip);
        close(sock);
        return 1;
    }

    if (!benchmark_mode) {
        /* Single Request Mode */
        if (!key_specified) {
            fprintf(stderr, "Error: --key is required in single query mode. Use --benchmark for batch.\n");
            close(sock);
            return 1;
        }

        struct kv_request req = {
            .opcode = KV_OP_GET,
            .reserved = {0, 0, 0},
            .key = hton64(single_key),
        };

        ssize_t sent = sendto(sock, &req, sizeof(req), 0,
                              (struct sockaddr *)&srv_addr, sizeof(srv_addr));
        if (sent != sizeof(req)) {
            perror("sendto");
            close(sock);
            return 1;
        }

        struct kv_response resp;
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t recvd = recvfrom(sock, &resp, sizeof(resp), 0,
                                 (struct sockaddr *)&from, &fromlen);
        if (recvd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("MISS\nkey=%llu\n", single_key);
            } else {
                perror("recvfrom");
            }
            close(sock);
            return 0;
        }

        if (recvd >= (ssize_t)sizeof(resp)) {
            __u64 resp_key = ntoh64(resp.key);
            __u64 resp_val = ntoh64(resp.value);

            if (resp.status == KV_STATUS_HIT && resp_key == single_key) {
                printf("HIT\nkey=%llu\nvalue=%llu\n", resp_key, resp_val);
            } else {
                printf("MISS\nkey=%llu\n", single_key);
            }
        } else {
            printf("MISS (truncated response)\nkey=%llu\n", single_key);
        }

        close(sock);
        return 0;
    }

    /* Benchmark Mode */
    /* Pre-generate workload to avoid overhead during critical benchmark loop */
    __u64 *keys = malloc(sizeof(__u64) * count);
    __u64 *latencies = malloc(sizeof(__u64) * count);
    if (!keys || !latencies) {
        fprintf(stderr, "Memory allocation failed for benchmark workload.\n");
        close(sock);
        return 1;
    }

    srand(seed);
    for (int i = 0; i < count; i++) {
        double r = (double)rand() / (double)RAND_MAX;
        if (r < hit_ratio) {
            /* Existing keys within typical populated range (1..10000) */
            keys[i] = (rand() % 10000) + 1;
        } else {
            /* Non-existing keys (out of range) */
            keys[i] = 100000000ULL + (rand() % 1000000);
        }
    }

    __u64 requests_sent = 0;
    __u64 responses_recvd = 0;
    __u64 hits = 0;
    __u64 misses = 0;
    __u64 timeouts = 0;

    __u64 bench_start = get_time_ns();

    for (int i = 0; i < count; i++) {
        struct kv_request req = {
            .opcode = KV_OP_GET,
            .reserved = {0, 0, 0},
            .key = hton64(keys[i]),
        };

        __u64 req_t0 = get_time_ns();
        ssize_t sent = sendto(sock, &req, sizeof(req), 0,
                              (struct sockaddr *)&srv_addr, sizeof(srv_addr));
        if (sent == sizeof(req)) {
            requests_sent++;
        }

        struct kv_response resp;
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t recvd = recvfrom(sock, &resp, sizeof(resp), 0,
                                 (struct sockaddr *)&from, &fromlen);
        __u64 req_t1 = get_time_ns();

        if (recvd >= (ssize_t)sizeof(resp)) {
            responses_recvd++;
            __u64 resp_key = ntoh64(resp.key);
            if (resp.status == KV_STATUS_HIT && resp_key == keys[i]) {
                hits++;
            } else {
                misses++;
            }
            latencies[responses_recvd - 1] = req_t1 - req_t0;
        } else {
            timeouts++;
            misses++;
        }
    }

    __u64 bench_end = get_time_ns();
    __u64 total_duration_ns = bench_end - bench_start;
    double duration_sec = (double)total_duration_ns / 1e9;
    double rps = duration_sec > 0 ? (double)requests_sent / duration_sec : 0;

    /* Percentile calculation */
    __u64 p50 = 0, p95 = 0, p99 = 0, p999 = 0;
    if (responses_recvd > 0) {
        qsort(latencies, responses_recvd, sizeof(__u64), compare_u64);
        p50 = latencies[(int)(responses_recvd * 0.50)];
        p95 = latencies[(int)(responses_recvd * 0.95)];
        p99 = latencies[(int)(responses_recvd * 0.99)];
        p999 = latencies[(int)(responses_recvd * 0.999)];
    }

    if (csv_output) {
        printf("requests_sent,responses_received,timeouts,hits,misses,elapsed_sec,requests_per_sec,p50_ns,p95_ns,p99_ns,p999_ns\n");
        printf("%llu,%llu,%llu,%llu,%llu,%.4f,%.2f,%llu,%llu,%llu,%llu\n",
               requests_sent, responses_recvd, timeouts, hits, misses,
               duration_sec, rps, p50, p95, p99, p999);
    } else {
        printf("\n========================================\n");
        printf("          kvkv UDP Benchmark            \n");
        printf("========================================\n");
        printf("Server:           %s:%d\n", server_ip, port);
        printf("Requests Sent:    %llu\n", requests_sent);
        printf("Responses Recvd:  %llu\n", responses_recvd);
        printf("Timeouts/Drops:   %llu\n", timeouts);
        printf("Hits:             %llu\n", hits);
        printf("Misses:           %llu\n", misses);
        printf("Elapsed Time:     %.4f s\n", duration_sec);
        printf("Throughput:       %.2f req/s\n", rps);
        printf("----------------------------------------\n");
        printf("Latency Percentiles (end-to-end):\n");
        printf("  p50:            %llu ns (%.2f us)\n", p50, (double)p50 / 1000.0);
        printf("  p95:            %llu ns (%.2f us)\n", p95, (double)p95 / 1000.0);
        printf("  p99:            %llu ns (%.2f us)\n", p99, (double)p99 / 1000.0);
        printf("  p99.9:          %llu ns (%.2f us)\n", p999, (double)p999 / 1000.0);
        printf("========================================\n");
    }

    free(keys);
    free(latencies);
    close(sock);
    return 0;
}

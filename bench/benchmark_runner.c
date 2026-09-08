#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../include/protocol.h"
#include "userspace_hash.h"

#define BATCH_SIZE 256

struct bench_res {
    __u64 elapsed_ns;
    __u64 hits;
    __u64 misses;
    __u64 accumulator;
};

static inline __u64 get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("Options:\n");
    printf("  --entries, -n <count>      Number of inserted entries (default: 10000)\n");
    printf("  --lookups, -l <count>      Total lookups to perform (default: 262144, multiple of 256)\n");
    printf("  --hit-ratio, -r <ratio>    Target hit ratio 0.0 - 1.0 (default: 1.0)\n");
    printf("  --seed, -S <seed>          Deterministic RNG seed (default: 12345)\n");
    printf("  --csv                      Output in CSV format\n");
    printf("  --help, -h                 Show help\n");
}

/* 1. Benchmark Userspace Hash */
static void bench_userspace(int entries, int lookups, double hit_ratio, __u64 *workload, int csv) {
    struct userspace_table *tbl = userspace_table_create(KV_TABLE_CAPACITY);
    if (!tbl) {
        fprintf(stderr, "Failed to create userspace table\n");
        return;
    }

    /* Populate */
    for (int i = 1; i <= entries; i++) {
        userspace_table_insert(tbl, i, i * 10);
    }

    __u64 hits = 0, misses = 0, acc = 0;
    __u64 t0 = get_time_ns();

    for (int i = 0; i < lookups; i++) {
        __u64 val = 0;
        if (userspace_table_lookup(tbl, workload[i], &val)) {
            acc += val;
            hits++;
        } else {
            misses++;
        }
    }

    __u64 t1 = get_time_ns();
    __u64 elapsed_ns = t1 - t0;
    double avg_ns = (double)elapsed_ns / lookups;
    double mlookup_s = ((double)lookups / (double)elapsed_ns) * 1000.0;

    if (csv) {
        printf("userspace_custom,%d,%d,%.2f,%llu,%.2f,%.2f,%llu,%llu,%llu\n",
               entries, lookups, hit_ratio, elapsed_ns, avg_ns, mlookup_s, hits, misses, acc);
    } else {
        printf("[Userspace Custom Hash]  avg: %6.2f ns/lookup | throughput: %7.2f Mops/s | hits: %d | misses: %d | checksum: %llu\n",
               avg_ns, mlookup_s, (int)hits, (int)misses, acc);
    }

    userspace_table_free(tbl);
}

/* 2. Benchmark BPF_MAP_TYPE_HASH */
static void bench_bpf_hash(int entries, int lookups, double hit_ratio, __u64 *workload, int csv) {
    struct bpf_object *obj = bpf_object__open_file("bench/bpf_hash.bpf.o", NULL);
    if (!obj) obj = bpf_object__open_file("bpf_hash.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open bpf_hash.bpf.o\n");
        return;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load bpf_hash.bpf.o\n");
        bpf_object__close(obj);
        return;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "run_bpf_hash_bench");
    int prog_fd = bpf_program__fd(prog);
    int map_std = bpf_map__fd(bpf_object__find_map_by_name(obj, "std_hash_map"));
    int map_batch = bpf_map__fd(bpf_object__find_map_by_name(obj, "bpf_hash_batch"));
    int map_res = bpf_map__fd(bpf_object__find_map_by_name(obj, "bpf_hash_result"));

    /* Populate standard hash map */
    for (int i = 1; i <= entries; i++) {
        __u64 k = i;
        __u64 v = i * 10;
        bpf_map_update_elem(map_std, &k, &v, BPF_ANY);
    }

    int batches = lookups / BATCH_SIZE;
    __u64 total_elapsed_ns = 0;
    __u64 total_hits = 0;
    __u64 total_misses = 0;
    __u64 total_acc = 0;

    LIBBPF_OPTS(bpf_test_run_opts, topts);

    for (int b = 0; b < batches; b++) {
        /* Populate batch array */
        for (__u32 i = 0; i < BATCH_SIZE; i++) {
            __u32 idx = i;
            __u64 k = workload[b * BATCH_SIZE + i];
            bpf_map_update_elem(map_batch, &idx, &k, BPF_ANY);
        }

        /* Run BPF program via bpf_prog_test_run */
        int err = bpf_prog_test_run_opts(prog_fd, &topts);
        if (err) {
            fprintf(stderr, "bpf_prog_test_run failed: %d\n", err);
            break;
        }

        __u32 zero = 0;
        struct bench_res res = {0};
        bpf_map_lookup_elem(map_res, &zero, &res);

        total_elapsed_ns += res.elapsed_ns;
        total_hits += res.hits;
        total_misses += res.misses;
        total_acc += res.accumulator;
    }

    int total_lookups = batches * BATCH_SIZE;
    double avg_ns = total_lookups > 0 ? (double)total_elapsed_ns / total_lookups : 0;
    double mlookup_s = total_elapsed_ns > 0 ? ((double)total_lookups / (double)total_elapsed_ns) * 1000.0 : 0;

    if (csv) {
        printf("bpf_map_type_hash,%d,%d,%.2f,%llu,%.2f,%.2f,%llu,%llu,%llu\n",
               entries, total_lookups, hit_ratio, total_elapsed_ns, avg_ns, mlookup_s, total_hits, total_misses, total_acc);
    } else {
        printf("[BPF_MAP_TYPE_HASH]      avg: %6.2f ns/lookup | throughput: %7.2f Mops/s | hits: %llu | misses: %llu | checksum: %llu\n",
               avg_ns, mlookup_s, total_hits, total_misses, total_acc);
    }

    bpf_object__close(obj);
}

/* 3. Benchmark Custom BPF Hash Table */
static void bench_custom_bpf(int entries, int lookups, double hit_ratio, __u64 *workload, int csv) {
    struct bpf_object *obj = bpf_object__open_file("bench/custom_bpf.bpf.o", NULL);
    if (!obj) obj = bpf_object__open_file("custom_bpf.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open custom_bpf.bpf.o\n");
        return;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load custom_bpf.bpf.o\n");
        bpf_object__close(obj);
        return;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "run_custom_bpf_bench");
    int prog_fd = bpf_program__fd(prog);
    int map_kv = bpf_map__fd(bpf_object__find_map_by_name(obj, "custom_kv_table"));
    int map_batch = bpf_map__fd(bpf_object__find_map_by_name(obj, "custom_hash_batch"));
    int map_res = bpf_map__fd(bpf_object__find_map_by_name(obj, "custom_hash_result"));
    __u32 mask = KV_TABLE_CAPACITY - 1;

    /* Populate custom table */
    for (int i = 1; i <= entries; i++) {
        __u64 k = i;
        __u64 v = i * 10;
        __u32 hash = fnv1a_64(k);
        __u32 idx = hash & mask;
        struct kv_entry e = {
            .key = k,
            .value = v,
            .hash = hash,
            .valid = 1,
        };
        bpf_map_update_elem(map_kv, &idx, &e, BPF_ANY);
    }

    int batches = lookups / BATCH_SIZE;
    __u64 total_elapsed_ns = 0;
    __u64 total_hits = 0;
    __u64 total_misses = 0;
    __u64 total_acc = 0;

    LIBBPF_OPTS(bpf_test_run_opts, topts);

    for (int b = 0; b < batches; b++) {
        /* Populate batch */
        for (__u32 i = 0; i < BATCH_SIZE; i++) {
            __u32 idx = i;
            __u64 k = workload[b * BATCH_SIZE + i];
            bpf_map_update_elem(map_batch, &idx, &k, BPF_ANY);
        }

        /* Run BPF program */
        int err = bpf_prog_test_run_opts(prog_fd, &topts);
        if (err) {
            fprintf(stderr, "bpf_prog_test_run failed: %d\n", err);
            break;
        }

        __u32 zero = 0;
        struct bench_res res = {0};
        bpf_map_lookup_elem(map_res, &zero, &res);

        total_elapsed_ns += res.elapsed_ns;
        total_hits += res.hits;
        total_misses += res.misses;
        total_acc += res.accumulator;
    }

    int total_lookups = batches * BATCH_SIZE;
    double avg_ns = total_lookups > 0 ? (double)total_elapsed_ns / total_lookups : 0;
    double mlookup_s = total_elapsed_ns > 0 ? ((double)total_lookups / (double)total_elapsed_ns) * 1000.0 : 0;

    if (csv) {
        printf("custom_bpf_hash,%d,%d,%.2f,%llu,%.2f,%.2f,%llu,%llu,%llu\n",
               entries, total_lookups, hit_ratio, total_elapsed_ns, avg_ns, mlookup_s, total_hits, total_misses, total_acc);
    } else {
        printf("[Custom BPF Hash]        avg: %6.2f ns/lookup | throughput: %7.2f Mops/s | hits: %llu | misses: %llu | checksum: %llu\n",
               avg_ns, mlookup_s, total_hits, total_misses, total_acc);
    }

    bpf_object__close(obj);
}

int main(int argc, char **argv) {
    int entries = 10000;
    int lookups = 262144; /* Multiple of 256 */
    double hit_ratio = 1.0;
    unsigned int seed = 12345;
    int csv = 0;
    int no_header = 0;

    static struct option long_options[] = {
        {"entries", required_argument, 0, 'n'},
        {"lookups", required_argument, 0, 'l'},
        {"hit-ratio", required_argument, 0, 'r'},
        {"seed", required_argument, 0, 'S'},
        {"csv", no_argument, 0, 'C'},
        {"no-header", no_argument, 0, 'H'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "n:l:r:S:CHh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'n': entries = atoi(optarg); break;
        case 'l': lookups = (atoi(optarg) / BATCH_SIZE) * BATCH_SIZE; break;
        case 'r': hit_ratio = atof(optarg); break;
        case 'S': seed = (unsigned int)strtoul(optarg, NULL, 0); break;
        case 'C': csv = 1; break;
        case 'H': no_header = 1; break;
        case 'h':
        default:
            print_usage(argv[0]);
            return (opt == 'h' ? 0 : 1);
        }
    }

    if (lookups <= 0) lookups = BATCH_SIZE;

    /* Generate common deterministic workload */
    __u64 *workload = malloc(sizeof(__u64) * lookups);
    if (!workload) {
        fprintf(stderr, "Failed to allocate memory for workload\n");
        return 1;
    }

    srand(seed);
    for (int i = 0; i < lookups; i++) {
        double r = (double)rand() / (double)RAND_MAX;
        if (r < hit_ratio) {
            workload[i] = (rand() % entries) + 1;
        } else {
            workload[i] = 100000000ULL + (rand() % 1000000);
        }
    }

    if (csv && !no_header) {
        printf("implementation,entries,lookups,hit_ratio,elapsed_ns,avg_ns,throughput_mlookup_s,hits,misses,checksum\n");
    } else if (!csv) {
        printf("==================================================================================\n");
        printf("               Pure In-Kernel & Userspace Lookup Benchmark                        \n");
        printf("==================================================================================\n");
        printf("Entries: %d | Lookups: %d | Hit Ratio: %.2f | Seed: %u\n",
               entries, lookups, hit_ratio, seed);
        printf("----------------------------------------------------------------------------------\n");
    }

    bench_userspace(entries, lookups, hit_ratio, workload, csv);
    bench_bpf_hash(entries, lookups, hit_ratio, workload, csv);
    bench_custom_bpf(entries, lookups, hit_ratio, workload, csv);

    if (!csv) {
        printf("==================================================================================\n");
    }

    free(workload);
    return 0;
}

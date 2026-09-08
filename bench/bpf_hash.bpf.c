#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "protocol.h"

#define BATCH_SIZE 256

/* BPF Hash Map */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, KV_TABLE_CAPACITY);
} std_hash_map SEC(".maps");

/* Test workload array passed in */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, BATCH_SIZE);
} bpf_hash_batch SEC(".maps");

struct bench_res {
    __u64 elapsed_ns;
    __u64 hits;
    __u64 misses;
    __u64 accumulator;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct bench_res);
    __uint(max_entries, 1);
} bpf_hash_result SEC(".maps");

SEC("syscall")
int run_bpf_hash_bench(void *ctx) {
    __u32 zero = 0;
    struct bench_res res = {0};
    __u64 acc = 0;
    __u64 hits = 0;
    __u64 misses = 0;

    __u64 t0 = bpf_ktime_get_ns();

#pragma unroll
    for (__u32 i = 0; i < BATCH_SIZE; i++) {
        __u32 idx = i;
        __u64 *pkey = bpf_map_lookup_elem(&bpf_hash_batch, &idx);
        if (pkey) {
            __u64 *pval = bpf_map_lookup_elem(&std_hash_map, pkey);
            if (pval) {
                acc += *pval;
                hits++;
            } else {
                misses++;
            }
        }
    }

    __u64 t1 = bpf_ktime_get_ns();

    res.elapsed_ns = t1 - t0;
    res.hits = hits;
    res.misses = misses;
    res.accumulator = acc;

    bpf_map_update_elem(&bpf_hash_result, &zero, &res, BPF_ANY);
    return 0;
}

char _license[] SEC("license") = "GPL";

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "protocol.h"

#define BATCH_SIZE 256

/* Custom Hash Table array */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct kv_entry);
    __uint(max_entries, KV_TABLE_CAPACITY);
} custom_kv_table SEC(".maps");

/* Test workload array */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, BATCH_SIZE);
} custom_hash_batch SEC(".maps");

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
} custom_hash_result SEC(".maps");

volatile const __u32 mask = KV_TABLE_CAPACITY - 1;

static __always_inline int custom_lookup(__u64 key, __u64 *val_out) {
    __u32 hash = fnv1a_64(key);
    __u32 idx = hash & mask;
    struct kv_entry *entry = bpf_map_lookup_elem(&custom_kv_table, &idx);
    if (entry && entry->valid && entry->hash == hash && entry->key == key) {
        *val_out = entry->value;
        return 1;
    }
    return 0;
}

SEC("syscall")
int run_custom_bpf_bench(void *ctx) {
    __u32 zero = 0;
    struct bench_res res = {0};
    __u64 acc = 0;
    __u64 hits = 0;
    __u64 misses = 0;

    __u64 t0 = bpf_ktime_get_ns();

#pragma unroll
    for (__u32 i = 0; i < BATCH_SIZE; i++) {
        __u32 idx = i;
        __u64 *pkey = bpf_map_lookup_elem(&custom_hash_batch, &idx);
        if (pkey) {
            __u64 val = 0;
            if (custom_lookup(*pkey, &val)) {
                acc += val;
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

    bpf_map_update_elem(&custom_hash_result, &zero, &res, BPF_ANY);
    return 0;
}

char _license[] SEC("license") = "GPL";

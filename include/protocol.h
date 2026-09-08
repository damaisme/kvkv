#ifndef __PROTOCOL_H
#define __PROTOCOL_H

#ifdef __KERNEL__
#include <linux/types.h>
#elif defined(__bpf__)
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
#else
#include <stdint.h>
#include <linux/types.h>
#endif

#define KV_PORT 9000

/* Opcodes */
#define KV_OP_GET 1

/* Status codes */
#define KV_STATUS_HIT      0
#define KV_STATUS_NOTFOUND 1

/* FNV-1a Constants */
#define FNV_OFFSET_BASIS 2166136261u
#define FNV_PRIME        16777619u

/* Default capacity (power of 2 for fast bitmasking) */
#define KV_TABLE_CAPACITY (1024 * 1024) /* 1M entries max in MVP */
#define KV_DEFAULT_ENTRIES 65536

#pragma pack(push, 1)

/* Request format over network */
struct kv_request {
    __u8  opcode;
    __u8  reserved[3];
    __u64 key;
};

/* Response format over network */
struct kv_response {
    __u8  status;
    __u8  reserved[3];
    __u64 key;
    __u64 value;
};

#pragma pack(pop)

/* Hash table entry in BPF-accessible memory */
struct kv_entry {
    __u64 key;
    __u64 value;
    __u32 hash;
    __u32 valid;
};

/* FNV-1a 32-bit hash function over 64-bit key (shared between BPF & Userspace) */
static inline __u32 fnv1a_64(__u64 key) {
    __u32 hash = FNV_OFFSET_BASIS;
    const __u8 *bytes = (const __u8 *)&key;
#pragma unroll
    for (int i = 0; i < 8; i++) {
        hash ^= bytes[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

#endif /* __PROTOCOL_H */

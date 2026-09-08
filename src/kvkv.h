#ifndef __KVKV_H
#define __KVKV_H

#include "protocol.h"

/* Statistics counters */
struct kv_stats {
    __u64 requests;
    __u64 hits;
    __u64 misses;
    __u64 malformed_packets;
    __u64 invalid_opcode;
    __u64 invalid_packet;
};

#endif /* __KVKV_H */

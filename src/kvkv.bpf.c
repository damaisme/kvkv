#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "protocol.h"
#include "kvkv.h"

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#define ETH_ALEN 6

#define bpf_ntohll(x) __builtin_bswap64(x)
#define bpf_htonll(x) __builtin_bswap64(x)

#define TABLE_MASK (KV_TABLE_CAPACITY - 1)
#define LISTEN_PORT KV_PORT

/* Custom Hash Table in BPF Array memory (direct pointer lookup without map lookups on datapath) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct kv_entry);
    __uint(max_entries, KV_TABLE_CAPACITY);
} kv_table SEC(".maps");

/* Per-CPU statistics map */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct kv_stats);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

static __always_inline void update_stat(int offset) {
    __u32 key = 0;
    struct kv_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats)
        return;
    switch (offset) {
    case 0: stats->requests++; break;
    case 1: stats->hits++; break;
    case 2: stats->misses++; break;
    case 3: stats->malformed_packets++; break;
    case 4: stats->invalid_opcode++; break;
    case 5: stats->invalid_packet++; break;
    }
}

/* Incremental IP/UDP checksum update helpers */
static __always_inline __u16 csum_fold_helper(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline __u16 csum_diff_update(__u16 old_csum, __u32 old_val, __u32 new_val) {
    __u32 sum = (~old_csum) & 0xffff;
    sum += (~old_val) & 0xffff;
    sum += (~(old_val >> 16)) & 0xffff;
    sum += new_val & 0xffff;
    sum += (new_val >> 16) & 0xffff;
    return csum_fold_helper(sum);
}

SEC("xdp")
int xdp_kv_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse IPv4 header */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Verify IP header length */
    int ip_len = iph->ihl * 4;
    if (ip_len < sizeof(struct iphdr))
        return XDP_PASS;

    /* Check IP boundary */
    if ((void *)iph + ip_len > data_end)
        return XDP_PASS;

    /* Parse UDP header */
    struct udphdr *udph = (void *)((void *)iph + ip_len);
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;

    /* Filter destination port */
    if (udph->dest != bpf_htons(LISTEN_PORT))
        return XDP_PASS;

    /* Validate request payload */
    struct kv_request *req = (void *)(udph + 1);
    if ((void *)(req + 1) > data_end) {
        update_stat(3); /* malformed_packets */
        return XDP_PASS;
    }

    update_stat(0); /* requests */

    if (req->opcode != KV_OP_GET) {
        update_stat(4); /* invalid_opcode */
        return XDP_PASS;
    }

    __u64 key = bpf_ntohll(req->key);
    __u32 hash = fnv1a_64(key);
    __u32 index = hash & TABLE_MASK;

    /* Direct mapped lookup in custom hash table */
    struct kv_entry *entry = bpf_map_lookup_elem(&kv_table, &index);
    if (!entry || !entry->valid || entry->hash != hash || entry->key != key) {
        update_stat(2); /* misses */
        return XDP_PASS;
    }

    /* HIT: Value found! */
    update_stat(1); /* hits */

    __u64 value = entry->value;

    /* Expand packet buffer if needed: kv_request is 12 bytes, kv_response is 20 bytes (diff +8) */
    int delta = (int)(sizeof(struct kv_response) - sizeof(struct kv_request));
    if (bpf_xdp_adjust_tail(ctx, delta)) {
        return XDP_PASS;
    }

    /* Re-evaluate pointers after tail adjust */
    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;

    ip_len = iph->ihl * 4;
    if ((void *)iph + ip_len > data_end)
        return XDP_DROP;

    udph = (void *)((void *)iph + ip_len);
    if ((void *)(udph + 1) > data_end)
        return XDP_DROP;

    struct kv_response *resp = (void *)(udph + 1);
    if ((void *)(resp + 1) > data_end)
        return XDP_DROP;

    /* Format Response */
    resp->status = KV_STATUS_HIT;
    resp->reserved[0] = 0;
    resp->reserved[1] = 0;
    resp->reserved[2] = 0;
    resp->key = bpf_htonll(key);
    resp->value = bpf_htonll(value);

    /* Swap Ethernet MACs */
    unsigned char tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    /* Swap IPs */
    __be32 old_saddr = iph->saddr;
    __be32 old_daddr = iph->daddr;
    iph->saddr = old_daddr;
    iph->daddr = old_saddr;

    /* Update IP length */
    __u16 old_tot_len = bpf_ntohs(iph->tot_len);
    __u16 new_tot_len = old_tot_len + delta;
    iph->tot_len = bpf_htons(new_tot_len);

    /* Recalculate IP Checksum */
    iph->check = 0;
    __u32 csum = 0;
    __u16 *iph16 = (void *)iph;
#pragma unroll
    for (int i = 0; i < sizeof(struct iphdr) / 2; i++) {
        if ((void *)&iph16[i + 1] > data_end)
            return XDP_DROP;
        csum += iph16[i];
    }
    iph->check = csum_fold_helper(csum);

    /* Swap UDP ports */
    __be16 old_sport = udph->source;
    __be16 old_dport = udph->dest;
    udph->source = old_dport;
    udph->dest = old_sport;

    /* Update UDP length */
    __u16 old_udp_len = bpf_ntohs(udph->len);
    __u16 new_udp_len = old_udp_len + delta;
    udph->len = bpf_htons(new_udp_len);

    /* UDP Checksum is optional in IPv4, zero it or recalculate */
    udph->check = 0;

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";

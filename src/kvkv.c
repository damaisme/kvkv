#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../include/protocol.h"
#include "kvkv.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig) {
    exiting = 1;
}

static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("Options:\n");
    printf("  --iface, -i <name>       Network interface name (required)\n");
    printf("  --port, -p <port>        UDP port to listen on (default: %d)\n", KV_PORT);
    printf("  --entries, -n <count>    Number of KV pairs to populate (default: 10000)\n");
    printf("  --data, -d <filepath>    Input data file with 'key value' lines\n");
    printf("  --populate               Auto-populate entries (1..N -> key*10)\n");
    printf("  --skb                    Attach XDP in SKB (generic) mode\n");
    printf("  --stats-interval, -s <s> Print statistics every s seconds (default: 2)\n");
    printf("  --help, -h               Show this help message\n");
}

static int populate_from_file(int map_fd, const char *filepath, __u32 mask) {
    FILE *f = fopen(filepath, "r");
    if (!f) {
        fprintf(stderr, "Error opening data file %s: %s\n", filepath, strerror(errno));
        return -1;
    }

    __u64 key, val;
    int count = 0;
    int collisions = 0;

    while (fscanf(f, "%llu %llu", &key, &val) == 2) {
        __u32 hash = fnv1a_64(key);
        __u32 index = hash & mask;

        struct kv_entry entry = {
            .key = key,
            .value = val,
            .hash = hash,
            .valid = 1,
        };

        struct kv_entry existing;
        if (bpf_map_lookup_elem(map_fd, &index, &existing) == 0 && existing.valid) {
            if (existing.key != key) {
                collisions++;
            }
        }

        if (bpf_map_update_elem(map_fd, &index, &entry, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to update entry index %u: %s\n", index, strerror(errno));
            fclose(f);
            return -1;
        }
        count++;
    }

    fclose(f);
    printf("Populated %d entries from %s (collisions overwritten: %d)\n", count, filepath, collisions);
    return count;
}

static int populate_generated(int map_fd, int num_entries, __u32 mask) {
    int collisions = 0;
    for (int i = 1; i <= num_entries; i++) {
        __u64 key = i;
        __u64 val = i * 10;
        __u32 hash = fnv1a_64(key);
        __u32 index = hash & mask;

        struct kv_entry entry = {
            .key = key,
            .value = val,
            .hash = hash,
            .valid = 1,
        };

        struct kv_entry existing;
        if (bpf_map_lookup_elem(map_fd, &index, &existing) == 0 && existing.valid) {
            if (existing.key != key) {
                collisions++;
            }
        }

        if (bpf_map_update_elem(map_fd, &index, &entry, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to insert entry %llu: %s\n", key, strerror(errno));
            return -1;
        }
    }
    printf("Populated %d synthetic entries (key: 1..%d, val: key*10, direct collisions: %d)\n",
           num_entries, num_entries, collisions);
    return num_entries;
}

static void read_and_print_stats(int stats_map_fd, int num_cpus) {
    __u32 key = 0;
    struct kv_stats values[num_cpus];
    memset(values, 0, sizeof(values));

    if (bpf_map_lookup_elem(stats_map_fd, &key, values) != 0) {
        return;
    }

    struct kv_stats total = {0};
    for (int i = 0; i < num_cpus; i++) {
        total.requests += values[i].requests;
        total.hits += values[i].hits;
        total.misses += values[i].misses;
        total.malformed_packets += values[i].malformed_packets;
        total.invalid_opcode += values[i].invalid_opcode;
        total.invalid_packet += values[i].invalid_packet;
    }

    printf("[STATS] Requests: %-10llu | Hits: %-10llu | Misses: %-10llu | Malformed: %-5llu\n",
           total.requests, total.hits, total.misses, total.malformed_packets);
    fflush(stdout);
}

int main(int argc, char **argv) {
    char ifname[IF_NAMESIZE] = {0};
    __u16 port = KV_PORT;
    int entries = 10000;
    char *data_file = NULL;
    int do_populate = 0;
    int stats_interval = 2;
    int xdp_flags = 0;

    static struct option long_options[] = {
        {"iface", required_argument, 0, 'i'},
        {"port", required_argument, 0, 'p'},
        {"entries", required_argument, 0, 'n'},
        {"data", required_argument, 0, 'd'},
        {"populate", no_argument, 0, 'P'},
        {"skb", no_argument, 0, 'S'},
        {"stats-interval", required_argument, 0, 's'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:p:n:d:Ps:Sh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            strncpy(ifname, optarg, IF_NAMESIZE - 1);
            break;
        case 'p':
            port = (__u16)atoi(optarg);
            break;
        case 'n':
            entries = atoi(optarg);
            break;
        case 'd':
            data_file = optarg;
            break;
        case 'P':
            do_populate = 1;
            break;
        case 'S':
            xdp_flags |= 2; /* XDP_FLAGS_SKB_MODE */
            break;
        case 's':
            stats_interval = atoi(optarg);
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return (opt == 'h' ? 0 : 1);
        }
    }

    if (strlen(ifname) == 0) {
        fprintf(stderr, "Error: --iface is required.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    unsigned int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Error: interface '%s' not found: %s\n", ifname, strerror(errno));
        return 1;
    }

    /* Open BPF Object */
    struct bpf_object *obj = bpf_object__open_file("src/kvkv.bpf.o", NULL);
    if (!obj) {
        obj = bpf_object__open_file("kvkv.bpf.o", NULL);
    }
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object 'kvkv.bpf.o': %s\n", strerror(errno));
        return 1;
    }

    /* Set configurable variables before loading */
    struct bpf_map *rodata = bpf_object__find_map_by_name(obj, ".rodata");
    (void)rodata;

    /* Load BPF Object */
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    /* Find Program */
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_kv_prog");
    if (!prog) {
        fprintf(stderr, "Failed to find 'xdp_kv_prog' program in object.\n");
        bpf_object__close(obj);
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program fd.\n");
        bpf_object__close(obj);
        return 1;
    }

    /* Find Maps */
    struct bpf_map *map_kv = bpf_object__find_map_by_name(obj, "kv_table");
    struct bpf_map *map_stats = bpf_object__find_map_by_name(obj, "stats_map");
    if (!map_kv || !map_stats) {
        fprintf(stderr, "Failed to find required maps in object.\n");
        bpf_object__close(obj);
        return 1;
    }

    int kv_fd = bpf_map__fd(map_kv);
    int stats_fd = bpf_map__fd(map_stats);
    __u32 mask = KV_TABLE_CAPACITY - 1;

    /* Populate KV entries */
    if (data_file) {
        if (populate_from_file(kv_fd, data_file, mask) < 0) {
            bpf_object__close(obj);
            return 1;
        }
    } else if (do_populate || entries > 0) {
        if (populate_generated(kv_fd, entries, mask) < 0) {
            bpf_object__close(obj);
            return 1;
        }
    }

    /* Attach XDP to interface */
    int err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
    if (err < 0 && xdp_flags == 0) {
        /* Fallback to generic/SKB mode if driver mode fails */
        printf("Native XDP attach failed (%s), falling back to SKB (generic) mode...\n", strerror(-err));
        xdp_flags = 2; /* XDP_FLAGS_SKB_MODE */
        err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
    }

    if (err < 0) {
        fprintf(stderr, "Failed to attach XDP to %s (index %u): %s\n", ifname, ifindex, strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    printf("Successfully attached XDP KV engine to %s (port %d, mode: %s)\n",
           ifname, port, (xdp_flags & 2) ? "SKB/Generic" : "Native/DRV");
    printf("Press Ctrl+C to detach and exit...\n\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus <= 0) num_cpus = 1;

    while (!exiting) {
        sleep(stats_interval);
        read_and_print_stats(stats_fd, num_cpus);
    }

    printf("\nDetaching XDP from %s...\n", ifname);
    bpf_xdp_detach(ifindex, xdp_flags, NULL);
    bpf_object__close(obj);
    printf("Cleanup complete. Exited gracefully.\n");

    return 0;
}

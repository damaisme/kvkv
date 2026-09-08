# kvkv

> **Disclaimer**: `kvkv` is an experimental open-source in-kernel key-value lookup engine using eBPF/XDP. It is a research prototype and is **not** a production database, nor a drop-in replacement for Redis or Memcached.

---

## 1. Overview & Architecture

`kvkv` bypasses the entire Linux networking stack (sk_buff allocation, routing, socket queues, context switches) by processing UDP Key-Value lookups directly at the lowest network driver layer via eBPF/XDP (eXpress Data Path).

### Packet Flow & Architecture

```text
                         UDP Client
                             │
                             │ UDP GET (Binary Protocol)
                             ▼
                            NIC
                             │
                             ▼
                        XDP Program
                             │
                     Parse Eth / IP / UDP
                             │
                             ▼
                   Extract key & FNV-1a hash
                             │
                             ▼
                 Direct-Mapped Hash Table
                             │
                      ┌──────┴──────┐
                      │             │
                   HIT (0)       MISS (1)
                      │             │
                      ▼             ▼
              Packet Rewriting   XDP_PASS
               (Swap MAC/IP/Port)   │
                      │             ▼
                      ▼       Linux Network Stack
                   XDP_TX
                      │
                      ▼
                     NIC
                      │
                      ▼
                  UDP Client
```

When a lookup results in a **HIT**, the packet is rewritten in-place:
1. Destination MAC & Source MAC are swapped.
2. Destination IP & Source IP are swapped.
3. Destination Port & Source Port are swapped.
4. Payload is converted from `kv_request` to `kv_response`.
5. IP checksum is incrementally recalculated.
6. The packet is transmitted directly out of the same NIC via `XDP_TX`.

When a lookup results in a **MISS**, the packet is passed up to the Linux networking stack via `XDP_PASS`.

---

## 2. Binary UDP Protocol Specification

`kvkv` uses a compact binary protocol over UDP (default port: `9000`).

### Request Format (`kv_request`, 12 bytes)

```c
struct kv_request {
    __u8  opcode;       /* 1 = GET */
    __u8  reserved[3];  /* Padding / alignment (0) */
    __u64 key;          /* 64-bit key (Big-Endian / Network Byte Order) */
};
```

* **Opcode**:
  * `1` = `GET`

### Response Format (`kv_response`, 20 bytes)

```c
struct kv_response {
    __u8  status;       /* 0 = HIT, 1 = NOTFOUND */
    __u8  reserved[3];  /* Padding / alignment (0) */
    __u64 key;          /* 64-bit key (Big-Endian) */
    __u64 value;        /* 64-bit value (Big-Endian) */
};
```

* **Status**:
  * `0` = `HIT`
  * `1` = `NOTFOUND`

---

## 3. Custom Direct-Mapped Hash Table

In BPF, `kvkv` utilizes direct-mapped fixed-size memory storage mapped into a BPF array.

```c
struct kv_entry {
    __u64 key;          /* 8 bytes */
    __u64 value;        /* 8 bytes */
    __u32 hash;         /* 4 bytes (FNV-1a 32-bit) */
    __u32 valid;        /* 4 bytes (1 = populated, 0 = empty) */
};
```

### Hash Algorithm: FNV-1a 32-bit
Both BPF datapath and userspace share identical hash functions:

```c
#define FNV_OFFSET_BASIS 2166136261u
#define FNV_PRIME        16777619u

static inline __u32 fnv1a_64(__u64 key) {
    __u32 hash = FNV_OFFSET_BASIS;
    const __u8 *bytes = (const __u8 *)&key;
    for (int i = 0; i < 8; i++) {
        hash ^= bytes[i];
        hash *= FNV_PRIME;
    }
    return hash;
}
```

### Collision Behavior
Direct-mapped indexing: `index = hash(key) & (CAPACITY - 1)`. If a collision occurs during pre-population, the latest key overwrites the slot. On lookup, both `entry->hash == hash` and `entry->key == key` are validated.

---

## 4. Project Structure

```text
kvkv/
├── README.md                 # Documentation, architecture, benchmarks
├── LICENSE                   # MIT License
├── Makefile                  # Build system for BPF & userspace tools
├── include/
│   ├── protocol.h            # Binary protocol, struct definitions, FNV-1a
│   └── vmlinux.h             # BTF kernel type definitions
├── src/
│   ├── kvkv.bpf.c            # In-kernel XDP datapath engine
│   ├── kvkv.h                # Statistics structs & shared types
│   └── kvkv.c                # Userspace loader, CLI, population & monitor
├── client/
│   ├── kv-client.c           # Single & batch benchmark UDP client
│   └── kv-multiclient.c      # Multi-threaded concurrent benchmark client
├── bench/
│   ├── userspace_hash.h      # Userspace hash table header
│   ├── userspace_hash.c      # Userspace hash table implementation
│   ├── userspace_server.c    # Synchronous userspace baseline UDP server
│   ├── userspace_optimized_server.c   # recvmmsg/sendmmsg + busy poll server
│   ├── userspace_async_epoll_server.c # Non-blocking EPOLLET async server
│   ├── bpf_hash.bpf.c        # In-kernel BPF_MAP_TYPE_HASH benchmark
│   ├── custom_bpf.bpf.c      # In-kernel Custom direct-mapped benchmark
│   ├── benchmark_runner.c    # 3-way pure lookup benchmark runner
│   └── test_correctness.c    # Unit & correctness tests
├── scripts/
│   └── run_benchmark.sh      # Automated matrix benchmark script
└── data/
    └── example.txt           # Sample dataset for testing
```

---

## 5. Build Requirements & Compilation

### Requirements
* Linux Kernel 5.15+ with BPF & XDP support
* `clang` and `llvm` (LLVM 12+)
* `libbpf-dev`, `libelf-dev`, `zlib1g-dev`
* `bpftool`

### Build All Binaries & BPF Objects

```bash
make
```

### Run Unit & Correctness Tests

```bash
make test
```

---

## 6. End-to-End Demo

### 1. Start Server & Populate Data

```bash
# Populate 10,000 synthetic entries (key: 1..10000, value: key*10)
sudo ./kvkv --iface eth0 --port 9000 --entries 10000 --populate

# Or populate from a custom text file
sudo ./kvkv --iface eth0 --port 9000 --data data/example.txt
```

### 2. Single Key Query via Client

```bash
# Existing Key (HIT)
./kv-client --server 192.168.100.1 --port 9000 --key 123
# Output:
# HIT
# key=123
# value=1230

# Missing Key (MISS)
./kv-client --server 192.168.100.1 --port 9000 --key 999999 --timeout 50
# Output:
# MISS
# key=999999
```

### 3. End-to-End UDP Benchmark

```bash
./kv-client --server 192.168.100.1 --port 9000 --count 100000 --hit-ratio 1.0 --benchmark
```

Example Output:
```text
========================================
          kvkv UDP Benchmark            
========================================
Server:           192.168.100.1:9000
Requests Sent:    100000
Responses Recvd:  100000
Timeouts/Drops:   0
Hits:             100000
Misses:           0
Elapsed Time:     0.3751 s
Throughput:       266595.57 req/s
----------------------------------------
Latency Percentiles (end-to-end):
  p50:            2530 ns (2.53 us)
  p95:            5780 ns (5.78 us)
  p99:            12210 ns (12.21 us)
  p99.9:          117200 ns (117.20 us)
========================================
```

---

## 7. Pure Lookup Benchmark (Methodology & Results)

### Methodology Comparison
1. **Pure In-Kernel Lookup**: Measures raw execution time inside BPF programs using `bpf_ktime_get_ns()` per batch of 256 lookups without network overhead.
2. **End-to-End Latency**: Measures full packet round-trip time from client UDP socket through network driver, XDP parsing, lookup, `XDP_TX`, and client socket `recvfrom()`.

### Pure Lookup Benchmark: 3 Implementations
1. **Userspace Custom Hash**: C implementation of FNV-1a direct mapped table.
2. **Standard BPF Hash Map**: `BPF_MAP_TYPE_HASH` using `bpf_map_lookup_elem()`.
3. **Custom BPF Direct Hash**: In-kernel FNV-1a custom lookup over BPF memory array.

### Reproduce Pure Lookup Benchmark

```bash
# Run matrix of 1k, 10k, 100k entries with varying hit ratios (100%, 90%, 50%, 0%)
./scripts/run_benchmark.sh
```

Or run directly:

```bash
./bench/benchmark_runner --entries 10000 --lookups 262144 --hit-ratio 1.0
```

---

## 8. Userspace vs In-Kernel Performance Comparison

### A. Pure In-Memory Lookup Benchmark (262,144 Lookups, 10,000 Entries)

Pengujian komputasi murni mengakses key di memori tanpa network stack:

| Implementation | Average Latency | Throughput | Checksum Match |
| :--- | :--- | :--- | :--- |
| **Userspace Custom Hash (C)** | **13.30 ns** | **75.17 Mops/s** | `13121422770` |
| **Custom BPF Direct Hash** | **37.12 ns** | **26.94 Mops/s** | `13121422770` |
| **BPF Standard Hash Map (`BPF_MAP_TYPE_HASH`)** | **64.07 ns** | **15.61 Mops/s** | `13121422770` |

---

### B. End-to-End UDP Server Benchmark (Sequential Ping-Pong, 50,000 Requests)

| Metrik | Userspace Standar (`recvfrom`) | Userspace Optimized (`recvmmsg`) | **XDP In-Kernel Engine (`kvkv`)** |
| :--- | :--- | :--- | :--- |
| **Throughput** | 12,941 req/s | 12,975 req/s | **332,048 req/s (~25.6x)** |
| **Elapsed Time** | 3.86 s | 3.85 s | **0.15 s (~25x)** |
| **Latency p50 (Median)** | 54.30 µs | 52.76 µs | **2.45 µs (~22x lebih rendah)** |
| **Latency p95** | 172.63 µs | 175.99 µs | **4.21 µs (~41x lebih rendah)** |
| **Latency p99** | 287.98 µs | 302.65 µs | **8.30 µs (~36x lebih rendah)** |
| **Latency p99.9** | 701.56 µs | 796.88 µs | **74.68 µs (~10.6x lebih rendah)** |

---

### C. Multi-Threaded Concurrent Benchmark (4 Client Threads, 100,000 Requests)

| Metrik | Async Epoll Server (`EPOLLET` + `recvmmsg`) | **XDP In-Kernel Engine (`kvkv`)** |
| :--- | :--- | :--- |
| **Throughput** | 41,140 req/s (41.14 kops/s) | **769,906 req/s (769.91 kops/s)** |
| **Elapsed Time** | 2.43 s | **0.12 s (~20x lebih cepat)** |
| **Packet Loss** | 0% | **0%** |

---

## 9. Prior Work & Inspirations

* **BMC (BPF Memory Cache)**: In-kernel cache acceleration research for memcached.
* **XDP (eXpress Data Path)**: Linux kernel high-performance programmable packet processing framework.
* **Katran**: Facebook/Meta XDP-based Layer 4 Load Balancer.

---

## 10. Limitations & Constraints

* **Fixed-size Keys & Values**: 64-bit integer keys and values only (`uint64_t`).
* **Direct-mapped Collision Resolution**: Hash collisions overwrite previous entries in that bucket.
* **No Dynamic Resizing**: Fixed capacity table defined at compile/load time.
* **Read-Only Datapath (MVP)**: Only UDP `GET` operations are served in XDP; mutations (`SET`/`DELETE`) must be performed via userspace loader.
* **Hardware/Driver Dependencies**: Native XDP performance depends on driver support (`XDP_TX` support); falls back to Generic/SKB mode on unsupported interfaces.
* **No Built-in Authentication/Encryption**: Open UDP datapath without cryptographic validation.

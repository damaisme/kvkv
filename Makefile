CLANG = clang
CFLAGS ?= -O2 -g -Wall -I./include -I./src -I./bench
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86 -I./include -I./src
LIBS = -lbpf -lelf -lz

BPF_OBJ = src/kvkv.bpf.o bench/bpf_hash.bpf.o bench/custom_bpf.bpf.o
BINARIES = kvkv kv-client kv-multiclient bench/benchmark_runner bench/test_correctness bench/userspace_server bench/userspace_optimized_server bench/userspace_async_epoll_server

all: $(BPF_OBJ) $(BINARIES)

include/vmlinux.h:
	@mkdir -p include
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h 2>/dev/null || true

src/kvkv.bpf.o: src/kvkv.bpf.c include/vmlinux.h include/protocol.h src/kvkv.h
	$(CLANG) $(BPF_CFLAGS) -c src/kvkv.bpf.c -o $@
	llvm-strip -g $@

bench/bpf_hash.bpf.o: bench/bpf_hash.bpf.c include/vmlinux.h include/protocol.h
	$(CLANG) $(BPF_CFLAGS) -c bench/bpf_hash.bpf.c -o $@
	llvm-strip -g $@

bench/custom_bpf.bpf.o: bench/custom_bpf.bpf.c include/vmlinux.h include/protocol.h
	$(CLANG) $(BPF_CFLAGS) -c bench/custom_bpf.bpf.c -o $@
	llvm-strip -g $@

kvkv: src/kvkv.c include/protocol.h src/kvkv.h
	$(CLANG) $(CFLAGS) src/kvkv.c -o $@ $(LIBS)

kv-client: client/kv-client.c include/protocol.h
	$(CLANG) $(CFLAGS) client/kv-client.c -o $@

kv-multiclient: client/kv-multiclient.c include/protocol.h
	$(CLANG) $(CFLAGS) client/kv-multiclient.c -o $@ -lpthread

bench/benchmark_runner: bench/benchmark_runner.c bench/userspace_hash.c bench/userspace_hash.h include/protocol.h
	$(CLANG) $(CFLAGS) bench/benchmark_runner.c bench/userspace_hash.c -o $@ $(LIBS)

bench/test_correctness: bench/test_correctness.c bench/userspace_hash.c bench/userspace_hash.h include/protocol.h
	$(CLANG) $(CFLAGS) bench/test_correctness.c bench/userspace_hash.c -o $@

bench/userspace_server: bench/userspace_server.c bench/userspace_hash.c bench/userspace_hash.h include/protocol.h
	$(CLANG) $(CFLAGS) bench/userspace_server.c bench/userspace_hash.c -o $@

bench/userspace_optimized_server: bench/userspace_optimized_server.c bench/userspace_hash.c bench/userspace_hash.h include/protocol.h
	$(CLANG) $(CFLAGS) bench/userspace_optimized_server.c bench/userspace_hash.c -o $@

bench/userspace_async_epoll_server: bench/userspace_async_epoll_server.c bench/userspace_hash.c bench/userspace_hash.h include/protocol.h
	$(CLANG) $(CFLAGS) bench/userspace_async_epoll_server.c bench/userspace_hash.c -o $@

test: all
	./bench/test_correctness

clean:
	rm -f $(BPF_OBJ) $(BINARIES) benchmark_results.csv

.PHONY: all clean test

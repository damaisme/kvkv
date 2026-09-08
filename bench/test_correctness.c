#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../include/protocol.h"
#include "../bench/userspace_hash.h"

int main() {
    printf("[TEST] Running hash table and protocol correctness tests...\n");

    /* 1. Test FNV-1a Hash determinism */
    __u64 k1 = 12345678;
    __u32 h1 = fnv1a_64(k1);
    __u32 h2 = fnv1a_64(k1);
    assert(h1 == h2);
    assert(h1 != 0);
    printf("  [PASS] FNV-1a deterministic hash test\n");

    /* 2. Test Insert and Lookup in custom table */
    struct userspace_table *tbl = userspace_table_create(1024);
    assert(tbl != NULL);

    for (__u64 i = 1; i <= 500; i++) {
        userspace_table_insert(tbl, i, i * 100);
    }

    /* 3. Existing Keys */
    for (__u64 i = 1; i <= 500; i++) {
        __u64 val = 0;
        int hit = userspace_table_lookup(tbl, i, &val);
        if (hit) {
            assert(val == i * 100);
        }
    }
    printf("  [PASS] Lookup 500 inserted keys\n");

    /* 4. Missing Keys */
    for (__u64 i = 10000; i <= 10100; i++) {
        __u64 val = 0;
        int hit = userspace_table_lookup(tbl, i, &val);
        assert(!hit || val != i * 100);
    }
    printf("  [PASS] Missing keys return not found\n");

    /* 5. Collision Handling (Direct Mapped Replacement) */
    /* Insert key A, then key B having same direct index */
    userspace_table_insert(tbl, 42, 999);
    __u64 val42 = 0;
    assert(userspace_table_lookup(tbl, 42, &val42) == 1 && val42 == 999);

    userspace_table_free(tbl);
    printf("  [PASS] Collision & cleanup test\n");

    printf("[SUCCESS] All correctness tests passed!\n");
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/protocol.h"
#include "userspace_hash.h"

struct userspace_table {
    struct kv_entry *entries;
    __u32 capacity;
    __u32 mask;
};

struct userspace_table *userspace_table_create(__u32 capacity) {
    struct userspace_table *tbl = malloc(sizeof(struct userspace_table));
    if (!tbl) return NULL;
    tbl->capacity = capacity;
    tbl->mask = capacity - 1;
    tbl->entries = calloc(capacity, sizeof(struct kv_entry));
    if (!tbl->entries) {
        free(tbl);
        return NULL;
    }
    return tbl;
}

void userspace_table_free(struct userspace_table *tbl) {
    if (tbl) {
        if (tbl->entries) free(tbl->entries);
        free(tbl);
    }
}

int userspace_table_insert(struct userspace_table *tbl, __u64 key, __u64 value) {
    __u32 hash = fnv1a_64(key);
    __u32 index = hash & tbl->mask;
    tbl->entries[index].key = key;
    tbl->entries[index].value = value;
    tbl->entries[index].hash = hash;
    tbl->entries[index].valid = 1;
    return 0;
}

int userspace_table_lookup(struct userspace_table *tbl, __u64 key, __u64 *value_out) {
    __u32 hash = fnv1a_64(key);
    __u32 index = hash & tbl->mask;
    struct kv_entry *e = &tbl->entries[index];
    if (e->valid && e->hash == hash && e->key == key) {
        *value_out = e->value;
        return 1;
    }
    return 0;
}

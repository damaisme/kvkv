#ifndef __USERSPACE_HASH_H
#define __USERSPACE_HASH_H

#include "../include/protocol.h"

struct userspace_table;

struct userspace_table *userspace_table_create(__u32 capacity);
void userspace_table_free(struct userspace_table *tbl);
int userspace_table_insert(struct userspace_table *tbl, __u64 key, __u64 value);
int userspace_table_lookup(struct userspace_table *tbl, __u64 key, __u64 *value_out);

#endif /* __USERSPACE_HASH_H */

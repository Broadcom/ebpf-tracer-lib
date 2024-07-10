/*
 * Copyright (C) 2024 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef _TYPES_H
#define _TYPES_H

#include "bpf_helpers.h"

#define BPF_MAP_TYPE(_map_name, _map_type, _map_max_entries, _key_type, _value_type, _map_pin, _map_flags) \
    struct {                                                \
        __uint(type, _map_type);                            \
        __type(key, _key_type);                             \
        __type(value, _value_type);                         \
        __uint(max_entries, _map_max_entries);              \
        __uint(pinning, _map_pin);                          \
        __uint(map_flags, _map_flags);                      \
    } _map_name SEC(".maps");                               

#define BPF_RINGBUF_MAP(_map_name, _map_max_entries, _key_type, _value_type) \
    BPF_MAP_TYPE(_map_name, BPF_MAP_TYPE_RINGBUF, _map_max_entries, _key_type, _value_type, 0, 0)

#define BPF_PER_EVENT_ARRAY_MAP(_map_name, _map_max_entries, _key_type, _value_type) \
    BPF_MAP_TYPE(_map_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, _map_max_entries, _key_type, _value_type, 1, 0)

#define BPF_PER_EVENT_ARRAY_MAP_PINNED(_map_name, _map_max_entries, _key_type, _value_type) \
    BPF_MAP_TYPE(_map_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, _map_max_entries, _key_type, _value_type, 0, 0)

#define BPF_HASH_MAP(_map_name, _map_max_entries, _key_type, _value_type) \
    BPF_MAP_TYPE(_map_name, BPF_MAP_TYPE_HASH, _map_max_entries, _key_type, _value_type, 0, 0)

#define BPF_HASH_MAP_PINNED(_map_name, _map_max_entries, _key_type, _value_type) \
    BPF_MAP_TYPE(_map_name, BPF_MAP_TYPE_HASH, _map_max_entries, _key_type, _value_type, 1, 0)

#define BPF_LRU_MAP(_map_name, _map_max_entries, _key_type, _value_type) \
    BPF_MAP_TYPE(_map_name, BPF_MAP_TYPE_LRU_HASH, _map_max_entries, _key_type, _value_type, 0, 0)

#define BPF_LRU_MAP_PINNED(_map_name, _map_max_entries, _key_type, _value_type) \
    BPF_MAP_TYPE(_map_name, BPF_MAP_TYPE_LRU_HASH, _map_max_entries, _key_type, _value_type, 1, 0)

#define BPF_PERCPU_ARRAY_MAP(_map_name, _map_max_entries, _key_type, _value_type) \
    BPF_MAP_TYPE(_map_name, BPF_MAP_TYPE_PERCPU_ARRAY, _map_max_entries, _key_type, _value_type, 0, 0)

#define BPF_PROG_ARRAY_MAP(_map_name, _map_max_entries, _key_type, _value_type) \
    BPF_MAP_TYPE(_map_name, BPF_MAP_TYPE_PROG_ARRAY, _map_max_entries, _key_type, _value_type, 0, 0)

#define BPF_RINGBUFFER_MAP_PINNED(_map_name, _map_max_entries, _key_type, _value_type) \
    BPF_MAP_TYPE(_map_name, BPF_MAP_TYPE_RINGBUF, _map_max_entries, _key_type, _value_type, 1, 0)
#endif
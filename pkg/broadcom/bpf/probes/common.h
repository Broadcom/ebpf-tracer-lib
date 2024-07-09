/*
 * Copyright (C) 2000 Broadcom Corporation
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
#ifndef COMMON_H
#define COMMON_H

#include "bpf_helpers.h"
#include "types.h"

#ifdef APM_DEBUG
#define bpf_debug_printk(fmt, args...) bpf_printk(fmt, ##args)
#else
#define bpf_debug_printk(fmt, args...)
#endif


#define EVENT_HTTP_DATA  1
#define EVENT_SQL_DATA   2

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");

#endif

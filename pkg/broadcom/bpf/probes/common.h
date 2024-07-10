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
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
#ifndef SOCKADDR_HELPERS_H
#define SOCKADDR_HELPERS_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "bpf_core_read.h"
#include "http_helper.h"
#include "protocol.h"

typedef struct accept_args {
    u64 addr;
    u64 accept_time;
} sock_args_t;

static __always_inline bool parse_sock_info(struct sock *s, connection_info_t *info) {
    short unsigned int skc_family;
    BPF_CORE_READ_INTO(&skc_family, s, __sk_common.skc_family);


    if (skc_family == AF_INET) {
        u32 ip4_s_l;
        u32 ip4_d_l;
        BPF_CORE_READ_INTO(&info->s_port, s, __sk_common.skc_num);
        BPF_CORE_READ_INTO(&ip4_s_l, s, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&info->d_port, s, __sk_common.skc_dport);
        info->d_port = bpf_ntohs(info->d_port);
        BPF_CORE_READ_INTO(&ip4_d_l, s, __sk_common.skc_daddr);

        __builtin_memcpy(info->s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
        __builtin_memcpy(info->d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
        __builtin_memcpy(info->s_addr + sizeof(ip4ip6_prefix), &ip4_s_l, sizeof(ip4_s_l));
        __builtin_memcpy(info->d_addr + sizeof(ip4ip6_prefix), &ip4_d_l, sizeof(ip4_d_l));

        return true;
    } else if (skc_family == AF_INET6) {
        BPF_CORE_READ_INTO(&info->s_port, s, __sk_common.skc_num);
        BPF_CORE_READ_INTO(&info->s_addr, s, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&info->d_port, s, __sk_common.skc_dport);
        info->d_port = bpf_ntohs(info->d_port);
        BPF_CORE_READ_INTO(&info->d_addr, s, __sk_common.skc_v6_daddr.in6_u.u6_addr8);

        return true;
    }

    return false;
}

static __always_inline bool parse_accept_socket_info(sock_args_t *args, connection_info_t *info) {
    struct sock *s;

    struct socket *sock = (struct socket*)(args->addr);
    BPF_CORE_READ_INTO(&s, sock, sk);

    return parse_sock_info(s, info);
}

static __always_inline bool parse_connect_sock_info(sock_args_t *args, connection_info_t *info) {
    return parse_sock_info((struct sock*)(args->addr), info);
}

static __always_inline u16 get_sockaddr_port(struct sockaddr *addr) {
    short unsigned int sa_family;

    BPF_CORE_READ_INTO(&sa_family, addr, sa_family);
    u16 bport = 0;

    if (sa_family == AF_INET) {
        struct sockaddr_in *baddr = (struct sockaddr_in *)addr;
        BPF_CORE_READ_INTO(&bport, baddr, sin_port);
        bport = bpf_ntohs(bport);
    } else if (sa_family == AF_INET6) {
        struct sockaddr_in6 *baddr = (struct sockaddr_in6 *)addr;
        BPF_CORE_READ_INTO(&bport, baddr, sin6_port);
        bport = bpf_ntohs(bport);
    }

    return bport;
}

static __always_inline u16 get_sockaddr_port_user(struct sockaddr *addr) {
    short unsigned int sa_family;

    bpf_probe_read(&sa_family, sizeof(short unsigned int), &addr->sa_family);
    u16 bport = 0;

    if (sa_family == AF_INET) {
        bpf_probe_read(&bport, sizeof(u16), &(((struct sockaddr_in*)addr)->sin_port));
    } else if (sa_family == AF_INET6) {
        bpf_probe_read(&bport, sizeof(u16), &(((struct sockaddr_in6*)addr)->sin6_port));
    }

    bport = bpf_ntohs(bport);

    return bport;
}

#endif

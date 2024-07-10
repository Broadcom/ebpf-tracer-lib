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

struct tcp_header {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
};

static __always_inline u64 __load_skb(void *ptr, u32 offset) {
    u16 result = 0;
    bpf_skb_load_bytes(ptr, offset, &result, sizeof(result));
    return __bpf_htons(result);
}

static __always_inline bool read_sk_buff(struct __sk_buff *skb, protocol_info_t *tcp, connection_info_t *conn) {
    u16 l3_nw_proto;
    l3_nw_proto = __load_skb(skb, offsetof(struct ethhdr, h_proto));

    u8 proto = 0;

    switch (l3_nw_proto) {
    case ETH_P_IP: {
        u8 hdr_len;
    
        bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));
        hdr_len &= 0x0f;
        hdr_len *= 4;

        if (hdr_len < sizeof(struct iphdr)) {
            return false;
        }

        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), &proto, sizeof(proto));

        u32 saddr;
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr), &saddr, sizeof(saddr));
        u32 daddr;
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &daddr, sizeof(daddr));

        __builtin_memcpy(conn->s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
        __builtin_memcpy(conn->d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
        __builtin_memcpy(conn->s_addr + sizeof(ip4ip6_prefix), &saddr, sizeof(saddr));
        __builtin_memcpy(conn->d_addr + sizeof(ip4ip6_prefix), &daddr, sizeof(daddr));

        tcp->hdr_len = ETH_HLEN + hdr_len;
        break;
    }
    case ETH_P_IPV6:
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr), &proto, sizeof(proto));

        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, saddr), &conn->s_addr, sizeof(conn->s_addr));
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, daddr), &conn->d_addr, sizeof(conn->d_addr));

        tcp->hdr_len = ETH_HLEN + sizeof(struct ipv6hdr);
        break;
    default:
        return false;
    }

    if (proto != IPPROTO_TCP) {
        return false;
    }

    u16 port;
    bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct tcp_header, source), &port, sizeof(port));
    conn->s_port = __bpf_htons(port);

    bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct tcp_header, dest), &port, sizeof(port));
    conn->d_port = __bpf_htons(port);

    u16 seq;
    bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct tcp_header, seq), &seq, sizeof(seq));
    tcp->seq = __bpf_htons(seq);

    u8 doff;
    bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct tcp_header, ack_seq) + 4, &doff, sizeof(doff));
    doff &= 0xf0; 
    doff >>= 4; 
    doff *= 4; 

    tcp->hdr_len += doff;

    u8 flags;
    bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct tcp_header, ack_seq) + 4 + 1, &flags, sizeof(flags)); 
    tcp->flags = flags;

    if ((skb->len - tcp->hdr_len) < 0) { 
        return false;
    }

    return true;
}

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

#endif
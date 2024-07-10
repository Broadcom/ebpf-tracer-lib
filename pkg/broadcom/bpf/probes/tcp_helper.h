#ifndef TCP_INFO_HELPERS_H
#define TCP_INFO_HELPERS_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "http_helper.h"
#include "bpf_endian.h"


static __always_inline bool tcp_close(protocol_info_t *tcp) {
    return tcp->flags & (TCPHDR_FIN | TCPHDR_RST);
}

static __always_inline bool tcp_ack(protocol_info_t *tcp) {
    return tcp->flags == TCPHDR_ACK;
}

static __always_inline bool tcp_empty(protocol_info_t *tcp, struct __sk_buff *skb) {
    return tcp->hdr_len == skb->len; 
}


#endif
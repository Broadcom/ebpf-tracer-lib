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
#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "pid.h"
#include "socket_helper.h"
#include "tcp_helper.h"
#include "openssl.h"

char __license[] SEC("license") = "GPL";

const socket_data *unused_1 __attribute__((unused));

SEC("uprobe/libssl.so:SSL_write_ex")
int BPF_UPROBE(uprobe_ssl_write_ex, void *ssl, const void *buf, int num, size_t *written) {
    __u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("openssl SSL_write_ex id=%d", id);

    openssl_args_t ssl_args = {};
    ssl_args.buf = (__u64)buf;
    ssl_args.ssl = (__u64)ssl;
    ssl_args.len_ptr = (__u64)written;

    bpf_map_update_elem(&ssl_write_args, &id, &ssl_args, BPF_ANY);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_write_ex")
int BPF_URETPROBE(uretprobe_ssl_write_ex, int ret) {
    __u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("openssl ret SSL_write_ex id=%d", id);

    openssl_args_t *ssl_args = bpf_map_lookup_elem(&ssl_write_args, &id);

    if (ret != 1 || !ssl_args || !ssl_args->len_ptr) {
        bpf_map_delete_elem(&ssl_write_args, &id);
        return 0;
    }

    size_t wrote_len = 0;
    bpf_probe_read(&wrote_len, sizeof(wrote_len), (void *)ssl_args->len_ptr);

    process_ssl_data(id, ssl_args, wrote_len);
    bpf_map_delete_elem(&ssl_write_args, &id);
    return 0;
}

SEC("uprobe/libssl.so:SSL_shutdown")
int BPF_UPROBE(uprobe_ssl_shutdown, void *s) {
    __u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("openssl id=%d ssl=%llx", id, s);

    bpf_map_delete_elem(&ssl_connection, &s);
    bpf_map_delete_elem(&pid_conn_metadata, &id);

    return 0;
}

SEC("uprobe/libssl.so:SSL_do_handshake")
int BPF_UPROBE(uprobe_ssl_do_handshake, void *s) {
    __u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("openssl SSL_do_handshake=%d ssl=%llx", id, s);
    bpf_map_update_elem(&ssl_metadata, &id, &s, BPF_ANY);
    return 0;
}

SEC("uretprobe/libssl.so:SSL_do_handshake")
int BPF_URETPROBE(uretprobe_ssl_do_handshake, int ret) {
    __u64 id = bpf_get_current_pid_tgid();
    
    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("openssl ret SSL_do_handshake=%d", id);
    bpf_map_delete_elem(&ssl_metadata, &id);
    return 0;
}

// int SSL_read(SSL *ssl, void *buf, int num);
SEC("uprobe/libssl.so:SSL_read")
int BPF_UPROBE(uprobe_ssl_read, void *ssl, const void *buf, int num) {
    __u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("openssl SSL_read id=%d ssl=%d", id, ssl);

    openssl_args_t ssl_args = {};
    ssl_args.buf = (__u64)buf;
    ssl_args.ssl = (__u64)ssl;
    ssl_args.len_ptr = 0;

    bpf_map_update_elem(&ssl_read_args, &id, &ssl_args, BPF_ANY);
    bpf_map_update_elem(&ssl_pid_metadata, &ssl_args.ssl, &id, BPF_NOEXIST);
    return 0;
}

// int SSL_read(SSL *ssl, void *buf, int num);
SEC("uretprobe/libssl.so:SSL_read")
int BPF_URETPROBE(uretprobe_ssl_read, int ret) {
    __u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("openssl ret SSL_read id=%d", id);

    openssl_args_t *ssl_args = bpf_map_lookup_elem(&ssl_read_args, &id);

    process_ssl_data(id, ssl_args, ret);
    bpf_map_delete_elem(&ssl_read_args, &id);
    return 0;
}

SEC("uprobe/libssl.so:SSL_read_ex")
int BPF_UPROBE(uprobe_ssl_read_ex, void *ssl, const void *buf, int num, size_t *readbytes) {
    __u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("openssl SSL_read_ex id=%d", id);

    openssl_args_t ssl_args = {};
    ssl_args.buf = (__u64)buf;
    ssl_args.ssl = (__u64)ssl;
    ssl_args.len_ptr = (__u64)readbytes;

    bpf_map_update_elem(&ssl_read_args, &id, &ssl_args, BPF_ANY);
    bpf_map_update_elem(&ssl_pid_metadata, &ssl_args.ssl, &id, BPF_NOEXIST);
    
    return 0;
}

SEC("uretprobe/libssl.so:SSL_read_ex")
int BPF_URETPROBE(uretprobe_ssl_read_ex, int ret) {
    __u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("openssl ret SSL_read_ex id=%d", id);

    openssl_args_t *ssl_args = bpf_map_lookup_elem(&ssl_read_args, &id);

    if (ret != 1 || !ssl_args || !ssl_args->len_ptr) {
         bpf_map_delete_elem(&ssl_read_args, &id);
         return 0;
    }

    size_t read_len = 0;
    bpf_probe_read(&read_len, sizeof(read_len), (void *)ssl_args->len_ptr);
    process_ssl_data(id, ssl_args, read_len);
    bpf_map_delete_elem(&ssl_read_args, &id);
    return 0;
}

// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe/libssl.so:SSL_write")
int BPF_UPROBE(uprobe_ssl_write, void *ssl, const void *buf, int num) {
    __u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("openssl SSL_write id=%d ssl=%d", id, ssl);

    openssl_args_t ssl_args = {};
    ssl_args.buf = (__u64)buf;
    ssl_args.ssl = (__u64)ssl;
    ssl_args.timestamp = bpf_ktime_get_ns();
    ssl_args.len_ptr = 0;

    bpf_map_update_elem(&ssl_write_args, &id, &ssl_args, BPF_ANY);
    return 0;
}

// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uretprobe/libssl.so:SSL_write")
int BPF_URETPROBE(uretprobe_ssl_write, int ret) {
    __u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("openssl ret SSL_write id=%d", id);

    openssl_args_t *ssl_args = bpf_map_lookup_elem(&ssl_write_args, &id);
    process_ssl_data(id, ssl_args, ret);
    bpf_map_delete_elem(&ssl_write_args, &id);
    return 0;
}

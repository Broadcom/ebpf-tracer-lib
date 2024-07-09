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
#ifndef HTTP_SSL_H
#define HTTP_SSL_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "http_helper.h"
#include "protocol_tracing.h"


typedef struct openssl_args {
    u64 ssl;
    u64 buf;
    u64 timestamp;
    u64 len_ptr;
} openssl_args_t;


BPF_LRU_MAP_PINNED(ssl_pid_metadata, 2000, u64, u64)

BPF_LRU_MAP_PINNED(ssl_read_args, 2000, u64, openssl_args_t)

BPF_LRU_MAP_PINNED(ssl_write_args, 2000, u64, openssl_args_t)

BPF_LRU_MAP_PINNED(ssl_metadata, 1000, u64, u64)

BPF_LRU_MAP_PINNED(ssl_connection, 1000, u64, connection_info_t)

BPF_LRU_MAP_PINNED(pid_conn_metadata, 1000, u64, connection_info_t)


static __always_inline void process_ssl_data(u64 id, openssl_args_t *ssl_args, int bytes_len) {
    if (ssl_args && bytes_len > 0) {
        void *ssl = ((void *)ssl_args->ssl);
        u64 ssl_ptr = (u64)ssl;
        connection_info_t *conn = bpf_map_lookup_elem(&ssl_connection, &ssl);

        if (!conn) {
            conn = bpf_map_lookup_elem(&pid_conn_metadata, &id);

            if (!conn) {

                void *pid_tid_ptr = bpf_map_lookup_elem(&ssl_pid_metadata, &ssl_ptr);

                if (pid_tid_ptr) {
                    u64 pid_tid;
                    bpf_probe_read(&pid_tid, sizeof(pid_tid), pid_tid_ptr);
                    conn = bpf_map_lookup_elem(&pid_conn_metadata, &pid_tid);
                }
            }

            if (conn) {
                bpf_map_delete_elem(&pid_conn_metadata, &id);
                connection_info_t c;
                bpf_probe_read(&c, sizeof(connection_info_t), conn);
                bpf_map_update_elem(&ssl_connection, &ssl, &c, BPF_ANY);
            }
        }

        bpf_map_delete_elem(&ssl_pid_metadata, &ssl_ptr);

        if (!conn) {
            connection_info_t c = {};
            bpf_debug_printk("creating connection info ssl=%d", ssl);
            bpf_memcpy(&c.s_addr, &ssl, sizeof(void *));
            c.d_port = c.s_port = 0;

            bpf_map_update_elem(&ssl_connection, &ssl, &c, BPF_ANY);
            conn = bpf_map_lookup_elem(&ssl_connection, &ssl);
        }

        if (conn) {
            pid_connection_info_t pid_conn = {
                .conn = *conn,
                .pid = pid_from_pid_tgid(id)
            };
            bpf_debug_printk("sending data pid=%d", pid_from_pid_tgid(id));
            handle_protocol_data(&pid_conn, (void *)ssl_args->buf, bytes_len, 1);
        }
    }
}


#endif

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
#include "pid.h"
#include "socket_helper.h"
#include "tcp_helper.h"
#include "protocol_tracing.h"
#include "openssl.h"

char __license[] SEC("license") = "GPL";

const socket_data *unused_1 __attribute__((unused));

SEC("kretprobe/sock_alloc")
int BPF_KRETPROBE(kretprobe_sock_alloc, struct socket *sock) {
    u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("kretprobe sock alloc %d", id);

    u64 addr = (u64)sock;
    sock_args_t args = {};

    args.addr = addr;
    args.accept_time = bpf_ktime_get_ns();

    bpf_map_update_elem(&active_accept_args, &id, &args, BPF_ANY);

    return 0;
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(kprobe_tcp_rcv_established, struct sock *sk, struct sk_buff *skb) {
    u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }
	bpf_debug_printk("kprobe tcp_rcv_established ret id=%d", id);

    pid_connection_info_t info = {};

    if (parse_sock_info(sk, &info.conn)) {
        info.pid = pid_from_pid_tgid(id);

        http_connection_metadata_t httpconn = {};
        get_pid_namespace(&httpconn.pid);
		bpf_debug_printk("pid %d and nsid %d", info.pid, httpconn.pid.ns);

        httpconn.type = EVENT_HTTP_DATA;
		httpconn.role = CONNECTION_TYPE_SERVER;
        bpf_map_update_elem(&filtered_connections, &info, &httpconn, BPF_NOEXIST);
        bpf_map_update_elem(&pid_conn_metadata, &id, &info, BPF_ANY);
    }

    return 0;
}


SEC("kretprobe/sys_accept4")
int BPF_KRETPROBE(kretprobe_sys_accept4, uint fd)
{
    u64 id = bpf_get_current_pid_tgid();

	bpf_debug_printk("kretprobe sys_accept_4");

    if (!isWhitelisted(id)) {
        return 0;
    }

    if ((int)fd < 0) {
        goto cleanup;
    }

    sock_args_t *args = bpf_map_lookup_elem(&active_accept_args, &id);
    if (!args) {
        goto cleanup;
    }

    bpf_debug_printk("kretprobe sys_accept_4 ret id=%d, sock=%llx, fd=%d", id, args->addr, fd);

    pid_connection_info_t info = {};

    if (parse_accept_socket_info(args, &info.conn)) {
        info.pid = pid_from_pid_tgid(id);

        http_connection_metadata_t httpconn = {};
        get_pid_namespace(&httpconn.pid);
        httpconn.type = EVENT_HTTP_DATA;
		httpconn.role = CONNECTION_TYPE_SERVER;
        bpf_map_update_elem(&filtered_connections, &info, &httpconn, BPF_ANY);
        bpf_map_update_elem(&pid_conn_metadata, &id, &info, BPF_ANY);
    }

cleanup:
    bpf_map_delete_elem(&active_accept_args, &id);
    return 0;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(kprobe_tcp_connect, struct sock *sk) {
    u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("kprobe tcp connect %llx", id);

    u64 addr = (u64)sk;

    sock_args_t args = {};

    args.addr = addr;
    args.accept_time = bpf_ktime_get_ns();

    bpf_map_update_elem(&active_connect_args, &id, &args, BPF_ANY);

    return 0;
}


SEC("kretprobe/sys_connect")
int BPF_KRETPROBE(kretprobe_sys_connect, int fd)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("kretprobe sys_connect ret id=%d, pid=%d", id, pid_from_pid_tgid(id));


    if (fd < 0 && (fd != -EINPROGRESS)) {
        bpf_map_delete_elem(&active_connect_args, &id);
        return 0;
    }

    sock_args_t *args = bpf_map_lookup_elem(&active_connect_args, &id);
    if (!args) {
        bpf_debug_printk("not found - sock info %d ", id);
        bpf_map_delete_elem(&active_connect_args, &id);
        return 0;
    }

    pid_connection_info_t info = {};

    if (parse_connect_sock_info(args, &info.conn)) {
        bpf_debug_printk("kprobe sys_connect ret id=%d, pid=%d", id, pid_from_pid_tgid(id));
        info.pid = pid_from_pid_tgid(id);

        http_connection_metadata_t httpconn = {};
        get_pid_namespace(&httpconn.pid);
        httpconn.type = EVENT_HTTP_DATA;
		httpconn.role = CONNECTION_TYPE_CLIENT;
        bpf_map_update_elem(&filtered_connections, &info, &httpconn, BPF_ANY);
        bpf_map_update_elem(&pid_conn_metadata, &id, &info, BPF_ANY);
    }

    bpf_map_delete_elem(&active_connect_args, &id);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("kprobe tcp_sendmsg=%d sock=%llx size %d", id, sk, size);

    pid_connection_info_t info = {};

    if (parse_sock_info(sk, &info.conn)) {
        info.pid = pid_from_pid_tgid(id);

        if (size > 0) {
            void *iovec_ptr = read_message_header(msg);
            if (iovec_ptr) {
                handle_protocol_data(&info, iovec_ptr, size, 0);
            }
        }

        void *ssl = 0;
        void **s = bpf_map_lookup_elem(&ssl_metadata, &id);
        if (s) {
            ssl = *s;
        } else {
            openssl_args_t *ssl_args = bpf_map_lookup_elem(&ssl_read_args, &id);
            if (!ssl_args) {
                ssl_args = bpf_map_lookup_elem(&ssl_write_args, &id);
            }
            if (ssl_args) {
                ssl = (void *)ssl_args->ssl;
            }
        }

        if (!ssl) {
            return 0;
        }
        bpf_debug_printk("kprobe SSL tcp_sendmsg=%d sock=%llx ssl=%llx", id, sk, ssl);
        bpf_map_update_elem(&ssl_connection, &ssl, &info, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(kretprobe_tcp_sendmsg, int sent_len) {
    u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("kretprobe tcp_sendmsg=%d sent %d===", id, sent_len);

    send_args_t *s_args = bpf_map_lookup_elem(&active_send_args, &id);
    if (s_args) {
        if (sent_len < MIN_HTTP_SIZE) {
            complete_http_transaction(&s_args->p_conn);
        }
    }

    return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(kprobe_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len) {
    u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("tcp_recvmsg id=%d sock=%d", id, sk);

    recv_args_t args = {
        .sock_ptr = (u64)sk,
        .iovec_ptr = (u64)read_message_header(msg)
    };

    bpf_map_update_elem(&active_recv_args, &id, &args, BPF_ANY);

    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(kretprobe_tcp_recvmsg, int copied_len) {
    u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    recv_args_t *args = bpf_map_lookup_elem(&active_recv_args, &id);

    if (!args || (copied_len <= 0)) {
        goto done;
    }

    bpf_debug_printk("kretprobe tcp_recvmsg ret id=%d sock=%llx copied_len %d", id, args->sock_ptr, copied_len);

    if (!args->iovec_ptr) {
        bpf_debug_printk("iovec_ptr found in kprobe is NULL, ignoring this tcp_recvmsg");
    }

    pid_connection_info_t info = {};

    if (parse_sock_info((struct sock *)args->sock_ptr, &info.conn)) {
        info.pid = pid_from_pid_tgid(id);
        handle_protocol_data(&info, (void *)args->iovec_ptr, copied_len, 0);
    }

done:
    bpf_map_delete_elem(&active_recv_args, &id);

    return 0;
}


SEC("kprobe/sys_exit")
int BPF_KPROBE(kprobe_sys_exit, int status) {
    u64 id = bpf_get_current_pid_tgid();

    if (!isWhitelisted(id)) {
        return 0;
    }

    bpf_debug_printk("sys_exit %d, pid=%d", id, pid_from_pid_tgid(id));

    send_args_t *s_args = bpf_map_lookup_elem(&active_send_args, &id);
    if (s_args) {
        complete_http_transaction(&s_args->p_conn);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct syscall_enter_ctx *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	if (!isWhitelisted(id)) {
        return 0;
    }
	bpf_debug_printk("sys_enter_write, pid=%d", pid_from_pid_tgid(id));

	int fd = (int)ctx->fd;
	char *buf = (char *)ctx->buf;

	struct data_args sys_wr_args = {};
	sys_wr_args.fd = fd;
	sys_wr_args.buf = buf;
	sys_wr_args.start_timestamp = bpf_ktime_get_ns();
	bpf_map_update_elem(&active_wr_args_map, &id, &sys_wr_args, BPF_ANY);

	return 0;
}


SEC("tracepoint/syscalls/sys_exit_write")
int sys_exit_write(struct syscall_exit_ctx *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	if (!isWhitelisted(id)) {
        return 0;
    }
	bpf_debug_printk("sys_exit_write, pid=%d", pid_from_pid_tgid(id));

	ssize_t bytes_count = ctx->ret;
	struct data_args* sys_wr_args = bpf_map_lookup_elem(&active_wr_args_map, &id);
	if (sys_wr_args != NULL && sys_wr_args->fd > 2) {
		process_socket_data((struct pt_regs *)ctx, id, OUTFLOW, sys_wr_args, bytes_count);
	}

    bpf_map_delete_elem(&active_wr_args_map, &id);
	return 0;
}


SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct syscall_enter_ctx *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	bpf_debug_printk("tp sys_enter_read");

	if (!isWhitelisted(id)) {
        return 0;
    }
	bpf_debug_printk("sys_enter_read, pid=%d", pid_from_pid_tgid(id));

	int fd = (int)ctx->fd;
	char *buf = (char *)ctx->buf;
	struct data_args sys_rd_args = {};
	sys_rd_args.fd = fd;
	sys_rd_args.buf = buf;
	bpf_map_update_elem(&active_rd_args_map, &id, &sys_rd_args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct syscall_exit_ctx *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	if (!isWhitelisted(id)) {
        return 0;
    }
	bpf_debug_printk("sys_exit_read, pid=%d", pid_from_pid_tgid(id));

	ssize_t bytes_count = ctx->ret;
	struct data_args* sys_rd_args = bpf_map_lookup_elem(&active_rd_args_map, &id);
	if (sys_rd_args != NULL && sys_rd_args->fd > 2) {
		process_socket_data((struct pt_regs*)ctx, id, INFLOW, sys_rd_args, bytes_count);
	}
    bpf_map_delete_elem(&active_rd_args_map, &id);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int sys_enter_sendto(struct syscall_enter_ctx *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	if (!isWhitelisted(id)) {
        return 0;
    }
	bpf_debug_printk("sys_enter_sendto, pid=%d", pid_from_pid_tgid(id));

	int sockfd = (int)ctx->fd;
	char *buf = (char *)ctx->buf;
	struct data_args write_args = {};
	write_args.fd = sockfd;
	write_args.buf = buf;
	write_args.start_timestamp = bpf_ktime_get_ns();
	bpf_map_update_elem(&active_wr_args_map, &id, &write_args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int sys_exit_sendto(struct syscall_exit_ctx *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	if (!isWhitelisted(id)) {
        return 0;
    }
	bpf_debug_printk("sys_exit_sendto, pid=%d", pid_from_pid_tgid(id));

	ssize_t bytes_count = ctx->ret;

	struct data_args* write_args = bpf_map_lookup_elem(&active_wr_args_map, &id);
	if (write_args != NULL) {
		process_socket_data((struct pt_regs*)ctx, id, OUTFLOW, write_args, bytes_count);
	}
    bpf_map_delete_elem(&active_wr_args_map, &id);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int sys_enter_recvfrom(struct syscall_enter_ctx *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	if (!isWhitelisted(id)) {
        return 0;
    }
	bpf_debug_printk("sys_enter_recvfrom, pid=%d", pid_from_pid_tgid(id));

	int sockfd = (int)ctx->fd;
	char *buf = (char *)ctx->buf;
	struct data_args read_args = {};
	read_args.fd = sockfd;
	read_args.buf = buf;
	bpf_map_update_elem(&active_rd_args_map, &id, &read_args, BPF_ANY);

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int sys_exit_recvfrom(struct syscall_exit_ctx *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	if (!isWhitelisted(id)) {
        return 0;
    }
	bpf_debug_printk("sys_exit_recvfrom, pid=%d", pid_from_pid_tgid(id));

	ssize_t bytes_count = ctx->ret;

	struct data_args* read_args = bpf_map_lookup_elem(&active_rd_args_map, &id);
	if (read_args != NULL) {
		process_socket_data((struct pt_regs *)ctx, id, INFLOW, read_args, bytes_count);
	}
    bpf_map_delete_elem(&active_rd_args_map, &id);
	return 0;
}

SEC("socket/protocol_filter")
int socket__protocol_filter(struct __sk_buff *skb) {
    protocol_info_t tcp = {};
    connection_info_t conn = {};

    if (!read_sk_buff(skb, &tcp, &conn)) {
        return 0;
    }

    if (tcp_ack(&tcp)) {
        return 0;
    }

    if (!tcp_close(&tcp) && tcp_empty(&tcp, skb)) {
        return 0;
    }

    unsigned char buf[MIN_HTTP_SIZE] = {0};
    bpf_skb_load_bytes(skb, tcp.hdr_len, (void *)buf, sizeof(buf));

    u32 len = skb->len - tcp.hdr_len;
    if (len > MIN_HTTP_SIZE) {
        len = MIN_HTTP_SIZE;
    }

    u8 message_type = 0;
    if (is_http(buf, len, &message_type)) {
        http_data_t info = {0};
        info.conn_info = conn;

        if (message_type == REQUEST_TYPE) {
            u32 full_len = skb->len - tcp.hdr_len;
            if (full_len > HTTP_BUFFER_SIZE) {
                full_len = HTTP_BUFFER_SIZE;
            }
            read_skb_bytes(skb, tcp.hdr_len, info.buf, full_len);
            bpf_debug_printk("socket filter len=%d %s", len, buf);
            set_protocol_info(&info, &conn, skb->len - tcp.hdr_len);
        }
    }

    return 0;
}


SEC("tracepoint/syscalls/sys_enter_close")
int sys_enter_close(struct syscall_enter_ctx *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	if (!isWhitelisted(id)) {
        return 0;
    }
	bpf_debug_printk("sys_enter_close, pid=%d", pid_from_pid_tgid(id));
	int fd = ctx->fd;
	u64 sock_addr = (u64)get_socket_from_fd(fd, pid_from_pid_tgid(id));
	if (sock_addr) {
		u64 conn_key = get_connkey(bpf_get_current_pid_tgid() >> 32, (u64)fd);
		struct socket_info_t *socket_info_ptr = bpf_map_lookup_elem(&socket_info_map, &conn_key);
		if (socket_info_ptr != NULL)
			delete_socket_info(conn_key, socket_info_ptr);
		bpf_map_delete_elem(&connection_type_map, &conn_key);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int sys_exit_accept(struct syscall_exit_ctx *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	if (!isWhitelisted(id)) {
        return 0;
    }
	bpf_debug_printk("sys_exit_accept, pid=%d", pid_from_pid_tgid(id));
	u64 fd = (u64)ctx->ret;
    u64 conn_key = get_connkey(id >> 32, fd);
	u32 role = CONNECTION_TYPE_SERVER;
	bpf_map_update_elem(&connection_type_map, &conn_key, &role, BPF_ANY);
	return 0;
}


SEC("tracepoint/syscalls/sys_exit_accept4")
int sys_exit_accept4(struct syscall_exit_ctx *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	if (!isWhitelisted(id)) {
        return 0;
    }
	bpf_debug_printk("sys_exit_accept4, pid=%d", pid_from_pid_tgid(id));
	u64 fd = (u64)ctx->ret;
    u64 conn_key = get_connkey(id >> 32, fd);
	u32 role = CONNECTION_TYPE_SERVER;
	bpf_map_update_elem(&connection_type_map, &conn_key, &role, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int sys_enter_connect(struct syscall_enter_ctx *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	if (!isWhitelisted(id)) {
        return 0;
    }
	bpf_debug_printk("sys_exit_accept4, pid=%d", pid_from_pid_tgid(id));
	int fd = ctx->fd;
    u64 conn_key = get_connkey(id >> 32, fd);
	u32 role = CONNECTION_TYPE_CLIENT;
	bpf_map_update_elem(&connection_type_map, &conn_key, &role, BPF_ANY);
	return 0;
}


SEC("tracepoint/syscalls/sys_exit_socket")
int sys_exit_socket(struct syscall_exit_ctx *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	if (!isWhitelisted(id)) {
        return 0;
    }
    bpf_debug_printk("sys_exit_socket, pid=%d", pid_from_pid_tgid(id));

	u64 fd = (u64)ctx->ret;
	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));

	if (!(comm[0] == 'n' && comm[1] == 'g' && comm[2] == 'i' &&
	      comm[3] == 'n' && comm[4] == 'x' && comm[5] == '\0'))
		return 0;

    struct socket_info_t socket_info = { 0 };
	u64 conn_key = get_connkey(id >> 32, fd);
	bpf_map_update_elem(&socket_info_map, &conn_key, &socket_info, BPF_ANY);

	return 0;
}

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
#ifndef PROTOCOL_TRACE_H
#define PROTOCOL_TRACE_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "types.h"
#include "common.h"
#include "protocol.h"
#include "pid.h"


#define MIN_HTTP_SIZE 12 
#define MIN_MYSQL_SIZE 5
#define RESPONSE_STATUS_POS 9 
#define DATA_BUF_MAX  32


BPF_HASH_MAP(active_wr_args_map, 1000, __u64, data_args_t)

BPF_HASH_MAP(active_rd_args_map, 1000, __u64, data_args_t)

BPF_HASH_MAP(socket_info_map, 1000, __u64, struct socket_info_t)

BPF_PER_EVENT_ARRAY_MAP(socket_data_map, 1000, int, __u32)

BPF_LRU_MAP(active_accept_args, 1000, __u64, sock_args_t)

BPF_LRU_MAP(active_connect_args, 1000, __u64, sock_args_t)

BPF_LRU_MAP(active_recv_args, 1000, __u64, recv_args_t)

BPF_HASH_MAP(connection_type_map, 1000, __u64, __u32)

BPF_LRU_MAP_PINNED(filtered_connections, 1000, pid_connection_info_t, http_connection_metadata_t)

BPF_LRU_MAP_PINNED(http_pid_map, 1000, pid_connection_info_t, http_data_t)

BPF_LRU_MAP_PINNED(http_conn_map, 1024, connection_info_t, http_data_t)

BPF_PERCPU_ARRAY_MAP(httpinfo_map, 1024, int, http_data_t)

BPF_LRU_MAP(active_send_args, 1000, __u64, send_args_t)



struct conn_info_t {
	__u8 l4_dst_addr[IP_V6_ADDR_LEN];
	__u8 l4_rcv_saddr[IP_V6_ADDR_LEN];
	__u8 l4_addr_len;
	__u8 l4_protocol;
	__u16 l4_dport;
	__u16 l4_sport;
	__u16 l4_num;
	__u16 skc_family;	
	__u16 sk_type;	
	__u8  skc_ipv6only;
	__u32 fd;
	void *sk;

	enum protocol_monitored_type protocol;
	enum message_type message_type;

	enum dataflow_type flow_type; 
	size_t prev_count;
	char prev_buf[4];
	struct socket_info_t *socket_info_ptr; 
};

typedef long __kernel_time_t;

typedef struct {
	__u32 payload_length:24;
	__u8 seqid;
	__u8 command_type;
} mysql_header;

struct timespec {
	__kernel_time_t tv_sec;
	long tv_nsec;
};


struct syscall_enter_ctx {
	__u64 pad_0;		
	int syscall_nr;	
	__u32 pad_1;		
	union {
		struct {
			__u64 fd;		
			char *buf;		
		};

		struct {
			clockid_t which_clock; 
			struct timespec * tp;  
		};
	};
	size_t count;		
};

struct syscall_exit_ctx {
	__u64 pad_0;		
	int syscall_nr;	
	__u32 pad_1;		
	__u64 ret;		
};


static __always_inline bool is_mysql_data(unsigned char *p, __u32 len) {
    static const __u8 kComQuery = 0x03;
	static const __u8 kComGreetingV9 = 0x09;
	static const __u8 kComGreetingV10 = 0x0a;
	static const __u8 kComStmtPrepare = 0x16;

    if (len < MIN_MYSQL_SIZE) {
        return false;
    }
	mysql_header header = *((mysql_header *)p);

	if(header.payload_length == 0) {
		return false;
	}

	switch(header.command_type) {
		case kComQuery:
		case kComStmtPrepare:
             bpf_debug_printk("MYSQL comm query data found %d, seqid %d, cmd %d", header.payload_length, header.seqid, header.command_type);
        case kComGreetingV9:
		case kComGreetingV10:
            bpf_debug_printk("MYSQL greeting data found %d, seqid %d, cmd %d", header.payload_length, header.seqid, header.command_type);
		default:
		    return false;

	}
}


static __always_inline bool is_http(unsigned char *p, __u32 len, __u8 *message_type) {
    if (len < MIN_HTTP_SIZE) {
        return false;
    }
    if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
       *message_type = RESPONSE_TYPE;
    } else if (
		((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D') && (p[4] == ' ') && (p[5] == '/')) ||                                    
        ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T') && (p[3] == ' ') && (p[4] == '/')) ||                                                      
		((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T') && (p[3] == ' ') && (p[4] == '/')) ||                                                      
        ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T') && (p[4] == ' ') && (p[5] == '/')) ||                                     
        ((p[0] == 'P') && (p[1] == 'A') && (p[2] == 'T') && (p[3] == 'C') && (p[4] == 'H') && (p[5] == ' ') && (p[6] == '/')) ||                   
        ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E') && (p[6] == ' ') && (p[7] == '/')) ||   
        ((p[0] == 'O') && (p[1] == 'P') && (p[2] == 'T') && (p[3] == 'I') && (p[4] == 'O') && (p[5] == 'N') && (p[6] == 'S') && (p[7] == ' ') && (p[8] == '/'))
    ) {
        *message_type = REQUEST_TYPE;
    }

    return true;
}

struct _iov_iter {
	__u8 iter_type;
	bool copy_mc;
	bool nofault;
	bool data_source;
	bool user_backed;
	union {
		size_t iov_offset;
		int last_offset;
	};
	union {
		struct iovec __ubuf_iovec;
		struct {
			union {
				const struct iovec *__iov;
				const struct kvec *kvec;
				const struct bio_vec *bvec;
				struct xarray *xarray;
				void *ubuf;
			};
			size_t count;
		};
	};
};

static __always_inline __u64 get_connkey(__u64 param_1, __u64 param_2)
{
	return ((param_1 << 32) | (__u32)param_2);
}


static __always_inline void *read_message_header(struct msghdr *mheader) {
    unsigned int m_flags;
    struct iov_iter msg_iter;

    bpf_probe_read_kernel(&m_flags, sizeof(unsigned int), &(mheader->msg_flags));
    bpf_probe_read_kernel(&msg_iter, sizeof(struct iov_iter), &(mheader->msg_iter));

    __u8 msg_iter_type = 0;

    if (bpf_core_field_exists(msg_iter.iter_type)) {
        bpf_probe_read(&msg_iter_type, sizeof(__u8), &(msg_iter.iter_type));
    }

    bpf_debug_printk("message header type %d, iter type %d", m_flags, msg_iter_type);

    struct iovec *iov = NULL;

    if (bpf_core_field_exists(msg_iter.iov)) {
        bpf_probe_read(&iov, sizeof(struct iovec *), &(msg_iter.iov));
    } else {
        struct _iov_iter _msg_iter;
        bpf_probe_read_kernel(&_msg_iter, sizeof(struct _iov_iter), &(mheader->msg_iter));
        
        if (msg_iter_type == 5) {
            struct iovec vec;
            bpf_probe_read(&vec, sizeof(struct iovec), &(_msg_iter.__ubuf_iovec));

            return vec.iov_base;
        } else {
            bpf_probe_read(&iov, sizeof(struct iovec *), &(_msg_iter.__iov));
        }     
    }
    
    if (!iov) {
        return NULL;
    }

    if (msg_iter_type == 6) {
        bpf_debug_printk("direct char buffer type=6 iov %d", iov);
        return iov;
    }

    struct iovec vec;
    bpf_probe_read(&vec, sizeof(struct iovec), iov);
    return vec.iov_base;    
}


static __always_inline http_data_t* get_http_info() {
    int zero = 0;
    http_data_t *value = bpf_map_lookup_elem(&httpinfo_map, &zero);
    if (value) {
        bpf_memset(value, 0, sizeof(http_data_t));
    }
    return value;
}

static __always_inline void send_http_data(http_data_t *info) {
    if (info->start_monotime_ns != 0 && info->status != 0 && info->pid.host_pid != 0) {
		socket_data *perf_data = bpf_ringbuf_reserve(&events, sizeof(socket_data), 0);

		__u64 pid_tgid = bpf_get_current_pid_tgid();
		__u32 pid = pid_from_pid_tgid(pid_tgid);
      
        if (perf_data) {
	        struct data_args* write_args = bpf_map_lookup_elem(&active_wr_args_map, &pid_tgid);
	        if (write_args != NULL) {
               __u64 conn_key = get_connkey((__u64)pid, (__u64)write_args->fd);
	           __u32 *role = bpf_map_lookup_elem(&connection_type_map, &conn_key);
			   perf_data->connection_type = role ? *role: 0;
	        } 

			if (perf_data->connection_type == 0) {
			    perf_data->connection_type = info->role;
			}

			perf_data->l4_protocol = IPPROTO_TCP;
			bpf_memcpy(perf_data->l4_dst_addr, info->conn_info.d_addr, sizeof(perf_data->l4_dst_addr));
            bpf_memcpy(perf_data->l4_rcv_saddr, info->conn_info.s_addr, sizeof(perf_data->l4_rcv_saddr));

			perf_data->l4_dport = info->conn_info.d_port;
			perf_data->l4_sport = info->conn_info.s_port;
			perf_data->data_type = HTTP1_PROTOCOL;
			perf_data->tid = pid_tgid;
			perf_data->pid = pid;
            perf_data->nsid = info->pid.ns;
			perf_data->start_timestamp = info->start_monotime_ns;
			perf_data->finish_timestamp = info->end_monotime_ns;

			perf_data->http_data.resp_len = info->resp_len;
			perf_data->http_data.status = info->status;
			perf_data->http_data.len = info->len;
			perf_data->http_data.ssl = info->ssl;

			bpf_probe_read(perf_data->data, HTTP_BUFFER_SIZE + 1, info->buf);
            
			bpf_debug_printk("Sending http performance data %lx", perf_data);

            bpf_ringbuf_submit(perf_data, 0);
        }

		 pid_connection_info_t pid_conn = {
            .conn = info->conn_info,
            .pid = pid
        };
        bpf_map_delete_elem(&http_pid_map, &pid_conn);
    }        
}

static __always_inline http_data_t *get_or_set_http_info(http_data_t *info, pid_connection_info_t *pid_conn, __u8 message_type) {
    if (message_type == REQUEST_TYPE) {
        http_data_t *prev_info = bpf_map_lookup_elem(&http_pid_map, pid_conn);
        if (prev_info) {
            send_http_data(prev_info);
        }

        bpf_map_update_elem(&http_pid_map, pid_conn, info, BPF_ANY);
    }

    return bpf_map_lookup_elem(&http_pid_map, pid_conn);
}

static __always_inline void set_protocol_info(http_data_t *info, connection_info_t *conn, int len) {
    info->start_monotime_ns = bpf_ktime_get_ns();
    info->status = 0;
    info->len = len;
    bpf_map_update_elem(&http_conn_map, conn, info, BPF_ANY);
}


static __always_inline bool transaction_progress_state(http_data_t *info) {
    return info->status == 0 && info->start_monotime_ns != 0;
}

static __always_inline void process_http_request(http_data_t *info, int len) {
    info->start_monotime_ns = bpf_ktime_get_ns();
    info->status = 0;
    info->len = len;
}

static __always_inline void process_http_response(http_data_t *info, unsigned char *buf, http_connection_metadata_t *meta, int len) {
    info->pid = meta->pid;
    info->type = meta->type;
	info->role = meta->role;
    info->resp_len = len;
    info->end_monotime_ns = bpf_ktime_get_ns();
    info->status = 0;
    info->status += (buf[RESPONSE_STATUS_POS]     - '0') * 100;
    info->status += (buf[RESPONSE_STATUS_POS + 1] - '0') * 10;
    info->status += (buf[RESPONSE_STATUS_POS + 2] - '0');
}

static __always_inline void handle_http_response(unsigned char *small_buf, pid_connection_info_t *pid_conn, http_data_t *info, int orig_len) {
    http_connection_metadata_t *meta = bpf_map_lookup_elem(&filtered_connections, pid_conn);
    http_connection_metadata_t dummy_meta = {
        .type = EVENT_HTTP_DATA
    };

    if (!meta) {
        get_pid_namespace(&dummy_meta.pid);
        meta = &dummy_meta;
    }

    process_http_response(info, small_buf, meta, orig_len);
    send_http_data(info);
}

static __always_inline void handle_protocol_data(pid_connection_info_t *pid_conn, void *u_buf, int bytes_len, __u8 ssl) {
    unsigned char small_buf[MIN_HTTP_SIZE] = {0};
    bpf_probe_read(small_buf, MIN_HTTP_SIZE, u_buf);

    bpf_debug_printk("buf=%s, pid=%d", small_buf, pid_conn->pid);

    __u8 message_type = UNKNOWN_MESSAGE_TYPE;
    if (is_http(small_buf, MIN_HTTP_SIZE, &message_type)) {
        http_data_t *in = get_http_info();
        if (!in) {
            bpf_debug_printk("Error allocating http data from the map");
            return;
        }
        in->conn_info = pid_conn->conn;
        in->ssl = ssl;

        http_data_t *info = get_or_set_http_info(in, pid_conn, message_type);
        if (!info) {
            info = bpf_map_lookup_elem(&http_conn_map, &pid_conn->conn);
            if (!info) {
                return;
            }
        } 

        if (message_type == REQUEST_TYPE && (info->status == 0)) {    
            bpf_probe_read(info->buf, HTTP_BUFFER_SIZE, u_buf);
            process_http_request(info, bytes_len);
        } else if (message_type == RESPONSE_TYPE) {
            handle_http_response(small_buf, pid_conn, info, bytes_len);
        } else if (transaction_progress_state(info)) {
            info->len += bytes_len;
        }     

        bpf_map_delete_elem(&http_conn_map, &pid_conn->conn);
    }
}

#define BUF_COPY_BLOCK_SIZE 16

static __always_inline void read_skb_bytes(const void *skb, __u32 offset, unsigned char *buf, const __u32 len) {
    __u32 max = offset + len;
    int b = 0;
    for (; b < (HTTP_BUFFER_SIZE/BUF_COPY_BLOCK_SIZE); b++) {
        if ((offset + (BUF_COPY_BLOCK_SIZE - 1)) >= max) {
            break;
        }
        bpf_skb_load_bytes(skb, offset, (void *)(&buf[b * BUF_COPY_BLOCK_SIZE]), BUF_COPY_BLOCK_SIZE);
        offset += BUF_COPY_BLOCK_SIZE;
    }

    if ((b * BUF_COPY_BLOCK_SIZE) >= len) {
        return;
    }

    s64 remainder = (s64)max - (s64)offset;

    if (remainder <= 0) {
        return;
    }

    int remaining_to_copy = (remainder < (BUF_COPY_BLOCK_SIZE - 1)) ? remainder : (BUF_COPY_BLOCK_SIZE - 1);
    int space_in_buffer = (len < (b * BUF_COPY_BLOCK_SIZE)) ? 0 : len - (b * BUF_COPY_BLOCK_SIZE);

    if (remaining_to_copy <= space_in_buffer) {
        bpf_skb_load_bytes(skb, offset, (void *)(&buf[b * BUF_COPY_BLOCK_SIZE]), remaining_to_copy);
    }
}

static __always_inline bool is_same_command(char *a, char *b)
{
	static const int KERNEL_COMM_MAX = 16;
	for (int idx = 0; idx < KERNEL_COMM_MAX; ++idx) {
		if (a[idx] == '\0') {
            if (a[idx] == b[idx])
			    return true;
			else
			    return false;
		}
	}
	return true;
}

static __always_inline bool is_mysqld(char *comm)
{
	static const int KERNEL_COMM_MAX = 16;
	char current_comm[KERNEL_COMM_MAX];

	if (bpf_get_current_comm(&current_comm, sizeof(current_comm)))
		return false;

	return is_same_command(comm, current_comm);
}

static __always_inline bool is_socket_valid(struct socket_info_t *sk_info)
{
	return (sk_info != NULL);
}

static __always_inline int is_http_response(const char *data)
{
	return (data[0] == 'H' && data[1] == 'T' && data[2] == 'T'
		&& data[3] == 'P' && data[4] == '/' && data[5] == '1'
		&& data[6] == '.' && data[8] == ' ');
}

static __always_inline int is_http_request(const char *data, int data_len)
{
	switch (data[0]) {
	case 'D':
		if ((data[1] != 'E') || (data[2] != 'L') || (data[3] != 'E')
		    || (data[4] != 'T') || (data[5] != 'E')
		    || (data[6] != ' ')) {
			return 0;
		}
		break;

	case 'G':
		if ((data[1] != 'E') || (data[2] != 'T') || (data[3] != ' ')) {
			return 0;
		}
		break;

	case 'H':
		if ((data[1] != 'E') || (data[2] != 'A') || (data[3] != 'D')
		    || (data[4] != ' ')) {
			return 0;
		}
		break;

	case 'O':
		if (data_len < 8 || (data[1] != 'P') || (data[2] != 'T')
		    || (data[3] != 'I') || (data[4] != 'O') || (data[5] != 'N')
		    || (data[6] != 'S') || (data[7] != ' ')) {
			return 0;
		}
		break;

	case 'P':
		switch (data[1]) {
		case 'A':
			if ((data[2] != 'T') || (data[3] != 'C')
			    || (data[4] != 'H') || (data[5] != ' ')) {
				return 0;
			}
			break;
		case 'O':
			if ((data[2] != 'S') || (data[3] != 'T')
			    || (data[4] != ' ')) {
				return 0;
			}
			break;
		case 'U':
			if ((data[2] != 'T') || (data[3] != ' ')) {
				return 0;
			}
			break;
		default:
			return 0;
		}
		break;

	default:
		return 0;
	}

	return 1;
}

static __always_inline enum message_type parse_http_message(const char *buf,
						     size_t count, struct conn_info_t *conn_info)
{
	if (is_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != HTTP1_PROTOCOL)
			return UNKNOWN_MESSAGE_TYPE;
	}
	
	if (count < 14) {
		return UNKNOWN_MESSAGE_TYPE;
	}

	if (is_http_response(buf)) {
		return RESPONSE_TYPE;
	}

	if (is_http_request(buf, count)) {
		return REQUEST_TYPE;
	}

	return UNKNOWN_MESSAGE_TYPE;
}


static __always_inline enum message_type parse_mysql_message(const char *buf, size_t count, struct conn_info_t *conn_info)
{
	//3, 9, 10, 11, 22, 23, 24
	static const __u8 kComQuery = 0x03;
	static const __u8 kComGreetingV9 = 0x09;
	static const __u8 kComGreetingV10 = 0x0a;
	static const __u8 kComConnect = 0x0b;
	static const __u8 kComStmtPrepare = 0x16;
	static const __u8 kComStmtExecute = 0x17;
	static const __u8 kComStmtClose = 0x19;

	if (is_socket_valid(conn_info->socket_info_ptr)) {
		bpf_debug_printk("Mysql parser s %d - %d", conn_info->socket_info_ptr->l7_proto, pid_from_pid_tgid(bpf_get_current_pid_tgid()));
		if (conn_info->socket_info_ptr->l7_proto != MYSQL_PROTOCOL)
			return UNKNOWN_MESSAGE_TYPE;
	} else {
		bpf_debug_printk("Mysql parser v - %d", pid_from_pid_tgid(bpf_get_current_pid_tgid()));
	}

	if (!conn_info->sk)
		return UNKNOWN_MESSAGE_TYPE;

   bpf_debug_printk("Mysql parser  %d", pid_from_pid_tgid(bpf_get_current_pid_tgid()));

	__u32 len;
	__u8 seq, com;

	len = *((__u32 *) buf) & 0x00ffffff;
	seq = buf[3];
	com = buf[4];

	if (conn_info->prev_count == 4) {
		len = *(__u32 *) conn_info->prev_buf & 0x00ffffff;
		if (len == count) {
			seq = conn_info->prev_buf[3];
			count += 4;
			com = buf[0];
		}
	}
	if (count < 5 || len == 0)
		return UNKNOWN_MESSAGE_TYPE;

	bpf_debug_printk("Mysql parser cnt %d - %d", conn_info->prev_count, pid_from_pid_tgid(bpf_get_current_pid_tgid()));


	if (is_socket_valid(conn_info->socket_info_ptr)){
		if (seq == 0 || seq == 1)
			goto exitmethod;
		return UNKNOWN_MESSAGE_TYPE;
	}

    if (is_mysqld("mysqld")) {
		return conn_info->flow_type == INFLOW ? REQUEST_TYPE : RESPONSE_TYPE;
	}

	bpf_debug_printk("Mysql parser seq %d - %d - %d", seq, com, pid_from_pid_tgid(bpf_get_current_pid_tgid()));


	if (seq != 0) {
		com = buf[0];
		bpf_debug_printk("Mysql parser com %d - %d", com, pid_from_pid_tgid(bpf_get_current_pid_tgid()));
		if (com ==  kComQuery || com == kComStmtPrepare ||
	    com == kComStmtExecute) {
		    return conn_info->flow_type == INFLOW ? REQUEST_TYPE : RESPONSE_TYPE;
	    } 
		return UNKNOWN_MESSAGE_TYPE;
	}

	if (len > 10000) {
		return UNKNOWN_MESSAGE_TYPE;
	}
		
		
	if (com != kComGreetingV9 && com != kComGreetingV10 && 
	    com != kComConnect && com != kComQuery && com != kComStmtPrepare &&
	    com != kComStmtExecute && com != kComStmtClose) {
		return UNKNOWN_MESSAGE_TYPE;
	}

exitmethod:
	if (is_mysqld("mysqld")) 
		return conn_info->flow_type == INFLOW ? REQUEST_TYPE : RESPONSE_TYPE;
	else 
		return conn_info->flow_type == INFLOW ? RESPONSE_TYPE : REQUEST_TYPE;

	return UNKNOWN_MESSAGE_TYPE;
}

static __always_inline bool filter_by_process_command(void)
{
	char comm[16];

	if (bpf_get_current_comm(&comm, sizeof(comm)))
		return false;

	if (is_same_command("sshd", comm))
		return true;

	if (is_same_command("ssh", comm))
		return true;

	if (is_same_command("scp", comm))
		return true;

	return false;
}

static __always_inline struct protocol_data_t parse_protocol_data(const char *buf,
							 size_t count, struct conn_info_t *conn_info, __u8 sk_state)
{
	struct protocol_data_t protocol_info;
	protocol_info.protocol = UNKNOWN_PROTOCOL;
	protocol_info.type = UNKNOWN_MESSAGE_TYPE;

	if (conn_info->sk_type == SOCK_STREAM &&
	    sk_state != SOCK_CHECK_TYPE_TCP_ES)
		return protocol_info;

	if (conn_info->l4_dport == 0 || conn_info->l4_num == 0) {
		return protocol_info;
	}

	if (count < 4 || conn_info->sk == NULL)
		return protocol_info;
		
	if (conn_info != NULL && is_socket_valid(conn_info->socket_info_ptr)) {
		if (filter_by_process_command())
			return protocol_info;
	}
	
	bpf_debug_printk("Protocol intial checks passed -> count=%d, sk_state=%d",count, sk_state);


	char protocol_buffer[DATA_BUF_MAX];
	bpf_probe_read(&protocol_buffer, sizeof(protocol_buffer), buf);


	if ((protocol_info.type = parse_http_message(protocol_buffer, count, conn_info)) != UNKNOWN_MESSAGE_TYPE) {
		protocol_info.protocol = HTTP1_PROTOCOL;
	} 

	if (protocol_info.protocol != UNKNOWN_MESSAGE_TYPE) {
        bpf_debug_printk("Protocol found ->  protocol %d", protocol_info.protocol);
		return protocol_info;
	}

	if (count == 4) {
		if (conn_info != NULL && is_socket_valid(conn_info->socket_info_ptr)) {
			*(__u32 *) conn_info->socket_info_ptr->prev_data = *(__u32 *) protocol_buffer;
			conn_info->socket_info_ptr->prev_data_len = 4;
			conn_info->socket_info_ptr->flow_type =
			    conn_info->flow_type;
		} else {
			*(__u32 *) conn_info->prev_buf = *(__u32 *) protocol_buffer;
			conn_info->prev_count = 4;
		}

		protocol_info.type = SEEN;
        bpf_debug_printk("Protocol seen ->  protocol %d", protocol_info.protocol);
		return protocol_info;
	}
	
	if (conn_info->socket_info_ptr != NULL && 
	    conn_info->socket_info_ptr->prev_data_len != 0) {
		if (conn_info->flow_type !=
		    conn_info->socket_info_ptr->flow_type)
			return protocol_info;

		*(__u32 *) conn_info->prev_buf = *(__u32 *) conn_info->socket_info_ptr->prev_data;
		conn_info->prev_count = 4;
		conn_info->socket_info_ptr->prev_data_len = 0;
	}

	if ((protocol_info.type = parse_mysql_message(protocol_buffer, count, conn_info)) != UNKNOWN_MESSAGE_TYPE) {
		protocol_info.protocol = MYSQL_PROTOCOL;
	}
    bpf_debug_printk("Protocol parsed ->  protocol %d, pid %d", protocol_info.protocol, pid_from_pid_tgid(bpf_get_current_pid_tgid()));
	return protocol_info;
}

static __always_inline void complete_http_transaction(pid_connection_info_t *pid_conn) {
    http_data_t *info = bpf_map_lookup_elem(&http_pid_map, pid_conn);
    if (info) {        
        send_http_data(info);
    }
}

static __always_inline void process_protocol_data(struct conn_info_t* conn_info,
				    enum dataflow_type flow_type, const char* buf,
				    size_t count, __u8 sk_type) {
	if (conn_info == NULL) {
		return;
	}

	struct protocol_data_t protocol_data = parse_protocol_data(buf, count, conn_info, sk_type);
	if (protocol_data.protocol == UNKNOWN_PROTOCOL &&
	    protocol_data.type == UNKNOWN_MESSAGE_TYPE) {
		conn_info->protocol = UNKNOWN_PROTOCOL;
		return;
	}

	conn_info->protocol = protocol_data.protocol;
	conn_info->message_type = protocol_data.type;
}


static __always_inline void delete_socket_info(__u64 conn_key,
					struct socket_info_t *socket_info_ptr)
{
	if (socket_info_ptr == NULL)
		return;

    bpf_map_delete_elem(&socket_info_map, &conn_key);
}


static __always_inline int process_layer4_data(void *sk,
				    struct conn_info_t *conn_info)
{
	struct sock *__sk = sk;
	struct sock_common *sk_common = sk;
	conn_info->skc_ipv6only = BPF_CORE_READ_BITFIELD_PROBED(sk_common, skc_ipv6only);
	bpf_core_read(&conn_info->skc_family, sizeof(conn_info->skc_family),
		      &__sk->__sk_common.skc_family);

	switch (conn_info->skc_family) {
	case PF_INET:
		break;
	case PF_INET6:
		if (conn_info->skc_ipv6only == 0)
			conn_info->skc_family = PF_INET;
		break;
	default:
		return SOCK_CHECK_TYPE_ERROR;
	}

    conn_info->sk_type = BPF_CORE_READ_BITFIELD_PROBED(__sk, sk_type);

	if (conn_info->sk_type == SOCK_DGRAM) {
		conn_info->l4_protocol = IPPROTO_UDP;
		return SOCK_CHECK_TYPE_UDP;
	}

	if (conn_info->sk_type != SOCK_STREAM) {
		return SOCK_CHECK_TYPE_ERROR;
	}

	unsigned char skc_state;
	bpf_core_read(&skc_state, sizeof(unsigned short),
		      &__sk->__sk_common.skc_state);
    

	if ((1 << skc_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) {
		return SOCK_CHECK_TYPE_ERROR;
	}
	
	conn_info->l4_protocol = IPPROTO_TCP;
	return SOCK_CHECK_TYPE_TCP_ES;
}

static __always_inline void init_connection_data(__u32 tgid, __u32 fd,
				    struct conn_info_t *conn_info,
				    void *sk)
{
	__be16 inet_dport;
	__u16 inet_sport;
	struct sock *__sk = sk;
	bpf_core_read(&inet_dport, sizeof(inet_dport),
		      &__sk->__sk_common.skc_dport);
	bpf_core_read(&inet_sport, sizeof(inet_sport),
		      &__sk->__sk_common.skc_num);

	conn_info->l4_dport = bpf_ntohs(inet_dport);
	conn_info->l4_sport = bpf_ntohs(inet_sport);
	conn_info->l4_num = inet_sport;
	conn_info->prev_count = 0;
	conn_info->flow_type = 0;
	*((__u32 *) conn_info->prev_buf) = 0;
	conn_info->fd = fd;

	conn_info->sk = sk;
	__u64 conn_key = get_connkey((__u64)tgid, (__u64)conn_info->fd);
	conn_info->socket_info_ptr = bpf_map_lookup_elem(&socket_info_map, &conn_key);

}

static __always_inline bool get_socket_address_data(struct socket_data_t *perf_data,
				     void *sk,
				     __u16 skc_family)
{
	if (perf_data == NULL || sk == NULL)
		return false;

	struct sock *__sk = sk;

	switch (skc_family) {
	case PF_INET:
		bpf_core_read(perf_data->l4_rcv_saddr, 4, &__sk->__sk_common.skc_rcv_saddr);
		bpf_core_read(perf_data->l4_dst_addr, 4, &__sk->__sk_common.skc_daddr);
		perf_data->l4_addr_len = 4;
		break;
	case PF_INET6:
		bpf_core_read(perf_data->l4_rcv_saddr, 16, &__sk->__sk_common.skc_v6_rcv_saddr);
		bpf_core_read(perf_data->l4_dst_addr, 16, &__sk->__sk_common.skc_v6_daddr);
		perf_data->l4_addr_len = 16;
		break;
	default:
		return false;
	}

	return true;
}

static __always_inline void send_data(struct pt_regs *ctx, struct conn_info_t* conn_info, 
const struct data_args* args, __u32 syscall_len, __u64 timestamp)
{
	if (conn_info == NULL) {
		return;
	}

	if (conn_info->sk == NULL ||  conn_info->message_type == UNKNOWN_MESSAGE_TYPE) {
		return;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32) (pid_tgid >> 32);
	
	__u64 conn_key = get_connkey((__u64)tgid, (__u64)conn_info->fd);


	if (conn_info->message_type == CLEAR) {
		delete_socket_info(conn_key, conn_info->socket_info_ptr);
		return;
	}

	__u32 tcp_seq = 0;

	if (conn_info->flow_type == INFLOW && conn_info->l4_protocol == IPPROTO_TCP) {
		struct tcp_sock *tp_sock = (struct tcp_sock *)conn_info->sk;
		bpf_core_read(&tcp_seq, sizeof(tcp_seq),
			      &tp_sock->copied_seq);

	} else if (conn_info->flow_type == OUTFLOW && conn_info->l4_protocol == IPPROTO_TCP) {
		struct tcp_sock *tp_sock = (struct tcp_sock *)conn_info->sk;
		bpf_core_read(&tcp_seq, sizeof(tcp_seq),
			      &tp_sock->write_seq);

	}

	struct socket_info_t socket_info = { 0 };
	struct socket_info_t *socket_info_ptr = conn_info->socket_info_ptr;

	if (!is_socket_valid(socket_info_ptr)) {
	    socket_info.l7_proto = conn_info->protocol;
	    socket_info.flow_type = conn_info->flow_type;
	    socket_info.msg_type = conn_info->message_type;

	    if (conn_info->message_type == SEEN) {
		    *(__u32 *)socket_info.prev_data = *(__u32 *)conn_info->prev_buf;
		    socket_info.prev_data_len = 4;
		    socket_info.uid = 0;
	    }

	    //bpf_debug_printk("send_data, add socket for pid =%d", pid_from_pid_tgid(pid_tgid));
	    bpf_map_update_elem(&socket_info_map, &conn_key, &socket_info, BPF_ANY);
	}

	if (conn_info->message_type == SEEN)
		return;

    socket_data *perf_data = bpf_ringbuf_reserve(&events, sizeof(socket_data), 0);
	if (!perf_data) {
        return;
    } 
	get_socket_address_data(perf_data, conn_info->sk, conn_info->skc_family);
	__u32 *role = bpf_map_lookup_elem(&connection_type_map, &conn_key);

	perf_data->l4_protocol = conn_info->l4_protocol;
	perf_data->l4_dport = conn_info->l4_dport;
	perf_data->l4_sport = conn_info->l4_sport;
	perf_data->l4_num = conn_info->l4_num;
	perf_data->data_type = conn_info->protocol;
	perf_data->socket_id = socket_info.uid;
	perf_data->data_seq = socket_info.seq;
	perf_data->tid = pid_tgid;
	perf_data->pid = tgid;
	perf_data->nsid = get_namespace_pid();
	perf_data->timestamp = (conn_info->flow_type == OUTFLOW) ? timestamp: bpf_ktime_get_ns();
	perf_data->flow_type = conn_info->flow_type;
	perf_data->syscall_len = syscall_len;
	perf_data->msg_type = conn_info->message_type;
	perf_data->connection_type = role ? *role: 0;
			
	bpf_get_current_comm(perf_data->comm, sizeof(perf_data->comm));

	__u32 len = syscall_len & (sizeof(perf_data->data) - 1);

	if (syscall_len <= sizeof(perf_data->data)) {
		bpf_probe_read(perf_data->data, len + 1, args->buf);
	} 
	if (syscall_len >= sizeof(perf_data->data)) {
		if (unlikely(bpf_probe_read(perf_data->data, sizeof(perf_data->data), args->buf) != 0)) {
			bpf_ringbuf_discard(perf_data, 0);
			return;
		}
		len = sizeof(perf_data->data); 
	} 
	
	perf_data->data_len = len;
	
	bpf_debug_printk("send_data, send ringbuf for pid =%d", tgid);
	bpf_ringbuf_submit(perf_data, 0);
}

static __always_inline void process_socket_data(struct pt_regs* ctx, __u64 id,
				  const enum dataflow_type flow_type,
				  const struct data_args* args, ssize_t bytes_count) {
	__u32 tgid = id >> 32;
	bpf_debug_printk("process_data  pid= %d, flowtype %d\n", tgid, flow_type);
	if (args->buf == NULL)
		return;

	if (unlikely(args->fd < 0 || (int)bytes_count <= 0))
		return;


	void *sk = get_socket_from_fd(args->fd, pid_from_pid_tgid(id));

	if(sk != NULL) {
		bpf_debug_printk("process_data sk != NULL %d\n", pid_from_pid_tgid(id));
	} else {
		bpf_debug_printk("process_data sk == NULL %d\n", pid_from_pid_tgid(id));
	}
	struct conn_info_t *conn_info, __conn_info = {};
	conn_info = &__conn_info;
	conn_info->skc_family = 0;
	conn_info->l4_addr_len = 0;
	conn_info->l4_protocol = 0;
	conn_info->l4_dport = 0;
	conn_info->l4_sport = 0;
	conn_info->l4_num = 0;
	conn_info->sk_type = 0;
	conn_info->skc_ipv6only = 0;

	__u8 sock_state;
	
	if (!(sk != NULL &&
	      ((sock_state = process_layer4_data(sk, conn_info))
	       != SOCK_CHECK_TYPE_ERROR))) {
		return;
	}

	init_connection_data(tgid, args->fd, &__conn_info, sk);
	conn_info->flow_type = flow_type;

	process_protocol_data(conn_info, flow_type, args->buf, bytes_count, sock_state);

	if (conn_info->protocol == MYSQL_PROTOCOL) {
	    bpf_debug_printk("Protocol -> protocol=%d, message_type=%d", conn_info->protocol, conn_info->message_type);
		send_data(ctx, conn_info, args, (__u32)bytes_count, args->start_timestamp);
	}
}
#endif

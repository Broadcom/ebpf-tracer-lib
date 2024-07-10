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
#ifndef __PROTO_H__
#define __PROTO_H__

#include "http_helper.h"
#include "common.h"

#define SOCK_CHECK_TYPE_ERROR           0
#define SOCK_CHECK_TYPE_UDP             1
#define SOCK_CHECK_TYPE_TCP_ES          2

#define AF_INET         2	
#define PF_INET         AF_INET
#define AF_INET6        10	
#define PF_INET6        AF_INET6

#define SOCKET_DATA_SIZE 1024

#define IP_V6_ADDR_LEN 16


#define EPHEMERAL_PORT_MIN 32768
#define	EINPROGRESS	115	

#define ETH_HLEN	14          
#define ETH_P_IP	0x0800      
#define ETH_P_IPV6	0x86DD		


#define IPPROTO_TCP 6          

#define TCPHDR_FIN 0x01
#define TCPHDR_SYN 0x02
#define TCPHDR_RST 0x04
#define TCPHDR_PSH 0x08
#define TCPHDR_ACK 0x10
#define TCPHDR_URG 0x20
#define TCPHDR_ECE 0x40
#define TCPHDR_CWR 0x80

#ifndef unlikely
#define unlikely(x)             __builtin_expect(!!(x), 0)
#endif

enum connection_type {
	CONNECTION_TYPE_UNKNOWN,
	CONNECTION_TYPE_SERVER,
	CONNECTION_TYPE_CLIENT
};

enum message_type {
	UNKNOWN_MESSAGE_TYPE,
	REQUEST_TYPE,
	RESPONSE_TYPE,

	SEEN,
	CLEAR
};

enum dataflow_type {
	OUTFLOW,
	INFLOW
};

enum protocol_monitored_type {
	UNKNOWN_PROTOCOL,
	HTTP1_PROTOCOL,
	MYSQL_PROTOCOL,
	HTTP2_PROTOCOL
};

typedef struct recv_args {
    __u64 sock_ptr; 
    __u64 iovec_ptr;
} recv_args_t;


typedef struct data_args {
	__u32 fd;
	const char *buf;
	const struct iovec *iov;
	size_t iovlen;
	union {
		unsigned int *msg_len;
		struct timespec *timestamp_ptr;
	};
	__u64 start_timestamp;
	__u64 finish_timestamp;
} data_args_t;

struct protocol_data_t {
	enum protocol_monitored_type protocol;
	enum message_type type;
};

typedef struct http_perf_data {
    __u32 len;
    __u32 resp_len;
    __u16 status;    
    __u8  ssl;
} http_perf_data_t;


typedef struct socket_data_t {
	__u32 pid;  
	__u32 tid;
	__u32 nsid;
	__u8  comm[16];
    http_perf_data_t http_data;
	__u64 socket_id;  
	__u8 l4_dst_addr[IP_V6_ADDR_LEN];
	__u8 l4_rcv_saddr[IP_V6_ADDR_LEN];
	__u8 l4_addr_len;
	__u8 l4_protocol;
	__u16 l4_dport;
	__u16 l4_sport;
	__u16 l4_num;

	__u64 timestamp;     
	__u64 start_timestamp;    
	__u64 finish_timestamp;    
	__u8  flow_type;  
	__u8  connection_type;
	__u8  msg_type;

	__u64 syscall_len;   
	__u64 data_seq;      
	__u16 data_type;     
	__u16 data_len;      
	unsigned char data[SOCKET_DATA_SIZE] __attribute__ ((aligned (8)));
} __attribute__((packed)) socket_data;


struct socket_info_t {
	__u64 l7_proto: 8;
	__u64 seq: 56; 

	__u8 prev_data[4];
	__u8 flow_type: 1;
	__u8 msg_type: 2;	
	__u8 role: 5;           

	__u32 prev_data_len;
	__u64 trace_id;
	__u64 uid; 
};

static __inline void *get_socket_from_fd(int fd_num, __u32 pid)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	void *file = NULL;
	struct file **fd = BPF_CORE_READ(task, files, fdt, fd);
	bpf_probe_read(&file, sizeof(file), fd + fd_num);

	if (file == NULL) {
		return NULL;
	}
	void *private_data = NULL;
	struct file *__file = file;
	private_data = BPF_CORE_READ(__file, private_data);

	if (private_data == NULL) {
		bpf_debug_printk("private_data == NULL %d\n", pid);
		return NULL;
	}

	struct socket *socket = private_data;
	short socket_type;
	void *check_file;
	void *sk;
	socket_type = BPF_CORE_READ(socket, type);
	check_file = BPF_CORE_READ(socket, file);
	sk = BPF_CORE_READ(socket, sk);


	if ((socket_type == SOCK_STREAM || socket_type == SOCK_DGRAM) &&
	    check_file == file  ) {
		return sk;
	}
	return NULL;
}
#endif
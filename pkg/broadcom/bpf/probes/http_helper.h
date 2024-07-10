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
#ifndef HTTP_TYPES_H
#define HTTP_TYPES_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "protocol.h"
#include "pid.h"

#define HTTP_BUFFER_SIZE 160 
#define AF_INET		2	
#define AF_INET6	10

#define IP_V6_ADDR_LEN 16


#define EPHEMERAL_PORT_MIN 32768

#define	EINPROGRESS	115	

#define ETH_HLEN	14          
#define ETH_P_IP	0x0800      
#define ETH_P_IPV6	0x86DD		


#define IPPROTO_TCP 6     

typedef struct http_connection_info {
    __u8  s_addr[IP_V6_ADDR_LEN];
    __u8  d_addr[IP_V6_ADDR_LEN];
    __u16 s_port;
    __u16 d_port;
} connection_info_t;

typedef struct http_pid_connection_info {
    connection_info_t conn;
    __u32 pid;
} pid_connection_info_t;


typedef struct send_args {
    pid_connection_info_t p_conn;
    __u64 size;
} send_args_t;

typedef struct http_data {
    __u8 flags; 
    connection_info_t conn_info;
    __u64 start_monotime_ns;
    __u64 end_monotime_ns;
    unsigned char buf[HTTP_BUFFER_SIZE] __attribute__ ((aligned (8))); 
    __u32 len;
    __u32 resp_len;
    __u16 status;    
    __u8  type;
    __u8  ssl;
    __u32 role;
    pid_info pid;
} http_data_t;

typedef struct protocol_info {
    __u32 hdr_len;
    __u32 seq;
    __u8  flags;
} protocol_info_t;

typedef struct http_connection_metadata {
    pid_info pid;
    __u8  type;
    __u32 role;
} http_connection_metadata_t;

const http_data_t *unused __attribute__((unused));

const __u8 ip4ip6_prefix[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

#endif
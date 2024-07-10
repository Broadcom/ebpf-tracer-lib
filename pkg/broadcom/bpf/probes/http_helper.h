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
    u8  s_addr[IP_V6_ADDR_LEN];
    u8  d_addr[IP_V6_ADDR_LEN];
    u16 s_port;
    u16 d_port;
} connection_info_t;

typedef struct http_pid_connection_info {
    connection_info_t conn;
    u32 pid;
} pid_connection_info_t;


typedef struct send_args {
    pid_connection_info_t p_conn;
    u64 size;
} send_args_t;

typedef struct http_data {
    u8 flags; 
    connection_info_t conn_info;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    unsigned char buf[HTTP_BUFFER_SIZE] __attribute__ ((aligned (8))); 
    u32 len;
    u32 resp_len;
    u16 status;    
    u8  type;
    u8  ssl;
    u32 role;
    pid_info pid;
} http_data_t;

typedef struct protocol_info {
    u32 hdr_len;
    u32 seq;
    u8  flags;
} protocol_info_t;

typedef struct http_connection_metadata {
    pid_info pid;
    u8  type;
    u32 role;
} http_connection_metadata_t;

const http_data_t *unused __attribute__((unused));

const u8 ip4ip6_prefix[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

#endif
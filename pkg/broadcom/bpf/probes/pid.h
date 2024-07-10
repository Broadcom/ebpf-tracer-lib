#ifndef PID_H
#define PID_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "types.h"
#include "common.h"

typedef struct pid_ns_key {
    u32 nsid;
    u32 pid;  
} __attribute__((packed)) pid_ns_key_t;


typedef struct pid_info_t {
    u32 host_pid;
    u32 user_pid;
    u32 ns; 
} __attribute__((packed)) pid_info;


BPF_LRU_MAP_PINNED(whitelist_map, 3000, pid_ns_key_t, u8)

volatile const s32 enable_whitelist = 0;


static __always_inline u32 pid_from_pid_tgid(u64 id) {
    return (u32)(id >> 32);
}

static __always_inline void get_pid_namespace(pid_info *pid) {
    struct upid upid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    pid->host_pid = (u32)BPF_CORE_READ(task, tgid);

    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    struct pid *ns_pid = (struct pid *)BPF_CORE_READ(task, group_leader, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);
    pid->user_pid = (u32)upid.nr;
    struct ns_common ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns);
    pid->ns = ns.inum;
}

static __always_inline u32 get_namespace_pid() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct ns_common ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns);
    return (u32)ns.inum;
}

/*static __always_inline void get_pid_namespace(pid_info *pid) {
    struct nsproxy *nsproxy;
    struct pid_namespace *pid_ns;
    u32 ns_inumber;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    nsproxy = BPF_CORE_READ(task, nsproxy);
    pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);

    ns_inumber = BPF_CORE_READ(pid_ns, ns.inum);
    pid->ns = ns_inumber;
    return;
} */

static __always_inline u32 isWhitelisted(u64 id) {
    u32 host_pid = id >> 32;


    if (!enable_whitelist) {
        return host_pid;
    }

     pid_ns_key_t p_key = {
        .pid = host_pid
    };

    u32 *found = bpf_map_lookup_elem(&whitelist_map, &p_key);
    if (found) {
        bpf_debug_printk("WhiteListed Pid=%d,Tid=%d", host_pid, id);
        return 1;
    }
    return 0;
}

#endif

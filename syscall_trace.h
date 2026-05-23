#pragma once
/*
 * syscall_trace.h – Shared between BPF kernel program and userspace loader.
 *
 * Do NOT include <linux/types.h> or any kernel headers here.
 * - BPF side:       vmlinux.h (included before this) provides all types.
 * - Userspace side: the generated skeleton header pulls in what's needed.
 */

#define COMM_LEN     16
#define MAX_PATH_LEN 256

/*
 * event – one record pushed to the ring buffer per syscall entry.
 *
 *   offset   0: pid    (__u32)
 *   offset   4: tid    (__u32)
 *   offset   8: uid    (__u32)
 *   offset  12: _pad   (__u32)
 *   offset  16: id     (__u64)   syscall number
 *   offset  24: ts     (__u64)   bpf_ktime_get_ns()
 *   offset  32: comm   char[16]
 *   offset  48: path   char[256]
 *   offset 304: path2  char[256]
 *   total: 560 bytes
 */
struct event {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 _pad;
    __u64 id;
    __u64 ts;
    char  comm[COMM_LEN];
    char  path[MAX_PATH_LEN];
    char  path2[MAX_PATH_LEN];
};
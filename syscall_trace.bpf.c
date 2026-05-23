#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "syscall_trace.h"

char LICENSE[] SEC("license") = "GPL";


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} pid_filter SEC(".maps");


volatile __u32 filter_enabled = 0;
volatile __u32 loader_pid     = 0;  


#define COMMON_FIELDS           \
    __u16 common_type;          \
    __u8  common_flags;         \
    __u8  common_preempt_count; \
    __s32 common_pid;           \
    int   __syscall_nr

struct tp_open {
    COMMON_FIELDS;
    const char *filename;
    int         flags;
    umode_t     mode;
};

struct tp_openat {
    COMMON_FIELDS;
    int         dfd;
    const char *filename;
    int         flags;
    umode_t     mode;
};

struct tp_openat2 {
    COMMON_FIELDS;
    int         dfd;
    const char *filename;
    struct open_how *how;
    size_t      usize;
};

struct tp_creat {
    COMMON_FIELDS;
    const char *pathname;
    umode_t     mode;
};

struct tp_access {
    COMMON_FIELDS;
    const char *filename;
    int         mode;
};

struct tp_newfstatat {
    COMMON_FIELDS;
    int              dfd;
    const char      *filename;
    struct stat     *statbuf;
    int              flag;
};

struct tp_mkdir {
    COMMON_FIELDS;
    const char *pathname;
    umode_t     mode;
};

struct tp_mkdirat {
    COMMON_FIELDS;
    int         dfd;
    const char *pathname;
    umode_t     mode;
};

struct tp_rmdir {
    COMMON_FIELDS;
    const char *pathname;
};

struct tp_unlink {
    COMMON_FIELDS;
    const char *pathname;
};

struct tp_unlinkat {
    COMMON_FIELDS;
    int         dfd;
    const char *pathname;
    int         flag;
};

struct tp_chmod {
    COMMON_FIELDS;
    const char *filename;
    umode_t     mode;
};

struct tp_fchmodat {
    COMMON_FIELDS;
    int         dfd;
    const char *filename;
    umode_t     mode;
};

struct tp_chown {
    COMMON_FIELDS;
    const char *filename;
    uid_t       user;
    gid_t       group;
};

struct tp_readlink {
    COMMON_FIELDS;
    const char *path;
    char       *buf;
    int         bufsiz;
};

struct tp_readlinkat {
    COMMON_FIELDS;
    int         dfd;
    const char *pathname;
    char       *buf;
    int         bufsiz;
};

struct tp_link {
    COMMON_FIELDS;
    const char *oldname;
    const char *newname;
};

struct tp_linkat {
    COMMON_FIELDS;
    int         olddfd;
    const char *oldname;
    int         newdfd;
    const char *newname;
    int         flags;
};

struct tp_symlink {
    COMMON_FIELDS;
    const char *oldname;
    const char *newname;
};

struct tp_symlinkat {
    COMMON_FIELDS;
    const char *oldname;
    int         newdfd;
    const char *newname;
};

struct tp_rename {
    COMMON_FIELDS;
    const char *oldname;
    const char *newname;
};

struct tp_renameat {
    COMMON_FIELDS;
    int         olddfd;
    const char *oldname;
    int         newdfd;
    const char *newname;
};

struct tp_renameat2 {
    COMMON_FIELDS;
    int          olddfd;
    const char  *oldname;
    int          newdfd;
    const char  *newname;
    unsigned int flags;
};

struct tp_execve {
    COMMON_FIELDS;
    const char        *filename;
    const char *const *argv;
    const char *const *envp;
};

/*Helpers*/

static __always_inline int pid_allowed(__u32 pid)
{
    if (!filter_enabled)
        return 1;
    __u32 *in_filter = bpf_map_lookup_elem(&pid_filter, &pid);
    return in_filter != NULL;
}

static __always_inline struct event *reserve_event(__u64 syscall_id)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();
    __u32 pid      = (__u32)(pid_tgid >> 32);
    __u32 tid      = (__u32)pid_tgid;

    if (loader_pid && pid == loader_pid)
        return NULL;

    if (!pid_allowed(pid))
        return NULL;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return NULL;

    e->pid  = pid;
    e->tid  = tid;
    e->uid  = (__u32)uid_gid;
    e->_pad = 0;
    e->id   = syscall_id;
    e->ts   = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->path[0]  = '\0';
    e->path2[0] = '\0';

    return e;
}

static __always_inline void read_user_path(char *dst, const void *ptr)
{
    if (!ptr) {
        dst[0] = '\0';
        return;
    }
    long ret = bpf_probe_read_user_str(dst, MAX_PATH_LEN, ptr);
    if (ret < 0)
        dst[0] = '\0';
}

/*Tracepoint handlers*/

SEC("tracepoint/syscalls/sys_enter_open")
int handle_open(struct tp_open *ctx)
{
    struct event *e = reserve_event(2);
    if (!e) return 0;
    read_user_path(e->path, ctx->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct tp_openat *ctx)
{
    struct event *e = reserve_event(257);
    if (!e) return 0;
    read_user_path(e->path, ctx->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int handle_openat2(struct tp_openat2 *ctx)
{
    struct event *e = reserve_event(437);
    if (!e) return 0;
    read_user_path(e->path, ctx->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int handle_creat(struct tp_creat *ctx)
{
    struct event *e = reserve_event(85);
    if (!e) return 0;
    read_user_path(e->path, ctx->pathname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_access")
int handle_access(struct tp_access *ctx)
{
    struct event *e = reserve_event(21);
    if (!e) return 0;
    read_user_path(e->path, ctx->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstatat")
int handle_newfstatat(struct tp_newfstatat *ctx)
{
    struct event *e = reserve_event(262);
    if (!e) return 0;
    read_user_path(e->path, ctx->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdir")
int handle_mkdir(struct tp_mkdir *ctx)
{
    struct event *e = reserve_event(83);
    if (!e) return 0;
    read_user_path(e->path, ctx->pathname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int handle_mkdirat(struct tp_mkdirat *ctx)
{
    struct event *e = reserve_event(258);
    if (!e) return 0;
    read_user_path(e->path, ctx->pathname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int handle_rmdir(struct tp_rmdir *ctx)
{
    struct event *e = reserve_event(84);
    if (!e) return 0;
    read_user_path(e->path, ctx->pathname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int handle_unlink(struct tp_unlink *ctx)
{
    struct event *e = reserve_event(87);
    if (!e) return 0;
    read_user_path(e->path, ctx->pathname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct tp_unlinkat *ctx)
{
    struct event *e = reserve_event(263);
    if (!e) return 0;
    read_user_path(e->path, ctx->pathname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int handle_chmod(struct tp_chmod *ctx)
{
    struct event *e = reserve_event(90);
    if (!e) return 0;
    read_user_path(e->path, ctx->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int handle_fchmodat(struct tp_fchmodat *ctx)
{
    struct event *e = reserve_event(268);
    if (!e) return 0;
    read_user_path(e->path, ctx->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chown")
int handle_chown(struct tp_chown *ctx)
{
    struct event *e = reserve_event(92);
    if (!e) return 0;
    read_user_path(e->path, ctx->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlink")
int handle_readlink(struct tp_readlink *ctx)
{
    struct event *e = reserve_event(89);
    if (!e) return 0;
    read_user_path(e->path, ctx->path);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlinkat")
int handle_readlinkat(struct tp_readlinkat *ctx)
{
    struct event *e = reserve_event(267);
    if (!e) return 0;
    read_user_path(e->path, ctx->pathname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_link")
int handle_link(struct tp_link *ctx)
{
    struct event *e = reserve_event(86);
    if (!e) return 0;
    read_user_path(e->path,  ctx->oldname);
    read_user_path(e->path2, ctx->newname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int handle_linkat(struct tp_linkat *ctx)
{
    struct event *e = reserve_event(265);
    if (!e) return 0;
    read_user_path(e->path,  ctx->oldname);
    read_user_path(e->path2, ctx->newname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int handle_symlink(struct tp_symlink *ctx)
{
    struct event *e = reserve_event(88);
    if (!e) return 0;
    read_user_path(e->path,  ctx->oldname);
    read_user_path(e->path2, ctx->newname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int handle_symlinkat(struct tp_symlinkat *ctx)
{
    struct event *e = reserve_event(266);
    if (!e) return 0;
    read_user_path(e->path,  ctx->oldname);
    read_user_path(e->path2, ctx->newname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int handle_rename(struct tp_rename *ctx)
{
    struct event *e = reserve_event(82);
    if (!e) return 0;
    read_user_path(e->path,  ctx->oldname);
    read_user_path(e->path2, ctx->newname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_renameat(struct tp_renameat *ctx)
{
    struct event *e = reserve_event(264);
    if (!e) return 0;
    read_user_path(e->path,  ctx->oldname);
    read_user_path(e->path2, ctx->newname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2(struct tp_renameat2 *ctx)
{
    struct event *e = reserve_event(316);
    if (!e) return 0;
    read_user_path(e->path,  ctx->oldname);
    read_user_path(e->path2, ctx->newname);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct tp_execve *ctx)
{
    struct event *e = reserve_event(59);
    if (!e) return 0;
    read_user_path(e->path, ctx->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "syscall_trace.skel.h"
#include "syscall_trace.h"

#define SYSCALL_NR(id)  ((id) & 0x7FFFFFFFull)

static const char *syscall_names[] = {
    [0]   = "read",              [1]   = "write",           [2]   = "open",
    [3]   = "close",             [4]   = "stat",            [5]   = "fstat",
    [6]   = "lstat",             [7]   = "poll",            [8]   = "lseek",
    [9]   = "mmap",              [10]  = "mprotect",        [11]  = "munmap",
    [12]  = "brk",               [13]  = "rt_sigaction",    [14]  = "rt_sigprocmask",
    [15]  = "rt_sigreturn",      [16]  = "ioctl",           [17]  = "pread64",
    [18]  = "pwrite64",          [19]  = "readv",           [20]  = "writev",
    [21]  = "access",            [22]  = "pipe",            [23]  = "select",
    [24]  = "sched_yield",       [25]  = "mremap",          [26]  = "msync",
    [28]  = "madvise",           [29]  = "shmget",          [32]  = "dup",
    [33]  = "dup2",              [35]  = "nanosleep",       [39]  = "getpid",
    [41]  = "socket",            [42]  = "connect",         [43]  = "accept",
    [44]  = "sendto",            [45]  = "recvfrom",        [49]  = "bind",
    [50]  = "listen",            [51]  = "getsockname",     [56]  = "clone",
    [57]  = "fork",              [58]  = "vfork",           [59]  = "execve",
    [60]  = "exit",              [61]  = "wait4",           [62]  = "kill",
    [63]  = "uname",             [72]  = "fcntl",           [73]  = "flock",
    [74]  = "fsync",             [78]  = "getdents",        [79]  = "getcwd",
    [80]  = "chdir",             [81]  = "fchdir",          [82]  = "rename",
    [83]  = "mkdir",             [84]  = "rmdir",           [85]  = "creat",
    [86]  = "link",              [87]  = "unlink",          [88]  = "symlink",
    [89]  = "readlink",          [90]  = "chmod",           [92]  = "chown",
    [95]  = "umask",             [96]  = "gettimeofday",    [97]  = "getrlimit",
    [99]  = "sysinfo",           [102] = "getuid",          [104] = "getgid",
    [105] = "setuid",            [106] = "setgid",          [107] = "geteuid",
    [108] = "getegid",           [110] = "getppid",         [111] = "getpgrp",
    [112] = "setsid",            [131] = "sigaltstack",     [157] = "prctl",
    [158] = "arch_prctl",        [186] = "gettid",          [202] = "futex",
    [217] = "getdents64",        [218] = "set_tid_address", [228] = "clock_gettime",
    [230] = "clock_nanosleep",   [231] = "exit_group",      [232] = "epoll_wait",
    [233] = "epoll_ctl",         [257] = "openat",          [258] = "mkdirat",
    [262] = "newfstatat",        [263] = "unlinkat",        [264] = "renameat",
    [265] = "linkat",            [266] = "symlinkat",       [267] = "readlinkat",
    [268] = "fchmodat",          [270] = "pselect6",        [273] = "set_robust_list",
    [281] = "epoll_pwait",       [291] = "epoll_create1",   [292] = "dup3",
    [293] = "pipe2",             [302] = "prlimit64",       [316] = "renameat2",
    [318] = "getrandom",         [334] = "rseq",
    [425] = "io_uring_setup",    [426] = "io_uring_enter",  [427] = "io_uring_register",
};

#define SYSCALL_TABLE_SIZE  (sizeof(syscall_names) / sizeof(syscall_names[0]))

static const char *syscall_name(__u64 raw_id)
{
    __u64 nr = SYSCALL_NR(raw_id);
    if (nr < SYSCALL_TABLE_SIZE && syscall_names[nr])
        return syscall_names[nr];
    return NULL;
}

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

static FILE *out_fp = NULL;

static void print_header(void)
{
    fprintf(out_fp, "%-16s  %-8s %-8s %-7s  %-24s  %s\n",
            "TIMESTAMP(s)", "PID", "TID", "UID", "SYSCALL", "COMM");
    fprintf(out_fp, "%-16s  %-8s %-8s %-7s  %-24s  %s\n",
            "----------------", "-------", "-------", "------",
            "------------------------", "----------------");
    fflush(out_fp);
}

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    (void)size;

    const struct event *e = data;
    const char *name = syscall_name(e->id);
    __u64 nr = SYSCALL_NR(e->id);
    double ts_sec = (double)e->ts / 1e9;

    if (name){
        fprintf(out_fp, "[%14.6f] PID=%-7u TID=%-7u UID=%-6u %-24s %.16s",
               ts_sec, e->pid, e->tid, e->uid, name, e->comm);
    }else{
        fprintf(out_fp, "[%14.6f] PID=%-7u TID=%-7u UID=%-6u %-24llu %.16s",
               ts_sec, e->pid, e->tid, e->uid, nr, e->comm);
    }
    
    fprintf(out_fp, " PATH=<%s> PATH2=<%s>", e->path, e->path2);

    fputc('\n', out_fp);
    return 0;
}

static int populate_pid_filter(struct syscall_trace_bpf *skel,
                                int pid_argc, char **pid_argv)
{
    int map_fd = bpf_map__fd(skel->maps.pid_filter);

    for (int i = 0; i < pid_argc; i++) {
        char  *end;
        unsigned long v = strtoul(pid_argv[i], &end, 10);
        if (*end != '\0' || v == 0) {
            fprintf(stderr, "Invalid PID (must be a non-zero integer): %s\n",
                    pid_argv[i]);
            return -1;
        }
        __u32 pid = (__u32)v;
        __u32 val = 1;
        if (bpf_map_update_elem(map_fd, &pid, &val, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to insert PID %u into filter map: %s\n",
                    pid, strerror(errno));
            return -1;
        }
        printf("Filtering: PID %u\n", pid);
    }
    return 0;
}

/*Usage*/
static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-o <logfile>] [pid ...]\n"
            "  -o <logfile>  Write events to <logfile> instead of stdout\n"
            "  pid ...       Trace only these PIDs (default: trace all)\n",
            prog);
}

int main(int argc, char **argv)
{
    struct syscall_trace_bpf *skel = NULL;
    struct ring_buffer       *rb   = NULL;
    FILE                     *log_fp = NULL;
    int                       ret  = 0;
    const char               *log_path = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "o:h")) != -1) {
        switch (opt) {
        case 'o':
            log_path = optarg;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    int    pid_argc = argc - optind;
    char **pid_argv = argv + optind;

    if (log_path) {
        log_fp = fopen(log_path, "a");
        out_fp = log_fp;
    } else {
        log_fp = fopen("/home/vboxuser/Desktop/syscall_trace.log", "a");
        if (!log_fp) {
            fprintf(stderr, "Failed to open log file: %s\n", strerror(errno));
            return 1;
        }
        setvbuf(log_fp, NULL, _IOLBF, 0);
        out_fp = log_fp;
    }

    struct sigaction sa = { .sa_handler = sig_handler, .sa_flags = 0 };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    skel = syscall_trace_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton: %s\n", strerror(errno));
        ret = 1;
        goto cleanup;
    }

    if (pid_argc > 0)
        skel->bss->filter_enabled = 1;

    skel->bss->loader_pid = (__u32)getpid();

    ret = syscall_trace_bpf__load(skel);
    if (ret) {
        fprintf(stderr, "Failed to load BPF skeleton: %s\n", strerror(-ret));
        goto cleanup;
    }

    if (pid_argc > 0) {
        if (populate_pid_filter(skel, pid_argc, pid_argv) != 0) {
            ret = 1;
            goto cleanup;
        }
    }

    ret = syscall_trace_bpf__attach(skel);
    if (ret) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(-ret));
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(errno));
        ret = 1;
        goto cleanup;
    }

    printf("Tracing syscalls... Ctrl+C to stop\n");
    if (pid_argc > 0)
        printf("(PID filter active)\n");
    printf("\n");

    print_header();
    if (log_fp) {
        FILE *saved = out_fp;
        out_fp = stdout;
        print_header();
        out_fp = saved;
    }

    while (running) {
        ret = ring_buffer__poll(rb, 100);

        if (!running)
            break;

        if (ret == -EINTR) {
            ret = 0;
            break;
        }

        if (ret < 0) {
            fprintf(stderr, "Ring buffer poll error: %s\n", strerror(-ret));
            break;
        }
        ret = 0;
    }

    ring_buffer__consume(rb);

cleanup:
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }
    ring_buffer__free(rb);
    syscall_trace_bpf__destroy(skel);
    printf("\nDone.\n");
    return ret;
}
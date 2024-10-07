// Filename: bpf_prog.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Perf buffer to send data to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} events SEC(".maps");

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

// Define the tracepoint structure for sys_enter_openat
struct sys_enter_openat_args {
    unsigned long long unused;
    long syscall_nr;
    long dfd;
    const char *filename;
    long flags;
    long mode;
};

// Syscall hook for sys_enter_openat
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct sys_enter_openat_args* ctx) {
    struct data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;

    const char *filename = ctx->filename;
    if (filename == NULL) {
        return 0;
    }
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
        // Send the data to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char _license[] SEC("license") = "GPL";

EBPF tracepoints
----------------

### First trace with eBPF
This is a simple example of how to use eBPF to trace a kernel function. 
The example traces the `sys_enter_openat` function in the kernel with `bpftrace`.
(`/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat`)

```bash
bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'
```

let's add info to the call:
```bash
 cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
```

```bash
 bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s %d\n", comm, str(args->filename),args->flags); }'
```

#### Linux Tracepoints
Linux tracepoints are a way to trace the kernel that can be used by eBPF and other tools for example `perf`.

```
 perf list 'syscalls:sys_enter_openat*'
```

example:
```
perf stat -e syscalls:sys_enter_openat ls
```

see strace:
```
strace ls
```






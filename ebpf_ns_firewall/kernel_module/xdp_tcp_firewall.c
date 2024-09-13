#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <bpf/bpf_tracing.h>


#define IPPROTO_TCP  6
#define ETH_P_IP  0x0800

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} port_filter SEC(".maps");


SEC("xdp") int xdp_tcp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *) (long) ctx->data_end;
    void *data = (void *) (long) ctx->data;
    struct ethhdr *eth = data;
    if ((void *) (eth + 1) > data_end) {
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *) (iph + 1) > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void *) (tcp + 1) > data_end) {
        return XDP_PASS;
    }


    u32 key = 0;
    u64 *value;
    value = bpf_map_lookup_elem(&port_filter, &key);
    if (value == NULL) {
        bpf_printk("[EBPF Kernel Space VALUE]  value is NULL \n");
    } else {

        if (bpf_htons(tcp->dest) == 22) {
            return XDP_PASS;
        }
        if (bpf_htons(tcp->dest) != *value) {
            return XDP_PASS;
        } else {
            bpf_printk("[ebpf firewall] packets to port: %d will be dropped. \n", *value);

            return XDP_DROP;
        }

    }
    return XDP_PASS;
}


struct event {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");


SEC("kprobe/__x64_sys_tcp_connect")
int kprobe__tcp_connect(struct pt_regs *ctx)
{
   bpf_printk("[ebpf firewall] tcp_connect: %d \n", 0);
   return 0;

}

char _license[] SEC("license") = "GPL";

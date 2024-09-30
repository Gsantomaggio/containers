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


SEC("xdp_redirect")
int xdp_redirect_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Only consider IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Only consider TCP packets
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Calculate destination interface index for redirection (e.g., `ifindex = 2`)
    // You'll need to set this appropriately for your setup.
    int ifindex = 2;  // Replace with the index of the target virtual Ethernet interface

    // Redirect the packet to the new interface
    return bpf_redirect(ifindex, 0);
}



char _license[] SEC("license") = "GPL";

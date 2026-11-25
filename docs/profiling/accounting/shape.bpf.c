// Lab witness placed before RustiFlow on the disposable lower veth only.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct totals {
    __u64 skbs;
    __u64 gso_skbs;
    __u64 gso_segments;
    __u64 size_512;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 24);
    __type(key, __u32);
    __type(value, struct totals);
} rf09_shapes SEC(".maps");

SEC("classifier")
int rf09_shape(struct __sk_buff *skb) {
    __be16 type;
    __u32 bucket = 0; // Unreadable Ethernet header.
    if (bpf_skb_load_bytes(skb, 12, &type, sizeof(type)) == 0) {
        if (type == bpf_htons(ETH_P_IP))
            bucket = 1;
        else if (type == bpf_htons(ETH_P_IPV6))
            bucket = 2;
        else if (type == bpf_htons(ETH_P_8021Q))
            bucket = 3;
        else if (type == bpf_htons(0x88b5))
            bucket = 4;
        else
            bucket = 5;
    }
    if (skb->vlan_present) {
        if (skb->vlan_proto == bpf_htons(ETH_P_8021Q))
            bucket += 6;
        else if (skb->vlan_proto == bpf_htons(ETH_P_8021AD))
            bucket += 12;
        else
            bucket += 18;
    }

    struct totals *value = bpf_map_lookup_elem(&rf09_shapes, &bucket);
    if (value) {
        value->skbs++;
        if (skb->gso_segs > 1) {
            value->gso_skbs++;
            value->gso_segments += skb->gso_segs;
            value->size_512 += skb->gso_size == 512;
        }
    }
    return TC_ACT_UNSPEC;
}

char LICENSE[] SEC("license") = "GPL";

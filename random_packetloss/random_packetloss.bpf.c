#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} drop_rate_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u32 key = 0;
    __u32 *rate = bpf_map_lookup_elem(&drop_rate_map, &key);
    if (!rate) return XDP_PASS;

    __u32 r = bpf_get_prandom_u32() % 100;
    if (r < *rate) return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

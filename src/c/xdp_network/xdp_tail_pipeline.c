// SPDX-License-Identifier: GPL-2.0
// xdp_tail_pipeline.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>


/* === Maps === */

// 1) Program array for tail calls: dispatcher jumps to handlers here.
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} c_prog_array SEC(".maps");

// 2) devmap to forward out to IFACE_B (index 0 -> ifindex of IFACE_B)
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, struct bpf_devmap_val);   // ifindex + mapindex
} tx_devmap SEC(".maps");

// 4) (Optional) Token bucket state per path_id for throttling
struct tb_state {
    __u64 tokens;
    __u64 last_ns;
    __u64 rate_q32;   // rate in tokens/ns * 2^32
    __u64 burst;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);        // path_id
    __type(value, struct tb_state);
} tb_map SEC(".maps");


enum {
    H_IPV4  = 0,
    H_IPV6  = 1,
    H_RATE_LIMIT = 2,
    H_OTHER = 3,
};

/* === Dispatcher (attached at IFACE_A ingress) === */
SEC("xdp")
int xdp_dispatch(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // minimal L2 bounds check
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;

    __u16 proto = bpf_ntohs(eth->h_proto);

    __u32 idx = (proto == ETH_P_IP)    ? H_IPV4 :
                (proto == ETH_P_IPV6) ? H_IPV4 :
                                        H_OTHER;

    //bpf_printk("xdp_dispatch: proto=0x%x idx=%d\n", proto, idx);

    bpf_tail_call(ctx, &c_prog_array, idx);

    // if slot not populated, just pass (or DROP/ABORT if you prefer)
    return XDP_PASS;
}

/* === Optional handler: token-bucket rate-limit, then forward === */

static __always_inline int tb_consume(__u32 path_id, __u32 cost_bytes)
{
    struct tb_state *st = bpf_map_lookup_elem(&tb_map, &path_id);
    if (!st)
        return 1;

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - st->last_ns;
    if ((__s64)elapsed < 0)
        elapsed = 0;

    /* approximate (elapsed * rate_q32) >> 32 without 128-bit ops */
    __u64 add = (elapsed >> 10) * (st->rate_q32 >> 22);

    __u64 new_tokens = st->tokens + add;
    if (new_tokens > st->burst)
        new_tokens = st->burst;

    st->last_ns = now;

    if (new_tokens >= cost_bytes) {
        st->tokens = new_tokens - cost_bytes;
        return 1;
    } else {
        st->tokens = new_tokens;
        return 0;
    }
}

SEC("xdp")
int xdp_rate_then_forward(struct xdp_md *ctx)
{
    __u32 path_id = 0;  // same as dispatcher’s key
    __u32 pkt_len = (__u32)(ctx->data_end - ctx->data); // cost = length

    if (!tb_consume(path_id, pkt_len))
        return XDP_DROP;
    
    //bpf_printk("xdp_rate_then_forward\n");

    __u32 key = 0; // forward to devmap[0] -> IFACE_B
    return bpf_redirect_map(&tx_devmap, key, 0);
}

SEC("xdp")
int xdp_encap(struct xdp_md *ctx)
{
    //bpf_printk("xdp_encap: redirecting via devmap\n");

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // minimal L2 bounds check
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;

    __builtin_memcpy(eth->h_dest, "\xb8\xce\xf6\x1b\x4d\x5d", ETH_ALEN); 
    
    //bpf_printk("xdp_encap: eth->h_dest set to %x:%x:%x:%x:%x:%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    bpf_tail_call(ctx, &c_prog_array, H_RATE_LIMIT); 

    return XDP_PASS;
}

SEC("xdp/devmap")
int xdp_decap(struct xdp_md *ctx)
{
    //bpf_printk("xdp_decap: TX back out interface %d\n", ctx->ingress_ifindex);
    
    return XDP_PASS;  // bounce back out same interface
}

char _license[] SEC("license") = "GPL";

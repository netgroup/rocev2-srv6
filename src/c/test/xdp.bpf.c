#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


#define PRINT_LEVEL 4

#include "common.h"
#include "parse_helpers.h"

/* define routing acceleration; if set the routing is carried out in XDP/eBPF
 * context and packet is directly redirect to the egress device; Otherwise, the
 * packet is passed up to the kernel stack for further processing.
*/
#if 1
#define ROUTING_ACC
#endif

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);   // 1 = impacted, 0 = normal
} flagged_qp SEC(".maps");


struct sr6_encap_red_info {
	struct in6_addr tunsrc;
	struct in6_addr sid;
};
static const struct in6_addr PRIMARY_SID = {
    .in6_u.u6_addr8 = {
        0xfc, 0xf0, 0x00, 0x00, 0x00, 0xa2, 0x00, 0xd4,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    }
};
// static const struct in6_addr SECONDARY_SID = {
//     .in6_u.u6_addr8 = {
//         0xfc, 0xf0, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x0e,
//         0x00, 0xa2, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x00
//     }
// };
static const struct in6_addr TUN_SRC = {
    .in6_u.u6_addr8 = {
        0xfd, 0x00, 0x00, 0xa1, 0x00, 0xb0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    }
};

struct mac_fwd_entry {
    __u8  dst_mac[6];
    __u8  src_mac[6];
    __u32 ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct in6_addr);  
    __type(value, struct mac_fwd_entry);
} mac_fwd_map SEC(".maps");


//ipv4 forwarding map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __be32);                  
    __type(value, struct mac_fwd_entry);
} mac_fwd_v4_map SEC(".maps");


// struct xdp_route_entry {
//     __u32 ifindex;       // interfaccia di uscita
//     __u8  smac[6];       // MAC sorgente
//     __u8  dmac[6];       // MAC destinazione (next hop)
// };

// #define ROUTE_MAP_MAX 1024
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, ROUTE_MAP_MAX);
//     __type(key, struct in6_addr);
//     __type(value, struct xdp_route_entry);
// } xdp_route_map SEC(".maps");




/*structures to mantain the association between local and remote information (at the moment only QP number)*/
struct local_info{
	__be32 local_qp;
};

struct remote_info{
	__be32 remote_qp;
};

struct { __uint(type, BPF_MAP_TYPE_ARRAY); 
	__uint(max_entries, 1); 
	__type(key, __u32);
	__type(value, __be32); 
}impacted_qp SEC(".maps");


struct qp_pair {
    __be32 local_qp;
    __be32 remote_qp;
};

#define INFO_MAX_ASSOC 4



// Coda per i locali in attesa
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 256);
    __type(value, __be32);   // solo local_qp
} pending_locals SEC(".maps");

// Coda per i remoti in attesa
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 256);
    __type(value, __be32);   // solo remote_qp
} pending_remotes SEC(".maps");

struct{
	__uint(type,BPF_MAP_TYPE_LRU_HASH); //LRU HASH eliminates least recently used entry when full
	__uint(max_entries, INFO_MAX_ASSOC);
	__type(key, struct local_info);
	__type(value, struct remote_info);
}local_remote_association SEC(".maps");

#define SR6_ENCAP_RED_HEADROOM sizeof(struct ipv6hdr)

struct sr6_decap_info {
	__u32 tbid;
	__u32 reserved;
};

#define SRH_ENCAPV4_MAX_ENTRIES 256
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SRH_ENCAPV4_MAX_ENTRIES);
	__type(key, __be32);
	__type(value, struct sr6_encap_red_info);
} sr6encap_ip4_table SEC(".maps");

#define SRH_DECAP_MAX_ENTRIES	256
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SRH_DECAP_MAX_ENTRIES);
	__type(key, struct in6_addr);
	__type(value, struct sr6_decap_info);
} sr6decap_table SEC(".maps");

//key for the QP map: it contains the destination address and the QP

struct encap_qp_key {
    __be32 dst_ip;   
    __be32  qpn;     
};

// Policy per-QP (override), fallback: sr6encap_ip4_table
#define SRH_ENCAPV4_QP_MAX_ENTRIES 512
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, SRH_ENCAPV4_QP_MAX_ENTRIES);
    __type(key, struct encap_qp_key);
    __type(value, struct sr6_encap_red_info);
} sr6encap_ip4_qp_table SEC(".maps");

// Structures to keep trace of the per-QP throughput 
struct qp_stats {
    __u64 bytes;
    __u64 start_ns;
    __u64 last_ns;
    __u64 last_bps;
    __u64 below_ns_accum;
};

#define QP_STATS_MAX        4096
#define Mbps(x) ((x) * 1000000ULL)
#define Gbps(x) ((x) * 1000000000ULL)
#define ms(x) ((x)*1000000ULL)
#define BASE_THRESHOLD_BPS 500000ULL  // 0.5 Mbps

#define BELOW_TARGET_NS ms(200)   // 200 ms

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, QP_STATS_MAX);
    __type(key, __be32);            
    __type(value, struct qp_stats);
} qp_throughput SEC(".maps");

struct meta {
    __u32 path_id;
};

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

int __always_inline 
prepare_metadata(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;

    int need = -(int)sizeof(struct meta);
    if (bpf_xdp_adjust_meta(ctx, need) < 0)
        return XDP_ABORTED;

    /* Recompute pointers after adjust_meta */
    void *data_meta = (void *)(long)ctx->data_meta;

    /* Bounds check: metadata must fit entirely before L2 header */
    if (data_meta + sizeof(struct meta) > data)
        return XDP_ABORTED;

    return 1;
}

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
                (proto == ETH_P_IPV6)  ? H_IPV6 :
                                        H_OTHER;

    bpf_printk("xdp_dispatch: proto=0x%x idx=%d\n", proto, idx);

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
    
    bpf_printk("xdp_rate_then_forward\n");

    __u32 key = 0; // forward to devmap[0] -> IFACE_B
    return bpf_redirect_map(&tx_devmap, key, 0);
}

//helper to extract QP from BTH
static __always_inline bool rocev2_extract_qpn(void *bth, void *data_end, __u32 *qpn_out)
{
    const __u8 *p = bth;
    /* servono almeno 8 byte del BTH per arrivare a p[7] */
    if ((void *)(p + 8) > data_end)
        return false;

    __u32 raw32 = 0;
    raw32 = ((__u32)p[5] << 16) | ((__u32)p[6] << 8) | (__u32)p[7];
    //  bpf_printk("BTH[5..7]= %02x %02x %02x  raw32=0x%x\n",
    //                p[5], p[6], p[7], raw32);
     *qpn_out =bpf_htonl(raw32);
    return true;
}

// Usa parse_ethhdr(), parse_ip4hdr(), parse_ip6hdr() dai tuoi helpers.
// Suppone esistenza di hdr_cursor.h (già incluso nel tuo header).


static __always_inline
__be32 parse_ascii_to_be32(const char *ascii)
{
    __u32 val = 0;

#pragma clang loop unroll(full)
    for (int i = 0; i < 6; i++) {
        char c = ascii[i];
        __u8 nibble = 0;

        if (c >= '0' && c <= '9')
            nibble = c - '0';
        else if (c >= 'a' && c <= 'f')
            nibble = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F')
            nibble = 10 + (c - 'A');
        else
            return 0;  // invalid char, fallback to 0

        val = (val << 4) | nibble;
    }

    return bpf_htonl(val);
}

// static __always_inline void flip_route_for_ip_qp(__be32 dst_ip_n, __u32 dqpn)
// {
//     __u32 key0 = 0;
//     __u32 *stored_qp = bpf_map_lookup_elem(&impacted_qp, &key0);

//     if (stored_qp) {
//         if (dqpn == *stored_qp){
//     //         bpf_printk("flipping route for qp=0x%x (impacted)", dqpn);
	
//     //     else
//     //         bpf_printk("flipping route for impacted qp=0x%x", dqpn);
//     // } else {
//     //     bpf_printk("flipping route for qp=0x%x (no impacted_qp set)", dqpn);
//     // }

//     struct encap_qp_key k = {
//         .dst_ip = bpf_ntohl(dst_ip_n),
//         .qpn    = dqpn
//     };

//     struct sr6_encap_red_info *cur = bpf_map_lookup_elem(&sr6encap_ip4_qp_table, &k);
//     if (!cur)
//         return;

//     // Toggle SID mantenendo tunsrc
//     struct sr6_encap_red_info newv = {0};
//     __builtin_memcpy(&newv.tunsrc, &cur->tunsrc, sizeof(newv.tunsrc));

//     if (__builtin_memcmp(&cur->sid, &PRIMARY_SID, sizeof(PRIMARY_SID)) == 0) {
//         __builtin_memcpy(&newv.sid, &SECONDARY_SID, sizeof(newv.sid));
//     //    bpf_printk("qp=0x%x switched from PRIMARY to SECONDARY", dqpn);
//     } else {
//         __builtin_memcpy(&newv.sid, &PRIMARY_SID, sizeof(newv.sid));
//    //     bpf_printk("qp=0x%x switched from SECONDARY to PRIMARY", dqpn);
//     }

//     bpf_map_update_elem(&sr6encap_ip4_qp_table, &k, &newv, BPF_ANY);}}
// }


static __always_inline void restore_dscp(__be32 dst_ip_n, __u32 dqpn)
{
    __u32 key0 = 0;
    __u32 *stored_qp = bpf_map_lookup_elem(&impacted_qp, &key0);
    if (!stored_qp || dqpn != *stored_qp)
        return;

    // Trova l'entry per questo (dst_ip, qpn)
    struct encap_qp_key k = {
        .dst_ip = bpf_ntohl(dst_ip_n),
        .qpn    = dqpn
    };

    struct sr6_encap_red_info *cur = bpf_map_lookup_elem(&sr6encap_ip4_qp_table, &k);
    if (!cur)
        return;

    /* Reset DSCP a 0 mantenendo ECN nel Traffic Class del SID IPv6 */

    struct sr6_encap_red_info newv = {0};
    __builtin_memcpy(&newv, cur, sizeof(*cur));

    /* Il DSCP è nei 6 bit alti del Traffic Class.
     * In IPv6, Traffic Class = Byte 0 (TC) e 2 bit del Byte 1 (flow label).
     * Quindi azzeriamo solo i 6 bit DSCP e lasciamo invariati ECN.
     */
    newv.sid.in6_u.u6_addr8[0] &= 0x03;  // mantieni solo ECN, DSCP=0

    bpf_map_update_elem(&sr6encap_ip4_qp_table, &k, &newv, BPF_ANY);

	bpf_printk("DSCP reset for qp=0x%x", dqpn);
}


static __always_inline void
qp_update_throughput_and_maybe_reroute(struct xdp_md *ctx,
                                       struct hdr_cursor *cur,
                                       struct iphdr *ip4h,
                                       __u16 udp_len)
{
    void *data_end  = (void *)(long)ctx->data_end;
    void *bth       = cur_data(ctx, cur);
    __u8 *bth_bytes = (__u8 *)bth;

    if ((void *)(bth_bytes + 1) > data_end)
        return;

    __u8 opcode = bth_bytes[0] & 0x7F;  // opcode RDMA
    if (opcode == 0x11 || opcode == 0x81) {
        // ACK → ignora
        return;
    }

    __be32 local_qpn;
    if (!rocev2_extract_qpn(bth, data_end, &local_qpn))
        return;

    struct local_info loc_info = { .local_qp = local_qpn };
    struct remote_info *rem_info =
        bpf_map_lookup_elem(&local_remote_association, &loc_info);
    if (!rem_info)
        return;

    __u64 now   = bpf_ktime_get_ns();
    __u64 bytes = (udp_len >= 8) ? (udp_len - 8) : 0;

    // --- assicura entry SRv6 encap ---
    struct encap_qp_key k = {
        .dst_ip = bpf_ntohl(ip4h->saddr),
        .qpn    = rem_info->remote_qp
    };

    if (!bpf_map_lookup_elem(&sr6encap_ip4_qp_table, &k)) {
        struct sr6_encap_red_info init = {0};
        __u32 dst_host = bpf_ntohl(ip4h->saddr);
        struct sr6_encap_red_info *fallback =
            bpf_map_lookup_elem(&sr6encap_ip4_table, &dst_host);

        if (fallback) {
            init = *fallback;
        } else {
            __builtin_memcpy(&init.tunsrc, &TUN_SRC, sizeof(TUN_SRC));
            __builtin_memcpy(&init.sid, &PRIMARY_SID, sizeof(PRIMARY_SID));
        }

        bpf_map_update_elem(&sr6encap_ip4_qp_table, &k, &init, BPF_ANY);
    }

    // --- update throughput con finestra 100ms ---
    struct qp_stats *old_st =
        bpf_map_lookup_elem(&qp_throughput, &rem_info->remote_qp);

    struct qp_stats st;
    if (!old_st) {
        st.bytes          = bytes;
        st.start_ns       = now;
        st.last_ns        = now;
        st.last_bps       = 0;
        st.below_ns_accum = 0;
        bpf_map_update_elem(&qp_throughput, &rem_info->remote_qp, &st, BPF_ANY);
        return;
    } else {
        __builtin_memcpy(&st, old_st, sizeof(st));
        st.bytes   += bytes;
        st.last_ns  = now;
    }

    __u64 dt = now - st.start_ns;

    if (dt >= 100000000ULL) { // 100 ms
        __u64 inst_bps = (st.bytes * 8ULL * 1000000000ULL) / dt;

        // α = 0.5 → media mobile su circa 200 ms
        const int alpha_num = 50;
        const int alpha_den = 100;

        st.last_bps = (st.last_bps * (alpha_den - alpha_num) +
                       inst_bps   * alpha_num) / alpha_den;

        st.bytes    = 0;
        st.start_ns = now;

        // bpf_printk("EMA throughput qp=0x%x: %llu bps",
        //            rem_info->remote_qp, st.last_bps);
    }

    // --- check soglia e flip rotta ---
    if (st.last_bps < BASE_THRESHOLD_BPS) {
        st.below_ns_accum += dt;
        if (st.below_ns_accum >= BELOW_TARGET_NS) {
           
            //flip_route_for_ip_qp(ip4h->saddr, rem_info->remote_qp);
            restore_dscp(ip4h->saddr, rem_info->remote_qp);
			st.below_ns_accum = 0;
        }
    } else {
        st.below_ns_accum = 0;
    }

    // scrivi indietro in mappa i valori aggiornati
    bpf_map_update_elem(&qp_throughput, &rem_info->remote_qp, &st, BPF_ANY);
}



static __always_inline
struct sr6_encap_red_info *encap_policy_lookup_ip4(const struct iphdr *ip4h)
{
	const __u32 addr = bpf_ntohl(ip4h->daddr);

	return bpf_map_lookup_elem(&sr6encap_ip4_table, &addr);
}

static __always_inline
struct sr6_encap_red_info *
encap_policy_lookup_ip4_qp(struct xdp_md *ctx,
                           struct hdr_cursor *cur,
                           const struct iphdr *ip4h)
{
    // cur->thoff è alla fine dell'IPv4 header (grazie a do_srh_encap_ip4)
    struct udphdr *udph = (void *)cur_header_pointer(ctx, cur->thoff, sizeof(*udph));
    void *data_end = (void *)(long)ctx->data_end;

    /* BTH parte subito dopo l’UDP header */
    void *bth = cur_header_pointer(ctx, cur->thoff + sizeof(*udph), 12);
    __u32 dqpn;

    if (bth && rocev2_extract_qpn(bth, data_end, &dqpn)) {
        struct encap_qp_key k = {
            .dst_ip = bpf_ntohl(ip4h->daddr),
            .qpn    = dqpn,
        };

        struct sr6_encap_red_info *v =
            bpf_map_lookup_elem(&sr6encap_ip4_qp_table, &k);

        if (v) {
            if (ip4h->saddr == bpf_htonl(0x0a370101)) {
                 // Logica DSCP per QP “impattato”
                 __u32 key0 = 0;
                 __u32 *stored_qp = bpf_map_lookup_elem(&impacted_qp, &key0);
				__u32 flag_key = 0;
				__u8 flag_val = 0;
                 if (!stored_qp || *stored_qp == 0) {
                    // Salva il primo QP osservato
                    bpf_map_update_elem(&impacted_qp, &key0, &dqpn, BPF_ANY);
					flag_val=1;
				
					
                        // struct iphdr *iph = (struct iphdr *)ip4h;
                        // __u8 new_dscp = 20 << 2;   // DSCP CS1
                        // __u8 mask     = 0xFC;     // preserva i 2 bit ECN
                        // iph->tos = (iph->tos & ~mask) | new_dscp;
                    

                    // __u32 init_counter = 1;
                   
                } else if (*stored_qp == dqpn) {
                    // Match → cambia DSCP
                    // struct iphdr *iph = (struct iphdr *)ip4h;
                    // __u8 new_dscp = 20 << 2;   // DSCP CS1
                    // __u8 mask     = 0xFC;     // preserva i 2 bit ECN
                    // iph->tos = (iph->tos & ~mask) | new_dscp;

					flag_val=1;
					
                }else{
				flag_val=0;}
				bpf_map_update_elem(&flagged_qp, &flag_key, &flag_val, BPF_ANY);
            }
            return v;
        }
    }else{

    /* fallback per-dest */
    bpf_printk("fallback");
    return encap_policy_lookup_ip4(ip4h);}
}


static __always_inline
int cur_xdp_shrink_head(struct xdp_md *ctx, struct hdr_cursor *cur, int len)
{
	int rc;

	rc = cur_xdp_adjust_head(ctx, cur, len);
	if (unlikely(rc)) {
		pr_err("cannot resize (%d) the xdp frame correctly", len);
		return rc;
	}

	return 0;
}

static __always_inline
int cur_xdp_expand_head(struct xdp_md *ctx, struct hdr_cursor *cur, int len)
{
	return cur_xdp_shrink_head(ctx, cur, -len);
}

static __always_inline int rebuild_mac_header(struct xdp_md *ctx,
					      struct hdr_cursor *cur, int len,
					      __u16 proto)
{
#define get_ethhdr(ctx, cur)						\
	((struct ethhdr *)cur_header_pointer(ctx, (cur)->mhoff,		\
					     sizeof(struct ethhdr)))
	struct ethhdr *old_eth, *eth;

	old_eth = get_ethhdr(ctx, cur);
	if (unlikely(!old_eth))
		goto err;

	/* set the data pointer to the beginning of expanded xdp frame */
	__push(cur, len);
	cur_reset_mac_header(cur);

	eth = get_ethhdr(ctx, cur);
	if (unlikely(!eth))
		goto err;

	/* note that the two headers do not overlap each other */
	memcpy(eth, old_eth, sizeof(*eth));
	eth->h_proto = bpf_htons(proto);

	__pull(cur, sizeof(*eth));

	return 0;

err:
	pr_err("invalid access to Ethernet header");
	return -EINVAL;
#undef get_ethhdr
}

struct ip6_payload_info {
	struct sr6_encap_red_info *encap_info;
	__u16 payload_len;
	__u8 nexthdr;
	__u8 tos;
};

#define get_ipv4hdr(ctx, cur)						\
	((struct iphdr *)cur_header_pointer(ctx, (cur)->nhoff,		\
					    sizeof(struct iphdr)))

#define get_ipv6hdr(ctx, cur)						\
	((struct ipv6hdr *)cur_header_pointer(ctx, (cur)->nhoff,	\
					      sizeof(struct ipv6hdr)))

struct fib_res_lookup {
	struct bpf_fib_lookup fib_params;
	__u32 flags;
	__u32 tbid;
	__u32 proto;
	int action;
};

#ifdef ROUTING_ACC
static __always_inline
int fib_lookup(struct xdp_md *ctx, struct hdr_cursor *cur,
	       struct fib_res_lookup *res)
{
	struct bpf_fib_lookup *fib_params = &res->fib_params;
	int *action = &res->action;
	__u32 flags = res->flags;
	struct ethhdr *eth;
	int rc;

	rc = bpf_fib_lookup(ctx, fib_params, sizeof(*fib_params), flags);
	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:
		/* lookup successful */
		eth = cur_header_pointer(ctx, cur->mhoff, sizeof(*eth));
		if (unlikely(!eth)) {
			pr_err("invalid access to Ethernet header");

			*action = XDP_ABORTED;
			return -EINVAL;
		}

		memcpy(eth->h_dest, fib_params->dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params->smac, ETH_ALEN);

		*action = bpf_redirect(fib_params->ifindex, 0);
		break;

	case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
		*action = XDP_DROP;
		break;

	case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
	case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
		*action = XDP_PASS;
		break;
	}

	pr_debug("xdp fib_lookup: (proto 0x%x, lookup ifindex=%d) result=%d, action=%d",
		 res->proto, fib_params->ifindex, rc, *action);

	return rc;
}


// static __always_inline
// int map_route_lookup(struct xdp_md *ctx, struct hdr_cursor *cur,
//                      const struct in6_addr *dst)
// {

//     struct xdp_route_entry *ri = bpf_map_lookup_elem(&xdp_route_map, dst);
//     struct ethhdr *eth;

//     if (!ri)
//         return XDP_PASS;  // se non trovi nulla → lascia al kernel

//     eth = cur_header_pointer(ctx, cur->mhoff, sizeof(*eth));
//     if (!eth)
//         return XDP_ABORTED;

//     __builtin_memcpy(eth->h_source, ri->smac, ETH_ALEN);
//     __builtin_memcpy(eth->h_dest,   ri->dmac, ETH_ALEN);
// 	bpf_printk("routing through xdp map");
	
//    return bpf_redirect(ri->ifindex, 0);
//    }


// static __always_inline
// int xdp_fwd(struct xdp_md *ctx, struct hdr_cursor *cur,
// 	    struct fib_res_lookup *res)
// {
// 	struct bpf_fib_lookup *fib_params = &res->fib_params;
// 	int *action = &res->action;
// 	__u32 proto = res->proto;
// 	__u32 tbid = res->tbid;
// 	struct ipv6hdr *ip6h;
// 	struct iphdr *ip4h;
// 	int rc;

// 	memset((void *)fib_params, 0, sizeof(*fib_params));

// 	if (proto == ETH_P_IPV6) {
// 		struct in6_addr *saddr, *daddr;
// 		__be32 flowlabel;

// 		ip6h = get_ipv6hdr(ctx, cur);
// 		if (unlikely(!ip6h)) {
// 			pr_err("invalid access to IPv6 header");
// 			goto error;
// 		}

// 		if (ip6h->hop_limit <= 1) {
// 			pr_debug("hop limit is <= 1, forward it to the kernel stack");
// 			return XDP_PASS;
// 		}

// 		saddr = (struct in6_addr *)fib_params->ipv6_src;
// 		daddr = (struct in6_addr *)fib_params->ipv6_dst;

// 		flowlabel = ip6_flowlabel(ip6h);

// 		fib_params->family	= AF_INET6;
// 		fib_params->flowinfo	= flowlabel;
// 		fib_params->l4_protocol	= ip6h->nexthdr;
// 		fib_params->tot_len	= bpf_ntohs(ip6h->payload_len);
// 		*saddr			= ip6h->saddr;
// 		*daddr			= ip6h->daddr;
// 	} else if (proto == ETH_P_IP) {
// 		ip4h = get_ipv4hdr(ctx, cur);
// 		if (unlikely(!ip4h)) {
// 			pr_err("invalid access to IPv4 header");
// 			goto error;
// 		}

// 		if (ip4h->ttl <= 1) {
// 			pr_debug("ttl <= 1, forward it to the kernel stack");
// 			return XDP_PASS;
// 		}

// 		fib_params->family	= AF_INET;
// 		fib_params->tos		= ip4h->tos;
// 		fib_params->l4_protocol	= ip4h->protocol;
// 		fib_params->tot_len	= bpf_ntohs(ip4h->tot_len);
// 		fib_params->ipv4_src	= ip4h->saddr;
// 		fib_params->ipv4_dst	= ip4h->daddr;
// 	} else {
// 		pr_warn("xdp forward unsupported protocol 0x%x", proto);
// 		return XDP_PASS;
// 	}

// 	if (tbid)
// 		fib_params->tbid = tbid;

// 	fib_params->sport	= 0;
// 	fib_params->dport	= 0;
// 	fib_params->ifindex	= ctx->ingress_ifindex;

// 	rc = fib_lookup(ctx, cur, res);
// 	if (unlikely(rc < 0))
// 		goto error;
// 	if (rc != BPF_FIB_LKUP_RET_SUCCESS)
// 		goto out;

// 	/* decrease hop limit or ttl depending on the current protocol */
// 	if (proto == ETH_P_IPV6)
// 		ip6h->hop_limit--;
// 	else if (proto == ETH_P_IP)
// 		ip_decrease_ttl(ip4h);
// out:
// 	return *action;

// error:
// 	return XDP_ABORTED;
// }


static __always_inline
int xdp_fwd(struct xdp_md *ctx, struct hdr_cursor *cur,
            struct fib_res_lookup *res)
{
    struct bpf_fib_lookup *fib_params = &res->fib_params;
    int *action = &res->action;
    __u32 proto = res->proto;
    struct ipv6hdr *ip6h;
    struct iphdr *ip4h;
    struct mac_fwd_entry *fwd;
    struct in6_addr ip6_key;
    __u32 ip4_key;
    void *data, *data_end;
    struct ethhdr *eth;
    int rc;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    if (proto == ETH_P_IPV6) {
        ip6h = get_ipv6hdr(ctx, cur);
        if (unlikely(!ip6h))
            goto error;
        if (ip6h->hop_limit <= 1)
            return XDP_PASS;

        ip6_key = ip6h->daddr;
        fwd = bpf_map_lookup_elem(&mac_fwd_map, &ip6_key);
        if (!fwd) {
            bpf_printk("xdp_fwd: no entry in map (proto=0x%x)", proto);
            return XDP_PASS;
        }

        bpf_printk("xdp_fwd: redirect ifindex=%u", fwd->ifindex);
        bpf_printk("src=%02x:%02x:%02x:%02x:%02x:%02x dst=%02x:%02x:%02x:%02x:%02x:%02x",
                fwd->src_mac[0], fwd->src_mac[1], fwd->src_mac[2],
                fwd->src_mac[3], fwd->src_mac[4], fwd->src_mac[5],
                fwd->dst_mac[0], fwd->dst_mac[1], fwd->dst_mac[2],
                fwd->dst_mac[3], fwd->dst_mac[4], fwd->dst_mac[5]);

    } else if (proto == ETH_P_IP) {
        ip4h = get_ipv4hdr(ctx, cur);
        if (unlikely(!ip4h))
            goto error;
        if (ip4h->ttl <= 1)
            return XDP_PASS;

        ip4_key = ip4h->daddr;
        fwd = bpf_map_lookup_elem(&mac_fwd_v4_map, &ip4_key);
    } else {
        pr_warn("unsupported protocol 0x%x", proto);
        return XDP_PASS;
    }

    if (!fwd) {
        pr_debug("no entry in MAC map, pass to kernel");
        return XDP_PASS;
    }

    /* modifica header Ethernet */
    eth = data;
    if ((void *)(eth + 1) > data_end)
        goto error;

    __builtin_memcpy(eth->h_source, fwd->src_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, fwd->dst_mac, ETH_ALEN);

    /* decrementa TTL o Hop Limit */
    if (proto == ETH_P_IPV6)
        ip6h->hop_limit--;
    else if (proto == ETH_P_IP)
        ip_decrease_ttl(ip4h);

    /* inoltra sul device specificato */
    rc = bpf_redirect(fwd->ifindex, 0);
    if (rc)
        return rc;

    return XDP_PASS;

error:
    return XDP_ABORTED;
}


static __always_inline
int ipv6_route(struct xdp_md *ctx, struct hdr_cursor *cur,
	       struct fib_res_lookup *res)
{
	return xdp_fwd(ctx, cur, res);
}

static __always_inline
int ipv4_route(struct xdp_md *ctx, struct hdr_cursor *cur,
	       struct fib_res_lookup *res)
{
	return xdp_fwd(ctx, cur, res);
}
#endif /* ROUTING_ACC */

// static __always_inline
// int ip6_packet_forward(struct xdp_md *ctx, struct hdr_cursor *cur,
// 		       struct fib_res_lookup *res)
// {
// #ifdef ROUTING_ACC
// 	/* route the packet within XDP context */
// 	return ipv6_route(ctx, cur, res);
// #else
// 	/* pass the packet up to the kernel stack */
// 	pr_debug("forward encap packet to the kernel stack");
// 	return XDP_PASS;
// #endif
// }

static __always_inline
int ip4_packet_forward(struct xdp_md *ctx, struct hdr_cursor *cur,
		       struct fib_res_lookup *res)
{
#ifdef ROUTING_ACC
	/* route the packet within XDP context */
	return ipv4_route(ctx, cur, res);
#else
	/* pass the packet up to the kernel stack */
	pr_debug("forward decap packet to the kernel stack");
	return XDP_PASS;
#endif
}

static __always_inline
void ipv6hdr_push_encap_red(struct ipv6hdr *ip6h,
			    const struct sr6_encap_red_info *einfo)
{
	memcpy(&ip6h->saddr, &einfo->tunsrc, sizeof(einfo->tunsrc));
	memcpy(&ip6h->daddr, &einfo->sid, sizeof(einfo->sid));
}

static __always_inline
int build_ipv6hdr(struct xdp_md *ctx, struct hdr_cursor *cur,
		  struct ip6_payload_info *pinfo)
{
	const struct sr6_encap_red_info *einfo = pinfo->encap_info;
	struct ipv6hdr *ip6h;

	ip6h = get_ipv6hdr(ctx, cur);
	if (unlikely(!ip6h)) {
		pr_err("invalid access to IPv6 header");
		return -EINVAL;
	}

	/* ipv4 tos is copied into IPv6 traffic class */
	ip6_flow_hdr(ip6h, pinfo->tos, 0);

	ip6h->nexthdr = pinfo->nexthdr;
	ip6h->hop_limit = 64;
	ip6h->payload_len = bpf_htons(pinfo->payload_len);

	/* move the transport header cursor to the end of IPv6 header */
	__cur_set_header_off(cur, thoff, cur->nhoff + SR6_ENCAP_RED_HEADROOM);

	ipv6hdr_push_encap_red(ip6h, einfo);

	return 0;
}

static __always_inline
int get_local_qp(struct xdp_md *ctx, struct hdr_cursor *cur)
{
    struct tcphdr *tcph = cur_header_pointer(ctx, cur->thoff, sizeof(*tcph));
    if (!tcph) return -1;

    __u32 thlen = tcph->doff << 2;
    if (thlen < sizeof(*tcph)) return -1;

    unsigned char *payload = cur_header_pointer(ctx, cur->thoff + thlen, 16);
    if (!payload) return -1;

    char ascii[7] = {};
#pragma clang loop unroll(full)
    for (int i = 0; i < 6; i++)
        ascii[i] = payload[10 + i];

    __be32 local_qp = parse_ascii_to_be32(ascii);
 //   bpf_printk("LOCAL QP (parsed): 0x%x", local_qp);

    __be32 remote_qp;
    if (bpf_map_pop_elem(&pending_remotes, &remote_qp) == 0) {
        // Abbiamo già un remote in attesa → accoppia subito
        struct local_info loc = { .local_qp = local_qp };
        struct remote_info rem = { .remote_qp = remote_qp };
        bpf_map_update_elem(&local_remote_association, &loc, &rem, BPF_ANY);
   //     bpf_printk("ASSOCIATED (local first): local=0x%x remote=0x%x",
              //     loc.local_qp, rem.remote_qp);
    } else {
        // Nessun remote → accoda il local
        bpf_map_push_elem(&pending_locals, &local_qp, BPF_ANY);
     //   bpf_printk("PENDING local=0x%x", local_qp);
    }
    return 0;
}
static __always_inline
int get_remote_qp(struct xdp_md *ctx, struct hdr_cursor *cur)
{
    struct tcphdr *tcph = cur_header_pointer(ctx, cur->thoff, sizeof(*tcph));
    if (!tcph) return -1;

    __u32 thlen = tcph->doff << 2;
    if (thlen < sizeof(*tcph)) return -1;

    unsigned char *payload = cur_header_pointer(ctx, cur->thoff + thlen, 16);
    if (!payload) return -1;

    char ascii[7] = {};
#pragma clang loop unroll(full)
    for (int i = 0; i < 6; i++)
        ascii[i] = payload[10 + i];

    __be32 remote_qp = parse_ascii_to_be32(ascii);
 //   bpf_printk("REMOTE QP (parsed): 0x%x", remote_qp);

    __be32 local_qp;
    if (bpf_map_pop_elem(&pending_locals, &local_qp) == 0) {
        // Abbiamo già un local in attesa → accoppia subito
        struct local_info loc = { .local_qp = local_qp };
        struct remote_info rem = { .remote_qp = remote_qp };
        bpf_map_update_elem(&local_remote_association, &loc, &rem, BPF_ANY);
   //     bpf_printk("ASSOCIATED (remote first): local=0x%x remote=0x%x",
               //    loc.local_qp, rem.remote_qp);
    } else {
        // Nessun local → accoda il remote
        bpf_map_push_elem(&pending_remotes, &remote_qp, BPF_ANY);
   //     bpf_printk("PENDING remote=0x%x", remote_qp);
    }
    return 0;
}


static __always_inline
int do_srh_encap_red_ip4_core(struct xdp_md *ctx, struct hdr_cursor *cur,
                              struct iphdr *ip4h)
{
    const __u16 encap_len = SR6_ENCAP_RED_HEADROOM;
    struct ip6_payload_info payload_info = { 0, };
    struct sr6_encap_red_info *einfo;
    struct fib_res_lookup res = {
        .flags = 0,
        .action = XDP_ABORTED,
        .proto = ETH_P_IPV6,
    };
    int rc;
    void *data_meta = (void *)(long)ctx->data_meta;
    struct meta *m = data_meta;

    // xARI --> use it with m->path_id (__u32)

    /* lookup for the IPv4 DA in the encap policy table (per-QP preferred) */
    einfo = encap_policy_lookup_ip4_qp(ctx, cur, ip4h);
    if (!einfo) {
        einfo = encap_policy_lookup_ip4(ip4h);
        if (!einfo)
            return XDP_PASS;
    }

    /* collect info for IPv6 encap */
    payload_info.payload_len = bpf_ntohs(ip4h->tot_len);
    payload_info.nexthdr = IPPROTO_IPIP;
    payload_info.tos = ip4h->tos;
    payload_info.encap_info = einfo;

    /* se è TCP → estrai local_qp per associazione */
    if (ip4h->protocol == IPPROTO_TCP)
        get_local_qp(ctx, cur);

    /* se QP impattato, cambia DSCP in payload_info prima di build_ipv6hdr() */
    __u32 flag_key = 0;
    __u8 *flag_val = bpf_map_lookup_elem(&flagged_qp, &flag_key);
    if (flag_val && *flag_val == 1) {
        __u8 new_dscp = 20 << 2; // DSCP CS1 (0x50)
        __u8 mask = 0xFC;        // primi 6 bit DSCP, ultimi 2 ECN
        payload_info.tos = (payload_info.tos & ~mask) | new_dscp;
        bpf_printk("Encap: DSCP=CS1 set (QP impattato)");
    }

    /* espandi il frame per aggiungere header IPv6 */
    rc = cur_xdp_expand_head(ctx, cur, encap_len);
    if (unlikely(rc))
        goto abort;

    /* rebuild Ethernet header per nuovo frame IPv6 */
    rc = rebuild_mac_header(ctx, cur, encap_len + sizeof(struct ethhdr),
                            ETH_P_IPV6);
    if (unlikely(rc))
        goto abort;

    cur_reset_network_header(cur);

    /* costruisci header IPv6 (usa il DSCP da payload_info.tos) */
    rc = build_ipv6hdr(ctx, cur, &payload_info);
    if (unlikely(rc))
        goto abort;

    /* routing → tail call verso rate limiter */
    bpf_printk("%d",ctx->ingress_ifindex);
    if(ctx->ingress_ifindex==5){
        bpf_tail_call(ctx, &c_prog_array, H_RATE_LIMIT);
    }else{
        bpf_tail_call(ctx, &c_prog_array, H_IPV6);
    }
    return XDP_PASS;

abort:
    return XDP_ABORTED;
}


static __always_inline
int do_srh_encap_ip4(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	struct iphdr *ip4h;
	__u8  hdr_len;
	int nexthdr;

	nexthdr = parse_ip4hdr(ctx, cur, &ip4h);
	if (unlikely(nexthdr < 0)) {
		/* if we are in trouble... pass the packet to the kernel :-) */
		pr_warn("cannot parse IPv4 header; forward it to the kernel stack");
		return XDP_PASS;
	}

	/* IPv4 has been processed;
	 * cur->dataoff points to the end of IPv4 header and we update the
	 * transport header offset accordingly.
	 */
	cur_reset_transport_header(cur);
	
	/* as parse_ip4hdr consumed the IPv4 header, we move back the dataoff;
	 * aligned to network header offset.
	 */
	hdr_len = ip4_header_len(ip4h);
	__push(cur, hdr_len);
	return do_srh_encap_red_ip4_core(ctx, cur, ip4h);
}

SEC("xdp")
int xdp_sr6encap(struct xdp_md *ctx)

{
	struct hdr_cursor _cur, *const cur = &_cur;
	struct ethhdr *eth;
	int eth_type;
	__u16 proto;
	bpf_printk("Encap");
	/* init the header cursor helper structure used for tracking parsed
	 * protocols while packet gets processed. Prepare the metadata as well.
	 */
	cur_init(cur);
	cur_reset_mac_header(cur);
    
    if (!prepare_metadata(ctx)) {
        pr_err("cannot prepare metadata");
        return XDP_ABORTED;
    }

	eth_type = parse_ethhdr(ctx, cur, &eth);
	if (unlikely(eth_type < 0)) {
		pr_warn("cannot parse Ethernet header; forward it to the kernel stack");
		goto pass;
	}

	cur_reset_network_header(cur);

	proto = bpf_ntohs((__be16)eth_type);
	if (proto != ETH_P_IP)
		goto pass;

	/* we do not need to care about VLANs as we have just checked the proto
	 * type AND is NOT vlan!
	 */

	return do_srh_encap_ip4(ctx, cur);

pass:
	return XDP_PASS;
}

static __always_inline
struct sr6_decap_info *sr6_decap_sid_lookup(const struct in6_addr *sid)
{
	return bpf_map_lookup_elem(&sr6decap_table, sid);
}

static __always_inline
int process_decap_ip4(struct xdp_md *ctx, struct hdr_cursor *cur, __u8 tclass,
		      __u32 tbid)
{
	struct fib_res_lookup res = {
		.flags = BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_TBID,
		.action = XDP_ABORTED,
		.tbid = tbid,
		.proto = ETH_P_IP,
	};
	struct iphdr *ip4h;
	int nexthdr;

	nexthdr = parse_ip4hdr(ctx, cur, &ip4h);
	if (unlikely(nexthdr < 0)) {
		/* if we are in trouble... pass the packet to the kernel :-) */
		pr_warn("cannot parse IPv4 header; forward it to the kernel stack");
		return XDP_PASS;
	}

	cur_reset_transport_header(cur);

	/* update the IPvv4 TOS field */
	/*ipv4_change_dsfield(ip4h, 0xff, tclass);

	return ip4_packet_forward(ctx, cur, &res);
	
	*/
	if(nexthdr==IPPROTO_TCP){
		get_remote_qp(ctx,cur);

	}else if (nexthdr == IPPROTO_UDP) {
			

            struct udphdr *udph = (void *)cur_header_pointer(ctx, cur->thoff, sizeof(*udph));
            if (udph && bpf_ntohs(udph->dest) == 4791 /* RoCEv2 */) {

                __u16 udp_len = bpf_ntohs(udph->len); //udph->len contains udp lenght: header + payload
                if (udp_len >= 8 + 12) { // header UDP (8) + 12 byte minimi di BTH
                    /* Sposta il cursore all’inizio del BTH */
                    cur_pull(ctx, cur, sizeof(*udph));
					
                    /* Misura throughput per-QP + eventuale flip SID dopo 200ms < 0.5Gbps */
                    qp_update_throughput_and_maybe_reroute(ctx, cur, ip4h, udp_len);

                } else {
                    bpf_printk("RoCEv2: UDP too short (%u)\n", udp_len);
                }
    		}
	}


        ipv4_change_dsfield(ip4h, 0xff, tclass);
        bpf_printk("decap processed");

        return ip4_packet_forward(ctx, cur, &res);

}

static __always_inline
int do_srh_decap_ip4_core(struct xdp_md *ctx, struct hdr_cursor *cur,
			  struct ipv6hdr *ip6h)
{
	const struct in6_addr *da = &ip6h->daddr;
	struct sr6_decap_info *dinfo;
	int shrinklen;
	__u8 tclass;
	__u32 tbid;
	int rc;

	/* check whether the currend IPv6 DA is bound to a decap SID */
	dinfo = sr6_decap_sid_lookup(da);
	if (!dinfo) {
#define __addr32(DA, IDX) bpf_ntohl((DA)->in6_u.u6_addr32[(IDX)])
		/* No decap SID found */
		pr_debug("No decap SID found for IPv6 DA %x %x %x %x",
			 __addr32(da, 0), __addr32(da, 1),
			 __addr32(da, 2), __addr32(da, 3));
		return XDP_PASS;
#undef __addr32
	}

	tclass = ipv6_get_dsfield(ip6h);
	/* retrieve the table id used for fib lookup on decap packet */
	tbid = dinfo->tbid;

	/* dataoff and thoff are aligned at this point */
	shrinklen = cur->dataoff - sizeof(struct ethhdr);
	if (unlikely(shrinklen < 0)) {
		pr_err("invalid size (%d) for xdp frame shrink operation",
		        shrinklen);
		goto abort;
	}

	/* set nhoff aligned with dataoff/thoff */
	cur_reset_network_header(cur);

	/* mhoff maclen   dataoff = nhoff = thoff
	 * |.....|       /
	 * v     v      v
	 * +-----+------+-------+-----+
	 * | MAC | IPv6 | IPv4  | ... |
	 * +-----+------+-------+-----+
	 *        \____/
	 *          |
	 *     to shrink
	 */

	/* rebuild the mac header considering the encap overhead */
	rc = rebuild_mac_header(ctx, cur, sizeof(struct ethhdr), ETH_P_IP);
	if (unlikely(rc))
		goto abort;

	/* 0     mhoff     dataoff = nhoff = thoff
	 * |      |      /
	 * v      v     v
	 * +------+-----+-------+-----+
	 * | xxxx | MAC | IPv4  | ... |
	 * +------+-----+-------+-----+
	 *  \____/
	 *    |
	 *   to be removed as the packet gets shrunk
	 */

	rc = cur_xdp_shrink_head(ctx, cur, shrinklen);
	if (unlikely(rc))
		goto abort;

	return process_decap_ip4(ctx, cur, tclass, tbid);

abort:
	return XDP_ABORTED;
}

static __always_inline
int do_srh_decap_ip4(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	struct ipv6hdr *ip6h;
	int nexthdr;

	nexthdr = parse_ip6hdr(ctx, cur, &ip6h);
	if (unlikely(nexthdr < 0)) {
		/* if we are in trouble... pass the packet to the kernel :-) */
		pr_warn("cannot parse IPv6 header; forward it to the kernel stack");
		goto pass;
	}

	/* let's check the nexthdr type; ATM we only support IPv4 directly
	 * encapsulated.
	 */
	if (nexthdr != IPPROTO_IPIP)
		goto pass;

	/* transport header offset now points to IPv4 header */
	cur_reset_transport_header(cur);

	return do_srh_decap_ip4_core(ctx, cur, ip6h);

pass:
	return XDP_PASS;
}

SEC("xdp/devmap")
int xdp_sr6decap(struct xdp_md *ctx)
{
	struct hdr_cursor _cur, *const cur = &_cur;
	struct ethhdr *eth;
	int eth_type;
	__u16 proto;
	bpf_printk("Decap");
	/* init the header cursor helper structure used for tracking parsed
	 * protocols while packet gets processed.
	 */
	cur_init(cur);
	cur_reset_mac_header(cur);

	eth_type = parse_ethhdr(ctx, cur, &eth);
	if (unlikely(eth_type < 0)) {
		pr_warn("cannot parse Ethernet header; forward it to the kernel stack");
		goto pass;
	}

	cur_reset_network_header(cur);

	proto = bpf_ntohs((__be16)eth_type);
	if (proto != ETH_P_IPV6)
		goto pass;

	/* we do not need to care about VLANs as we have just checked the proto
	 * type AND is NOT vlan!
	 */

	return do_srh_decap_ip4(ctx, cur);

pass:
	return XDP_PASS;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";








#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

struct sr6_encap_red_info {
	struct in6_addr tunsrc;
	struct in6_addr sid;
};
static const struct in6_addr PRIMARY_SID = {
    .in6_u.u6_addr8 = {
        0xfc, 0xf0, 0x00, 0x00, 0x00, 0xb1, 0x00, 0x0e,
        0x00, 0xa2, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x00
    }
};
static const struct in6_addr SECONDARY_SID = {
    .in6_u.u6_addr8 = {
        0xfc, 0xf0, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x0e,
        0x00, 0xa2, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x00
    }
};
static const struct in6_addr TUN_SRC = {
    .in6_u.u6_addr8 = {
        0xfd, 0x00, 0x00, 0xa1, 0x00, 0xb0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    }
};
/*structures to mantain the association between local and remote information (at the moment only QP number)*/
struct local_info{
	__be32 local_qp;
};

struct remote_info{
	__be32 remote_qp;
};

#define INFO_MAX_ASSOC	256
struct{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, INFO_MAX_ASSOC);
	__type(key, struct remote_info);
	__type(value, struct local_info);

}local_remote_assoc SEC(".maps");



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
#define BASE_THRESHOLD_BPS  (10000000000ULL)   // 10 Gbps
#define BELOW_TARGET_NS     (1000000ULL)   // 1 ms

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, QP_STATS_MAX);
    __type(key, __be32);            
    __type(value, struct qp_stats);
} qp_throughput SEC(".maps");

//helper to extract QP from BTH
static __always_inline bool rocev2_extract_qpn(void *bth, void *data_end, __u32 *qpn_out)
{
    const __u8 *p = bth;
    /* servono almeno 8 byte del BTH per arrivare a p[7] */
    if ((void *)(p + 8) > data_end)
        return false;

    __u32 raw32 = 0;
    raw32 = ((__u32)p[5] << 16) | ((__u32)p[6] << 8) | (__u32)p[7];
    // bpf_printk("BTH[5..7]= %02x %02x %02x  raw32=0x%x\n",
    //               p[5], p[6], p[7], raw32);
    *qpn_out =raw32;
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


static __always_inline
int get_remote_qp(struct xdp_md *ctx, struct hdr_cursor *cur)
{
    void *data_end = (void *)(long)ctx->data_end;

    /* tcph all’inizio del trasporto: usa cur->thoff e non toccare cur->pos */
    struct tcphdr *tcph = (struct tcphdr *)cur_header_pointer(ctx, cur->thoff, sizeof(*tcph));
    if (!tcph)
        return -1;

    __u32 thlen = (__u32)tcph->doff << 2;
    if (thlen < sizeof(*tcph))
        return -1;

    /* Puntatore al payload TCP: vogliamo almeno 16 byte per leggere DATA[15] */
    unsigned char *payload = (unsigned char *)cur_header_pointer(ctx, cur->thoff + thlen, 16);
    if (!payload)
        return -1;

    char ascii[7] = {0};
#pragma clang loop unroll(full)
    for (int i = 0; i < 6; i++) {
        ascii[i] = payload[10 + i];
    }
    ascii[6] = '\0';

    bpf_printk("REMOTE QP: ASCII DATA[10..15] = %s\n", ascii);
	bpf_printk("be32:  0x%x",parse_ascii_to_be32(ascii));

    return 0;
}


int get_local_qp(struct xdp_md *ctx, struct hdr_cursor *cur)
{
    void *data_end = (void *)(long)ctx->data_end;

    /* tcph all’inizio del trasporto: usa cur->thoff e non toccare cur->pos */
    struct tcphdr *tcph = (struct tcphdr *)cur_header_pointer(ctx, cur->thoff, sizeof(*tcph));
    if (!tcph)
        return -1;

    __u32 thlen = (__u32)tcph->doff << 2;
    if (thlen < sizeof(*tcph))
        return -1;

    /* Puntatore al payload TCP: vogliamo almeno 16 byte per leggere DATA[15] */
    unsigned char *payload = (unsigned char *)cur_header_pointer(ctx, cur->thoff + thlen, 16);
    if (!payload)
        return -1;

    char ascii[7] = {0};
#pragma clang loop unroll(full)
    for (int i = 0; i < 6; i++) {
        ascii[i] = payload[10 + i];
    }
    ascii[6] = '\0';

    bpf_printk("LOCAL QP: ASCII DATA[10..15] = %s\n", ascii);
    return 0;
}




// Aggiorna o toggla la policy per (dst_ip, qpn).
// Se non esiste entry per-QP, prende tunsrc/sid dal fallback per-dest.
static __always_inline void flip_route_for_ip_qp(__be32 dst_ip_n, __u32 dqpn)
{
   // bpf_printk("flipping route");
    struct encap_qp_key k = { .dst_ip = bpf_ntohl(dst_ip_n), .qpn =dqpn};
   // bpf_printk("address in the key 0x%x", k.dst_ip);
   // bpf_printk("qpn in the key 0x%x", k.qpn);
    struct sr6_encap_red_info base = {0};
    struct sr6_encap_red_info *cur = bpf_map_lookup_elem(&sr6encap_ip4_qp_table, &k);

    if (cur) {
        // toggla PRIMARY <-> SECONDARY, mantieni tunsrc
       

        struct sr6_encap_red_info newv = {0};
        __builtin_memcpy(&newv.tunsrc, &cur->tunsrc, sizeof(newv.tunsrc));
        if (__builtin_memcmp(&cur->sid, &PRIMARY_SID, sizeof(PRIMARY_SID)) == 0){
			//bpf_printk("primary SID detected: %u",cur->sid);
            __builtin_memcpy(&newv.sid, &SECONDARY_SID, sizeof(newv.sid));}
        else{
			//bpf_printk("secondary SID detected: %u", cur->sid);
            __builtin_memcpy(&newv.sid, &PRIMARY_SID, sizeof(newv.sid));}
        bpf_map_update_elem(&sr6encap_ip4_qp_table, &k, &newv, BPF_ANY);
        return;
    }
  /*
  //entry per QP dovrebbe già esser stata inizializzata
    // Nessuna entry per-QP: prendi fallback per-dest come base
    __u32 dst_host = bpf_ntohl(dst_ip_n);
    struct sr6_encap_red_info *fallback = bpf_map_lookup_elem(&sr6encap_ip4_table, &dst_host);
    if (fallback) {
        base = *fallback;
    } else {
        
        __builtin_memcpy(&base.tunsrc, &TUN_SRC, sizeof(base.tunsrc));
        __builtin_memcpy(&base.sid, &PRIMARY_SID, sizeof(base.sid));
    }

   
    if (__builtin_memcmp(&base.sid, &PRIMARY_SID, sizeof(PRIMARY_SID)) == 0)
        __builtin_memcpy(&base.sid, &SECONDARY_SID, sizeof(base.sid));
    else
        __builtin_memcpy(&base.sid, &PRIMARY_SID, sizeof(base.sid));

    bpf_map_update_elem(&sr6encap_ip4_qp_table, &k, &base, BPF_ANY);*/
}


// Call dopo cur_pull(...udph) → cur è all'inizio del BTH
static __always_inline void qp_update_throughput_and_maybe_reroute(struct xdp_md *ctx,
                                                                   struct hdr_cursor *cur,
                                                                   struct iphdr *ip4h,
                                                                   __u16 udp_len)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *bth      = cur_data(ctx, cur);
    __u32 qpn;
    if (!rocev2_extract_qpn(bth, data_end, &qpn))
        return;

    __u64 now   = bpf_ktime_get_ns();
    __u64 bytes = (udp_len >= 8) ? (udp_len - 8) : 0;

    /* --- se non c’è ancora entry per-QP, copia quella per-dest se esiste --- */
    struct encap_qp_key k = { .dst_ip = bpf_ntohl(ip4h->saddr), .qpn =qpn};
 //   bpf_printk("qpn in the key 0x%x", k.qpn);
    
    struct sr6_encap_red_info *curv = bpf_map_lookup_elem(&sr6encap_ip4_qp_table, &k);
    if(curv){
        const __u8 *ts = curv->tunsrc.in6_u.u6_addr8;
        const __u8 *sd = curv->sid.in6_u.u6_addr8;
        
       /* bpf_printk("tunsrc = %02x %02x %02x %02x %02x %02x %02x %02x\n",
                   ts[0], ts[1], ts[2], ts[3], ts[4], ts[5], ts[6], ts[7]);
        bpf_printk("         %02x %02x %02x %02x %02x %02x %02x %02x\n",
                   ts[8], ts[9], ts[10], ts[11], ts[12], ts[13], ts[14], ts[15]);

        bpf_printk("sid    = %02x %02x %02x %02x %02x %02x %02x %02x\n",
                   sd[0], sd[1], sd[2], sd[3], sd[4], sd[5], sd[6], sd[7]);
        bpf_printk("         %02x %02x %02x %02x %02x %02x %02x %02x\n",
                   sd[8], sd[9], sd[10], sd[11], sd[12], sd[13], sd[14], sd[15]);*/
    }    
               
               
    if (!curv) {
     //   bpf_printk("Entry not found");
        struct sr6_encap_red_info init = {0,};

        __u32 dst_host = bpf_ntohl(ip4h->saddr);
        struct sr6_encap_red_info *fallback = bpf_map_lookup_elem(&sr6encap_ip4_table, &dst_host);

        if (fallback) {
            /* copia direttamente la policy di fallback */
            init = *fallback;
        } else {
            /* nessuna entry nemmeno per-dest: usa un default */
            __builtin_memcpy(&init.tunsrc, &TUN_SRC, sizeof(TUN_SRC));
            __builtin_memcpy(&init.sid, &PRIMARY_SID, sizeof(PRIMARY_SID));
        }

        bpf_map_update_elem(&sr6encap_ip4_qp_table, &k, &init, BPF_ANY); 
    //    bpf_printk("QP init: dst=%x qpn=0x%x (da fallback? %s)\n",
      //             bpf_ntohl(ip4h->saddr),qpn,
        //           fallback ? "YES" : "DEFAULT");
    }

    /* --- update throughput --- */
   
    struct qp_stats *st = bpf_map_lookup_elem(&qp_throughput, &qpn);
    if (!st) {
        struct qp_stats init_st = {.bytes=bytes, .start_ns=now, .last_ns=now};
        bpf_map_update_elem(&qp_throughput, &qpn, &init_st, BPF_ANY);
        return;
    }

    st->bytes  += bytes;
    st->last_ns = now;

    __u64 dt = now - st->start_ns;
  

    __u64 bps = st->bytes ? (st->bytes * 8ULL * 1000000000ULL) / dt : 0;
    st->last_bps = bps;
  //  bpf_printk("throughput: %ld", st->last_bps);
    if (bps < BASE_THRESHOLD_BPS) {
        st->below_ns_accum += dt;
        if (st->below_ns_accum >= BELOW_TARGET_NS) {
            /* flip della rotta solo dopo soglia */
            flip_route_for_ip_qp(ip4h->saddr,  qpn);
            st->below_ns_accum = 0;
        }
    } else {
        st->below_ns_accum = 0;
    }

    st->bytes    = 0;
    st->start_ns = now;
}


static __always_inline
struct sr6_encap_red_info *encap_policy_lookup_ip4(const struct iphdr *ip4h)
{
	const __u32 addr = bpf_ntohl(ip4h->daddr);

	return bpf_map_lookup_elem(&sr6encap_ip4_table, &addr);
}
//helper for the encapsulation using the QP logic
//Lookup in the per-QP table, otherwise fallback dest table
static __always_inline
struct sr6_encap_red_info *encap_policy_lookup_ip4_qp(struct xdp_md *ctx,
                                                      struct hdr_cursor *cur,
                                                      const struct iphdr *ip4h)
{
    // cur->thoff è alla fine dell'IPv4 header (grazie a do_srh_encap_ip4)
    struct udphdr *udph = (void *)cur_header_pointer(ctx, cur->thoff, sizeof(*udph));
    void *data_end = (void *)(long)ctx->data_end;
    /* BTH parte subito dopo l’UDP header, all’offset thoff + sizeof(udph) */
    void *bth = cur_header_pointer(ctx, cur->thoff + sizeof(*udph), 12);
    __u32 dqpn;
    if (bth && rocev2_extract_qpn(bth, data_end, &dqpn)) {
        
           struct encap_qp_key k = { .dst_ip = bpf_ntohl(ip4h->daddr), .qpn =dqpn };
          // bpf_printk("dst_ip: 0x%32x qpn retrieved:0x%06x",k.dst_ip, k.qpn);
            
            struct sr6_encap_red_info *v = bpf_map_lookup_elem(&sr6encap_ip4_qp_table, &k);
            if (v) {
            /*   bpf_printk("entry found: dst=%pI4 qpn=0x%06x (%u)\n",
                           &ip4h->daddr, dqpn & 0xFFFFFF, dqpn);*/
               return v;
           }
      } else {
           // __push(cur, sizeof(*udph));
           /*fallback per-dest */
            return encap_policy_lookup_ip4(ip4h);

        }
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

static __always_inline
int xdp_fwd(struct xdp_md *ctx, struct hdr_cursor *cur,
	    struct fib_res_lookup *res)
{
	struct bpf_fib_lookup *fib_params = &res->fib_params;
	int *action = &res->action;
	__u32 proto = res->proto;
	__u32 tbid = res->tbid;
	struct ipv6hdr *ip6h;
	struct iphdr *ip4h;
	int rc;

	memset((void *)fib_params, 0, sizeof(*fib_params));

	if (proto == ETH_P_IPV6) {
		struct in6_addr *saddr, *daddr;
		__be32 flowlabel;

		ip6h = get_ipv6hdr(ctx, cur);
		if (unlikely(!ip6h)) {
			pr_err("invalid access to IPv6 header");
			goto error;
		}

		if (ip6h->hop_limit <= 1) {
			pr_debug("hop limit is <= 1, forward it to the kernel stack");
			return XDP_PASS;
		}

		saddr = (struct in6_addr *)fib_params->ipv6_src;
		daddr = (struct in6_addr *)fib_params->ipv6_dst;

		flowlabel = ip6_flowlabel(ip6h);

		fib_params->family	= AF_INET6;
		fib_params->flowinfo	= flowlabel;
		fib_params->l4_protocol	= ip6h->nexthdr;
		fib_params->tot_len	= bpf_ntohs(ip6h->payload_len);
		*saddr			= ip6h->saddr;
		*daddr			= ip6h->daddr;
	} else if (proto == ETH_P_IP) {
		ip4h = get_ipv4hdr(ctx, cur);
		if (unlikely(!ip4h)) {
			pr_err("invalid access to IPv4 header");
			goto error;
		}

		if (ip4h->ttl <= 1) {
			pr_debug("ttl <= 1, forward it to the kernel stack");
			return XDP_PASS;
		}

		fib_params->family	= AF_INET;
		fib_params->tos		= ip4h->tos;
		fib_params->l4_protocol	= ip4h->protocol;
		fib_params->tot_len	= bpf_ntohs(ip4h->tot_len);
		fib_params->ipv4_src	= ip4h->saddr;
		fib_params->ipv4_dst	= ip4h->daddr;
	} else {
		pr_warn("xdp forward unsupported protocol 0x%x", proto);
		return XDP_PASS;
	}

	if (tbid)
		fib_params->tbid = tbid;

	fib_params->sport	= 0;
	fib_params->dport	= 0;
	fib_params->ifindex	= ctx->ingress_ifindex;

	rc = fib_lookup(ctx, cur, res);
	if (unlikely(rc < 0))
		goto error;
	if (rc != BPF_FIB_LKUP_RET_SUCCESS)
		goto out;

	/* decrease hop limit or ttl depending on the current protocol */
	if (proto == ETH_P_IPV6)
		ip6h->hop_limit--;
	else if (proto == ETH_P_IP)
		ip_decrease_ttl(ip4h);
out:
	return *action;

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

static __always_inline
int ip6_packet_forward(struct xdp_md *ctx, struct hdr_cursor *cur,
		       struct fib_res_lookup *res)
{
#ifdef ROUTING_ACC
	/* route the packet within XDP context */
	return ipv6_route(ctx, cur, res);
#else
	/* pass the packet up to the kernel stack */
	pr_debug("forward encap packet to the kernel stack");
	return XDP_PASS;
#endif
}

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

/* NOTE: ATM we support only 1 sid in the encap policy */
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

	

	/* lookup for the IPv4 DA in the encap policy table */
	//einfo = encap_policy_lookup_ip4(ip4h);
	einfo = encap_policy_lookup_ip4_qp(ctx, cur, ip4h); //substitution with per-qp lookup function

	if (!einfo) {
		
		einfo = encap_policy_lookup_ip4(ip4h);
		if (!einfo) {
			bpf_printk("encap policy for IPv4 DA %x not found",
				bpf_ntohl(ip4h->daddr));
			return XDP_PASS;
		}
	}


	/* collect all the data for proceeding with encap */
	payload_info.payload_len = bpf_ntohs(ip4h->tot_len);
	payload_info.nexthdr = IPPROTO_IPIP;
	payload_info.tos = ip4h->tos;
	bpf_printk("tos field: %u", ip4h->tos);

	payload_info.encap_info = einfo;

	/* expand the xdp frame. Note that xdp frame pointers will be
	 * invalidated after this operation.
	 */
	rc = cur_xdp_expand_head(ctx, cur, encap_len);
	if (unlikely(rc))
		goto abort;

	/* rebuild the mac header considering the encap overhead */
	rc = rebuild_mac_header(ctx, cur, encap_len + sizeof(struct ethhdr),
				ETH_P_IPV6);
	if (unlikely(rc))
		goto abort;

	cur_reset_network_header(cur);

	/* build the ipv6 header with encap */
	rc = build_ipv6hdr(ctx, cur, &payload_info);
	if (unlikely(rc))
		goto abort;

	/* forward the packet doing routing lookup */
	return ip6_packet_forward(ctx, cur, &res);

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

SEC("__xdp_sr6encap")
int xdp_sr6encap(struct xdp_md *ctx)
{
	struct hdr_cursor _cur, *const cur = &_cur;
	struct ethhdr *eth;
	int eth_type;
	__u16 proto;

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

                __u16 udp_len = bpf_ntohs(udph->len);
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


        // aggiorna DSCP/ECT dal tclass e fai forward
        ipv4_change_dsfield(ip4h, 0xff, tclass);
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

SEC("__xdp_sr6decap")
int xdp_sr6decap(struct xdp_md *ctx)
{
	struct hdr_cursor _cur, *const cur = &_cur;
	struct ethhdr *eth;
	int eth_type;
	__u16 proto;

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

SEC("__xdp_pass")
int xdp_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";



#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"
#include "parse_helpers.h"

/* define routing acceleration; if set the routing is carried out in XDP/eBPF
 * context and packet is directly redirect to the egress device; Otherwise, the
 * packet is passed up to thek kernel stack for further processing.
*/
#if 0
#define ROUTING_ACC
#endif

struct sr6_encap_red_info {
	struct in6_addr tunsrc;
	struct in6_addr sid;
};
#define SR6_ENCAP_RED_HEADROOM sizeof(struct ipv6hdr)

struct sr6_decap_info {
	__u64 reserved;
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

static __always_inline
struct sr6_encap_red_info *encap_policy_lookup_ip4(const struct iphdr *ip4h)
{
	const __u32 addr = bpf_ntohl(ip4h->daddr);

	return bpf_map_lookup_elem(&sr6encap_ip4_table, &addr);
}

static __always_inline
int cur_xdp_expand_head(struct xdp_md *ctx, struct hdr_cursor *cur, int len)
{
	int rc;

	/* expand the xdp frame */
	rc = cur_xdp_adjust_head(ctx, cur, -len);
	if (unlikely(rc)) {
		bpf_printk("cannot expand the xdp frame correctly");
		return rc;
	}

	return 0;
}

static __always_inline
int cur_xdp_shrink_head(struct xdp_md *ctx, struct hdr_cursor *cur, int len)
{
	int rc;

	/* shrink the xdp frame */
	rc = cur_xdp_adjust_head(ctx, cur, len);
	if (unlikely(rc)) {
		bpf_printk("cannot shrink the xdp frame correctly");
		return rc;
	}

	return 0;
}

static __always_inline int vlan_check(struct hdr_cursor *cur)
{
	int maclen = cur->nhoff - cur->mhoff;

	return (maclen == sizeof(struct ethhdr)) ? 0 : -EOPNOTSUPP;
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
	bpf_printk("invalid access to ethernet header");
	return -EINVAL;
#undef get_ethhdr
}

struct ip6_payload_info {
	struct sr6_encap_red_info *encap_info;
	__u16 payload_len;
	__u8 nexthdr;
	__u8 tos;
};

#define get_ipv6hdr(ctx, cur)						\
	((struct ipv6hdr *)cur_header_pointer(ctx, (cur)->nhoff,	\
					      sizeof(struct ipv6hdr)))

#ifdef ROUTING_ACC
static __always_inline
int ipv6_route(struct xdp_md *ctx, struct hdr_cursor *cur, __u32 flags)
{
	struct bpf_fib_lookup fib_params;
	struct in6_addr *saddr, *daddr;
	struct ipv6hdr *ip6h;
	struct ethhdr *eth;
	__be32 flowlabel;
	int action;
	int rc;

	memset((void *)&fib_params, 0, sizeof(fib_params));

	ip6h = get_ipv6hdr(ctx, cur);
	if (unlikely(!ip6h))
		goto error;

	if (ip6h->hop_limit <= 1)
		/* we let the kernel decide what to do in this situation */
		return XDP_PASS;

	saddr = (struct in6_addr *)fib_params.ipv6_src;
	daddr = (struct in6_addr *)fib_params.ipv6_dst;

	flowlabel = ip6_flowlabel(ip6h);

	*saddr			= ip6h->saddr;
	*daddr			= ip6h->daddr;
	fib_params.family	= AF_INET6;
	fib_params.flowinfo	= flowlabel;
	fib_params.tot_len	= bpf_ntohs(ip6h->payload_len);
	fib_params.l4_protocol	= ip6h->nexthdr;
	fib_params.sport	= 0;
	fib_params.dport	= 0;
	fib_params.ifindex	= ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), flags);
	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:
		/* lookup successful */

		/* decrease the hop-limit and prepare the ethernet layer
		 * for submitting the frame.
		 */
		ip6h->hop_limit--;

		eth = cur_header_pointer(ctx, cur->mhoff, sizeof(*eth));
		if (unlikely(!eth))
			goto error;

		memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

		action = bpf_redirect(fib_params.ifindex, 0);
		break;

	case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
		action = XDP_DROP;
		break;

	case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
	case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
		action = XDP_PASS;
		break;
	}

	return action;

error:
	return XDP_ABORTED;
}
#endif

static __always_inline
int ip6_packet_forward(struct xdp_md *ctx, struct hdr_cursor *cur, __u32 flags)
{
#ifdef ROUTING_ACC
	/* route the packet within XDP context */
	return ipv6_route(ctx, cur, flags);
#else
	/* pass the packet up to the kernel stack */
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
		bpf_printk("invalid access to ipv6 header");
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
	int rc;

	/* lookup for the IPv4 DA in the encap policy table */
	einfo = encap_policy_lookup_ip4(ip4h);
	if (!einfo)
		/* policy not found */
		return XDP_PASS;

	/* collect all the data for proceeding with encap */
	payload_info.payload_len = bpf_ntohs(ip4h->tot_len);
	payload_info.nexthdr = IPPROTO_IPIP;
	payload_info.tos = ip4h->tos;

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
	return ip6_packet_forward(ctx, cur, 0);

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
	if (unlikely(nexthdr < 0))
		/* if we are in trouble... pass the packet to the kernel :-) */
		return XDP_PASS;

	/* IPv4 has been processed;
	 * cur->dataoff points to the end of IPv4 header and we update the
	 * transport header offset accordingly.
	 */
	cur_reset_transport_header(cur);

	/* as parse_ip4hdr consumed the IPv4 header, we move backt the dataoff;
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
	if (unlikely(eth_type < 0))
		goto pass;

	cur_reset_network_header(cur);

	proto = bpf_ntohs((__be16)eth_type);
	if (proto != ETH_P_IP)
		/* ATM we are only processing IPv4 traffic */
		goto pass;

	return do_srh_encap_ip4(ctx, cur);

pass:
	return XDP_PASS;
}

static __always_inline int sr6_decap_sid_lookup(const struct in6_addr *sid)
{
	return bpf_map_lookup_elem(&sr6decap_table, sid) ? 0 : -ENOENT;
}

static __always_inline
int process_decap_ip4(struct xdp_md *ctx, struct hdr_cursor *cur, __u8 tclass)
{
	struct iphdr *ip4h;
	int nexthdr;

	nexthdr = parse_ip4hdr(ctx, cur, &ip4h);
	if (unlikely(nexthdr < 0))
		/* if we are in trouble... pass the packet to the kernel :-) */
		return XDP_PASS;

	cur_reset_transport_header(cur);

	/* update the IPvv4 TOS field */
	ipv4_change_dsfield(ip4h, 0xff, tclass);

	return XDP_PASS;
}

static __always_inline
int do_srh_decap_ip4_core(struct xdp_md *ctx, struct hdr_cursor *cur,
			  struct ipv6hdr *ip6h)
{
	const struct in6_addr *da = &ip6h->daddr;
	int shrinklen;
	__u8 tclass;
	int rc;

	/* check whether the currend IPv6 DA is bound to a decap SID */
	rc = sr6_decap_sid_lookup(da);
	if (rc) {
		if (likely(rc == -ENOENT))
			/* No decap SID found */
			return XDP_PASS;

		goto abort;
	}

	tclass = ipv6_get_dsfield(ip6h);

	/* dataoff and thoff are aligned at this point */
	shrinklen = cur->dataoff - sizeof(struct ethhdr);
	if (unlikely(shrinklen < 0)) {
		bpf_printk("invalid size for xdp frame shrink operation");
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

	return process_decap_ip4(ctx, cur, tclass);

abort:
	return XDP_ABORTED;
}

static __always_inline
int do_srh_decap_ip4(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	struct ipv6hdr *ip6h;
	int nexthdr;

	nexthdr = parse_ip6hdr(ctx, cur, &ip6h);
	if (unlikely(nexthdr < 0))
		/* if we are in trouble... pass the packet to the kernel :-) */
		goto pass;

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
	if (unlikely(eth_type < 0))
		goto pass;

	cur_reset_network_header(cur);

	if (vlan_check(cur))
		/* VLAn is not supported yet */
		goto pass;

	proto = bpf_ntohs((__be16)eth_type);
	if (proto != ETH_P_IPV6)
		goto pass;

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

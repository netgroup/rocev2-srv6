
#ifndef _PARSE_HELPERS_H
#define _PARSE_HELPERS_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "hdr_cursor.h"

#define ETH_ALEN		6

#define AF_INET			2
#define AF_INET6		10

#define ETH_P_IP		0x0800 /* Internet Protocol v4 */
#define ETH_P_IPV6		0x86dd /* Internet Protocol v6 */
#define ETH_P_8021Q		0x8100	/* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD		0x88A8	/* 802.1ad Service VLAN */

/* NextHeader field of IPv6 header
 * see: https://elixir.bootlin.com/linux/latest/source/include/net/ipv6.h#L32
 */

#define NEXTHDR_HOP		0	/* Hop-by-hop option header. */
#define NEXTHDR_IPV4		4	/* IPv4 in IPv6 */
#define NEXTHDR_TCP		6	/* TCP segment. */
#define NEXTHDR_UDP		17	/* UDP message. */
#define NEXTHDR_IPV6		41	/* IPv6 in IPv6 */
#define NEXTHDR_ROUTING		43	/* Routing header. */
#define NEXTHDR_FRAGMENT	44	/* Fragmentation/reassembly header. */
#define NEXTHDR_GRE		47	/* GRE header. */
#define NEXTHDR_ESP		50	/* Encapsulating security payload. */
#define NEXTHDR_AUTH		51	/* Authentication header. */
#define NEXTHDR_ICMP		58	/* ICMP for IPv6. */
#define NEXTHDR_NONE		59	/* No next header */
#define NEXTHDR_DEST		60	/* Destination options header. */
#define NEXTHDR_SCTP		132	/* SCTP message. */
#define NEXTHDR_MOBILITY	135	/* Mobility header. */

#define NEXTHDR_MAX		255

/* @see
 * https://elixir.bootlin.com/linux/v6.13.4/source/include/net/dsfield.h#L22
 */


static __always_inline
void ipv4_change_dsfield(struct iphdr *iph,__u8 mask, __u8 value)
{
        __u32 check = bpf_ntohs((__be16)iph->check);
	__u8 dsfield = (iph->tos & mask) | value;

	check += iph->tos;
	if ((check + 1) >> 16)
		check = (check + 1) & 0xffff;

	check -= dsfield;
	 /* adjust carry */
	check += check >> 16;

	iph->check = (__be16)bpf_htons(check);
	iph->tos = dsfield;
}

static __always_inline  __u8 ipv4_get_dsfield(const struct iphdr *iph)
{
	return iph->tos;
}

static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = (__u32)iph->check;

	check += (__u32)bpf_htons(0x0100);
	iph->check = ( __be16)(check + (check >= 0xffff));

	return --iph->ttl;
}

#define IPV6_FLOWLABEL_MASK	bpf_htonl(0x0FFFFFFF)
static inline __be32 ip6_flowlabel(const struct ipv6hdr *hdr)
{
	return *(__be32 *)hdr & IPV6_FLOWLABEL_MASK;
}

static __always_inline __u8 ipv6_get_dsfield(const struct ipv6hdr *ip6h)
{
	return bpf_ntohs(*(const __be16 *)ip6h) >> 4;
}

static __always_inline
void ipv6_set_dsfield(struct ipv6hdr *const ip6h, __u8 mask, __u8 value)
{
	__be16 *p = (__be16 *)ip6h;

	/* A bit of explaination here, first 32 bits of an IPv6 packet:
	 * --------------------------------------------------------------------
	 * | Version (4 bits) | Traffic Class (8 bits) | Flow Label (20 bits) |
	 * --------------------------------------------------------------------
	 *
	 * we need to write in the Traffic Class, so we have to shift (left)
	 * both mask and value of 4 bits. Then, we need to keep the 4 bits of
	 * version field and the first 4 bits of the Flow Label field. So, here
	 * we have the mask 0xf00f.
	 * At this point it is just a matter of doing the bit-bit AND between
	 * the previous value of *p (the overall first 16 bits of the packet)
	 * with the adjusted mask value. Therefore, we proceed to consider the
	 * dscp value (doing the bit-bit OR).
	 */
	*p = (*p & bpf_htons((((__u16)mask << 4) | 0xf00f))) |
	      bpf_htons((__u16)value << 4);
}

/* Allow users of header file to redefine VLAN max depth */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 4
#endif

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int
parse_ethhdr(struct xdp_md *ctx, struct hdr_cursor *cur, struct ethhdr **ethhdr)
{
	struct ethhdr *eth = (struct ethhdr *)cur_data(ctx, cur);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (!cur_may_pull(ctx, cur, sizeof(*eth)))
		return -ENOBUFS;

	if (ethhdr)
		*ethhdr = eth;

	vlh = (struct vlan_hdr *)cur_pull(ctx, cur, sizeof(*eth));
	h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (!cur_may_pull(ctx, cur, sizeof(*vlh)))
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		cur_pull(ctx, cur, sizeof(*vlh));
	}
	return h_proto; /* network-byte-order */
}

static __always_inline __u8 ip4_header_len(struct iphdr *ip4h)
{
	return ip4h->ihl << 2;
}

static __always_inline
int parse_ip4hdr(struct xdp_md *ctx, struct hdr_cursor *cur,
		 struct iphdr **hdr)
{
	struct iphdr *ip4h = (struct iphdr *)cur_data(ctx, cur);
	__u8 hdr_len;

	if (!cur_may_pull(ctx, cur, sizeof(*ip4h)))
		return -ENOBUFS;

	/* TODO: ip options are not supported at the moment */
	if (unlikely(ip4h->ihl != 5))
		return -EOPNOTSUPP;

	if (hdr)
		*hdr = ip4h;

	hdr_len = ip4_header_len(ip4h);
	cur_pull(ctx, cur, hdr_len);

	return ip4h->protocol;
}

static __always_inline void
ip6_flow_hdr(struct ipv6hdr *hdr, unsigned int tclass, __be32 flowlabel)
{
	*(__be32 *)hdr = bpf_htonl(0x60000000 | (tclass << 20)) | flowlabel;
}

static __always_inline int
parse_ip6hdr(struct xdp_md *ctx, struct hdr_cursor *cur,
	     struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = (struct ipv6hdr *)cur_data(ctx, cur);

	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to. We will be using this style in the remainder
	 * of the tutorial.
	 */
	if (!cur_may_pull(ctx, cur, sizeof(*ip6h)))
		return -ENOBUFS;

	if (ip6hdr)
		*ip6hdr = ip6h;

	cur_pull(ctx, cur, sizeof(*ip6h));

	return ip6h->nexthdr;
}

#define ipv6_optlen(p)  (((p)->hdrlen+1) << 3)
#define ipv6_authlen(p) (((p)->hdrlen+2) << 2)

static __always_inline int ipv6_ext_hdr(__u8 nexthdr)
{
	/* find out if nexthdr is an extension header or a protocol */
	return   (nexthdr == NEXTHDR_HOP)	||
		 (nexthdr == NEXTHDR_ROUTING)	||
		 (nexthdr == NEXTHDR_FRAGMENT)	||
		 (nexthdr == NEXTHDR_AUTH)	||
		 (nexthdr == NEXTHDR_NONE)	||
		 (nexthdr == NEXTHDR_DEST);
}

#ifndef IPV6_EXTHDR_DEPTH_MAX
#define IPV6_EXTHDR_DEPTH_MAX	4
#endif

static __always_inline int
ipv6_skip_exthdr(struct xdp_md *ctx, struct hdr_cursor *cur, int *start,
		 __u8 *nexthdrp)
{
	struct ipv6_opt_hdr *hdr;
	__u8 nexthdr = *nexthdrp;
	int i, hdrlen;

	for (i = 0; i < IPV6_EXTHDR_DEPTH_MAX; ++i) {
		if (!ipv6_ext_hdr(nexthdr)) {
			*nexthdrp = nexthdr;
			return nexthdr;
		}

		if (nexthdr == NEXTHDR_NONE)
			return -EPERM;
		if (nexthdr == NEXTHDR_FRAGMENT)
			return -EOPNOTSUPP;

		hdr = (struct ipv6_opt_hdr *)cur_header_pointer(ctx, *start,
								sizeof(*hdr));
		if (!hdr)
			return -EINVAL;

		if (nexthdr == NEXTHDR_AUTH)
			hdrlen = ipv6_authlen(hdr);
		else
			hdrlen = ipv6_optlen(hdr);

		nexthdr = hdr->nexthdr;
		*start += hdrlen;
	}

	return -ELOOP;
}

/*
 * find the offset to specified header or the protocol number of last header
 * if target < 0. "last header" is transport protocol header, ESP, or
 * "No next header".
 *
 * Note that *offset is used as input/output parameter, and if it is not zero,
 * then it must be a valid offset to an inner IPv6 header. This can be used
 * to explore inner IPv6 header, eg. ICMPv6 error messages.
 * If *offset is zero, then the header cursor Network Offset (hdr_cursor->nhoff)
 * must be a valid offset pointing to the IPv6 Header.
 *
 * If target header is found, its offset is set in *offset and return protocol
 * number. Otherwise, return -ENOENT.
 *
 * If the first fragment doesn't contain the final protocol header or
 * NEXTHDR_NONE it is considered invalid.
 *
 * IP6_FH_F_AUTH flag is set and target < 0, then this function will
 * stop at the AH header.
 * If IP6_FH_F_SKIP_RH flag was passed, then this function will skip all those
 * routing headers, where segments_left was 0.
 *
 * ---
 *
 * NOTE: fragment header is not supported yet.
 *
 * NOTE: while searching for target header, the max depth (number of examined
 * protocols) is set to IPV6_EXTHDR_DEPTH_MAX. If the max depth limit is
 * reached before the target header is found, then return -ELOOP.
 */
static __always_inline int
ipv6_find_hdr(struct xdp_md *ctx, struct hdr_cursor *cur, int *offset,
	      int target, unsigned short *fragoff, int *flags)
{
#define __PTRHDR cur_header_pointer
	unsigned int start = *offset ?: cur->nhoff;
	struct ipv6_opt_hdr *hp;
	struct ipv6hdr *ip6h;
	unsigned int hdrlen;
	__u8 nexthdr;
	__u8 found;
	int i = 0;

	ip6h = (struct ipv6hdr *)__PTRHDR(ctx, start, sizeof(*ip6h));
	if (unlikely(!ip6h || ip6h->version != 6))
		return -EBADMSG;

	nexthdr = ip6h->nexthdr;
	start += sizeof(*ip6h);

	do {
		found = (nexthdr == target);

		if (!ipv6_ext_hdr(nexthdr) || nexthdr == NEXTHDR_NONE) {
			if (target < 0 || found)
				break;

			return -ENOENT;
		}

		hp = (struct ipv6_opt_hdr *)__PTRHDR(ctx, start, sizeof(*hp));
		if (unlikely(!hp))
			return -EBADMSG;

		if (nexthdr == NEXTHDR_ROUTING) {
			struct ipv6_rt_hdr *rh;

			rh = (struct ipv6_rt_hdr *)__PTRHDR(ctx, start,
							    sizeof(*rh));
			if (unlikely(!rh))
				return -EBADMSG;

			if (flags && (*flags & IP6_FH_F_SKIP_RH) &&
			    rh->segments_left == 0)
				found = 0;
		}

		if (nexthdr == NEXTHDR_FRAGMENT) {
			/* TODO: unsupported for the moment */
			return -EOPNOTSUPP;
		} else if (nexthdr == NEXTHDR_AUTH) {
			if (flags && (*flags & IP6_FH_F_AUTH) && target < 0)
				break;

			hdrlen = ipv6_authlen(hp);
		} else {
			hdrlen = ipv6_optlen(hp);
		}

		if (!found) {
			nexthdr = hp->nexthdr;
			start += hdrlen;
		}

		/* check for the max depth; bound the loop in the worst case */
		if (unlikely(i >= IPV6_EXTHDR_DEPTH_MAX))
			return -ELOOP;
		++i;
	} while (!found);

	*offset = start;
	return nexthdr;
#undef __PTRHDR
}

static __always_inline
void ipv6_change_dsfield(struct ipv6hdr *ip6h, __u8 mask, __u8 value)
{
    __u8 tclass = ipv6_get_dsfield(ip6h);   // legge Traffic Class (8 bit: DSCP+ECN)
    tclass = (tclass & mask) | value;       // aggiorna solo i bit richiesti
    ip6_flow_hdr(ip6h, tclass, ip6_flowlabel(ip6h));  // riscrive tclass mantenendo flowlabel
}

#endif /* end of #ifdef for include header file */



#ifndef _HDR_CURSOR_H
#define _HDR_CURSOR_H

#include "compiler.h"
#include "errno.h"

/* header cursor to keep track of current parsing position within the packet */
struct hdr_cursor {
	unsigned int dataoff;
	unsigned int mhoff;
	unsigned int nhoff;
	unsigned int thoff;
};

/* the maximum offset at which a generic protocol is considered to be valid
 * from the beginning (head) of the hdr_cursor.
 *
 * XXX: SUPPORTED UP TO 16K OFFSET
 */
#define PROTO_OFF_MAX 0x3fff

static __always_inline void cur_reset_mac_header(struct hdr_cursor *cur)
{
	cur->mhoff = cur->dataoff;
}

static __always_inline void cur_reset_network_header(struct hdr_cursor *cur)
{
	cur->nhoff = cur->dataoff;
}

static __always_inline void cur_reset_transport_header(struct hdr_cursor *cur)
{
	cur->thoff = cur->dataoff;
}

static __always_inline unsigned char *xdp_md_head(struct xdp_md *ctx)
{
	return (unsigned char *)((long)ctx->data);
}

static __always_inline unsigned char *xdp_md_tail(struct xdp_md *ctx)
{
	return (unsigned char *)((long)ctx->data_end);
}

static __always_inline unsigned char *
cur_data(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	return xdp_md_head(ctx) + cur->dataoff;
}

static __always_inline unsigned char *
cur_mac_header(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	return xdp_md_head(ctx) + cur->mhoff;
}

static __always_inline unsigned char *
cur_network_header(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	return xdp_md_head(ctx) + cur->nhoff;
}

static __always_inline unsigned char *
cur_transport_header(struct xdp_md *ctx, struct hdr_cursor *cur)
{
	return xdp_md_head(ctx) + cur->thoff;
}

#define __cur_set_header_off(CUR, OFF, VAL) \
	(CUR)->OFF = ((VAL) & PROTO_OFF_MAX)

static __always_inline void cur_data_unset(struct hdr_cursor *cur)
{
	__cur_set_header_off(cur, dataoff, PROTO_OFF_MAX);
}

static __always_inline void cur_mac_header_unset(struct hdr_cursor *cur)
{
	__cur_set_header_off(cur, mhoff, PROTO_OFF_MAX);
}

static __always_inline void cur_network_header_unset(struct hdr_cursor *cur)
{
	__cur_set_header_off(cur, nhoff, PROTO_OFF_MAX);
}

static __always_inline void cur_transport_header_unset(struct hdr_cursor *cur)
{
	__cur_set_header_off(cur, thoff, PROTO_OFF_MAX);
}

static __always_inline void
cur_init(struct hdr_cursor *cur)
{
	cur->dataoff = 0;

	cur_mac_header_unset(cur);
	cur_network_header_unset(cur);
	cur_transport_header_unset(cur);
}

#define  __cur_header_check_bounds(CUR, OFF) \
	((CUR)->OFF > PROTO_OFF_MAX)

static __always_inline int
__check_proto_offsets(struct hdr_cursor *cur)
{
	if (unlikely(__cur_header_check_bounds(cur, dataoff)))
		return -EINVAL;

	if (unlikely(__cur_header_check_bounds(cur, mhoff)))
		return -EINVAL;

	if (unlikely(__cur_header_check_bounds(cur, nhoff)))
		return -EINVAL;

	if (unlikely(__cur_header_check_bounds(cur, thoff)))
		return -EINVAL;

	return 0;
}

#define __cur_header_was_set(CUR, OFF) ((CUR)->OFF != PROTO_OFF_MAX)

static __always_inline int cur_data_was_set(struct hdr_cursor *cur)
{
	return __cur_header_was_set(cur, dataoff);
}

static __always_inline int cur_mac_header_was_set(struct hdr_cursor *cur)
{
	return __cur_header_was_set(cur, mhoff);
}

static __always_inline int cur_network_header_was_set(struct hdr_cursor *cur)
{
	return __cur_header_was_set(cur, nhoff);
}

static __always_inline int cur_transport_header_was_set(struct hdr_cursor *cur)
{
	return __cur_header_was_set(cur, thoff);
}

static __always_inline int
cur_adjust_proto_offsets(struct hdr_cursor *cur, int off)
{
	if (cur_data_was_set(cur))
		cur->dataoff += off;

	if (cur_mac_header_was_set(cur))
		cur->mhoff += off;

	if (cur_network_header_was_set(cur))
		cur->nhoff += off;

	if (cur_transport_header_was_set(cur))
		cur->thoff += off;

	return __check_proto_offsets(cur);
}

/*
 * The cur_xdp_adjust_head(...) helper function allows the user to adjust the
 * xdp frame head and to keep in sync the offsets in the header cursor
 * (hdr_cursor).
 *
 * This helper function is useful for shrinking or expanding the xdp frame head
 * (using bpf_xdp_adjust_head) when encap/encap operations on a packet are
 * needed.
 *
 * The cur_xdp_adjust_head(struct xdp_md *ctx, struct hdr_cursor *cur, int
 * off) helper function takes 3 arguments:
 *   - ctx: xdp context;
 *   - cur: the current header cursor;
 *   - off: number of bytes to shrink or expand in the xdp frame head.
 *
 * The sign of 'off' argument decides if the xdp frame head should be shrunk or
 * expanded.
 * If off < 0, the xdp frame head is expanded of "off" bytes; conversely, if
 * off >= 0, the xdp frame head is shrunk of "off" bytes.
 * Offsets of header cursor are adjusted according to the "-off" value.
 */
static __always_inline int
cur_xdp_adjust_head(struct xdp_md *ctx, struct hdr_cursor *cur, int off)
{
	int rc;

	rc = bpf_xdp_adjust_head(ctx, off);
	if (unlikely(rc < 0))
		return rc;

	/* note the -off (minus sign).
	 *
	 * when the xdp frame is going to be shrunk (+off), the hdr_cursor
	 * cur must be moved back (-off).
	 * Signs are swapped when the xdp frame is expanded.
	 */
	return cur_adjust_proto_offsets(cur, -off);
}

#define	__may_pull(ptr, len, ptrend)				\
({								\
	unsigned char *____e = (unsigned char *)(ptrend);	\
	unsigned char *____p = (unsigned char *)(ptr);		\
								\
	(____p + (len) <= ____e);				\
})

static __always_inline void __pull(struct hdr_cursor *cur, unsigned int len)
{
	cur->dataoff = (cur->dataoff + len) & PROTO_OFF_MAX;
}

static __always_inline void __push(struct hdr_cursor *cur, unsigned int len)
{
	cur->dataoff = (cur->dataoff - len) & PROTO_OFF_MAX;
}

static __always_inline int
cur_may_pull(struct xdp_md *ctx, struct hdr_cursor *cur, unsigned int len)
{
	unsigned char *data, *tail;

	data = cur_data(ctx, cur);
	tail = xdp_md_tail(ctx);

	return __may_pull(data, len, tail);
}

static __always_inline void *
cur_pull(struct xdp_md *ctx, struct hdr_cursor *cur, unsigned int len)
{
	if (!cur_may_pull(ctx, cur, len))
		return NULL;

	__pull(cur, len);
	return cur_data(ctx, cur);
}

static __always_inline void *
cur_header_pointer(struct xdp_md *ctx, unsigned int off, unsigned int len)
{
	unsigned char *head = xdp_md_head(ctx);
	unsigned char *tail = xdp_md_tail(ctx);
	void *p = head + off;

	if (!__may_pull(p, len, tail))
		return NULL;

	return p;
}

#endif

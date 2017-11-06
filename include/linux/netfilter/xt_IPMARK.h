#ifndef _XT_IPMARK_H
#define _XT_IPMARK_H

/* revision 1 */
enum {
	XT_IPMARK_SRC,
	XT_IPMARK_DST,
};

struct xt_ipmark_tginfo {
	__u32 andmask;
	__u32 ormask;
	__u8 selector;
	__u8 shift;
};

/* revision 2 */
enum {
	XT_IPMARK_FLAG_SRC	= 0,		/* XT_IPMARK_SRC */
	XT_IPMARK_FLAG_DST	= (1 << 0),	/* XT_IPMARK_DST */

	XT_IPMARK_FLAG_ACCEPT	= (1 << 1),

#ifdef __KERNEL__
	XT_IPMARK_FLAGS_V2	= (XT_IPMARK_FLAG_SRC|
				   XT_IPMARK_FLAG_DST|
				   XT_IPMARK_FLAG_ACCEPT),
#endif
};

struct xt_ipmark_tginfo2 {
	__u32 mark;
	__u32 mask;
	__u8 flags;
	__u8 shift;
};

#endif /* _XT_IPMARK_H */

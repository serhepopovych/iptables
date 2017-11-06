#ifndef _XT_RPATH_H
#define _XT_RPATH_H

#include <linux/types.h>

enum {
	XT_RPFILTER_LOOSE		= 1 << 0,
	XT_RPFILTER_VALID_MARK		= 1 << 1,
	XT_RPFILTER_ACCEPT_LOCAL	= 1 << 2,
	XT_RPFILTER_INVERT		= 1 << 3,
	XT_RPFILTER_PREFIXLEN		= 1 << 4,
	XT_RPFILTER_PREFIXLEN_INVERT	= 1 << 5,
	XT_RPFILTER_GROUP		= 1 << 6,
	XT_RPFILTER_GROUP_INVERT	= 1 << 7,
};

struct xt_rpfilter_mtinfo0 {
	__u8 flags;
};

struct xt_rpfilter_mtinfo1 {
	__u8 flags;		/* revision 0 compat */
	__u8 prefixlen;
	__u32 group;
	__u32 group_mask;
};

#endif

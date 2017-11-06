#ifndef _XT_SOCKET_H
#define _XT_SOCKET_H

#include <linux/types.h>

enum {
	XT_SOCKET_TRANSPARENT	= 1 << 0,
	XT_SOCKET_NOWILDCARD	= 1 << 1,
	XT_SOCKET_RESTORESKMARK = 1 << 2,
	XT_SOCKET_INVERT	= 1 << 3,
	XT_SOCKET_STATE		= 1 << 4,
	XT_SOCKET_USER		= 1 << 5,
	XT_SOCKET_GROUP		= 1 << 6,
#ifdef __KERNEL__
	XT_SOCKET_FLAGS_V1	= (XT_SOCKET_TRANSPARENT),
	XT_SOCKET_FLAGS_V2	= (XT_SOCKET_FLAGS_V1|
				   XT_SOCKET_NOWILDCARD),
	XT_SOCKET_FLAGS_V3	= (XT_SOCKET_FLAGS_V2|
				   XT_SOCKET_RESTORESKMARK),
	XT_SOCKET_FLAGS_V4	= (XT_SOCKET_FLAGS_V3|
				   XT_SOCKET_INVERT|
				   XT_SOCKET_STATE|
				   XT_SOCKET_USER|
				   XT_SOCKET_GROUP),
	XT_SOCKET_INVFLAGS_V3	= (XT_SOCKET_TRANSPARENT|
				   XT_SOCKET_STATE|
				   XT_SOCKET_USER|
				   XT_SOCKET_GROUP),
#endif
};

struct xt_socket_mtinfo1 {
	__u8 flags;
};

struct xt_socket_mtinfo2 {
	__u8 flags;
};

struct xt_socket_mtinfo3 {
	__u8 flags;
};

struct xt_socket_mtinfo4 {
	__u8 flags;
	__u8 invflags;
	__u32 state;
	__u32 uid_min, uid_max;
	__u32 gid_min, gid_max;
};

#endif /* _XT_SOCKET_H */

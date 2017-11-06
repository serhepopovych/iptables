#ifndef _XT_CLASSIFY_H
#define _XT_CLASSIFY_H

#include <linux/types.h>

/* revision 0 */
struct xt_classify_target_info {
	__u32 priority;
};

/* revision 1 */
struct xt_classify_tginfo {
	__u32 priority;
	__u32 mask;
};

#endif /*_XT_CLASSIFY_H */

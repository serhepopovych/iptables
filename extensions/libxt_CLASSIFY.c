/*
 * Copyright (c) 2003-2013 Patrick McHardy <kaber@trash.net>
 */

#include <stdio.h>
#include <xtables.h>
#include <linux/netfilter/xt_CLASSIFY.h>
#include <linux/pkt_sched.h>

enum {
	/* common */
	O_SET_CLASS	= 0,

	F_SET_CLASS	= (1 << O_SET_CLASS),

	F_COMMON	= F_SET_CLASS,

	/* revision 0 */
	F_REV0		= F_SET_CLASS,
	F_REV0_ALL	= F_COMMON | F_REV0,

	/* revision 1 */
	O_AND_CLASS	= 1,
	O_OR_CLASS	= 2,
	O_XOR_CLASS	= 3,
	O_SET_XCLASS	= 4,

	F_AND_CLASS	= (1 << O_AND_CLASS),
	F_OR_CLASS	= (1 << O_OR_CLASS),
	F_XOR_CLASS	= (1 << O_XOR_CLASS),
	F_SET_XCLASS	= (1 << O_SET_XCLASS),
	F_ANY_CLASS	= F_SET_CLASS | F_AND_CLASS | F_OR_CLASS |
			  F_XOR_CLASS | F_SET_XCLASS,

	F_REV1		= F_AND_CLASS | F_OR_CLASS | F_XOR_CLASS | F_SET_XCLASS,
	F_REV1_ALL	= F_COMMON | F_REV1,
};

static const struct xt_option_entry classify_opts[] = {
	[O_SET_CLASS] = {
		.name	= "set-class",
		.id	= O_SET_CLASS,
		.type	= XTTYPE_STRING,
		.excl	= F_ANY_CLASS,
	},
	[O_AND_CLASS] = {
		.name	= "and-class",
		.id	= O_AND_CLASS,
		.type	= XTTYPE_UINT32,
		.excl	= F_ANY_CLASS,
	},
	[O_OR_CLASS] = {
		.name	= "or-class",
		.id	= O_OR_CLASS,
		.type	= XTTYPE_UINT32,
		.excl	= F_ANY_CLASS,
	},
	[O_XOR_CLASS] = {
		.name	= "xor-class",
		.id	= O_XOR_CLASS,
		.type	= XTTYPE_UINT32,
		.excl	= F_ANY_CLASS,
	},
	[O_SET_XCLASS] = {
		.name	= "set-xclass",
		.id	= O_SET_XCLASS,
		.type	= XTTYPE_MARKMASK32,
		.excl	= F_ANY_CLASS,
	},
	XTOPT_TABLEEND,
};

static int classify_parse_priority(const char *s, unsigned int *p)
{
	unsigned int maj, min;

	if (sscanf(s, "%x:%x", &maj, &min) != 2 ||
	    maj > UINT16_MAX ||
	    min > UINT16_MAX)
		return -1;

	*p = TC_H_MAKE(maj << 16, min);
	return 0;
}

static void classify_print_priority(unsigned int p)
{
	printf(" %x:%x", TC_H_MAJ(p) >> 16, TC_H_MIN(p));
}

static void CLASSIFY_help_v0(void)
{
	printf(
"CLASSIFY target options:\n"
"  --set-class MAJOR:MINOR    Set skb->priority value\n"
	);
}

static void CLASSIFY_help(void)
{
	printf(
"CLASSIFY target options:\n"
"  --set-class MAJOR:MINOR    Set skb->priority value\n"
"or\n"
"  --set-xclass value[/mask]  Clear bits in mask and XOR value into CLASS\n"
"  --set-class value[/mask]   Clear bits in mask and OR value into CLASS\n"
"  --and-class bits           Binary AND the CLASS with bits\n"
"  --or-class bits            Binary OR the CLASS with bits\n"
"  --xor-class bits           Binary XOR the CLASS with bits\n"
	);
}

static void
CLASSIFY_show(const char *pfx, const struct xt_entry_target *target)
{
	const struct xt_classify_target_info *info = (const void *) target->data;
	const struct xt_classify_tginfo *info1 = (const void *) target->data;
	const unsigned int revision = target->u.user.revision;
	unsigned int mode, priority;

	if (!pfx)
		pfx = "";

	/* revision >= 1 */

	if (revision < 1 || info1->mask == ~0U) {
		printf(" %s%s", pfx, classify_opts[O_SET_CLASS].name);
		classify_print_priority(info->priority);
		if (revision < 1)
			return;
	} else {
		if (info1->priority == 0) {
			mode = O_AND_CLASS;
			priority = ~info1->mask;
		} else {
			if (info1->priority == info1->mask)
				mode = O_OR_CLASS;
			else if (info1->mask == 0)
				mode = O_XOR_CLASS;
			else
				mode = O_SET_XCLASS;
			priority = info1->priority;
		}

		printf(" %s%s", pfx, classify_opts[mode].name);

		printf(" 0x%x", priority);
		if (mode == O_SET_XCLASS)
			printf("/0x%x", info1->mask);
	}
}

static void
CLASSIFY_print(const void *ip, const struct xt_entry_target *target,
	       int numeric)
{
	printf(" CLASSIFY");
	CLASSIFY_show("", target);
}

static void
CLASSIFY_save(const void *ip, const struct xt_entry_target *target)
{
	CLASSIFY_show("--", target);
}

static void CLASSIFY_parse(struct xt_option_call *cb)
{
	struct xt_classify_target_info *info = cb->data;
	struct xt_classify_tginfo *info1 = cb->data;
	const unsigned int revision = (*cb->target)->u.user.revision;
	unsigned int id;

	xtables_option_parse(cb);
	id = cb->entry->id;

	switch (id) {
	case O_SET_CLASS:
		/* MAJ:MIN */
		if (!classify_parse_priority(cb->arg, &info->priority)) {
			/* revision >= 1 */
			if (revision > 0)
				info1->mask = -1;
			return;
		}

		/* revision >= 1 */
		if (revision < 1)
			xtables_error(PARAMETER_PROBLEM,
				     "Bad class value \"%s\"", cb->arg);

		xtables_parse_mark_mask(cb, &info1->priority, &info1->mask);
		info1->mask |= info1->priority;
		return;
	}

	/* revision >= 1 */
	if (revision < 1)
		goto no_supp;

	switch (id) {
	case O_AND_CLASS:
		info1->priority = 0;
		info1->mask = ~cb->val.u32;
		break;
	case O_OR_CLASS:
		info1->priority = info1->mask = cb->val.u32;
		break;
	case O_XOR_CLASS:
		info1->priority = cb->val.u32;
		info1->mask = 0;
		break;
	case O_SET_XCLASS:
		info1->priority = cb->val.mark;
		info1->mask = cb->val.mask;
		break;
	default:
		goto no_supp;
	}

	return;

no_supp:
	xtables_error(PARAMETER_PROBLEM,
		      "libxt_CLASSIFY.%u does not support --%s",
		      revision,
		      classify_opts[id].name);
}

static void CLASSIFY_check(struct xt_fcheck_call *cb)
{
	if (!(cb->xflags & F_ANY_CLASS)) {
		xtables_error(PARAMETER_PROBLEM,
			      "CLASSIFY: One of the --set-xclass, "
			      "--{and,or,xor,set}-class options is required");
	}
}

static void
CLASSIFY_arp_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_classify_target_info *clinfo =
		(const struct xt_classify_target_info *)target->data;

	printf(" --set-class %x:%x",
	       TC_H_MAJ(clinfo->priority)>>16, TC_H_MIN(clinfo->priority));
}

static void
CLASSIFY_arp_print(const void *ip,
      const struct xt_entry_target *target,
      int numeric)
{
	CLASSIFY_arp_save(ip, target);
}

static int CLASSIFY_xlate(struct xt_xlate *xl,
			  const struct xt_xlate_tg_params *params)
{
	const struct xt_classify_target_info *clinfo =
		(const struct xt_classify_target_info *)params->target->data;
	__u32 handle = clinfo->priority;

	xt_xlate_add(xl, "meta priority set ");

	switch (handle) {
	case TC_H_ROOT:
		xt_xlate_add(xl, "root");
		break;
	case TC_H_UNSPEC:
		xt_xlate_add(xl, "none");
		break;
	default:
		xt_xlate_add(xl, "%0x:%0x", TC_H_MAJ(handle) >> 16,
			     TC_H_MIN(handle));
		break;
	}

	return 1;
}

static struct xtables_target classify_tg_reg[] = {
	{
		.family		= NFPROTO_UNSPEC,
		.name		= "CLASSIFY",
		.version	= XTABLES_VERSION,
		.revision	= 0,
		.size		= XT_ALIGN(sizeof(struct xt_classify_target_info)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_classify_target_info)),
		.help		= CLASSIFY_help_v0,
		.print		= CLASSIFY_print,
		.save		= CLASSIFY_save,
		.xlate		= CLASSIFY_xlate,
		.x6_parse	= CLASSIFY_parse,
		.x6_fcheck	= CLASSIFY_check,
		.x6_options	= classify_opts,
	},
	{
		.family		= NFPROTO_UNSPEC,
		.name		= "CLASSIFY",
		.version	= XTABLES_VERSION,
		.revision	= 1,
		.size		= XT_ALIGN(sizeof(struct xt_classify_tginfo)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_classify_tginfo)),
		.help		= CLASSIFY_help,
		.print		= CLASSIFY_print,
		.save		= CLASSIFY_save,
		.xlate		= CLASSIFY_xlate,
		.x6_parse	= CLASSIFY_parse,
		.x6_fcheck	= CLASSIFY_check,
		.x6_options	= classify_opts,
	},
};

void _init(void)
{
	xtables_register_targets(classify_tg_reg, ARRAY_SIZE(classify_tg_reg));
}

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
};

static const struct xt_option_entry classify_opts[] = {
	[O_SET_CLASS] = {
		.name	= "set-class",
		.id	= O_SET_CLASS,
		.type	= XTTYPE_STRING,
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

static void classify_print_priority(const char *pfx, unsigned int p)
{
	printf(" %x:%x", TC_H_MAJ(p) >> 16, TC_H_MIN(p));
}

static void CLASSIFY_help(void)
{
	printf(
"CLASSIFY target options:\n"
"  --set-class MAJOR:MINOR    Set skb->priority value\n"
	);
}

static void
CLASSIFY_show(const char *pfx, const struct xt_entry_target *target)
{
	const struct xt_classify_target_info *info = (const void *) target->data;

	if (!pfx)
		pfx = "";

	classify_print_priority(pfx, info->priority);
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
	const unsigned int revision = (*cb->target)->u.user.revision;
	unsigned int id;

	xtables_option_parse(cb);
	id = cb->entry->id;

	switch (id) {
	case O_SET_CLASS:
		/* MAJ:MIN */
		if (!classify_parse_priority(cb->arg, &info->priority))
			break;

		xtables_error(PARAMETER_PROBLEM,
			     "Bad class value \"%s\"", cb->arg);
	default:
		xtables_error(PARAMETER_PROBLEM,
			      "libxt_CLASSIFY.%u does not support --%s",
			      revision,
			      classify_opts[id].name);
	}
}

static void CLASSIFY_check(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0) {
		xtables_error(PARAMETER_PROBLEM,
			      "CLASSIFY target: Parameter --set-class"
			      "is required");
	}
}

static void
arpCLASSIFY_print(const void *ip, const struct xt_entry_target *target,
		  int numeric)
{
	CLASSIFY_save(ip, target);
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
		.size		= XT_ALIGN(sizeof(struct xt_classify_target_info)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_classify_target_info)),
		.help		= CLASSIFY_help,
		.print		= CLASSIFY_print,
		.save		= CLASSIFY_save,
		.x6_parse	= CLASSIFY_parse,
		.x6_fcheck	= CLASSIFY_check,
		.x6_options	= CLASSIFY_opts,
		.xlate		= CLASSIFY_xlate,
	},
	{
		.family		= NFPROTO_ARP,
		.name		= "CLASSIFY",
		.version	= XTABLES_VERSION,
		.size		= XT_ALIGN(sizeof(struct xt_classify_target_info)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_classify_target_info)),
		.help		= CLASSIFY_help,
		.print		= arpCLASSIFY_print,
		.x6_parse	= CLASSIFY_parse,
		.x6_fcheck	= CLASSIFY_check,
		.x6_options	= CLASSIFY_opts,
		.xlate		= CLASSIFY_xlate,
	},
};

void _init(void)
{
	xtables_register_targets(classify_tg_reg, ARRAY_SIZE(classify_tg_reg));
}

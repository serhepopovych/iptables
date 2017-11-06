/*
 *	"IPMARK" target extension for iptables
 *	Copyright © Grzegorz Janoszka <Grzegorz.Janoszka@pro.onet.pl>, 2003
 *	Jan Engelhardt, 2008
 *	Sergey Popovich, 2014
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xtables.h>
#include <linux/netfilter/xt_IPMARK.h>

enum {
	/* common */
	O_ADDR		= 0,
	O_SRC_ADDR	= 1,
	O_DST_ADDR	= 2,
	O_SHIFT		= 3,

	F_ADDR		= 1 << O_ADDR,
	F_SRC_ADDR	= 1 << O_SRC_ADDR,
	F_DST_ADDR	= 1 << O_DST_ADDR,
	F_ANY_ADDR	= F_ADDR | F_SRC_ADDR | F_DST_ADDR,
	F_SHIFT		= 1 << O_SHIFT,

	F_COMMON	= F_ANY_ADDR | F_SHIFT,

	/* revision 1 */
	O_AND_MASK	= 4,
	O_OR_MASK	= 5,

	F_AND_MASK	= 1 << O_AND_MASK,
	F_OR_MASK	= 1 << O_OR_MASK,
	F_ANY_MASK	= F_AND_MASK | F_OR_MASK,

	F_REV1		= F_ANY_MASK,
	F_REV1_ALL	= F_COMMON | F_REV1,

	/* revision 2 */
	O_SET_MARK	= 6,
	O_AND_MARK	= 7,
	O_OR_MARK	= 8,
	O_XOR_MARK	= 9,
	O_SET_XMARK	= 10,

	F_SET_MARK	= 1 << O_SET_MARK,
	F_AND_MARK	= 1 << O_AND_MARK,
	F_OR_MARK	= 1 << O_OR_MARK,
	F_XOR_MARK	= 1 << O_XOR_MARK,
	F_SET_XMARK	= 1 << O_SET_XMARK,
	F_ANY_MARK	= F_SET_MARK | F_AND_MARK | F_OR_MARK |
			  F_XOR_MARK | F_SET_XMARK,

	F_REV2		= F_ANY_MARK,
	F_REV2_ALL	= F_COMMON | F_REV2,
};

static const struct xt_option_entry ipmark_opts[] = {
	/* common */
	[O_ADDR] = {
		.name	= "addr",
		.id	= O_ADDR,
		.type	= XTTYPE_STRING,
		.excl	= F_ANY_ADDR,
	},
	[O_SRC_ADDR] = {
		.name	= "src-addr",
		.id	= O_SRC_ADDR,
		.type	= XTTYPE_NONE,
		.excl	= F_ANY_ADDR,
	},
	[O_DST_ADDR] = {
		.name	= "dst-addr",
		.id	= O_DST_ADDR,
		.type	= XTTYPE_NONE,
		.excl	= F_ANY_ADDR,
	},
	[O_SHIFT] = {
		.name	= "shift",
		.id	= O_SHIFT,
		.type	= XTTYPE_UINT8,
	},
	/* revision 1 */
	[O_AND_MASK] = {
		.name	= "and-mask",
		.id	= O_AND_MASK,
		.type	= XTTYPE_UINT32,
	},
	[O_OR_MASK] = {
		.name	= "or-mask",
		.id	= O_OR_MASK,
		.type	= XTTYPE_UINT32,
	},
	/* revision 2 */
	[O_SET_MARK] = {
		.name	= "set-mark",
		.id	= O_SET_MARK,
		.type	= XTTYPE_MARKMASK32,
		.excl	= F_ANY_MARK,
	},
	[O_AND_MARK] = {
		.name	= "and-mark",
		.id	= O_AND_MARK,
		.type	= XTTYPE_UINT32,
		.excl	= F_ANY_MARK,
	},
	[O_OR_MARK] = {
		.name	= "or-mark",
		.id	= O_OR_MARK,
		.type	= XTTYPE_UINT32,
		.excl	= F_ANY_MARK,
	},
	[O_XOR_MARK] = {
		.name	= "xor-mark",
		.id	= O_XOR_MARK,
		.type	= XTTYPE_UINT32,
		.excl	= F_ANY_MARK,
	},
	[O_SET_XMARK] = {
		.name	= "set-xmark",
		.id	= O_SET_XMARK,
		.type	= XTTYPE_MARKMASK32,
		.excl	= F_ANY_MARK,
	},
	XTOPT_TABLEEND,
};

/* revision 1 */

static void IPMARK_help_v1(void)
{
	printf(
"IPMARK target options:\n"
"  --addr {src|dst}    Use source or destination ip address\n"
"  --shift value       Shift MARK right by value\n"
"  --and-mask bits     Binary AND the MARK with bits\n"
"  --or-mask bits      Binary OR the MARK with bits\n"
	);
}

static void
IPMARK_show_v1(const char *pfx, const struct xt_entry_target *target)
{
	const struct xt_ipmark_tginfo *info = (const void *) target->data;
	const char *addr;

	switch (info->selector) {
	case XT_IPMARK_SRC:
		addr = "src";
		break;
	case XT_IPMARK_DST:
		addr = "dst";
		break;
	default:
		return;
	}

	if (!pfx)
		pfx = "";

	printf(" %saddr %s", pfx, addr);
	if (info->shift != 0)
		printf(" %sshift %hhu", pfx, info->shift);
	if (info->andmask != ~0U)
		printf(" %sand-mask 0x%x", pfx, info->andmask);
	if (info->ormask != 0)
		printf(" %sor-mask 0x%x", pfx, info->ormask);
}

static void
IPMARK_print_v1(const void *ip, const struct xt_entry_target *target,
                int numeric)
{
	printf(" IPMARK");
	IPMARK_show_v1("", target);
}

static void
IPMARK_save_v1(const void *ip, const struct xt_entry_target *target)
{
	IPMARK_show_v1("--", target);
}

static void IPMARK_parse_v1(struct xt_option_call *cb)
{
	struct xt_ipmark_tginfo *info = cb->data;
	const unsigned int revision = (*cb->target)->u.user.revision;
	unsigned int id;

	xtables_option_parse(cb);
	id = cb->entry->id;

	switch (id) {
	case O_ADDR:
		if (!strcmp(cb->arg, "src"))
			info->selector = XT_IPMARK_SRC;
		else if (!strcmp(cb->arg, "dst"))
			info->selector = XT_IPMARK_DST;
		else
			xtables_error(PARAMETER_PROBLEM,
				      "IPMARK target: Parameter --addr "
				      "requires either \"src\" or \"dst\" "
				      "as it's argument, but \"%s\" is given",
				      cb->arg);
		break;
	case O_SRC_ADDR:
		info->selector = XT_IPMARK_SRC;
		break;
	case O_DST_ADDR:
		info->selector = XT_IPMARK_DST;
		break;
	case O_SHIFT:
		info->shift = cb->val.u8;
		break;
	case O_AND_MASK:
		info->andmask = cb->val.u32;
		break;
	case O_OR_MASK:
		info->ormask = cb->val.u32;
		break;
	default:
		xtables_error(PARAMETER_PROBLEM,
			      "libxt_IPMARK.%u does not support --%s",
			      revision,
			      ipmark_opts[id].name);
	}
}

static void IPMARK_check_v1(struct xt_fcheck_call *cb)
{
	if (!(cb->xflags & F_ANY_ADDR)) {
		xtables_error(PARAMETER_PROBLEM,
			      "IPMARK target: Parameter "
			      "--addr {src|dst} is required");
	}
}

/* revision 2 */

static void IPMARK_help_v2(void)
{
	printf(
"IPMARK target options:\n"
"  --src-addr                Use source address for MARK\n"
"  --dst-addr                Use destination address for MARK\n"
"  --shift value             Shift MARK right by value\n"
"  --set-xmark value[/mask]  Clear bits in mask and XOR value into MARK\n"
"  --set-mark value[/mask]   Clear bits in mask and OR value into MARK\n"
"  --and-mark bits           Binary AND the MARK with bits\n"
"  --or-mark bits            Binary OR the MARK with bits\n"
"  --xor-mask bits           Binary XOR the MARK with bits\n"
	);
}

static void
IPMARK_show_v2(const char *pfx, const struct xt_entry_target *target)
{
	const struct xt_ipmark_tginfo2 *info = (const void *) target->data;
	const char *addr;
	unsigned int mode, mark;

	if (info->flags & XT_IPMARK_FLAG_DST)
		addr = "dst";
	else
		addr = "src";

	if (!pfx)
		pfx = "";

	printf(" %s%s-addr", pfx, addr);

	if (info->shift != 0)
		printf(" %sshift %hhu", pfx, info->shift);

	if (info->mark == 0) {
		mode = O_AND_MARK;
		mark = ~info->mask;
	} else {
		if (info->mark == info->mask)
			mode = O_OR_MARK;
		else if (info->mask == 0)
			mode = O_XOR_MARK;
		else if (info->mask == ~0U)
			mode = O_SET_MARK;
		else
			mode = O_SET_XMARK;
		mark = info->mark;
	}

	printf(" %s%s", pfx, ipmark_opts[mode].name);

	printf(" 0x%x", mark);
	if (mode == O_SET_XMARK)
		printf("/0x%x", info->mask);
}

static void
IPMARK_print_v2(const void *ip, const struct xt_entry_target *target,
		int numeric)
{
	printf(" IPMARK");
	IPMARK_show_v2("", target);
}

static void
IPMARK_save_v2(const void *ip, const struct xt_entry_target *target)
{
	IPMARK_show_v2("--", target);
}

static void IPMARK_parse_v2(struct xt_option_call *cb)
{
	struct xt_ipmark_tginfo2 *info = cb->data;
	const unsigned int revision = (*cb->target)->u.user.revision;
	unsigned int id;

	xtables_option_parse(cb);
	id = cb->entry->id;

	switch (id) {
	case O_ADDR:
		if (!strcmp(cb->arg, "src"))
			info->flags |= XT_IPMARK_FLAG_SRC;
		else if (!strcmp(cb->arg, "dst"))
			info->flags |= XT_IPMARK_FLAG_DST;
		else
			xtables_error(PARAMETER_PROBLEM,
				      "IPMARK target: Parameter --addr "
				      "requires either \"src\" or \"dst\" "
				      "as it's argument, but \"%s\" is given",
				      cb->arg);
		break;
	case O_SRC_ADDR:
		info->flags |= XT_IPMARK_FLAG_SRC;
		break;
	case O_DST_ADDR:
		info->flags |= XT_IPMARK_FLAG_DST;
		break;
	case O_SHIFT:
		info->shift = cb->val.u8;
		break;
	case O_SET_MARK:
		info->mark = cb->val.mark;
		info->mask = cb->val.mark | cb->val.mask;
		break;
	case O_AND_MARK:
		info->mark = 0;
		info->mask = ~cb->val.u32;
		break;
	case O_OR_MARK:
		info->mark = info->mask = cb->val.u32;
		break;
	case O_XOR_MARK:
		info->mark = cb->val.u32;
		info->mask = 0;
		break;
	case O_SET_XMARK:
		info->mark = cb->val.mark;
		info->mask = cb->val.mask;
		break;
	default:
		xtables_error(PARAMETER_PROBLEM,
			      "libxt_IPMARK.%u does not support --%s",
			      revision,
			      ipmark_opts[id].name);
	}
}

static void IPMARK_check_v2(struct xt_fcheck_call *cb)
{
	if (!(cb->xflags & F_ANY_ADDR)) {
		xtables_error(PARAMETER_PROBLEM,
			      "IPMARK target: Parameter "
			      "--{src|dst}-addr is required");
	}
}

static struct xtables_target ipmark_tg_reg[] = {
	{
		.family		= NFPROTO_UNSPEC,
		.name		= "IPMARK",
		.version	= XTABLES_VERSION,
		.revision	= 1,
		.size		= XT_ALIGN(sizeof(struct xt_ipmark_tginfo)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_ipmark_tginfo)),
		.help		= IPMARK_help_v1,
		.print		= IPMARK_print_v1,
		.save		= IPMARK_save_v1,
		.x6_parse	= IPMARK_parse_v1,
		.x6_fcheck	= IPMARK_check_v1,
		.x6_options	= ipmark_opts,
	},
	{
		.family		= NFPROTO_UNSPEC,
		.name		= "IPMARK",
		.version	= XTABLES_VERSION,
		.revision	= 2,
		.size		= XT_ALIGN(sizeof(struct xt_ipmark_tginfo2)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_ipmark_tginfo2)),
		.help		= IPMARK_help_v2,
		.print		= IPMARK_print_v2,
		.save		= IPMARK_save_v2,
		.x6_parse	= IPMARK_parse_v2,
		.x6_fcheck	= IPMARK_check_v2,
		.x6_options	= ipmark_opts,
	},
};

void _init(void)
{
	xtables_register_targets(ipmark_tg_reg, ARRAY_SIZE(ipmark_tg_reg));
}

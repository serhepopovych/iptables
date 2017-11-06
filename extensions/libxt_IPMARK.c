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
	O_ADDR		= 0,
	O_SHIFT		= 1,
	O_AND_MASK	= 2,
	O_OR_MASK	= 3,

	F_ADDR		= 1 << O_ADDR,
	F_SHIFT		= 1 << O_SHIFT,
	F_AND_MASK	= 1 << O_AND_MASK,
	F_OR_MASK	= 1 << O_OR_MASK,
};

static const struct xt_option_entry ipmark_opts[] = {
	[O_ADDR] = {
		.name	= "addr",
		.id	= O_ADDR,
		.type	= XTTYPE_STRING,
	},
	[O_SHIFT] = {
		.name	= "shift",
		.id	= O_SHIFT,
		.type	= XTTYPE_UINT8,
	},
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
	XTOPT_TABLEEND,
};

static void IPMARK_help(void)
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
IPMARK_show(const char *pfx, const struct xt_entry_target *target)
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
IPMARK_print(const void *ip, const struct xt_entry_target *target,
                int numeric)
{
	printf(" IPMARK");
	IPMARK_show("", target);
}

static void
IPMARK_save(const void *ip, const struct xt_entry_target *target)
{
	IPMARK_show("--", target);
}

static void IPMARK_parse(struct xt_option_call *cb)
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

static void IPMARK_check(struct xt_fcheck_call *cb)
{
	if (!(cb->xflags & F_ADDR)) {
		xtables_error(PARAMETER_PROBLEM,
			      "IPMARK target: Parameter "
			      "--addr {src|dst} is required");
	}
}

static struct xtables_target ipmark_tg_reg = {
	.family		= NFPROTO_UNSPEC,
	.name		= "IPMARK",
	.version	= XTABLES_VERSION,
	.revision	= 1,
	.size		= XT_ALIGN(sizeof(struct xt_ipmark_tginfo)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_ipmark_tginfo)),
	.help		= IPMARK_help,
	.print		= IPMARK_print,
	.save		= IPMARK_save,
	.x6_parse	= IPMARK_parse,
	.x6_fcheck	= IPMARK_check,
	.x6_options	= ipmark_opts,
};

void _init(void)
{
	xtables_register_target(&ipmark_tg_reg);
}

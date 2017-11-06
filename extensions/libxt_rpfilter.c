#include <stdio.h>
#include <xtables.h>
#include <linux/netfilter/xt_rpfilter.h>

enum {
	O_LOOSE = 0,
	O_VMARK,
	O_ACCEPT_LOCAL,
	O_INVERT,
};

static const struct xt_option_entry rpfilter_opts[] = {
	[O_LOOSE] = {
		.name	= "loose",
		.id	= O_LOOSE,
		.type	= XTTYPE_NONE,
	},
	[O_VMARK] = {
		.name	= "validmark",
		.id	= O_VMARK,
		.type	= XTTYPE_NONE,
	},
	[O_ACCEPT_LOCAL] = {
		.name	= "accept-local",
		.id	= O_ACCEPT_LOCAL,
		.type	= XTTYPE_NONE,
	},
	[O_INVERT] = {
		.name	= "invert",
		.id	= O_INVERT,
		.type	= XTTYPE_NONE,
	},
	XTOPT_TABLEEND,
};

static void rpfilter_help(void)
{
	printf(
"rpfilter match options:\n"
"    --loose                  permit reverse path via any interface\n"
"    --validmark              use skb nfmark when performing route lookup\n"
"    --accept-local           do not reject packets with a local source address\n"
"    --invert                 match packets that failed the reverse path test\n"
	);
}

static void rpfilter_parse(struct xt_option_call *cb)
{
	struct xt_rpfilter_info *rpfinfo = cb->data;
	const unsigned int revision = (*cb->match)->u.user.revision;
	unsigned int id, flags;

	xtables_option_parse(cb);
	id = cb->entry->id;

	switch (id) {
	case O_LOOSE:
		flags = XT_RPFILTER_LOOSE;
		break;
	case O_VMARK:
		flags = XT_RPFILTER_VALID_MARK;
		break;
	case O_ACCEPT_LOCAL:
		flags = XT_RPFILTER_ACCEPT_LOCAL;
		break;
	case O_INVERT:
		flags = XT_RPFILTER_INVERT;
		break;
	default:
		xtables_error(PARAMETER_PROBLEM,
			      "libxt_rpfilter.%u does not support --%s",
			      revision,
			      rpfilter_opts[id].name);
	}

	rpfinfo->flags |= flags;
}

static void
rpfilter_show(const char *pfx, unsigned int flags)
{
	if (flags & XT_RPFILTER_LOOSE)
		printf(" %s%s", pfx, rpfilter_opts[O_LOOSE].name);
	if (flags & XT_RPFILTER_VALID_MARK)
		printf(" %s%s", pfx, rpfilter_opts[O_VMARK].name);
	if (flags & XT_RPFILTER_ACCEPT_LOCAL)
		printf(" %s%s", pfx, rpfilter_opts[O_ACCEPT_LOCAL].name);
	if (flags & XT_RPFILTER_INVERT)
		printf(" %s%s", pfx, rpfilter_opts[O_INVERT].name);
}

static void
rpfilter_print(const void *ip, const struct xt_entry_match *match,
	       int numeric)
{
	const struct xt_rpfilter_info *info = (const void *) match->data;

	printf(" rpfilter");
	rpfilter_show("", info->flags);
}

static void
rpfilter_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_rpfilter_info *info = (const void *) match->data;

	rpfilter_show("--", info->flags);
}

static int rpfilter_xlate(struct xt_xlate *xl,
			  const struct xt_xlate_mt_params *params)
{
	const struct xt_rpfilter_info *info = (void *)params->match->data;
	bool invert = info->flags & XT_RPFILTER_INVERT;

	if (info->flags & XT_RPFILTER_ACCEPT_LOCAL) {
		if (invert)
			xt_xlate_add(xl, "fib saddr type != local ");
		else
			return 0;
	}

	xt_xlate_add(xl, "fib saddr ");

	if (info->flags & XT_RPFILTER_VALID_MARK)
		xt_xlate_add(xl, ". mark ");
	if (!(info->flags & XT_RPFILTER_LOOSE))
		xt_xlate_add(xl, ". iif ");

	xt_xlate_add(xl, "oif %s0", invert ? "" : "!= ");

	return 1;
}

static struct xtables_match rpfilter_match = {
	.family		= NFPROTO_UNSPEC,
	.name		= "rpfilter",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_rpfilter_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_rpfilter_info)),
	.help		= rpfilter_help,
	.print		= rpfilter_print,
	.save		= rpfilter_save,
	.x6_parse	= rpfilter_parse,
	.x6_options	= rpfilter_opts,
	.xlate		= rpfilter_xlate,
};

void _init(void)
{
	xtables_register_match(&rpfilter_match);
}

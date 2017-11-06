#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <xtables.h>
#include <linux/netfilter/xt_rpfilter.h>

enum {
	O_LOOSE = 0,
	O_VMARK,
	O_ACCEPT_LOCAL,
	O_INVERT,
	O_PREFIXLEN,
	O_DEVGROUP,
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
	[O_PREFIXLEN] = {
		.name	= "prefixlen",
		.id	= O_PREFIXLEN,
		.type	= XTTYPE_PLEN,
		.flags	= XTOPT_INVERT,
	},
	[O_DEVGROUP] = {
		.name	= "devgroup",
		.id	= O_DEVGROUP,
		.type	= XTTYPE_STRING,
		.flags	= XTOPT_INVERT,
	},
	XTOPT_TABLEEND,
};

static const char f_devgroups[] = "/etc/iproute2/group";
/* map of devgroups from f_devgroups[] */
static struct xtables_lmap_table *devgroups;

static void rpfilter_help(void)
{
	printf(
"rpfilter match options:\n"
"    --loose                  permit reverse path via any interface\n"
"    --validmark              use skb nfmark when performing route lookup\n"
"    --accept-local           do not reject packets with a local source address\n"
"    --invert                 match packets that failed the reverse path test\n"
"[!] --prefixlen <length>     match if reverse path route prefix length is\n"
"                             shorter than or equal to length\n"
"[!] --devgroup value[/mask]  match if reverse path route outgoing interface is\n"
"                             in device group\n"
	);
}

static void rpfilter_parse(struct xt_option_call *cb)
{
	struct xt_rpfilter_mtinfo1 *info = cb->data;
	const unsigned int revision = (*cb->match)->u.user.revision;
	unsigned int id, flags;
	unsigned int group, mask;

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
	case O_PREFIXLEN:
		/* revision >= 1 */
		if (revision < 1)
			goto no_supp;
		info->prefixlen = cb->val.hlen;
		flags = XT_RPFILTER_PREFIXLEN;
		if (cb->invert)
			flags |= XT_RPFILTER_PREFIXLEN_INVERT;
		break;
	case O_DEVGROUP:
		/* revision >= 1 */
		if (revision < 1)
			goto no_supp;
		xtables_parse_val_mask(cb, &group, &mask, devgroups);
		info->group = group;
		info->group_mask = mask;
		flags = XT_RPFILTER_GROUP;
		if (cb->invert)
			flags |= XT_RPFILTER_GROUP_INVERT;
		break;
	default:
		goto no_supp;
	}

	info->flags |= flags;
	return;

no_supp:
	xtables_error(PARAMETER_PROBLEM,
		      "libxt_rpfilter.%u does not support %s--%s",
		      revision,
		      cb->invert ? "! " : "",
		      rpfilter_opts[id].name);
}

static void
rpfilter_show(const char *pfx, const struct xt_entry_match *match, bool numeric)
{
	const struct xt_rpfilter_mtinfo1 *info = (const void *) match->data;
	const unsigned int revision = match->u.user.revision;
	unsigned int flags = info->flags;
	const char *inv;

	if (!pfx)
		pfx = "";

	if (*pfx == '\0')
		printf(" rpfilter");

	/* revision >= 0 */

	if (flags & XT_RPFILTER_LOOSE)
		printf(" %s%s", pfx, rpfilter_opts[O_LOOSE].name);
	if (flags & XT_RPFILTER_VALID_MARK)
		printf(" %s%s", pfx, rpfilter_opts[O_VMARK].name);
	if (flags & XT_RPFILTER_ACCEPT_LOCAL)
		printf(" %s%s", pfx, rpfilter_opts[O_ACCEPT_LOCAL].name);
	if (flags & XT_RPFILTER_INVERT)
		printf(" %s%s", pfx, rpfilter_opts[O_INVERT].name);

	/* revision >= 1 */

	if (revision < 1)
		return;

	if (flags & XT_RPFILTER_PREFIXLEN) {
		inv = (flags & XT_RPFILTER_PREFIXLEN_INVERT) ? "! " : "";
		printf(" %s%s%s %u",
			inv, pfx,
			rpfilter_opts[O_PREFIXLEN].name,
			info->prefixlen);
	}

	if (flags & XT_RPFILTER_GROUP) {
		inv = (flags & XT_RPFILTER_GROUP_INVERT) ? "! " : "";
		printf(" %s%s%s",
			inv, pfx,
			rpfilter_opts[O_DEVGROUP].name);
		xtables_print_val_mask(info->group, info->group_mask,
				       numeric ? NULL : devgroups);
	}
}

static void
rpfilter_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	rpfilter_show("", match, numeric);
}

static void rpfilter_save(const void *ip, const struct xt_entry_match *match)
{
	rpfilter_show("--", match, false);
}

static int rpfilter_xlate(struct xt_xlate *xl,
			  const struct xt_xlate_mt_params *params)
{
	const struct xt_rpfilter_mtinfo1 *info = (void *)params->match->data;
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

static struct xtables_match rpfilter_mt_reg[] = {
	{
		.family		= NFPROTO_UNSPEC,
		.name		= "rpfilter",
		.version	= XTABLES_VERSION,
		.revision	= 0,
		.size		= XT_ALIGN(sizeof(struct xt_rpfilter_mtinfo0)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_rpfilter_mtinfo0)),
		.help		= rpfilter_help,
		.print		= rpfilter_print,
		.save		= rpfilter_save,
		.x6_parse	= rpfilter_parse,
		.x6_options	= rpfilter_opts,
		.xlate		= rpfilter_xlate,
	},
	{
		.family		= NFPROTO_UNSPEC,
		.name		= "rpfilter",
		.version	= XTABLES_VERSION,
		.revision	= 1,
		.size		= XT_ALIGN(sizeof(struct xt_rpfilter_mtinfo1)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_rpfilter_mtinfo1)),
		.help		= rpfilter_help,
		.print		= rpfilter_print,
		.save		= rpfilter_save,
		.x6_parse	= rpfilter_parse,
		.x6_options	= rpfilter_opts,
		.xlate		= rpfilter_xlate,
	},
};

void _init(void)
{
	devgroups = xtables_lmap_fromfile(f_devgroups, XTABLES_LMAP_SHIFT);
	if (devgroups == NULL && errno != ENOENT)
		fprintf(stderr, "Warning: %s: %s\n", f_devgroups,
			strerror(errno));

	xtables_register_matches(rpfilter_mt_reg, ARRAY_SIZE(rpfilter_mt_reg));
}

/*
 * Copyright (c) 2010-2013 Patrick McHardy <kaber@trash.net>
 */

#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/xt_CT.h>

enum {
	/* common */
	O_NOTRACK	= 0,
	O_ZONE		= 1,
	O_CTEVENTS	= 2,
	O_EXPEVENTS	= 3,
	O_HELPER	= 4,

	F_NOTRACK	= (1 << O_NOTRACK),
	F_ZONE		= (1 << O_ZONE),
	F_CTEVENTS	= (1 << O_CTEVENTS),
	F_EXPEVENTS	= (1 << O_EXPEVENTS),
	F_HELPER	= (1 << O_HELPER),

	F_COMMON	= F_NOTRACK | F_ZONE | F_CTEVENTS |
			  F_EXPEVENTS | F_HELPER,

	/* revision 1, 2 */
	O_TIMEOUT	= 5,
	O_ZONE_ORIG	= 6,
	O_ZONE_REPLY	= 7,

	F_TIMEOUT	= (1 << O_TIMEOUT),
	F_ZONE_ORIG	= (1 << O_ZONE_ORIG),
	F_ZONE_REPLY	= (1 << O_ZONE_REPLY),

	F_ZONE_ALL	= F_ZONE|F_ZONE_ORIG|F_ZONE_REPLY,

	F_REV1		= F_TIMEOUT|F_ZONE_ORIG|F_ZONE_REPLY,
	F_REV1_ALL	= F_COMMON | F_REV1,
};

static const struct xt_option_entry ct_opts[] = {
	[O_NOTRACK] = {
		.name	= "notrack",
		.id	= O_NOTRACK,
		.type	= XTTYPE_NONE,
		.excl	= F_ZONE_ALL|F_CTEVENTS|F_EXPEVENTS|F_HELPER|F_TIMEOUT,
	},
	[O_ZONE] = {
		.name	= "zone",
		.id	= O_ZONE,
		.type	= XTTYPE_UINT16,
		.excl	= F_NOTRACK,
	},
	[O_CTEVENTS] = {
		.name	= "ctevents",
		.id	= O_CTEVENTS,
		.type	= XTTYPE_STRING,
		.excl	= F_NOTRACK,
	},
	[O_EXPEVENTS] = {
		.name	= "expevents",
		.id	= O_EXPEVENTS,
		.type	= XTTYPE_STRING,
		.excl	= F_NOTRACK,
	},
	[O_HELPER] = {
		.name	= "helper",
		.id	= O_HELPER,
		.type	= XTTYPE_STRING,
		.flags	= XTOPT_PUT,
		XTOPT_POINTER(struct xt_ct_target_info, helper),
		.excl	= F_NOTRACK,
	},
	[O_TIMEOUT] = {
		.name	= "timeout",
		.id	= O_TIMEOUT,
		.type	= XTTYPE_STRING,
		.excl	= F_NOTRACK,
	},
	[O_ZONE_ORIG] = {
		.name	= "zone-orig",
		.id	= O_ZONE_ORIG,
		.type	= XTTYPE_STRING,
		.excl	= F_NOTRACK,
	},
	[O_ZONE_REPLY] = {
		.name	= "zone-reply",
		.id	= O_ZONE_REPLY,
		.type	= XTTYPE_STRING,
		.excl	= F_NOTRACK,
	},
	XTOPT_TABLEEND,
};

struct event_tbl {
	const char	*name;
	unsigned int	event;
};

static const struct event_tbl ct_event_tbl[] = {
	{ "new",		IPCT_NEW },
	{ "related",		IPCT_RELATED },
	{ "destroy",		IPCT_DESTROY },
	{ "reply",		IPCT_REPLY },
	{ "assured",		IPCT_ASSURED },
	{ "protoinfo",		IPCT_PROTOINFO },
	{ "helper",		IPCT_HELPER },
	{ "mark",		IPCT_MARK },
	{ "natseqinfo",		IPCT_NATSEQADJ },
	{ "secmark",		IPCT_SECMARK },
};

static const struct event_tbl exp_event_tbl[] = {
	{ "new",		IPEXP_NEW },
};

static void ct_parse_zone_id(const char *opt, unsigned int opt_id,
			     uint16_t *zone_id, uint16_t *flags)
{
	if (opt_id == O_ZONE_ORIG)
		*flags |= XT_CT_ZONE_DIR_ORIG;
	if (opt_id == O_ZONE_REPLY)
		*flags |= XT_CT_ZONE_DIR_REPL;

	*zone_id = 0;

	if (strcasecmp(opt, "mark") == 0) {
		*flags |= XT_CT_ZONE_MARK;
	} else {
		uintmax_t val;

		if (!xtables_strtoul(opt, NULL, &val, 0, UINT16_MAX))
			xtables_error(PARAMETER_PROBLEM,
				      "Cannot parse %s as a zone ID\n", opt);

		*zone_id = (uint16_t)val;
	}
}

static void ct_print_zone_id(const char *pfx, uint16_t zone_id, uint16_t flags)
{
	const char *opt;

	switch (flags & (XT_CT_ZONE_DIR_ORIG|XT_CT_ZONE_DIR_REPL)) {
	case XT_CT_ZONE_DIR_ORIG:
		opt = "-orig";
		break;
	case XT_CT_ZONE_DIR_REPL:
		opt = "-reply";
		break;
	}

	printf(" %szone%s", pfx, opt);

	if (flags & XT_CT_ZONE_MARK)
		printf(" mark");
	else
		printf(" %u", zone_id);
}

static uint32_t ct_parse_events(const struct event_tbl *tbl, unsigned int size,
				const char *events)
{
	char str[strlen(events) + 1], *e = str, *t;
	unsigned int mask = 0, i;

	strcpy(str, events);
	while ((t = strsep(&e, ","))) {
		for (i = 0; i < size; i++) {
			if (strcmp(t, tbl[i].name))
				continue;
			mask |= 1 << tbl[i].event;
			break;
		}

		if (i == size)
			xtables_error(PARAMETER_PROBLEM, "Unknown event type \"%s\"", t);
	}

	return mask;
}

static void ct_print_events(const char *pfx, const char *opt,
			    const struct event_tbl *tbl,
			    unsigned int size, uint32_t mask)
{
	const char *sep = "";
	unsigned int i;

	if (!pfx)
		pfx = "";

	printf(" %s%s ", pfx, opt);
	for (i = 0; i < size; i++) {
		if (mask & (1 << tbl[i].event)) {
			printf("%s%s", sep, tbl[i].name);
			sep = ",";
		}
	}
}

static void CT_help_v0(void)
{
	printf(
"CT target options:\n"
" --notrack                     Don't track connection\n"
" --zone ID                     Assign/Lookup connection in zone ID\n"
" --ctevents event[,event...]   Generate specified conntrack events for connection\n"
" --expevents event[,event...]  Generate specified expectation events for connection\n"
" --helper name                 Use conntrack helper 'name' for connection\n"
" --zone {ID|mark}              Assign/Lookup connection in zone ID/packet nfmark\n"
" --zone-orig {ID|mark}         Same as 'zone' option, but only applies to ORIGINAL direction\n"
" --zone-reply {ID|mark}        Same as 'zone' option, but only applies to REPLY direction\n"
	);
}

static void CT_help(void)
{
	CT_help_v0();
	printf(
" --timeout name                Use timeout policy 'name' for connection\n"
	);
}

static void CT_show(const char *pfx, const struct xt_entry_target *target)
{
	const struct xt_ct_target_info *info = (const void *) target->data;
	const struct xt_ct_target_info_v1 *info1 = (const void *) target->data;
	const unsigned int revision = target->u.user.revision;

	if (info->flags & XT_CT_NOTRACK)
		printf(" %snotrack", pfx);
	if (info->helper[0])
		printf(" %shelper %s", pfx, info->helper);
	if (info->ct_events)
		ct_print_events(pfx, "ctevents", ct_event_tbl,
				ARRAY_SIZE(ct_event_tbl), info->ct_events);
	if (info->exp_events)
		ct_print_events(pfx, "expevents", exp_event_tbl,
				ARRAY_SIZE(exp_event_tbl), info->exp_events);
	if ((info->flags & XT_CT_ZONE_MARK) || info->zone)
		ct_print_zone_id(pfx, info->zone, info->flags);

	/* revision >= 1 */
	if (revision < 1)
		return;

	if (info1->timeout[0])
		printf(" %stimeout %s", pfx, info1->timeout);
}

static void CT_print(const void *ip, const struct xt_entry_target *target,
		     int numeric)
{
	const struct xt_ct_target_info *info = (const void *) target->data;

	if (info->flags & XT_CT_NOTRACK_ALIAS) {
		fputs(" NOTRACK", stdout);
		return;
	}

	fputs(" CT", stdout);
	CT_show("", target);
}

static void CT_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_ct_target_info *info = (const void *) target->data;

	if (info->flags & XT_CT_NOTRACK_ALIAS)
		return;

	CT_show("--", target);
}

static void CT_parse(struct xt_option_call *cb)
{
	struct xt_ct_target_info *info = cb->data;
	struct xt_ct_target_info_v1 *info1 = cb->data;
	const unsigned int revision = (*cb->target)->u.user.revision;
	unsigned int id;

	xtables_option_parse(cb);
	id = cb->entry->id;

	switch (id) {
	case O_NOTRACK:
		info->flags |= XT_CT_NOTRACK;
		break;
	case O_ZONE_ORIG:
	case O_ZONE_REPLY:
		/* revision >= 1 */
		if (revision < 1)
			goto no_supp;
	case O_ZONE:
		ct_parse_zone_id(cb->arg, id, &info->zone, &info->flags);
		break;
	case O_CTEVENTS:
		info->ct_events = ct_parse_events(ct_event_tbl,
						  ARRAY_SIZE(ct_event_tbl),
						  cb->arg);
		break;
	case O_EXPEVENTS:
		info->exp_events = ct_parse_events(exp_event_tbl,
						   ARRAY_SIZE(exp_event_tbl),
						   cb->arg);
		break;
	case O_HELPER:
		break;
	case O_TIMEOUT:
		/* revision >= 1 */
		if (revision < 1)
			goto no_supp;
		snprintf(info1->timeout, sizeof(info1->timeout), "%s", cb->arg);
		break;
	default:
		goto no_supp;
	}

	return;

no_supp:
	xtables_error(PARAMETER_PROBLEM,
		      "libxt_CT.%u does not support --%s",
		      revision,
		      ct_opts[id].name);
}

static const char *
CT_print_name_alias(const struct xt_entry_target *target)
{
	struct xt_ct_target_info *info = (void *)target->data;

	return (info->flags & XT_CT_NOTRACK_ALIAS) ? "NOTRACK" : "CT";
}

static void NOTRACK_ct_tg_init(struct xt_entry_target *target)
{
	struct xt_ct_target_info_v1 *info = (void *) target->data;
	const unsigned int revision = target->u.user.revision;

	if (revision < 2)
		info->flags = XT_CT_NOTRACK;
	else
		info->flags = XT_CT_NOTRACK | XT_CT_NOTRACK_ALIAS;
}

static struct xtables_target ct_target_reg[] = {
	{
		.family		= NFPROTO_UNSPEC,
		.name		= "CT",
		.version	= XTABLES_VERSION,
		.size		= XT_ALIGN(sizeof(struct xt_ct_target_info)),
		.userspacesize	= offsetof(struct xt_ct_target_info, ct),
		.help		= CT_help_v0,
		.print		= CT_print,
		.save		= CT_save,
		.x6_parse	= CT_parse,
		.x6_options	= ct_opts,
	},
	{
		.family		= NFPROTO_UNSPEC,
		.name		= "CT",
		.revision	= 1,
		.version	= XTABLES_VERSION,
		.size		= XT_ALIGN(sizeof(struct xt_ct_target_info_v1)),
		.userspacesize	= offsetof(struct xt_ct_target_info_v1, ct),
		.help		= CT_help,
		.print		= CT_print,
		.save		= CT_save,
		.x6_parse	= CT_parse,
		.x6_options	= ct_opts,
	},
	{
		.family		= NFPROTO_UNSPEC,
		.name		= "CT",
		.revision	= 2,
		.version	= XTABLES_VERSION,
		.size		= XT_ALIGN(sizeof(struct xt_ct_target_info_v1)),
		.userspacesize	= offsetof(struct xt_ct_target_info_v1, ct),
		.help		= CT_help,
		.print		= CT_print,
		.save		= CT_save,
		.alias		= CT_print_name_alias,
		.x6_parse	= CT_parse,
		.x6_options	= ct_opts,
	},
	{
		.family		= NFPROTO_UNSPEC,
		.name		= "NOTRACK",
		.real_name	= "CT",
		.revision	= 0,
		.version	= XTABLES_VERSION,
		.size		= XT_ALIGN(sizeof(struct xt_ct_target_info)),
		.userspacesize	= offsetof(struct xt_ct_target_info, ct),
		.init		= NOTRACK_ct_tg_init,
	},
	{
		.family		= NFPROTO_UNSPEC,
		.name		= "NOTRACK",
		.real_name	= "CT",
		.revision	= 1,
		.version	= XTABLES_VERSION,
		.size		= XT_ALIGN(sizeof(struct xt_ct_target_info_v1)),
		.userspacesize	= offsetof(struct xt_ct_target_info_v1, ct),
		.init		= NOTRACK_ct_tg_init,
	},
	{
		.family		= NFPROTO_UNSPEC,
		.name		= "NOTRACK",
		.real_name	= "CT",
		.revision	= 2,
		.ext_flags	= XTABLES_EXT_ALIAS,
		.version	= XTABLES_VERSION,
		.size		= XT_ALIGN(sizeof(struct xt_ct_target_info_v1)),
		.userspacesize	= offsetof(struct xt_ct_target_info_v1, ct),
		.init		= NOTRACK_ct_tg_init,
	},
	{
		.family		= NFPROTO_UNSPEC,
		.name		= "NOTRACK",
		.revision	= 0,
		.version	= XTABLES_VERSION,
	},
};

void _init(void)
{
	xtables_register_targets(ct_target_reg, ARRAY_SIZE(ct_target_reg));
}

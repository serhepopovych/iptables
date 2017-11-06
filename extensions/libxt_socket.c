/*
 * Shared library add-on to iptables to add early socket matching support.
 *
 * Copyright (C) 2007 BalaBit IT Ltd.
 */
#include <stdbool.h>
#include <stdio.h>
#include <xtables.h>
#include <linux/netfilter/xt_socket.h>

enum {
	O_TRANSPARENT = 0,
	O_NOWILDCARD,
	O_RESTORESKMARK,
};

static const struct xt_option_entry socket_opts[] = {
	[O_TRANSPARENT] = {
		.name	= "transparent",
		.id	= O_TRANSPARENT,
		.type	= XTTYPE_NONE,
	},
	[O_NOWILDCARD] = {
		.name	= "nowildcard",
		.id	= O_NOWILDCARD,
		.type	= XTTYPE_NONE,
	},
	[O_RESTORESKMARK] = {
		.name	= "restore-skmark",
		.id	= O_RESTORESKMARK,
		.type	= XTTYPE_NONE,
	},
	XTOPT_TABLEEND,
};

static void socket_help(void)
{
	printf(
"socket match options:\n"
"    --transparent                Ignore non-transparent sockets\n"
"    --nowildcard                 Don't ignore LISTEN sockets bound on INADDR_ANY\n"
"    --restore-skmark             Set the packet mark to the socket mark if\n"
"                                 the socket matches and transparent / \n"
"                                 nowildcard conditions are satisfied\n\n");
	);
}

static void
socket_parse(struct xt_option_call *cb)
{
	struct xt_socket_mtinfo2 *info = cb->data;
	const unsigned int revision = (*cb->match)->u.user.revision;
	unsigned int id;

	xtables_option_parse(cb);
	id = cb->entry->id;

	switch (id) {
	case O_TRANSPARENT:
		info->flags |= XT_SOCKET_TRANSPARENT;
		return;
	case O_NOWILDCARD:
		/* revision >= 2 */
		if (revision < 2)
			goto no_supp;
		info->flags |= XT_SOCKET_NOWILDCARD;
		return;
	case O_RESTORESKMARK:
		/* revision >= 3 */
		if (revision < 3)
			goto no_supp;
		info->flags |= XT_SOCKET_RESTORESKMARK;
		return;
	}

no_supp:
	xtables_error(PARAMETER_PROBLEM,
		      "libxt_socket.%u does not support --%s",
		      revision,
		      socket_opts[id].name);
}

static void
socket_show(const char *pfx, const struct xt_entry_match *match, bool numeric)
{
	const struct xt_socket_mtinfo2 *info = (const void *) match->data;
	const unsigned int revision = match->u.user.revision;

	if (!pfx)
		pfx = "";

	if (*pfx == '\0')
		printf(" socket");

	/* revision >= 1 */

	if (info->flags & XT_SOCKET_TRANSPARENT)
		printf(" %s%s", pfx, socket_opts[O_TRANSPARENT].name);

	/* revision >= 2 */

	if (revision < 2)
		return;

	if (info->flags & XT_SOCKET_NOWILDCARD)
		printf(" %s%s", pfx, socket_opts[O_NOWILDCARD].name);

	/* revision >= 3 */

	if (revision < 3)
		return;

	if (info->flags & XT_SOCKET_RESTORESKMARK)
		printf(" %s%s", pfx, socket_opts[O_RESTORESKMARK].name);
}

static void
socket_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	socket_show("", match, numeric);
}

static void socket_save(const void *ip, const struct xt_entry_match *match)
{
	socket_show("--", match, false);
}

static struct xtables_match socket_mt_reg[] = {
	{
		.name		= "socket",
		.revision	= 0,
		.family		= NFPROTO_IPV4,
		.version	= XTABLES_VERSION,
		.size		= XT_ALIGN(0),
		.userspacesize	= XT_ALIGN(0),
	},
	{
		.name		= "socket",
		.revision	= 1,
		.family		= NFPROTO_UNSPEC,
		.version	= XTABLES_VERSION,
		.size		= XT_ALIGN(sizeof(struct xt_socket_mtinfo1)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_socket_mtinfo1)),
		.help		= socket_help,
		.print		= socket_print,
		.save		= socket_save,
		.x6_parse	= socket_parse,
		.x6_options	= socket_opts,
	},
	{
		.name		= "socket",
		.revision	= 2,
		.family		= NFPROTO_UNSPEC,
		.version	= XTABLES_VERSION,
		.size		= XT_ALIGN(sizeof(struct xt_socket_mtinfo2)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_socket_mtinfo2)),
		.help		= socket_help,
		.print		= socket_print,
		.save		= socket_save,
		.x6_parse	= socket_parse,
		.x6_options	= socket_opts,
	},
	{
		.name		= "socket",
		.revision	= 3,
		.family		= NFPROTO_UNSPEC,
		.version	= XTABLES_VERSION,
		.size		= XT_ALIGN(sizeof(struct xt_socket_mtinfo3)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_socket_mtinfo3)),
		.help		= socket_help,
		.print		= socket_print,
		.save		= socket_save,
		.x6_parse	= socket_parse,
		.x6_options	= socket_opts,
	},
};

void _init(void)
{
	xtables_register_matches(socket_mt_reg, ARRAY_SIZE(socket_mt_reg));
}

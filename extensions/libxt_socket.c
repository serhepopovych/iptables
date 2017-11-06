/*
 * Shared library add-on to iptables to add early socket matching support.
 *
 * Copyright (C) 2007 BalaBit IT Ltd.
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <xtables.h>
#include <linux/netfilter/xt_socket.h>
#include <net/tcp_states.h>

enum {
	O_TRANSPARENT = 0,
	O_NOWILDCARD,
	O_RESTORESKMARK,
	O_INVERT,
	O_STATE,
	O_USER,
	O_GROUP,
};

static const struct xt_option_entry socket_opts[] = {
	[O_TRANSPARENT] = {
		.name	= "transparent",
		.id	= O_TRANSPARENT,
		.type	= XTTYPE_NONE,
		.flags	= XTOPT_INVERT,
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
	[O_INVERT] = {
		.name	= "invert",
		.id	= O_INVERT,
		.type	= XTTYPE_NONE,
	},
	[O_STATE] = {
		.name	= "state",
		.id	= O_STATE,
		.type	= XTTYPE_STRING,
		.flags	= XTOPT_INVERT,
	},
	[O_USER] = {
		.name	= "user",
		.id	= O_USER,
		.type	= XTTYPE_STRING,
		.flags	= XTOPT_INVERT,
	},
	[O_GROUP] = {
		.name	= "group",
		.id	= O_GROUP,
		.type	= XTTYPE_STRING,
		.flags	= XTOPT_INVERT,
	},
	XTOPT_TABLEEND,
};

static void socket_help(void)
{
	printf(
"socket match options:\n"
"[!] --transparent                Ignore non-transparent sockets\n"
"    --nowildcard                 Don't ignore LISTEN sockets bound on INADDR_ANY\n"
"    --restore-skmark             Set the packet mark to the socket mark if\n"
"                                 the socket matches and transparent / \n"
"                                 nowildcard conditions are satisfied\n\n"
"    --invert                     Invert matching result\n"
"[!] --state <sk_state>[,...]     Match socket states, where <sk_state> could be\n"
"          NEW         for sockets in state TCP_LISTEN, TCP_SYN_SENT or\n"
"                      TCP_SYN_RECV\n"
"          ESTABLISHED for sockets in state TCP_ESTABLISHED\n"
"          CLOSING     for sockets in state TCP_FIN_WAIT1, TCP_FIN_WAIT2,\n"
"                      TCP_TIME_WAIT, TCP_CLOSE, TCP_CLOSE_WAIT, TCP_LAST_ACK\n"
"                      or TCP_CLOSING\n"
"          ANY         for sockets in any state\n"
"        Also socket state could be matched individually with any combination of\n"
"        TCP_ESTABLISHED, TCP_SYN_SENT, TCP_SYN_RECV, TCP_FIN_WAIT1,\n"
"        TCP_FIN_WAIT2, TCP_TIME_WAIT, TCP_CLOSE, TCP_CLOSE_WAIT, TCP_LAST_ACK,\n"
"        TCP_LISTEN or TCP_CLOSING.\n"
"[!] --user  {<usrid>|from[-to]}  Match when socket owned by the user\n"
"[!] --group {<grpid>|from[-to]}  Match when socket owned by the group\n"
	);
}

#define TCPF_ALL (((1 << (TCP_MAX_STATES - 1)) - 1) << 1)

#define XT_SOCKET_STATE_NEW		\
	(TCPF_LISTEN|			\
	 TCPF_SYN_SENT|			\
	 TCPF_SYN_RECV)

#define XT_SOCKET_STATE_ESTABLISHED	\
	(TCPF_ESTABLISHED)

#define XT_SOCKET_STATE_CLOSING		\
	(TCPF_FIN_WAIT1|		\
	 TCPF_FIN_WAIT2|		\
	 TCPF_TIME_WAIT|		\
	 TCPF_CLOSE|			\
	 TCPF_CLOSE_WAIT|		\
	 TCPF_LAST_ACK|			\
	 TCPF_CLOSING)

#define XT_SOCKET_STATE_ANY		\
	(TCPF_ALL)

struct socket_state {
	const char *name;
	unsigned int state;
};

static const struct socket_state socket_states1[] = {
	{ "ANY",		XT_SOCKET_STATE_ANY,		},
	{ "NEW",		XT_SOCKET_STATE_NEW,		},
	{ "ESTABLISHED",	XT_SOCKET_STATE_ESTABLISHED,	},
	{ "CLOSING",		XT_SOCKET_STATE_CLOSING,	},
};

static const struct socket_state socket_states2[] = {
	{ "TCP_ESTABLISHED",	TCPF_ESTABLISHED,		},
	{ "TCP_SYN_SENT",	TCPF_SYN_SENT,			},
	{ "TCP_SYN_RECV",	TCPF_SYN_RECV,			},
	{ "TCP_FIN_WAIT1",	TCPF_FIN_WAIT1,			},
	{ "TCP_FIN_WAIT2",	TCPF_FIN_WAIT2,			},
	{ "TCP_TIME_WAIT",	TCPF_TIME_WAIT,			},
	{ "TCP_CLOSE",		TCPF_CLOSE,			},
	{ "TCP_CLOSE_WAIT",	TCPF_CLOSE_WAIT,		},
	{ "TCP_LAST_ACK",	TCPF_LAST_ACK,			},
	{ "TCP_LISTEN",		TCPF_LISTEN,			},
	{ "TCP_CLOSING",	TCPF_CLOSING,			},
};

static unsigned int
socket_parse_states(const char *token, const struct socket_state *sk_state,
		    size_t n)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		if (!strcasecmp(token, sk_state[i].name))
			return sk_state[i].state;
	}

	return 0;
}

static unsigned int
socket_parse_state(const char *s, const char *opt)
{
	const char *token;
	unsigned int states = 0;
	char *str;

	str = strdup(s);
	for (token = strtok(str, ","); token; token = strtok(NULL, ",")) {
		unsigned int state;

		state = socket_parse_states(token, socket_states1,
					    ARRAY_SIZE(socket_states1));
		if (!state) {
			state = socket_parse_states(token, socket_states2,
						    ARRAY_SIZE(socket_states2));
			if (!state) {
				xtables_param_act(XTF_BAD_VALUE, "socket", opt,
						  s);
			}
		}
		states |= state;
	}
	free(str);

	return states;
}

static void
socket_parse_cred(const char *s, unsigned int *from,
		  unsigned int *to, const char *opt)
{
	char *end;

	/* -1 is reversed, so the max is one less than that. */
	if (!xtables_strtoui(s, &end, from, 0, UINT32_MAX - 1))
		xtables_param_act(XTF_BAD_VALUE, "socket", opt, s);

	if (*end == '-' || *end == ':') {
		if (!xtables_strtoui(end + 1, &end, to, 0, UINT32_MAX - 1))
			xtables_param_act(XTF_BAD_VALUE, "socket", opt, s);
	} else {
		*to = *from;
	}

	if (*end != '\0')
		xtables_param_act(XTF_BAD_VALUE, "socket", opt, s);

	if (*from > *to)
		xtables_param_act(XTF_BAD_VALUE, "socket", opt, s);
}

static void
socket_parse(struct xt_option_call *cb)
{
	struct xt_socket_mtinfo4 *info = cb->data;
	const unsigned int revision = (*cb->match)->u.user.revision;
	unsigned int id, from, to;
	struct passwd *pwd;
	struct group *grp;

	xtables_option_parse(cb);
	id = cb->entry->id;

	switch (id) {
	case O_TRANSPARENT:
		info->flags |= XT_SOCKET_TRANSPARENT;
		/* revision >= 3 */
		if (cb->invert) {
			if (revision < 3)
				goto no_supp;
			info->invflags |= XT_SOCKET_TRANSPARENT;
		}
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

	/* revision >= 4 */

	if (revision < 4)
		goto no_supp;

	switch (id) {
	case O_INVERT:
		info->flags |= XT_SOCKET_INVERT;
		return;
	case O_STATE:
		info->state = socket_parse_state(cb->arg, "--state");
		info->flags |= XT_SOCKET_STATE;
		if (cb->invert)
			info->invflags |= XT_SOCKET_STATE;
		return;
	case O_USER:
		pwd = getpwnam(cb->arg);
		if (pwd)
			from = to = pwd->pw_uid;
		else
			socket_parse_cred(cb->arg, &from, &to, "--user");
		info->uid_min = from;
		info->uid_max = to;
		info->flags |= XT_SOCKET_USER;
		if (cb->invert)
			info->invflags |= XT_SOCKET_USER;
		return;
	case O_GROUP:
		grp = getgrnam(cb->arg);
		if (grp)
			from = to = grp->gr_gid;
		else
			socket_parse_cred(cb->arg, &from, &to, "--group");
		info->gid_min = from;
		info->gid_max = to;
		info->flags |= XT_SOCKET_GROUP;
		if (cb->invert)
			info->invflags |= XT_SOCKET_GROUP;
		return;
	}

no_supp:
	xtables_error(PARAMETER_PROBLEM,
		      "libxt_socket.%u does not support %s--%s",
		      revision,
		      cb->invert ? "! " : "",
		      socket_opts[id].name);
}

static char *
socket_show_states(char *buf, size_t buf_size, unsigned int states,
		   const struct socket_state *sk_state, size_t n)
{
	const char *comma = "";
	char *buf_ptr;
	int i;

	states &= TCPF_ALL;
	if (!states)
		return NULL;

	buf_ptr = buf;
	for (i = 0; i < n; i++) {
		unsigned int state = sk_state[i].state;
		int ret;

		if ((states & state) != state)
			continue;

		ret = snprintf(buf_ptr, buf_size, "%s%s",
			       comma, sk_state[i].name);
		if (ret < 0 || ret >= buf_size)
			return NULL;

		states &= ~state;
		if (!states)
			return buf;

		buf_ptr += ret;
		buf_size -= ret;

		comma = ",";
	}

	return NULL;
}

static void
socket_show_state(const char *pfx, const struct xt_socket_mtinfo4 *info)
{
	const char *inv;
	char buf[256], *p;

	if (!(info->flags & XT_SOCKET_STATE))
		return;

	p = socket_show_states(buf, sizeof(buf), info->state,
			       socket_states1, ARRAY_SIZE(socket_states1));
	if (!p) {
		p = socket_show_states(buf, sizeof(buf), info->state,
				       socket_states2,
				       ARRAY_SIZE(socket_states2));
		if (!p)
			return;
	}

	inv = (info->invflags & XT_SOCKET_STATE) ? "! " : "";
	printf(" %s%s%s %s", inv, pfx, socket_opts[O_STATE].name, buf);
}

static void
socket_show_cred(const char *pfx, const struct xt_socket_mtinfo4 *info,
		 bool numeric, unsigned int flag)
{
	const char *opt, *inv, *name = NULL;
	unsigned int from, to;

	switch (info->flags & flag) {
	case XT_SOCKET_USER:
		opt = socket_opts[O_USER].name;
		from = info->uid_min;
		to = info->uid_max;
		if (from == to && !numeric) {
			struct passwd *pwd = getpwuid(info->uid_min);

			if (pwd)
				name = pwd->pw_name;
		}
		break;
	case XT_SOCKET_GROUP:
		opt = socket_opts[O_GROUP].name;
		from = info->gid_min;
		to = info->gid_max;
		if (from == to && !numeric) {
			struct group *grp = getgrgid(info->gid_min);

			if (grp)
				name = grp->gr_name;
		}
		break;
	default:
		return;
	}

	inv = (info->invflags & flag) ? "! " : "";
	printf(" %s%s%s", inv, pfx, opt);

	if (from != to)
		printf(" %u-%u", from, to);
	else if (name)
		printf(" %s", name);
	else
		printf(" %u", from);
}

static void
socket_show(const char *pfx, const struct xt_entry_match *match, bool numeric)
{
	const struct xt_socket_mtinfo4 *info = (const void *) match->data;
	const unsigned int revision = match->u.user.revision;
	const char *inv;

	if (!pfx)
		pfx = "";

	if (*pfx == '\0')
		printf(" socket");

	/* revision >= 1 */

	if (info->flags & XT_SOCKET_TRANSPARENT) {
		inv = (info->invflags & XT_SOCKET_TRANSPARENT) &&
		      revision >= 3 ? "! " : "";
		printf(" %s%s%s", inv, pfx, socket_opts[O_TRANSPARENT].name);
	}

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

	/* revision >= 4 */

	if (revision < 4)
		return;

	if (info->flags & XT_SOCKET_INVERT)
		printf(" %s%s", pfx, socket_opts[O_INVERT].name);

	socket_show_state(pfx, info);
	socket_show_cred(pfx, info, numeric, XT_SOCKET_USER);
	socket_show_cred(pfx, info, numeric, XT_SOCKET_GROUP);
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
	{
		.name		= "socket",
		.revision	= 4,
		.family		= NFPROTO_UNSPEC,
		.version	= XTABLES_VERSION,
		.size		= XT_ALIGN(sizeof(struct xt_socket_mtinfo4)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_socket_mtinfo4)),
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

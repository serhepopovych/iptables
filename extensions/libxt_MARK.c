#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <xtables.h>
#include <linux/netfilter/xt_MARK.h>

/* revision 0 */
struct xt_mark_tginfo0 {
	unsigned long mark;
};

/* revision 1 */
enum {
	XT_MARK_SET = 0,
	XT_MARK_AND,
	XT_MARK_OR,
};

struct xt_mark_tginfo1 {
	unsigned long mark;
	uint8_t mode;
};

enum {
	/* common */
	O_SET_MARK	= 0,

	F_SET_MARK	= (1 << O_SET_MARK),

	F_COMMON	= F_SET_MARK,

	/* revision 0 */
	F_REV0		= F_SET_MARK,
	F_REV0_ALL	= F_COMMON | F_REV0,

	/* revision 1 */
	O_AND_MARK	= 1,
	O_OR_MARK	= 2,

	F_AND_MARK	= (1 << O_AND_MARK),
	F_OR_MARK	= (1 << O_OR_MARK),

	F_REV1		= F_AND_MARK | F_OR_MARK,
	F_REV1_ALL	= F_REV1 | F_REV0_ALL,

	/* revision 2 */
	O_XOR_MARK	= 3,
	O_SET_XMARK	= 4,

	F_XOR_MARK	= 1 << O_XOR_MARK,
	F_SET_XMARK	= 1 << O_SET_XMARK,

	F_REV2		= F_XOR_MARK | F_SET_XMARK,
	F_REV2_ALL	= F_REV2 | F_REV1_ALL,

	F_ANY_MARK	= F_SET_MARK | F_AND_MARK | F_OR_MARK |
			  F_XOR_MARK | F_SET_XMARK,
};

static const struct xt_option_entry mark_opts[] = {
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

static void
mark_show(const char *fmt, unsigned int mode, unsigned long mark)
{
	static const char mark_modes[][sizeof("set")] = {
		[XT_MARK_SET]	= "set",
		[XT_MARK_AND]	= "and",
		[XT_MARK_OR]	= "or",
	};

	if (mode < ARRAY_SIZE(mark_modes)) {
		printf(fmt, mark_modes[mode]);
		printf(" 0x%lx", mark);
	}
}

/* revision 0 */

static void MARK_help_v0(void)
{
	printf(
"MARK target options:\n"
"  --set-mark value    Set mark value\n"
	);
}

static void MARK_print_v0(const void *ip, const struct xt_entry_target *target,
			  int numeric)
{
	const struct xt_mark_tginfo0 *info = (const void *) target->data;

	mark_show(" MARK %s", XT_MARK_SET, info->mark);
}

static void MARK_save_v0(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_mark_tginfo0 *info = (const void *) target->data;

	mark_show(" --%s-mark", XT_MARK_SET, info->mark);
}

static void MARK_parse_v0(struct xt_option_call *cb)
{
	struct xt_mark_tginfo0 *info = cb->data;
	const unsigned int revision = (*cb->target)->u.user.revision;
	unsigned int id;

	xtables_option_parse(cb);
	id = cb->entry->id;

	switch (id) {
	case O_SET_MARK:
		info->mark = cb->val.mark;
		break;
	default:
		xtables_error(PARAMETER_PROBLEM,
			      "libxt_MARK.%u does not support --%s",
			      revision,
			      mark_opts[id].name);
	}
}

static void MARK_check_v0(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0) {
		xtables_error(PARAMETER_PROBLEM,
			      "MARK target: Parameter --set-mark"
			      " is required");
	}
}

/* revision 1 */

static void MARK_help_v1(void)
{
	MARK_help_v0();
	printf(
"  --and-mark bits     Binary AND the mark with bits\n"
"  --or-mark bits      Binary OR the mark with bits\n"
	);
}

static void MARK_print_v1(const void *ip, const struct xt_entry_target *target,
			  int numeric)
{
	const struct xt_mark_tginfo1 *info = (const void *) target->data;

	mark_show(" MARK %s", info->mode, info->mark);
}

static void MARK_save_v1(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_mark_tginfo1 *info = (const void *) target->data;

	mark_show(" --%s-mark", info->mode, info->mark);
}

static void MARK_parse_v1(struct xt_option_call *cb)
{
	struct xt_mark_tginfo1 *info = cb->data;
	const unsigned int revision = (*cb->target)->u.user.revision;
	unsigned int id;

	xtables_option_parse(cb);
	id = cb->entry->id;

	switch (id) {
	case O_SET_MARK:
		info->mode = XT_MARK_SET;
		info->mark = cb->val.mark;
		break;
	case O_AND_MARK:
		info->mode = XT_MARK_AND;
		info->mark = cb->val.u32;
		break;
	case O_OR_MARK:
		info->mode = XT_MARK_OR;
		info->mark = cb->val.u32;
		break;
	default:
		xtables_error(PARAMETER_PROBLEM,
			      "libxt_MARK.%u does not support --%s",
			      revision,
			      mark_opts[id].name);
	}
}

static void MARK_check_v1(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0) {
		xtables_error(PARAMETER_PROBLEM,
			      "MARK target: Parameter --{set,and,or}-mark"
			      " is required");
	}
}

/* revision >= 2 */

static void MARK_help_v2(void)
{
	printf(
"MARK target options:\n"
"  --set-xmark value[/mask]  Clear bits in mask and XOR value into nfmark\n"
"  --set-mark value[/mask]   Clear bits in mask and OR value into nfmark\n"
"  --and-mark bits           Binary AND the nfmark with bits\n"
"  --or-mark bits            Binary OR the nfmark with bits\n"
"  --xor-mark bits           Binary XOR the nfmark with bits\n"
	);
}

static void
MARK_show(const char *pfx, const struct xt_entry_target *target)
{
	const struct xt_mark_tginfo2 *info = (const void *) target->data;
	unsigned int mode, mark;

	if (!pfx)
		pfx = "";

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

	printf(" %s%s", pfx, mark_opts[mode].name);

	printf(" 0x%x", mark);
	if (mode == O_SET_XMARK)
		printf("/0x%x", info->mask);
}

static void
MARK_print(const void *ip, const struct xt_entry_target *target, int numeric)
{
	printf(" MARK");
	MARK_show("", target);
}

static void
MARK_save(const void *ip, const struct xt_entry_target *target)
{
	MARK_show("--", target);
}

static void MARK_parse(struct xt_option_call *cb)
{
	struct xt_mark_tginfo2 *info = cb->data;
	const unsigned int revision = (*cb->target)->u.user.revision;
	unsigned int id;

	xtables_option_parse(cb);
	id = cb->entry->id;

	switch (id) {
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
		goto no_supp;
	}

	return;

no_supp:
	xtables_error(PARAMETER_PROBLEM,
		      "libxt_MARK.%u does not support --%s",
		      revision,
		      mark_opts[id].name);
}

static void MARK_check(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0) {
		xtables_error(PARAMETER_PROBLEM, "MARK: One of the --set-xmark, "
			      "--{and,or,xor,set}-mark options is required");
	}
}

static void mark_tg_arp_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_mark_tginfo2 *info = (const void *)target->data;

	if (info->mark == 0)
		printf(" --and-mark %x", (unsigned int)(uint32_t)~info->mask);
	else if (info->mark == info->mask)
		printf(" --or-mark %x", info->mark);
	else
		printf(" --set-mark %x", info->mark);
}

static void mark_tg_arp_print(const void *ip,
			      const struct xt_entry_target *target, int numeric)
{
	mark_tg_arp_save(ip, target);
}

#define MARK_OPT 1
#define AND_MARK_OPT 2
#define OR_MARK_OPT 3

static struct option mark_tg_arp_opts[] = {
	{ .name = "set-mark", .has_arg = required_argument, .flag = 0, .val = MARK_OPT },
	{ .name = "and-mark", .has_arg = required_argument, .flag = 0, .val = AND_MARK_OPT },
	{ .name = "or-mark", .has_arg = required_argument, .flag = 0, .val =  OR_MARK_OPT },
	{ .name = NULL}
};

static int
mark_tg_arp_parse(int c, char **argv, int invert, unsigned int *flags,
		  const void *entry, struct xt_entry_target **target)
{
	struct xt_mark_tginfo2 *info =
		(struct xt_mark_tginfo2 *)(*target)->data;
	int i;

	switch (c) {
	case MARK_OPT:
		if (sscanf(argv[optind-1], "%x", &i) != 1) {
			xtables_error(PARAMETER_PROBLEM,
				"Bad mark value `%s'", optarg);
			return 0;
		}
		info->mark = i;
		if (*flags)
			xtables_error(PARAMETER_PROBLEM,
				"MARK: Can't specify --set-mark twice");
		*flags = 1;
		break;
	case AND_MARK_OPT:
		if (sscanf(argv[optind-1], "%x", &i) != 1) {
			xtables_error(PARAMETER_PROBLEM,
				"Bad mark value `%s'", optarg);
			return 0;
		}
		info->mark = 0;
		info->mask = ~i;
		if (*flags)
			xtables_error(PARAMETER_PROBLEM,
				"MARK: Can't specify --and-mark twice");
		*flags = 1;
		break;
	case OR_MARK_OPT:
		if (sscanf(argv[optind-1], "%x", &i) != 1) {
			xtables_error(PARAMETER_PROBLEM,
				"Bad mark value `%s'", optarg);
			return 0;
		}
		info->mark = info->mask = i;
		if (*flags)
			xtables_error(PARAMETER_PROBLEM,
				"MARK: Can't specify --or-mark twice");
		*flags = 1;
		break;
	default:
		return 0;
	}
	return 1;
}

static int mark_xlate(struct xt_xlate *xl,
		      const struct xt_xlate_tg_params *params)
{
	const struct xt_mark_tginfo2 *info = (const void *)params->target->data;

	xt_xlate_add(xl, "meta mark set ");

	if (info->mask == 0xffffffffU)
		xt_xlate_add(xl, "0x%x ", info->mark);
	else if (info->mark == 0)
		xt_xlate_add(xl, "mark and 0x%x ", ~info->mask);
	else if (info->mark == info->mask)
		xt_xlate_add(xl, "mark or 0x%x ", info->mark);
	else if (info->mask == 0)
		xt_xlate_add(xl, "mark xor 0x%x ", info->mark);
	else
		xt_xlate_add(xl, "mark and 0x%x xor 0x%x ", ~info->mask,
			     info->mark);

	return 1;
}

static int MARK_xlate(struct xt_xlate *xl,
		      const struct xt_xlate_tg_params *params)
{
	const struct xt_mark_tginfo1 *info = (const void *)params->target->data;

	xt_xlate_add(xl, "meta mark set ");

	switch(info->mode) {
	case XT_MARK_SET:
		xt_xlate_add(xl, "0x%x ", info->mark);
		break;
	case XT_MARK_AND:
		xt_xlate_add(xl, "mark and 0x%x ", info->mark);
		break;
	case XT_MARK_OR:
		xt_xlate_add(xl, "mark or 0x%x ", info->mark);
		break;
	}

	return 1;
}

static struct xtables_target mark_tg_reg[] = {
	{
		.family		= NFPROTO_UNSPEC,
		.name		= "MARK",
		.version	= XTABLES_VERSION,
		.revision	= 0,
		.size		= XT_ALIGN(sizeof(struct xt_mark_tginfo0)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_mark_tginfo0)),
		.help		= MARK_help_v0,
		.print		= MARK_print_v0,
		.save		= MARK_save_v0,
		.x6_parse	= MARK_parse_v0,
		.x6_fcheck	= MARK_check_v0,
		.x6_options	= mark_opts,
	},
	{
		.family		= NFPROTO_IPV4,
		.name		= "MARK",
		.version	= XTABLES_VERSION,
		.revision	= 1,
		.size		= XT_ALIGN(sizeof(struct xt_mark_tginfo1)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_mark_tginfo1)),
		.help		= MARK_help_v1,
		.print		= MARK_print_v1,
		.save		= MARK_save_v1,
		.x6_parse	= MARK_parse_v1,
		.x6_fcheck	= MARK_check_v1,
		.x6_options	= mark_opts,
		.xlate		= MARK_xlate,
	},
	{
		.version	= XTABLES_VERSION,
		.name		= "MARK",
		.revision	= 2,
		.family		= NFPROTO_UNSPEC,
		.size		= XT_ALIGN(sizeof(struct xt_mark_tginfo2)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_mark_tginfo2)),
		.help		= MARK_help_v2,
		.print		= MARK_print,
		.save		= MARK_save,
		.x6_parse	= MARK_parse,
		.x6_fcheck	= MARK_check,
		.x6_options	= mark_opts,
		.xlate		= mark_xlate,
	},
	{
		.version       = XTABLES_VERSION,
		.name          = "MARK",
		.revision      = 2,
		.family        = NFPROTO_ARP,
		.size          = XT_ALIGN(sizeof(struct xt_mark_tginfo2)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_mark_tginfo2)),
		.help          = mark_tg_help,
		.print         = mark_tg_arp_print,
		.save          = mark_tg_arp_save,
		.parse         = mark_tg_arp_parse,
		.extra_opts    = mark_tg_arp_opts,
	},
};

void _init(void)
{
	xtables_register_targets(mark_tg_reg, ARRAY_SIZE(mark_tg_reg));
}

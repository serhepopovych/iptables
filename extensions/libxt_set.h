#ifndef _LIBXT_SET_H
#define _LIBXT_SET_H

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include "../iptables/xshared.h"

static int
get_version(unsigned *version)
{
	int res, sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	struct ip_set_req_version req_version;
	socklen_t size = sizeof(req_version);
	
	if (sockfd < 0)
		xtables_error(OTHER_PROBLEM,
			      "Can't open socket to ipset.\n");

	if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) == -1) {
		xtables_error(OTHER_PROBLEM,
			      "Could not set close on exec: %s\n",
			      strerror(errno));
	}

	req_version.op = IP_SET_OP_VERSION;
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req_version, &size);
	if (res != 0)
		xtables_error(OTHER_PROBLEM,
			      "Kernel module xt_set is not loaded in.\n");

	*version = req_version.version;
	
	return sockfd;
}

static void
get_set_byid(char *setname, ip_set_id_t idx)
{
	struct ip_set_req_get_set req;
	socklen_t size = sizeof(struct ip_set_req_get_set);
	int res, sockfd;

	sockfd = get_version(&req.version);
	req.op = IP_SET_OP_GET_BYINDEX;
	req.set.index = idx;
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req, &size);
	close(sockfd);

	if (res != 0)
		xtables_error(OTHER_PROBLEM,
			"Problem when communicating with ipset, errno=%d.\n",
			errno);
	if (size != sizeof(struct ip_set_req_get_set))
		xtables_error(OTHER_PROBLEM,
			"Incorrect return size from kernel during ipset lookup, "
			"(want %zu, got %zu)\n",
			sizeof(struct ip_set_req_get_set), (size_t)size);
	if (req.set.name[0] == '\0')
		xtables_error(PARAMETER_PROBLEM,
			"Set with index %i in kernel doesn't exist.\n", idx);

	strncpy(setname, req.set.name, IPSET_MAXNAMELEN);
}

static void
get_set_byname_only(const char *setname, struct xt_set_info *info,
		    int sockfd, unsigned int version)
{
	struct ip_set_req_get_set req = { .version = version };
	socklen_t size = sizeof(struct ip_set_req_get_set);
	int res;

	req.op = IP_SET_OP_GET_BYNAME;
	strncpy(req.set.name, setname, IPSET_MAXNAMELEN);
	req.set.name[IPSET_MAXNAMELEN - 1] = '\0';
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req, &size);
	close(sockfd);

	if (res != 0)
		xtables_error(OTHER_PROBLEM,
			"Problem when communicating with ipset, errno=%d.\n",
			errno);
	if (size != sizeof(struct ip_set_req_get_set))
		xtables_error(OTHER_PROBLEM,
			"Incorrect return size from kernel during ipset lookup, "
			"(want %zu, got %zu)\n",
			sizeof(struct ip_set_req_get_set), (size_t)size);
	if (req.set.index == IPSET_INVALID_ID)
		xtables_error(PARAMETER_PROBLEM,
			      "Set %s doesn't exist.\n", setname);

	info->index = req.set.index;
}

static void
get_set_byname(const char *setname, struct xt_set_info *info)
{
	struct ip_set_req_get_set_family req;
	socklen_t size = sizeof(struct ip_set_req_get_set_family);
	int res, sockfd, version;

	sockfd = get_version(&req.version);
	version = req.version;
	req.op = IP_SET_OP_GET_FNAME;
	strncpy(req.set.name, setname, IPSET_MAXNAMELEN);
	req.set.name[IPSET_MAXNAMELEN - 1] = '\0';
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req, &size);

	if (res != 0 && errno == EBADMSG)
		/* Backward compatibility */
		return get_set_byname_only(setname, info, sockfd, version);

	close(sockfd);
	if (res != 0)
		xtables_error(OTHER_PROBLEM,
			"Problem when communicating with ipset, errno=%d.\n",
			errno);
	if (size != sizeof(struct ip_set_req_get_set_family))
		xtables_error(OTHER_PROBLEM,
			"Incorrect return size from kernel during ipset lookup, "
			"(want %zu, got %zu)\n",
			sizeof(struct ip_set_req_get_set_family),
			(size_t)size);
	if (req.set.index == IPSET_INVALID_ID)
		xtables_error(PARAMETER_PROBLEM,
			      "Set %s doesn't exist.\n", setname);
	if (!(req.family == afinfo->family ||
	      req.family == NFPROTO_UNSPEC))
		xtables_error(PARAMETER_PROBLEM,
			      "The protocol family of set %s is %s, "
			      "which is not applicable.\n",
			      setname,
			      req.family == NFPROTO_IPV4 ? "IPv4" : "IPv6");

	info->index = req.set.index;
}

static void
parse_dirs(const char *opt_arg, struct xt_set_info *info, unsigned int *physdev)
{
	char *saved = strdup(opt_arg);
	char *tmp = saved;
	int dim_max = IPSET_DIM_MAX - 1 * (info->index == IPSET_INVALID_ID);

	while (tmp != NULL) {
		char *ptr, *str;

		if (++info->dim > dim_max)
			xtables_error(PARAMETER_PROBLEM,
				      "Can't be more src/dst options than %d.",
				      dim_max);
		ptr = strsep(&tmp, ",");

		if (physdev != NULL && (str = strchr(ptr, ':')) != NULL) {
			*str++ = '\0';
			if (strncmp(ptr, "physdev", 7) != 0)
				xtables_error(PARAMETER_PROBLEM,
					      "'src' or 'dst' can only be prefixed with 'physdev'.");
			ptr = str;
			*physdev |= (1 << info->dim);
		}

		if (strncmp(ptr, "src", 3) == 0)
			info->flags |= (1 << info->dim);
		else if (strncmp(ptr, "dst", 3) != 0)
			xtables_error(PARAMETER_PROBLEM,
				"You must spefify (the comma separated list of) 'src' or 'dst'.");
	}

	free(saved);
}

static void
parse_dirs_v0(const char *opt_arg, struct xt_set_info_v0 *info)
{
	struct xt_set_info i = {};

	/* Kernel side in xt_set.c does not accept more than
	 * IPSET_DIM_MAX - 1 dimensions: follow this limit and
	 * report it correctly in userspace.
	 */
	i.index = IPSET_INVALID_ID;

	parse_dirs(opt_arg, &i, NULL);

	while (i.dim) {
		int flags = i.flags & (1 << i.dim) ? IPSET_SRC : IPSET_DST;
		info->u.flags[--i.dim] = flags;
	}
}

#endif /*_LIBXT_SET_H*/

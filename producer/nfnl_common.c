#include <errno.h>
#include <string.h>

#include <libmnl/libmnl.h>
#include <nurs/nurs.h>

#include "nfnl_common.h"

int mnl_socket_set_reliable(struct mnl_socket *nl)
{
	int on = 1;

	if (mnl_socket_setsockopt(nl, NETLINK_BROADCAST_ERROR,
				  &on, sizeof(int)) == -1)
		return -1;
	if (mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS,
				  &on, sizeof(int)) == -1)
		return -1;

	return 0;
}

void frame_destructor(void *data)
{
	struct nl_mmap_hdr *frame = data;
	frame->nm_status = NL_MMAP_STATUS_UNUSED;
}

struct mnl_socket *nurs_mnl_socket(const char *ns, int bus)
{
	int fd;

	if (!ns || !strlen(ns))
		return mnl_socket_open(bus);

	fd = nurs_nssocket(ns, AF_NETLINK, SOCK_RAW, bus);
	if (fd == -1)
		return NULL;

	return mnl_socket_fdopen(fd);
}

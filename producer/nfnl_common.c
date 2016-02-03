#include <libmnl/libmnl.h>

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

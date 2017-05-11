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

enum nurs_return_t nurs_ret_from_mnl(int rc)
{
        switch (rc) {
        case MNL_CB_OK: return NURS_RET_OK;
        case MNL_CB_STOP: return NURS_RET_STOP;
        case MNL_CB_ERROR:
		nurs_log(NURS_ERROR, "mnl_cb_run: [%d]%s\n",
			 errno, strerror(errno));
		return NURS_RET_ERROR;
        default:
                nurs_log(NURS_ERROR, "mnl_cb_run - unknown code: %d\n", rc);
                return NURS_RET_ERROR;
        }

        return NURS_RET_ERROR;
}

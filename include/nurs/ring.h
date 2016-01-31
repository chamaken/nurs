/*
 * (C) 2016 by Ken-ichirou MATSUZAWA <chamas@h4.dion.ne.jp>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * based on ulogd which was almost entirely written by Harald Welte,
 * with contributions from fellow hackers such as Pablo Neira Ayuso,
 * Eric Leblond and Pierre Chifflier.
 */
#ifndef _ULOGD_RING_H_
#define _ULOGD_RING_H_

#include <stdint.h>
#include <linux/netlink.h>
#include <libmnl/libmnl.h>

struct mnl_ring {
	unsigned int		head;
	void			*ring;
	unsigned int		frame_size;
	unsigned int		frame_max;
	unsigned int		block_size;
};

#ifndef MNL_FRAME_PAYLOAD
#define MNL_FRAME_PAYLOAD(frame) \
	((struct nlmsghdr *)((uintptr_t)(frame) + NL_MMAP_HDRLEN))
#endif
#ifndef MNL_NLMSG_FRAME
#define MNL_NLMSG_FRAME(nlh) \
	((struct nl_mmap_hdr *)((uintptr_t)(nlh) - NL_MMAP_HDRLEN))
#endif

struct mnl_ring *
mnl_socket_rx_mmap(struct mnl_socket *nls, struct nl_mmap_req *req, int flags);
struct mnl_ring *
mnl_socket_tx_mmap(struct mnl_socket *nls, struct nl_mmap_req *req, int flags);
int mnl_socket_unmap(struct mnl_ring *nlr);
void mnl_ring_advance(struct mnl_ring *nlr);
struct nl_mmap_hdr *mnl_ring_get_frame(const struct mnl_ring *nlr);
struct nl_mmap_hdr *mnl_ring_lookup_frame(struct mnl_ring *nlr,
					  enum nl_mmap_status status);

extern char *_frame_status_strlist[];

#endif

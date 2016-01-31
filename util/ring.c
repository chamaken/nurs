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
#include <stdlib.h>
#include <sys/mman.h>

#include <libmnl/libmnl.h>

#include <nurs/ring.h>

#include "../src/internal.h"

char *_frame_status_strlist[] = {
	[NL_MMAP_STATUS_UNUSED]		= "UNUSED",
        [NL_MMAP_STATUS_RESERVED]	= "RESERVED",
        [NL_MMAP_STATUS_VALID]		= "VALID",
        [NL_MMAP_STATUS_COPY]		= "COPY",
        [NL_MMAP_STATUS_SKIP]		= "SKIP",
};


static struct mnl_ring *alloc_ring(const struct nl_mmap_req *req)
{
	struct mnl_ring *ring;

	ring = calloc(1, sizeof(struct mnl_ring));
	if (ring == NULL)
		return NULL;

	ring->frame_size	= req->nm_frame_size;
	ring->frame_max		= req->nm_frame_nr - 1;
	ring->block_size	= req->nm_block_size;

	return ring;
}

static inline size_t ring_size(struct mnl_ring *ring)
{
	unsigned int frames_per_block = ring->block_size / ring->frame_size;
	unsigned int block_nr = (ring->frame_max + 1) / frames_per_block;
	return block_nr * ring->block_size;
}

static struct mnl_ring *
mnl_socket_mmap(struct mnl_socket *nls, struct nl_mmap_req *req,
		int flags, int optname)
{
	struct mnl_ring *nlr = alloc_ring(req);

	if (nlr == NULL)
		return NULL;

	if (mnl_socket_setsockopt(nls, optname, req, sizeof(*req)) == -1)
		goto fail;

	nlr->ring = mmap(NULL, ring_size(nlr), PROT_READ | PROT_WRITE, flags,
			 mnl_socket_get_fd(nls), 0);
	if (nlr->ring == MAP_FAILED)
		goto fail;

	return nlr;

fail:
	free(nlr);
	return NULL;
}


struct mnl_ring *
mnl_socket_rx_mmap(struct mnl_socket *nls, struct nl_mmap_req *req, int flags)
{
	return mnl_socket_mmap(nls, req, flags, NETLINK_RX_RING);
}
EXPORT_SYMBOL(mnl_socket_rx_mmap);

struct mnl_ring *
mnl_socket_tx_mmap(struct mnl_socket *nls, struct nl_mmap_req *req, int flags)
{
	return mnl_socket_mmap(nls, req, flags, NETLINK_TX_RING);
}
EXPORT_SYMBOL(mnl_socket_tx_mmap);

int mnl_socket_unmap(struct mnl_ring *nlr)
{
	int ret = munmap(nlr->ring, ring_size(nlr));
	nlr->ring = NULL;
	free(nlr);
	return ret;
}
EXPORT_SYMBOL(mnl_socket_unmap);

void mnl_ring_advance(struct mnl_ring *nlr)
{
	nlr->head = nlr->head != nlr->frame_max ? nlr->head + 1 : 0;
}
EXPORT_SYMBOL(mnl_ring_advance);

struct nl_mmap_hdr *mnl_ring_get_frame(const struct mnl_ring *nlr)
{
	unsigned int frames_per_block, block_pos, frame_off;

	frames_per_block = nlr->block_size / nlr->frame_size;
	block_pos = nlr->head / frames_per_block;
	frame_off = nlr->head % frames_per_block;

	return (struct nl_mmap_hdr *)((uintptr_t)nlr->ring
				      + block_pos * nlr->block_size
				      + frame_off * nlr->frame_size);
}
EXPORT_SYMBOL(mnl_ring_get_frame);

struct nl_mmap_hdr *mnl_ring_lookup_frame(struct mnl_ring *nlr,
					  enum nl_mmap_status status)
{
	struct nl_mmap_hdr *frame, *sentinel;

	sentinel = frame = mnl_ring_get_frame(nlr);
	do {
		if (frame->nm_status == status)
			return frame;
		mnl_ring_advance(nlr);
		frame = mnl_ring_get_frame(nlr);
	} while (frame != sentinel);

	return NULL;
}
EXPORT_SYMBOL(mnl_ring_lookup_frame);

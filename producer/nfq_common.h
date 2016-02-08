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
#ifndef _NURS_NFQ_COMMON_H
#define _NURS_NFQ_COMMON_H

#include <libmnl/libmnl.h>
#include <nurs/nurs.h>
#include <nurs/ring.h>

enum {
	NFQ_CONFIG_BLOCK_SIZE = 0,	/* 8192 */
	NFQ_CONFIG_BLOCK_NR,		/* 32 */
	NFQ_CONFIG_FRAME_SIZE,		/* 8192 */
	NFQ_CONFIG_QUEUE_NUM,
	NFQ_CONFIG_COPY_MODE,		/* NFQNL_COPY_META / NFQNL_COPY_PACKET */
	NFQ_CONFIG_COPY_RANGE,
	NFQ_CONFIG_FAIL_OPEN,		/* NFQA_CFG_F_FAIL_OPEN */
	NFQ_CONFIG_CONNTRACK,		/* NFQA_CFG_F_CONNTRACK */
	NFQ_CONFIG_GSO,			/* NFQA_CFG_F_GSO */
	NFQ_CONFIG_UID_GID,		/* NFQA_CFG_F_UID_GID */
	NFQ_CONFIG_SECCTX,		/* NFQA_CFG_F_SECCTX */
	NFQ_CONFIG_RELIABLE,
	NFQ_CONFIG_NAMESPACE,
	NFQ_CONFIG_MAX,
};

#define block_size_ce(x)	(unsigned int)nurs_config_integer(nurs_producer_config(x), NFQ_CONFIG_BLOCK_SIZE)
#define block_nr_ce(x)		(unsigned int)nurs_config_integer(nurs_producer_config(x), NFQ_CONFIG_BLOCK_NR)
#define frame_size_ce(x)	(unsigned int)nurs_config_integer(nurs_producer_config(x), NFQ_CONFIG_FRAME_SIZE)
#define queue_num_ce(x)		(uint32_t)nurs_config_integer(nurs_producer_config(x), NFQ_CONFIG_QUEUE_NUM)
#define copy_mode_ce(x)		nurs_config_string(nurs_producer_config(x), NFQ_CONFIG_COPY_MODE)
#define copy_range_ce(x)	(uint32_t)nurs_config_integer(nurs_producer_config(x), NFQ_CONFIG_COPY_RANGE)
#define fail_open_ce(x)		nurs_config_boolean(nurs_producer_config(x), NFQ_CONFIG_FAIL_OPEN)
#define conntrack_ce(x)		nurs_config_boolean(nurs_producer_config(x), NFQ_CONFIG_CONNTRACK)
#define gso_ce(x)		nurs_config_boolean(nurs_producer_config(x), NFQ_CONFIG_GSO)
#define uid_gid_ce(x)		nurs_config_boolean(nurs_producer_config(x), NFQ_CONFIG_UID_GID)
#define secctx_ce(x)		nurs_config_boolean(nurs_producer_config(x), NFQ_CONFIG_SECCTX)
#define reliable_ce(x)		nurs_config_boolean(nurs_producer_config(x), NFQ_CONFIG_RELIABLE)
#define namespace_ce(x)		nurs_config_string(nurs_producer_config(x), NFQ_CONFIG_NAMESPACE)

enum {
	NFQ_OUTPUT_NLATTRS,
	NFQ_OUTPUT_FAMILY,
	NFQ_OUTPUT_RES_ID,
	NFQ_OUTPUT_FRAME,
	NFQ_OUTPUT_MAX
};

/* need to sync nfq_priv::nfq.c mtnfq_priv::mnnfq.c */
struct nfq_common_priv {
	struct mnl_socket	*nl;
	uint32_t		portid;
	struct nurs_fd		*fd;
	struct mnl_ring		*nlr;
	bool			skipped;
};

void frame_destructor(void *data);
int nfq_read_cb(int fd, uint16_t when, void *data);

enum nurs_return_t
nfq_common_organize(const struct nurs_producer *producer);
enum nurs_return_t
nfq_common_disorganize(const struct nurs_producer *producer);
int config_nfq(const struct nurs_producer *producer);
int unbind_nfq(const struct nurs_producer *producer);

#endif

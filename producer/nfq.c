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
#include <errno.h>
#include <signal.h>
#include <string.h>

#include "config.h"
#include <nurs/nurs.h>

#include "nfq_common.h"

extern struct nurs_config_def nfq_config;
extern struct nurs_output_def nfq_output;

struct nfq_priv {
	struct mnl_socket	*nl;
	uint32_t		portid;
        struct nurs_fd		*fd;
};

static enum nurs_return_t nfq_organize(struct nurs_producer *producer)
{
	return nfq_common_organize(producer);
}

static enum nurs_return_t nfq_disorganize(struct nurs_producer *producer)
{
	return nfq_common_disorganize(producer);
}

static enum nurs_return_t _nfq_read_cb(struct nurs_fd *nfd, uint16_t when)
{
        return nfq_read_cb(nurs_fd_get_fd(nfd), when,
                           nurs_fd_get_data(nfd));
}

static enum nurs_return_t nfq_start(struct nurs_producer *producer)
{
	struct nfq_priv *priv = nurs_producer_context(producer);

	if (config_nfq(producer))
		return NURS_RET_ERROR;

        priv ->fd = nurs_fd_register(
                mnl_socket_get_fd(priv->nl), NURS_FD_F_READ,
                _nfq_read_cb, producer);
	if (!priv->fd) {
		nurs_log(NURS_ERROR, "nurs_fd_register failed: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static enum nurs_return_t nfq_stop(struct nurs_producer *producer)
{
	struct nfq_priv *priv = nurs_producer_context(producer);

	nurs_fd_unregister(priv->fd);
	if (unbind_nfq(producer))
		return NURS_RET_ERROR;
	return NURS_RET_OK;
}

static enum nurs_return_t
nfq_signal(struct nurs_producer *producer, uint32_t signal)
{
	switch (signal) {
	default:
		nurs_log(NURS_DEBUG, "receive signal: %d\n", signal);
	}

	return NURS_RET_OK;
}

static struct nurs_producer_def nfq_producer = {
	.version	= VERSION,
	.name		= "NFQ",
	.context_size	= sizeof(struct nfq_priv),
	.config_def	= &nfq_config,
	.output_def	= &nfq_output,
	.organize	= nfq_organize,
	.disorganize	= nfq_disorganize,
	.start		= nfq_start,
	.stop		= nfq_stop,
	.signal		= nfq_signal,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	nurs_producer_register(&nfq_producer);
}

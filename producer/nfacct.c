/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2012 by Intra2net AG <http://www.intra2net.com>
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
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <linux/netfilter/nfnetlink_acct.h> /* NFACCT_NAME_MAX */

#include <libmnl/libmnl.h>
#include <libnetfilter_acct/libnetfilter_acct.h>

#include <nurs/nurs.h>
#include "nfnl_common.h"

enum {
	NFACCT_CONFIG_POLLINTERVAL,
	NFACCT_CONFIG_ZEROCOUNTER,
	NFACCT_CONFIG_TIMESTAMP,
	NFACCT_CONFIG_NAMESPACE,
	NFACCT_CONFIG_MAX,
};

static struct nurs_config_def nfacct_config = {
	.len	= NFACCT_CONFIG_MAX,
	.keys = {
		[NFACCT_CONFIG_POLLINTERVAL] = {
			.name	 = "pollinterval",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 0,
		},
		[NFACCT_CONFIG_ZEROCOUNTER] = {
			.name	 = "zerocounter",
			.type	 = NURS_CONFIG_T_BOOLEAN,
			.boolean = true,
		},
		[NFACCT_CONFIG_TIMESTAMP] = {
			.name	 = "timestamp",
			.type	 = NURS_CONFIG_T_BOOLEAN,
			.boolean = true,
		},
		[NFACCT_CONFIG_NAMESPACE] = {
			.name	 = "namespace",
			.type	 = NURS_CONFIG_T_STRING,
			.flags   = NURS_CONFIG_F_NONE,
			.string	 = "",
		},
	},
};

#define config_pollint(x)	nurs_config_integer(nurs_producer_config(x), NFACCT_CONFIG_POLLINTERVAL)
#define config_zerocounter(x)	nurs_config_boolean(nurs_producer_config(x), NFACCT_CONFIG_ZEROCOUNTER)
#define config_timestamp(x)	nurs_config_boolean(nurs_producer_config(x), NFACCT_CONFIG_TIMESTAMP)
#define config_namespace(x)	nurs_config_string(nurs_producer_config(x), NFACCT_CONFIG_NAMESPACE)

enum nurs_nfacct_keys {
	NFACCT_OUTPUT_NAME,
	NFACCT_OUTPUT_PKTS,
	NFACCT_OUTPUT_BYTES,
	NFACCT_OUTPUT_RAW,
	NFACCT_OUTPUT_TIME_SEC,
	NFACCT_OUTPUT_TIME_USEC,
	NFACCT_OUTPUT_MAX,
};

static struct nurs_output_def nfacct_output = {
	.len	= NFACCT_OUTPUT_MAX,
	.keys	= {
		[NFACCT_OUTPUT_NAME] = {
			.name	= "sum.name",
			.type	= NURS_KEY_T_STRING,
			.flags	= NURS_OKEY_F_ALWAYS,
			.len	= NFACCT_NAME_MAX,
		},
		[NFACCT_OUTPUT_PKTS] = {
			.name	= "sum.pkts",
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[NFACCT_OUTPUT_BYTES] = {
			.name	= "sum.bytes",
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[NFACCT_OUTPUT_RAW] = {
			.name	= "nfacct",
			.type	= NURS_KEY_T_EMBED,
			.flags	= NURS_OKEY_F_ALWAYS,
			.len	= 4096, /* XXX: sizeof struct nfacct */
		},
		[NFACCT_OUTPUT_TIME_SEC] = {
			.name	= "oob.time.sec",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFACCT_OUTPUT_TIME_USEC] = {
			.name	= "oob.time.usec",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
	},
};

struct nfacct_priv {
	struct mnl_socket	*nl;
	uint32_t		portid;
	uint32_t		seq;
	struct nurs_fd		*fd;
	struct nurs_timer	*timer;
	struct timeval tv;
};

static enum nurs_return_t
propagate_nfacct(struct nurs_producer *producer,
		 struct nurs_output *output, struct nfacct *nfacct)
{
	struct nfacct_priv *priv = nurs_producer_context(producer);

	nurs_output_set_string(output, NFACCT_OUTPUT_NAME,
			       nfacct_attr_get_str(nfacct, NFACCT_ATTR_NAME));
	nurs_output_set_u64(output, NFACCT_OUTPUT_PKTS,
			    nfacct_attr_get_u64(nfacct, NFACCT_ATTR_PKTS));
	nurs_output_set_u64(output, NFACCT_OUTPUT_BYTES,
			    nfacct_attr_get_u64(nfacct, NFACCT_ATTR_BYTES));

	if (config_timestamp(producer)) {
		nurs_output_set_u32(output, NFACCT_OUTPUT_TIME_SEC,
				    (uint32_t)priv->tv.tv_sec);
		nurs_output_set_u32(output, NFACCT_OUTPUT_TIME_USEC,
				    (uint32_t)priv->tv.tv_usec);
	}

	return nurs_publish(output);
}

static int nfacct_mnl_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nurs_producer *producer = data;
	struct nurs_output *output = nurs_get_output(producer);
	struct nfacct *nfacct;

	nfacct = nurs_output_pointer(output, NFACCT_OUTPUT_RAW);
	if (nfacct_nlmsg_parse_payload(nlh, nfacct)) {
		nurs_log(NURS_ERROR, "failed to parse nfacct message: %s\n",
			 strerror(errno));
		nurs_put_output(output);
		return MNL_CB_ERROR;
	}
	nurs_output_set_valid(output, NFACCT_OUTPUT_RAW);

	if (propagate_nfacct(producer, output, nfacct) != NURS_RET_OK)
		return MNL_CB_ERROR;

	return MNL_CB_OK;
}

static enum nurs_return_t nfacct_read_cb(const struct nurs_fd *nfd, uint16_t when)
{
        struct nurs_producer *producer = nurs_fd_get_data(nfd);
	struct nfacct_priv *priv = nurs_producer_context(producer);
	char buf[MNL_SOCKET_BUFFER_SIZE];
	ssize_t nrecv;
        int ret;

        do {
                nrecv = mnl_socket_recvfrom(priv->nl, buf, sizeof(buf));
                if (nrecv < 0) {
                        nurs_log(NURS_ERROR, "mnl_socket_recvfrom: %s\n",
                                 strerror(errno));
                        return NURS_RET_ERROR;
                }
                ret = mnl_cb_run(buf, (size_t)nrecv, priv->seq,
                                 priv->portid, nfacct_mnl_cb, producer);
	} while (ret == MNL_CB_OK);
	if (ret == MNL_CB_ERROR) {
		nurs_log(NURS_ERROR, "mnl_cb_run: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static int nfacct_send_request(struct nurs_producer *producer)
{
	struct nfacct_priv *priv = nurs_producer_context(producer);
	struct nlmsghdr *nlh;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	uint8_t flushctr;

	if (config_zerocounter(producer))
		flushctr = NFNL_MSG_ACCT_GET_CTRZERO;
	else
		flushctr = NFNL_MSG_ACCT_GET;

	priv->seq = (uint32_t)time(NULL);
	nlh = nfacct_nlmsg_build_hdr(buf, flushctr, NLM_F_DUMP, priv->seq);
	if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
		nurs_log(NURS_ERROR, "mnl_socket_sendto: %s\n",
			 strerror(errno));
		return -1;
	}

	if (config_timestamp(producer)) {
		/* Compute time of query */
		gettimeofday(&priv->tv, NULL);
	}

	return 0;
}

static enum nurs_return_t nfacct_timer_cb(struct nurs_timer *t, void *data)
{
	struct nurs_producer *producer = data;

	if (nfacct_send_request(producer))
		return NURS_RET_ERROR;

	return NURS_RET_OK;
}

static enum nurs_return_t nfacct_organize(struct nurs_producer *producer)
{
	struct nfacct_priv *priv = nurs_producer_context(producer);

	if (config_pollint(producer) <= 0) {
		nurs_log(NURS_ERROR, "You have to set pollint\n");
		goto err_exit;
	}

	priv->nl = nurs_mnl_socket(config_namespace(producer),
				   NETLINK_NETFILTER);
	if (!priv->nl) {
		nurs_log(NURS_ERROR, "failed to create socket: %s\n",
			 strerror(errno));
		goto err_exit;
	}

	if (mnl_socket_bind(priv->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		nurs_log(NURS_ERROR, "mnl_socket_bind: %s\n", strerror(errno));
		goto err_close;
	}
	priv->portid = mnl_socket_get_portid(priv->nl);

	priv->fd = nurs_fd_create(mnl_socket_get_fd(priv->nl), NURS_FD_F_READ);
	if (!priv->fd) {
		nurs_log(NURS_ERROR, "failed to create fd: %s\n",
			 strerror(errno));
		goto err_close;
	}

	priv->timer = nurs_timer_create(nfacct_timer_cb, producer);
	if (!priv->timer) {
		nurs_log(NURS_ERROR, "failed to create timer: %s\n",
			 strerror(errno));
		goto err_destroy_fd;
	}

	return NURS_RET_OK;

err_destroy_fd:
	nurs_fd_destroy(priv->fd);
err_close:
	mnl_socket_close(priv->nl);
err_exit:
	return NURS_RET_ERROR;
}

static enum nurs_return_t nfacct_disorganize(struct nurs_producer *producer)
{
	struct nfacct_priv *priv = nurs_producer_context(producer);
	int ret = 0;

	ret |= nurs_timer_destroy(priv->timer);
	nurs_fd_destroy(priv->fd);

	if (ret)
		return NURS_RET_ERROR;

	return NURS_RET_OK;
}

static enum nurs_return_t nfacct_start(struct nurs_producer *producer)
{
	struct nfacct_priv *priv = nurs_producer_context(producer);
	int pollint = config_pollint(producer);

	if (nurs_fd_register(priv->fd, nfacct_read_cb, producer)) {
		nurs_log(NURS_ERROR, "failed to register fd: %s\n",
			 strerror(errno));
		goto err_exit;
	}

	if (nurs_itimer_add(priv->timer, pollint, pollint)) {
		nurs_log(NURS_ERROR, "failed to add itimer: %s\n",
			 strerror(errno));
		goto err_unregister_fd;
	}

	return NURS_RET_OK;

err_unregister_fd:
	nurs_fd_unregister(priv->fd);
err_exit:
	return NURS_RET_ERROR;
}

static enum nurs_return_t nfacct_stop(struct nurs_producer *producer)
{
	struct nfacct_priv *priv = nurs_producer_context(producer);
	int ret = 0;

	ret |= nurs_timer_del(priv->timer);
	ret |= nurs_fd_unregister(priv->fd);

	if (ret)
		return NURS_RET_ERROR;

	return NURS_RET_OK;
}

static enum nurs_return_t
nfacct_signal(struct nurs_producer *producer, uint32_t signum)
{
	switch (signum) {
	case SIGUSR2:
		if (nfacct_send_request(producer))
			return NURS_RET_ERROR;
		break;
	default:
		break;
	}

	return NURS_RET_OK;
}


static struct nurs_producer_def nfacct_producer = {
	.version	= VERSION,
	.name		= "NFACCT",
	.context_size	= sizeof(struct nfacct_priv),
	.config_def	= &nfacct_config,
	.output_def	= &nfacct_output,
	.organize	= nfacct_organize,
	.disorganize	= nfacct_disorganize,
	.start		= nfacct_start,
	.stop		= nfacct_stop,
	.signal		= nfacct_signal,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	nurs_producer_register(&nfacct_producer);
}

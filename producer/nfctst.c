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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

#include <libmnl/libmnl.h>

#include <nurs/nurs.h>
#include "nfnl_common.h"

enum nfctst_conf {
	NFCTST_CONFIG_POLLINT,
	NFCTST_CONFIG_NAMESPACE,
	NFCTST_CONFIG_MAX,
};

static struct nurs_config_def nfctst_config = {
	.len  = NFCTST_CONFIG_MAX,
	.keys = {
		[NFCTST_CONFIG_POLLINT] =  {
			.name	 = "pollinterval",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 60,
		},
		[NFCTST_CONFIG_NAMESPACE] = {
			.name	 = "namespace",
			.type	 = NURS_CONFIG_T_STRING,
			.flags   = NURS_CONFIG_F_NONE,
			.string	 = "",
		},
	},
};

#define config_pollint(x)	nurs_config_integer(nurs_producer_config(x), NFCTST_CONFIG_POLLINT)
#define config_namespace(x)	nurs_config_string(nurs_producer_config(x), NFCTST_CONFIG_NAMESPACE)

enum {
	NFCTST_OUTPUT_STATS_SEARCHED		= CTA_STATS_SEARCHED	   - 1,
	NFCTST_OUTPUT_STATS_FOUND		= CTA_STATS_FOUND	   - 1,
	NFCTST_OUTPUT_STATS_NEW			= CTA_STATS_NEW		   - 1,
	NFCTST_OUTPUT_STATS_INVALID		= CTA_STATS_INVALID	   - 1,
	NFCTST_OUTPUT_STATS_IGNORE		= CTA_STATS_IGNORE	   - 1,
	NFCTST_OUTPUT_STATS_DELETE		= CTA_STATS_DELETE	   - 1,
	NFCTST_OUTPUT_STATS_DELETE_LIST		= CTA_STATS_DELETE_LIST	   - 1,
	NFCTST_OUTPUT_STATS_INSERT		= CTA_STATS_INSERT	   - 1,
	NFCTST_OUTPUT_STATS_INSERT_FAILED	= CTA_STATS_INSERT_FAILED  - 1,
	NFCTST_OUTPUT_STATS_DROP		= CTA_STATS_DROP	   - 1,
	NFCTST_OUTPUT_STATS_EARLY_DROP		= CTA_STATS_EARLY_DROP	   - 1,
	NFCTST_OUTPUT_STATS_ERROR		= CTA_STATS_ERROR	   - 1,
	NFCTST_OUTPUT_STATS_SEARCH_RESTART 	= CTA_STATS_SEARCH_RESTART - 1,
	NFCTST_OUTPUT_MAX			= NFCTST_OUTPUT_STATS_SEARCH_RESTART + 1,
};

#define CTA2OUTPUT(cta) ((cta) - 1)

static struct nurs_output_def nfctst_output = {
	.len	= NFCTST_OUTPUT_MAX,
	.keys	= {
		[NFCTST_OUTPUT_STATS_SEARCHED] = {
			.name	= "nfct.stats.searched",
			.type 	= NURS_KEY_T_UINT32,
			.flags 	= NURS_OKEY_F_ALWAYS,
		},
		[NFCTST_OUTPUT_STATS_FOUND] = {
			.name	= "nfct.stats.found",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[NFCTST_OUTPUT_STATS_NEW] = {
			.name	= "nfct.stats.new",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[NFCTST_OUTPUT_STATS_INVALID] = {
			.name	= "nfct.stats.invalid",
			.type	= NURS_KEY_T_UINT32,
			.flags 	= NURS_OKEY_F_ALWAYS,
		},
		[NFCTST_OUTPUT_STATS_IGNORE] = {
			.name	= "nfct.stats.ignore",
			.type	= NURS_KEY_T_UINT32,
			.flags 	= NURS_OKEY_F_ALWAYS,
		},
		[NFCTST_OUTPUT_STATS_DELETE] = {
			.name	= "nfct.stats.delete",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[NFCTST_OUTPUT_STATS_DELETE_LIST] = {
			.name	= "nfct.stats.delete_list",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[NFCTST_OUTPUT_STATS_INSERT] = {
			.name	= "nfct.stats.insert",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[NFCTST_OUTPUT_STATS_INSERT_FAILED] = {
			.name	= "nfct.stats.insert_failed",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[NFCTST_OUTPUT_STATS_DROP] = {
			.name	= "nfct.stats.drop",
			.type 	= NURS_KEY_T_UINT32,
			.flags 	= NURS_OKEY_F_ALWAYS,
		},
		[NFCTST_OUTPUT_STATS_EARLY_DROP] = {
			.name	= "nfct.stats.early_drop",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[NFCTST_OUTPUT_STATS_ERROR] = {
			.name	= "nfct.stats.error",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[NFCTST_OUTPUT_STATS_SEARCH_RESTART] = {
			.name	= "nfct.stats.search_restart",
			.type	= NURS_KEY_T_UINT32,
			.flags 	= NURS_OKEY_F_ALWAYS,
		},
	},
};

struct nfctst_priv {
	struct mnl_socket *nls;
	unsigned int seq, portid;
	struct nurs_fd *fd;
	struct nurs_timer *timer;
	char dumpreq[sizeof(struct nlmsghdr) + sizeof(struct nfgenmsg)];
};

static int nlattr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTA_STATS_MAX) < 0)
		return MNL_CB_OK;

	if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
		nurs_log(NURS_ERROR, "invalid attribute: %s\n",
			  strerror(errno));
		return MNL_CB_ERROR;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int nlmsg_cb(const struct nlmsghdr *nlh, void *data)
{
	uint32_t *dst = data;
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	struct nlattr *src[CTA_STATS_MAX + 1] = {0};
	int i, ret;

	nurs_log(NURS_DEBUG, "got stats - CPU# %d\n", ntohs(nfg->res_id));
	ret = mnl_attr_parse(nlh, sizeof(struct nfgenmsg), nlattr_cb, src);
	if (ret != MNL_CB_OK)
		return ret;

	for (i = CTA_STATS_SEARCHED; i < CTA_STATS_MAX + 1; i++) {
		if (!src[i])
			continue;
		dst[CTA2OUTPUT(i)] += ntohl(mnl_attr_get_u32(src[i]));
	}

	return MNL_CB_OK;
}

static enum nurs_return_t nfctst_read_cb(int fd, uint16_t when, void *data)
{
	struct nurs_producer *producer = data;
	struct nfctst_priv *priv = nurs_producer_context(producer);
	struct nurs_output *output;
	uint32_t tb[NFCTST_OUTPUT_MAX] = {0};
	char buf[MNL_SOCKET_BUFFER_SIZE];
	ssize_t nrecv;
	uint16_t i;
	int ret;

	do {
		nrecv = mnl_socket_recvfrom(priv->nls, buf, sizeof(buf));
		if (nrecv < 0) {
			nurs_log(NURS_ERROR, "mnl_socket_recvfrom: %s\n",
				 strerror(errno));
			return NURS_RET_ERROR;
		}
		ret = mnl_cb_run(buf, (size_t)nrecv, priv->seq,
				 priv->portid, nlmsg_cb, tb);
	} while (ret == MNL_CB_OK);
	if (ret == MNL_CB_ERROR) {
		nurs_log(NURS_ERROR, "mnl_cb_run: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}

	output = nurs_get_output(producer);
	for (i = NFCTST_OUTPUT_STATS_SEARCHED; i < NFCTST_OUTPUT_MAX; i++)
		nurs_output_set_u32(output, i, tb[i]);

	if (nurs_propagate(producer, output))
		return NURS_RET_ERROR;

	return NURS_RET_OK;
}

static enum nurs_return_t nfctst_timer_cb(struct nurs_timer *t, void *data)
{
	struct nurs_producer *producer = data;
	struct nfctst_priv *priv = nurs_producer_context(producer);
	struct nlmsghdr *nlh = (struct nlmsghdr *)priv->dumpreq;

	nlh->nlmsg_seq = ++priv->seq;
	if (mnl_socket_sendto(priv->nls, nlh, nlh->nlmsg_len) < 0) {
		nurs_log(NURS_ERROR, "mnl_socket_sendto: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static enum nurs_return_t nfctst_organize(const struct nurs_producer *producer)
{
	struct nfctst_priv *priv = nurs_producer_context(producer);
	int pollint = config_pollint(producer);
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfh;
	void *cbdata = (void *)(uintptr_t)producer;

	if (pollint <= 0) {
		nurs_log(NURS_FATAL, "invalid pollinterval: %d\n",
			 pollint);
		return -1;
	}

	priv->nls = nurs_mnl_socket(config_namespace(producer),
				    NETLINK_NETFILTER);
	if (priv->nls == NULL) {
		nurs_log(NURS_ERROR, "failed to create socket: %s\n",
			 strerror(errno));
		goto err_exit;
	}
	if (mnl_socket_bind(priv->nls, 0, MNL_SOCKET_AUTOPID) < 0) {
		nurs_log(NURS_ERROR, "mnl_socket_bind: %s\n",
			 strerror(errno));
		goto err_close;
	}
	priv->portid = mnl_socket_get_portid(priv->nls);
	priv->seq = (unsigned int)time(NULL);

	nlh = mnl_nlmsg_put_header(priv->dumpreq);
	nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) |
			   IPCTNL_MSG_CT_GET_STATS_CPU;
	nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_DUMP;
	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = AF_INET;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	priv->timer = nurs_timer_create(nfctst_timer_cb, cbdata);
	if (!priv->timer) {
		nurs_log(NURS_ERROR, "failed to create timer: %s\n",
			 strerror(errno));
		goto err_close;
	}
	priv->fd = nurs_fd_create(mnl_socket_get_fd(priv->nls), NURS_FD_F_READ);
	if (!priv->fd) {
		nurs_log(NURS_ERROR, "failed to create fd: %s\n",
			 strerror(errno));
		goto err_destroy_timer;
	}

	return NURS_RET_OK;

err_destroy_timer:
	nurs_timer_destroy(priv->timer);
err_close:
	mnl_socket_close(priv->nls);
err_exit:
	return NURS_RET_ERROR;
}

static enum nurs_return_t
nfctst_disorganize(const struct nurs_producer *producer)
{
	struct nfctst_priv *priv = nurs_producer_context(producer);
	int ret = 0;

	ret |= nurs_timer_destroy(priv->timer);
	nurs_fd_destroy(priv->fd);

	if (ret)
		return NURS_RET_ERROR;

	return NURS_RET_OK;
}

static enum nurs_return_t nfctst_start(const struct nurs_producer *producer)
{
	struct nfctst_priv *priv = nurs_producer_context(producer);
	int pollint = config_pollint(producer);
	void *cbdata = (void *)(uintptr_t)producer;

	if (nurs_fd_register(priv->fd, nfctst_read_cb, cbdata)) {
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

static enum nurs_return_t nfctst_stop(const struct nurs_producer *producer)
{
	struct nfctst_priv *priv = nurs_producer_context(producer);
	int ret = 0;

	ret |= nurs_timer_del(priv->timer);
	ret |= nurs_fd_unregister(priv->fd);

	if (ret)
		return NURS_RET_ERROR;

	return NURS_RET_OK;
}

static struct nurs_producer_def nfctst_producer = {
	.version	= VERSION,
	.name		= "NFCTST",
	.context_size	= sizeof(struct nfctst_priv),
	.config_def	= &nfctst_config,
	.output_def	= &nfctst_output,
	.organize	= nfctst_organize,
	.disorganize	= nfctst_disorganize,
	.start		= nfctst_start,
	.stop		= nfctst_stop,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	nurs_producer_register(&nfctst_producer);
}

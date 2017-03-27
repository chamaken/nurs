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
#include <string.h>
#include <sys/mman.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <nurs/nurs.h>
#include "config.h"

#include "nfnl_common.h"
#include "nfq_common.h"

struct nurs_config_def nfq_config = {
	.len	= NFQ_CONFIG_MAX,
	.keys	= {
		[NFQ_CONFIG_QUEUE_NUM] = {
			.name	 = "queue_num",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 0,
		},
		[NFQ_CONFIG_COPY_MODE] = {
			.name	 = "copy_mode",
			.type	 = NURS_CONFIG_T_STRING,
			.string	 = "packet",
		},
		[NFQ_CONFIG_COPY_RANGE] = {
			.name	 = "copy_range",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 0xffff - NLA_HDRLEN,
			},
		[NFQ_CONFIG_FAIL_OPEN] = {
			.name	 = "fail_open",
			.type	 = NURS_CONFIG_T_BOOLEAN,
			.boolean = false,
		},
		[NFQ_CONFIG_CONNTRACK] = {
			.name	 = "conntrack",
			.type	 = NURS_CONFIG_T_BOOLEAN,
			.boolean = false,
		},
		[NFQ_CONFIG_GSO] = {
			.name	 = "gso",
			.type	 = NURS_CONFIG_T_BOOLEAN,
			.boolean = false,
		},
		[NFQ_CONFIG_UID_GID] = {
			.name	 = "uid_gid",
			.type	 = NURS_CONFIG_T_BOOLEAN,
			.boolean = false,
		},
		[NFQ_CONFIG_SECCTX] = {
			.name	 = "secctx",
			.type	 = NURS_CONFIG_T_BOOLEAN,
			.boolean = false,
		},
		[NFQ_CONFIG_RELIABLE] = {
			.name	= "reliable",
			.type	= NURS_CONFIG_T_BOOLEAN,
		},
	},
};

struct nurs_output_def nfq_output = {
	.len	= NFQ_OUTPUT_MAX,
	.keys	= {
		[NFQ_OUTPUT_NLATTRS] = {
			/* struct nlattr *attr[NFQA_MAX+1] = {}; */
			.name	= "nfq.attrs",
			.type	= NURS_KEY_T_EMBED,
			.flags	= NURS_OKEY_F_ALWAYS,
			.len	= sizeof(struct nlattr *) * (NFQA_MAX + 1),
		},
		[NFQ_OUTPUT_FAMILY] = {
			.name	= "oob.family",
			.type	= NURS_KEY_T_UINT8,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[NFQ_OUTPUT_RES_ID] = {
			.name	= "nfq.res_id",
			.type	= NURS_KEY_T_UINT16,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[NFQ_OUTPUT_FRAME] = {
			.name	= "nfq.frame",
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_ALWAYS | NURS_OKEY_F_DESTRUCT,
			.destructor = frame_destructor,
		},
                [NFQ_OUTPUT_RECV_BUFFER] = {
                        .type	= NURS_KEY_T_EMBED,
                        .flags	= NURS_OKEY_F_OPTIONAL, /* NURS_OKEY_NONE? */
                        .name	= "nflog.buffer",
                        .len	= 0x10000,
                },
	}
};

static int nfq_mnl_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	struct nurs_output *output = data;
	struct nlattr **attrs;

	nurs_output_set_u8(output, NFQ_OUTPUT_FAMILY, nfg->nfgen_family);
	nurs_output_set_u16(output, NFQ_OUTPUT_RES_ID, ntohs(nfg->res_id));

	attrs = (struct nlattr **)nurs_output_pointer(output,
						      NFQ_OUTPUT_NLATTRS);
	if (nfq_nlmsg_parse(nlh, attrs) < 0) {
		nurs_log(NURS_ERROR, "failed to parse nfq message: %s\n",
			 strerror(errno));
		return MNL_CB_ERROR;
	}
	nurs_output_set_valid(output, NFQ_OUTPUT_NLATTRS);

	return MNL_CB_OK;
}

static enum nurs_return_t
nfq_copy_frame(int fd, void *arg)
{
        struct nurs_producer *producer = arg;
        struct nfq_common_priv *priv = nurs_producer_context(producer);
        struct nurs_output *output = nurs_get_output(producer);
        ssize_t nrecv;
        void *buf;
        size_t buflen;
        if (!output) {
                nurs_log(NURS_ERROR, "failed to get output: %s\n",
                         strerror(errno));
                return NURS_RET_ERROR;
        }
        buf = nurs_output_pointer(output, NFQ_OUTPUT_RECV_BUFFER);
        if (!buf) {
                nurs_log(NURS_ERROR, "failed to get recv buffer: %s\n",
                         strerror(errno));
                return NURS_RET_ERROR;
        }
        buflen = (size_t)nurs_output_size(output, NFQ_OUTPUT_RECV_BUFFER);

        nrecv = recv(fd, buf, buflen, MSG_DONTWAIT);
        if (nrecv == -1) {
                nurs_log(NURS_ERROR, "failed to recv: %s\n",
                         strerror(errno));
                goto fail;
        }

        if (mnl_cb_run(buf, (size_t)nrecv, 0,
                       priv->portid, nfq_mnl_cb, output) == MNL_CB_ERROR) {
                nurs_log(NURS_ERROR, "failed to mnl_cb_run: %s\n",
                         strerror(errno));
                goto fail;
        }

	if (nurs_publish(output)) {
                nurs_log(NURS_ERROR, "failed to publish output: %s\n",
                         strerror(errno));
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;

fail:
        nurs_put_output(output);
        return NURS_RET_ERROR;
}

enum nurs_return_t nfq_read_cb(int fd, uint16_t when, void *data)
{
        return nfq_copy_frame(fd, data);
}

static int check_config_response(struct nfq_common_priv *priv)
{
        char buf[MNL_SOCKET_BUFFER_SIZE];
        ssize_t nrecv;

        nrecv = mnl_socket_recvfrom(priv->nl, buf, sizeof(buf));
        if (nrecv == -1) {
                nurs_log(NURS_ERROR, "failed to recv: %s\n",
                         strerror(errno));
                return -1;
        }

        if (mnl_cb_run(buf, (size_t)nrecv, 0, priv->portid, NULL, NULL)
            == MNL_CB_ERROR) {
                nurs_log(NURS_ERROR, "failed to mnl_cb_run: %s\n",
                         strerror(errno));
                return -1;
        }

	return 0;
}

/* copy from library examples */
static struct nlmsghdr *nfq_hdr_put(char *buf, int type, uint32_t queue_num)
{
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= (uint16_t)((NFNL_SUBSYS_QUEUE << 8) | type);
	nlh->nlmsg_flags = NLM_F_REQUEST;

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(queue_num);

	return nlh;
}

static int nfq_put_config(struct nlmsghdr *nlh,
			  const struct nurs_producer *producer)
{
	const char *copy_mode = config_copy_mode(producer);
	uint32_t flags = 0;

	if (!strcasecmp(copy_mode, "packet")) {
		uint32_t copy_range;
		copy_range = htonl(config_copy_range(producer));
		nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, (int)copy_range);
	} else if (!strcasecmp(copy_mode, "meta")) {
		nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_META, 0);
	} else if (!strcasecmp(copy_mode, "none")) {
		nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_NONE, 0);
	} else {
		nurs_log(NURS_ERROR, "unknow copy_mode: %s\n", copy_mode);
		return -1;
	}

	if (config_fail_open(producer))
		flags |= NFQA_CFG_F_FAIL_OPEN;
	if (config_conntrack(producer))
		flags |= NFQA_CFG_F_CONNTRACK;
	if (config_gso(producer))
		flags |= NFQA_CFG_F_GSO;
	if (config_uid_gid(producer))
		flags |= NFQA_CFG_F_UID_GID;
#if defined(NFQA_CFG_F_SECCTX)
	if (config_secctx(producer))
		flags |= NFQA_CFG_F_SECCTX;
#endif
	mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(flags));
	mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_MAX - 1));

	return 0;
}

int config_nfq(const struct nurs_producer *producer)
{
	struct nfq_common_priv *priv = nurs_producer_context(producer);
	struct nlmsghdr *nlh;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	uint32_t queue_num = config_queue_num(producer);

	/* kernels 3.8 and later is required to omit PF_(UN)BIND */
	/*
	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, 0);
	nlh->nlmsg_flags |= NLM_F_ACK;
	nfq_nlmsg_cfg_put_cmd(nlh, AF_UNSPEC, NFQNL_CFG_CMD_PF_BIND);
	if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
		nurs_log(NURS_ERROR, "failed to mnl_socket_send: %s\n",
			  strerror(errno));
		return NURS_RET_ERROR;;
	}
	if (check_config_response(priv)) {
		nurs_log(NURS_ERROR, "failed to NFQNL_CFG_CMD_PF_BIND: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;;
	}
	*/

	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nlh->nlmsg_flags |= NLM_F_ACK;
	nfq_nlmsg_cfg_put_cmd(nlh, AF_UNSPEC, NFQNL_CFG_CMD_BIND);
	if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
		nurs_log(NURS_ERROR, "mnl_socket_sendto: %s\n",
			strerror(errno));
		return NURS_RET_ERROR;
	}
	if (check_config_response(priv)) {
		nurs_log(NURS_ERROR, "failed to NFQNL_CFG_CMD_BIND: %s\n",
			  strerror(errno));
		return NURS_RET_ERROR;;
	}
	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nlh->nlmsg_flags |= NLM_F_ACK;
	if (nfq_put_config(nlh, producer) == -1)
		return NURS_RET_ERROR;;
	if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
		nurs_log(NURS_ERROR, "failed to mnl_socket_send: %s\n",
			strerror(errno));
		return NURS_RET_ERROR;;
	}
	if (check_config_response(priv)) {
		nurs_log(NURS_ERROR, "failed to NFQNL_MSG_CONFIG: %s\n",
			  strerror(errno));
		return NURS_RET_ERROR;;
	}

	return NURS_RET_OK;
}

enum nurs_return_t
nfq_common_organize(const struct nurs_producer *producer)
{
	struct nfq_common_priv *priv = nurs_producer_context(producer);

	priv->nl = nurs_mnl_socket(config_namespace(producer), NETLINK_NETFILTER);
	if (!priv->nl) {
		nurs_log(NURS_FATAL, "failed to mnl_socket_open: %s\n",
			  strerror(errno));
		return NURS_RET_ERROR;;
	}

	if (mnl_socket_bind(priv->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		nurs_log(NURS_FATAL, "failed to mnl_socket_bind: %s\n",
			 strerror(errno));
		goto error_close;
	}
	priv->portid = mnl_socket_get_portid(priv->nl);

	if (config_reliable(producer) &&
	    mnl_socket_set_reliable(priv->nl)) {
		nurs_log(NURS_ERROR, "failed to mnl_socket_set_reliable: %s\n",
			 strerror(errno));
		goto error_close;
	}

	priv->fd = nurs_fd_create(mnl_socket_get_fd(priv->nl),
				  NURS_FD_F_READ);
	if (!priv->fd)
		goto error_close;

	return NURS_RET_OK;
error_close:
	mnl_socket_close(priv->nl);
	return NURS_RET_ERROR;
}

enum nurs_return_t
nfq_common_disorganize(const struct nurs_producer *producer)
{
	struct nfq_common_priv *priv = nurs_producer_context(producer);
	int ret = 0;

	if (mnl_socket_close(priv->nl)) {
		nurs_log(NURS_ERROR, "failed to mnl_socket_close: %s\n",
			 strerror(errno));
		ret = -1;
	}

	if (ret)
		return NURS_RET_ERROR;

	return NURS_RET_OK;
}

int unbind_nfq(const struct nurs_producer *producer)
{
	struct nfq_common_priv *priv = nurs_producer_context(producer);
	uint32_t queue_num = config_queue_num(producer);
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
	if (!nlh) {
		nurs_log(NURS_ERROR, "failed to put NFQNL_MSG_CONFIG\n");
		return NURS_RET_ERROR;
	}
	nfq_nlmsg_cfg_put_cmd(nlh, AF_UNSPEC, NFQNL_CFG_CMD_UNBIND);
	if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
		nurs_log(NURS_ERROR, "failed to mnl_socket_sendto: %s\n",
			strerror(errno));
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

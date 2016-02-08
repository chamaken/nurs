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
#include <nurs/ring.h>

#include "nfnl_common.h"
#include "nfq_common.h"

/*
 * Each ring contains a number of continuous memory blocks, containing frames of
 * fixed size dependent on the parameters used for ring setup.
 *
 * Ring:[ block 0 ]
 * 		[ frame 0 ]
 * 		[ frame 1 ]
 * 	[ block 1 ]
 * 		[ frame 2 ]
 * 		[ frame 3 ]
 * 	...
 * 	[ block n ]
 * 		[ frame 2 * n ]
 * 		[ frame 2 * n + 1 ]
 *
 * The blocks are only visible to the kernel, from the point of view of user-space
 * the ring just contains the frames in a continuous memory zone.
 */
struct nurs_config_def nfq_config = {
	.len	= NFQ_CONFIG_MAX,
	.keys	= {
		[NFQ_CONFIG_BLOCK_SIZE] = {
			.name	 = "block_size",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 8192,
		},
		[NFQ_CONFIG_BLOCK_NR] = {
			.name	 = "block_nr",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 32,
		},
		[NFQ_CONFIG_FRAME_SIZE] = {
			.name	 = "frame_size",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 8192,
		},
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
			.integer = 0xFFFF - NLA_HDRLEN,
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
			.flags	= NURS_OKEY_F_ACTIVE,
			.len	= sizeof(struct nlattr *) * (NFQA_MAX + 1),
		},
		[NFQ_OUTPUT_FAMILY] = {
			.name	= "oob.family",
			.type	= NURS_KEY_T_UINT8,
			.flags	= NURS_OKEY_F_ACTIVE,
		},
		[NFQ_OUTPUT_RES_ID] = {
			.name	= "nfq.res_id",
			.type	= NURS_KEY_T_UINT16,
			.flags	= NURS_OKEY_F_ACTIVE,
		},
		[NFQ_OUTPUT_FRAME] = {
			.name	= "nfq.frame",
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_ACTIVE | NURS_OKEY_F_DESTRUCT,
			.destructor = frame_destructor,
		},
	}
};

static int nfq_mnl_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	struct nurs_producer *producer = data;
	struct nurs_output *output = nurs_get_output(producer);
	struct nlattr **attrs;
	struct nl_mmap_hdr *frame = MNL_NLMSG_FRAME(nlh);

	nurs_output_set_u8(output, NFQ_OUTPUT_FAMILY, nfg->nfgen_family);
	nurs_output_set_u16(output, NFQ_OUTPUT_RES_ID, ntohs(nfg->res_id));
	nurs_output_set_pointer(output, NFQ_OUTPUT_FRAME, frame);

	attrs = (struct nlattr **)nurs_output_pointer(output,
						      NFQ_OUTPUT_NLATTRS);
	if (nfq_nlmsg_parse(nlh, attrs) < 0) {
		nurs_log(NURS_ERROR, "failed to parse nfq message: %s\n",
			 strerror(errno));
		nurs_put_output(producer, output);
		return MNL_CB_ERROR;
	}
	nurs_output_set_valid(output, NFQ_OUTPUT_NLATTRS);
	return nurs_propagate(producer, output);

	return MNL_CB_OK;
}

static int handle_valid_frame(struct nurs_producer *producer,
			      struct nl_mmap_hdr *frame)
{
	struct nfq_common_priv *priv =	nurs_producer_context(producer);
	int ret;

	if (!frame->nm_len) {
		/* an error may occured in kernel */
		return NURS_RET_OK;
	}

	ret = mnl_cb_run(MNL_FRAME_PAYLOAD(frame), frame->nm_len,
			 0, priv->portid, nfq_mnl_cb, producer);
	if (ret == MNL_CB_ERROR) {
		nurs_log(NURS_ERROR, "mnl_cb_run: %d %s\n",
			 errno, strerror(errno));
		return NURS_RET_ERROR;;
	}

	return NURS_RET_OK;
}

int nfq_read_cb(int fd, uint16_t when, void *data)
{
	struct nurs_producer *producer = data;
	struct nfq_common_priv *priv =	nurs_producer_context(producer);
	struct nl_mmap_hdr *frame;
	ssize_t rc, nrecv;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int ret = NURS_RET_ERROR;

	if (!(when & NURS_FD_F_READ))
		return 0;

handle_frame:
	frame = mnl_ring_get_frame(priv->nlr);
	switch (frame->nm_status) {
	case NL_MMAP_STATUS_VALID:
		frame->nm_status = NL_MMAP_STATUS_SKIP;
		ret = handle_valid_frame(producer, frame);
		frame->nm_status = NL_MMAP_STATUS_UNUSED;
		mnl_ring_advance(priv->nlr);
		break;
	case NL_MMAP_STATUS_COPY:
		/* XXX: only consuming message */
		frame->nm_status = NL_MMAP_STATUS_SKIP;
		nurs_log(NURS_ERROR, "exceeded the frame size: %d\n",
			 frame->nm_len);
		for (nrecv = 0; nrecv < frame->nm_len; ) {
			rc = recv(fd, buf, (size_t)MNL_SOCKET_BUFFER_SIZE,
				  MSG_DONTWAIT);
			if (rc == -1) {
				nurs_log(NURS_ERROR, "failed to recv COPY"
					 " frame: %s\n", strerror(errno));
				/* XXX: needs error handling? */
				break;
			}
			nrecv += rc;
		}
		frame->nm_status = NL_MMAP_STATUS_UNUSED;
		mnl_ring_advance(priv->nlr);
		break;
	case NL_MMAP_STATUS_UNUSED:
	case NL_MMAP_STATUS_RESERVED:
		nurs_log(NURS_NOTICE, "found unintentional frame - status:"
			 " %d\n", frame->nm_status);
		if (!mnl_ring_lookup_frame(priv->nlr,
					   NL_MMAP_STATUS_VALID)) {
			nurs_log(NURS_ERROR,
				 "could not found valid frame\n");
			break;
		}
		goto handle_frame;
	case NL_MMAP_STATUS_SKIP:
		if (!priv->skipped) {
			priv->skipped = true;
			nurs_log(NURS_ERROR, "found SKIP frame"
				 ", ENOBUFS maybe\n");
		}
		break;
	default:
		nurs_log(NURS_ERROR, "unknown frame_status: %d\n",
			 frame->nm_status);
		break;
	}

	return ret;
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
	const char *copy_mode = copy_mode_ce(producer);
	uint32_t flags = 0;

	if (!strcasecmp(copy_mode, "packet")) {
		uint32_t copy_range;
		if (frame_size_ce(producer) < copy_range_ce(producer))
			nurs_log(NURS_NOTICE, "may cause COPY status"
				  " - frame size: %d, copy_range: %d\n",
				  frame_size_ce(producer), copy_range_ce(producer));
		copy_range = htonl(copy_range_ce(producer));
		nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, (int)copy_range);
	} else if (!strcasecmp(copy_mode, "meta")) {
		nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_META, 0);
	} else if (!strcasecmp(copy_mode, "none")) {
		nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_NONE, 0);
	} else {
		nurs_log(NURS_ERROR, "unknow copy_mode: %s\n", copy_mode);
		return -1;
	}

	if (fail_open_ce(producer))
		flags |= NFQA_CFG_F_FAIL_OPEN;
	if (conntrack_ce(producer))
		flags |= NFQA_CFG_F_CONNTRACK;
	if (gso_ce(producer))
		flags |= NFQA_CFG_F_GSO;
	if (uid_gid_ce(producer))
		flags |= NFQA_CFG_F_UID_GID;
#if defined(NFQA_CFG_F_SECCTX)
	if (secctx_ce(producer))
		flags |= NFQA_CFG_F_SECCTX;
#endif
	mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(flags));
	mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_MAX - 1));

	return 0;
}

static int check_config_response(struct nfq_common_priv *priv)
{
	struct mnl_ring *nlr = priv->nlr;
	struct nl_mmap_hdr *frame = mnl_ring_get_frame(nlr);
	void *buf = MNL_FRAME_PAYLOAD(frame);
	int ret;

	if (frame->nm_status != NL_MMAP_STATUS_VALID) {
		nurs_log(NURS_ERROR, "no valid response\n");
		return -1;
	}
	frame->nm_status = NL_MMAP_STATUS_SKIP;
	ret = mnl_cb_run(buf, frame->nm_len, 0, priv->portid, NULL, NULL);
	frame->nm_status = NL_MMAP_STATUS_UNUSED;
	mnl_ring_advance(nlr);

	if (ret == MNL_CB_ERROR)
		return -1;
	return 0;
}

int config_nfq(const struct nurs_producer *producer)
{
	struct nfq_common_priv *priv = nurs_producer_context(producer);
	struct nlmsghdr *nlh;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	uint32_t queue_num = queue_num_ce(producer);

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
	struct nl_mmap_req req = {
		.nm_block_size	= block_size_ce(producer),
		.nm_block_nr	= block_nr_ce(producer),
		.nm_frame_size	= frame_size_ce(producer),
		.nm_frame_nr	= block_size_ce(producer)
				  / frame_size_ce(producer)
				  * block_nr_ce(producer),
	};

	priv->nl = nurs_mnl_socket(namespace_ce(producer), NETLINK_NETFILTER);
	if (!priv->nl) {
		nurs_log(NURS_FATAL, "failed to mnl_socket_open: %s\n",
			  strerror(errno));
		return NURS_RET_ERROR;;
	}
	nurs_log(NURS_INFO, "mmap - block size: %d, block_nr: %d,"
		 " frame_size: %d, frame_nr: %d\n",
		 req.nm_block_size, req.nm_block_nr,
		 req.nm_frame_size, req.nm_frame_nr);
	priv->nlr = mnl_socket_rx_mmap(priv->nl, &req, MAP_SHARED);
	if (!priv->nlr) {
		nurs_log(NURS_FATAL, "failed to mnl_socket_mmap: %s\n",
			  strerror(errno));
		goto error_close_sock;
	}
	if (mnl_socket_bind(priv->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		nurs_log(NURS_FATAL, "failed to mnl_socket_bind: %s\n",
			 strerror(errno));
		goto error_unmap;
	}
	priv->portid = mnl_socket_get_portid(priv->nl);

	if (reliable_ce(producer) &&
	    mnl_socket_set_reliable(priv->nl)) {
		nurs_log(NURS_ERROR, "failed to mnl_socket_set_reliable: %s\n",
			 strerror(errno));
		goto error_unmap;
	}

	priv->fd = nurs_fd_create(mnl_socket_get_fd(priv->nl),
				  NURS_FD_F_READ);
	if (!priv->fd)
		goto error_unmap;

	return NURS_RET_OK;
error_unmap:
	mnl_socket_unmap(priv->nlr);
error_close_sock:
	mnl_socket_close(priv->nl);
	return NURS_RET_ERROR;
}

enum nurs_return_t
nfq_common_disorganize(const struct nurs_producer *producer)
{
	struct nfq_common_priv *priv = nurs_producer_context(producer);
	int ret = 0;

	if (mnl_socket_unmap(priv->nlr)) {
		nurs_log(NURS_ERROR, "failed to mnl_socket_unmap: %s\n",
			 strerror(errno));
		ret = -1;
	}
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
	uint32_t queue_num = queue_num_ce(producer);
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

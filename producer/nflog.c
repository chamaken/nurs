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
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_log/libnetfilter_log.h>

#include "config.h"
#include <nurs/nurs.h>
#include <nurs/ipfix_protocol.h>

#include "nfnl_common.h"

struct nflog_priv {
	struct mnl_socket	*nl;
	uint32_t		portid;
	struct nurs_fd		*fd;
	struct mnl_ring		*nlr;
	bool			skipped;
};

/* configuration entries */
enum {
	NFLOG_CONFIG_BIND,
	NFLOG_CONFIG_UNBIND,
	NFLOG_CONFIG_GROUP,
	NFLOG_CONFIG_SEQ_LOCAL,
	NFLOG_CONFIG_SEQ_GLOBAL,
	NFLOG_CONFIG_NUMLABEL,
	NFLOG_CONFIG_QTHRESH,
	NFLOG_CONFIG_QTIMEOUT,
	NFLOG_CONFIG_COPY_MODE,		/* NFULNL_COPY_ NONE / META / PACKET */
	NFLOG_CONFIG_COPY_RANGE,
	NFLOG_CONFIG_CONNTRACK,
	NFLOG_CONFIG_RELIABLE,
	NFLOG_CONFIG_NAMESPACE,
	NFLOG_CONFIG_MAX,
};

static struct nurs_config_def nflog_config = {
	.len = NFLOG_CONFIG_MAX,
	.keys = {
		[NFLOG_CONFIG_BIND] = {
			.name	 = "bind",
			.type	 = NURS_CONFIG_T_BOOLEAN,
			.boolean = false,
		},
		[NFLOG_CONFIG_UNBIND] = {
			.name	 = "unbind",
			.type	 = NURS_CONFIG_T_BOOLEAN,
			.boolean = true,
		},
		[NFLOG_CONFIG_GROUP] = {
                        .name     = "group",
			.type    = NURS_CONFIG_T_INTEGER,
			.integer = 0,
		},
		[NFLOG_CONFIG_SEQ_LOCAL] = {
			.name	 = "seq_local",
			.type	 = NURS_CONFIG_T_BOOLEAN,
			.boolean = false,
		},
		[NFLOG_CONFIG_SEQ_GLOBAL] = {
			.name	 = "seq_global",
			.type	 = NURS_CONFIG_T_BOOLEAN,
			.boolean = false,
		},
		[NFLOG_CONFIG_NUMLABEL] = {
			.name	 = "numeric_label",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 0,
		},
		[NFLOG_CONFIG_QTHRESH] = {
			.name    = "qthreshold",
			.type    = NURS_CONFIG_T_INTEGER,
			.integer = 0,
		},
		[NFLOG_CONFIG_QTIMEOUT] = {
			.name    = "qtimeout",
			.type    = NURS_CONFIG_T_INTEGER,
			.integer = 0,
		},
		[NFLOG_CONFIG_COPY_MODE] = {
			.name	 = "copy_mode",
			.type	 = NURS_CONFIG_T_STRING,
			.string  = "packet",
		},
		[NFLOG_CONFIG_COPY_RANGE] = {
			.name	 = "copy_range",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 0xffff - NLA_HDRLEN,
		},
		[NFLOG_CONFIG_CONNTRACK] = {
			.name    = "conntrack",
			.type    = NURS_CONFIG_T_BOOLEAN,
			.boolean = false,
		},
		[NFLOG_CONFIG_RELIABLE] = {
			.name    = "reliable",
			.type    = NURS_CONFIG_T_BOOLEAN,
			.boolean = false,
		},
		[NFLOG_CONFIG_NAMESPACE] = {
			.name	 = "namespace",
			.type	 = NURS_CONFIG_T_STRING,
			.flags   = NURS_CONFIG_F_NONE,
			.string	 = "",
		},
	}
};

#define config_bind(x)		nurs_config_boolean(nurs_producer_config(x), NFLOG_CONFIG_BIND)
#define config_unbind(x)	nurs_config_boolean(nurs_producer_config(x), NFLOG_CONFIG_UNBIND)
#define config_group(x)		(uint16_t)nurs_config_integer(nurs_producer_config(x), NFLOG_CONFIG_GROUP)
#define config_seq_local(x)	nurs_config_boolean(nurs_producer_config(x), NFLOG_CONFIG_SEQ_LOCAL)
#define config_seq_global(x)	nurs_config_boolean(nurs_producer_config(x), NFLOG_CONFIG_SEQ_GLOBAL)
#define config_label(x)		(uint8_t)nurs_config_integer(nurs_producer_config(x), NFLOG_CONFIG_NUMLABEL)
#define config_qthresh(x)	(uint32_t)nurs_config_integer(nurs_producer_config(x), NFLOG_CONFIG_QTHRESH)
#define config_qtimeout(x)	(uint32_t)nurs_config_integer(nurs_producer_config(x), NFLOG_CONFIG_QTIMEOUT)
#define config_copy_mode(x)	nurs_config_string(nurs_producer_config(x), NFLOG_CONFIG_COPY_MODE)
#define config_copy_range(x)	(uint32_t)nurs_config_integer(nurs_producer_config(x), NFLOG_CONFIG_COPY_RANGE)
#define config_conntrack(x)	nurs_config_boolean(nurs_producer_config(x), NFLOG_CONFIG_CONNTRACK)
#define config_reliable(x)	nurs_config_boolean(nurs_producer_config(x), NFLOG_CONFIG_RELIABLE)
#define config_namespace(x)	nurs_config_string(nurs_producer_config(x), NFLOG_CONFIG_NAMESPACE)

enum {
	NFLOG_OUTPUT_RAW_MAC,
	NFLOG_OUTPUT_RAW_PCKT,
	NFLOG_OUTPUT_RAW_PCKTLEN,
	NFLOG_OUTPUT_RAW_PCKTCOUNT,
	NFLOG_OUTPUT_OOB_PREFIX,
	NFLOG_OUTPUT_OOB_TIME_SEC,
	NFLOG_OUTPUT_OOB_TIME_USEC,
	NFLOG_OUTPUT_OOB_MARK,
	NFLOG_OUTPUT_OOB_IFINDEX_IN,
	NFLOG_OUTPUT_OOB_IFINDEX_OUT,
	NFLOG_OUTPUT_OOB_HOOK,
	NFLOG_OUTPUT_RAW_MAC_LEN,
	NFLOG_OUTPUT_OOB_SEQ_LOCAL,
	NFLOG_OUTPUT_OOB_SEQ_GLOBAL,
	NFLOG_OUTPUT_OOB_FAMILY,
	NFLOG_OUTPUT_OOB_PROTOCOL,
	NFLOG_OUTPUT_OOB_UID,
	NFLOG_OUTPUT_OOB_GID,
	NFLOG_OUTPUT_RAW_LABEL,
	NFLOG_OUTPUT_RAW_TYPE,
	NFLOG_OUTPUT_RAW_MAC_SADDR,
	NFLOG_OUTPUT_RAW_MAC_ADDRLEN,
	NFLOG_OUTPUT_NLATTRS,
        NFLOG_OUTPUT_RECV_BUFFER,
	NFLOG_OUTPUT_MAX,
};

static struct nurs_output_def nflog_output = {
	.len	= NFLOG_OUTPUT_MAX,
	.keys	= {
		[NFLOG_OUTPUT_RAW_MAC] = {
			.name	= "raw.mac",
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFLOG_OUTPUT_RAW_MAC_SADDR] = {
			.name	= "raw.mac.saddr",
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor	  = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_sourceMacAddress,
			},
		},
		[NFLOG_OUTPUT_RAW_PCKT] = {
			.name	= "raw.pkt",
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_NETFILTER,
				.field_id = IPFIX_NF_rawpacket,
			},
		},
		[NFLOG_OUTPUT_RAW_PCKTLEN] = {
			.name	= "raw.pktlen",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_NETFILTER,
				.field_id = IPFIX_NF_rawpacket_length,
			},
		},
		[NFLOG_OUTPUT_RAW_PCKTCOUNT] = {
			.name	= "raw.pktcount",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_packetDeltaCount,
			},
		},
		[NFLOG_OUTPUT_OOB_PREFIX] = {
			.name	= "oob.prefix",
			.type	= NURS_KEY_T_STRING,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.len	= 128, /* NF_LOG_PREFIXLEN */
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_NETFILTER,
				.field_id = IPFIX_NF_prefix,
			},
		},
		[NFLOG_OUTPUT_OOB_TIME_SEC] = {
			.type = NURS_KEY_T_UINT32,
			.flags = NURS_OKEY_F_OPTIONAL,
			.name = "oob.time.sec",
			.ipfix = {
				.vendor = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_flowStartSeconds,
			},
		},
		[NFLOG_OUTPUT_OOB_TIME_USEC] = {
			.name	= "oob.time.usec",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_flowStartMicroSeconds,
			},
		},
		[NFLOG_OUTPUT_OOB_MARK] = {
			.name	= "oob.mark",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_NETFILTER,
				.field_id = IPFIX_NF_mark,
			},
		},
		[NFLOG_OUTPUT_OOB_IFINDEX_IN] = {
			.name	= "oob.ifindex_in",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_ingressInterface,
			},
		},
		[NFLOG_OUTPUT_OOB_IFINDEX_OUT] = {
			.name	= "oob.ifindex_out",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_egressInterface,
			},
		},
		[NFLOG_OUTPUT_OOB_HOOK] = {
			.name	= "oob.hook",
			.type	= NURS_KEY_T_UINT8,
			.flags	= NURS_OKEY_F_ALWAYS, /* from NFULA_PACKET_HDR */
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_NETFILTER,
				.field_id = IPFIX_NF_hook,
			},
		},
		[NFLOG_OUTPUT_RAW_MAC_LEN] = {
			.name	= "raw.mac_len",
			.type	= NURS_KEY_T_UINT16,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFLOG_OUTPUT_RAW_MAC_ADDRLEN] = {
			.name	= "raw.mac.addrlen",
			.type	= NURS_KEY_T_UINT16,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFLOG_OUTPUT_OOB_SEQ_LOCAL] = {
			.name	= "oob.seq.local",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_NETFILTER,
				.field_id = IPFIX_NF_seq_local,
			},
		},
		[NFLOG_OUTPUT_OOB_SEQ_GLOBAL] = {
			.name	= "oob.seq.global",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_NETFILTER,
				.field_id = IPFIX_NF_seq_global,
			},
		},
		[NFLOG_OUTPUT_OOB_FAMILY] = {
			.name	= "oob.family",
			.type	= NURS_KEY_T_UINT8,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[NFLOG_OUTPUT_OOB_PROTOCOL] = {
			.name	= "oob.protocol",
			.type	= NURS_KEY_T_UINT16,
			.flags	= NURS_OKEY_F_ALWAYS, /* from NFULA_PACKET_HDR */
		},
		[NFLOG_OUTPUT_OOB_UID] = {
			.name	= "oob.uid",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFLOG_OUTPUT_OOB_GID] = {
			.name	= "oob.gid",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFLOG_OUTPUT_RAW_LABEL] = {
			.name	= "raw.label",
			.type	= NURS_KEY_T_UINT8,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFLOG_OUTPUT_RAW_TYPE] = {
			.name	= "raw.type",
			.type	= NURS_KEY_T_UINT16,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFLOG_OUTPUT_NLATTRS] = {
			/* struct nlattr *attr[NFULA_MAX+1] = {}; */
			.name	= "nflog.attrs",
			.type	= NURS_KEY_T_EMBED,
			.flags	= NURS_OKEY_F_ALWAYS,
			.len	= sizeof(struct nlattr *) * (NFULA_MAX + 1),
		},
                [NFLOG_OUTPUT_RECV_BUFFER] = {
                        .type	= NURS_KEY_T_EMBED,
                        .flags	= NURS_OKEY_F_OPTIONAL, /* NURS_OKEY_NONE? */
                        .name	= "nflog.buffer",
                        .len	= 0x10000,
                },
	}
};

struct mnl_cbarg {
	struct nurs_producer	*producer;
        struct nurs_output	*output;
};

static int nflog_mnl_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	struct nurs_output *output = data;
	struct nlattr **attrs;

	attrs = (struct nlattr **)
		nurs_output_pointer(output, NFLOG_OUTPUT_NLATTRS);
	if (nflog_nlmsg_parse(nlh, attrs) != MNL_CB_OK) {
		nurs_log(NURS_ERROR, "failed to parse nflog message: %s\n",
			 strerror(errno));
		return MNL_CB_ERROR;
	}
	nurs_output_set_valid(output, NFLOG_OUTPUT_NLATTRS);
	nurs_output_set_u8(output, NFLOG_OUTPUT_OOB_FAMILY, nfg->nfgen_family);
	if (attrs[NFULA_PACKET_HDR]) {
		struct nfulnl_msg_packet_hdr *ph
			= mnl_attr_get_payload(attrs[NFULA_PACKET_HDR]);
		nurs_output_set_u8(output, NFLOG_OUTPUT_OOB_HOOK, ph->hook);
		nurs_output_set_u16(output, NFLOG_OUTPUT_OOB_PROTOCOL,
				    ntohs(ph->hw_protocol));
	}

	if (attrs[NFULA_HWHEADER]) {
		nurs_output_set_pointer(
			output, NFLOG_OUTPUT_RAW_MAC,
			mnl_attr_get_payload(attrs[NFULA_HWHEADER]));
		nurs_output_set_u16(
			output, NFLOG_OUTPUT_RAW_MAC_LEN,
			ntohs(mnl_attr_get_u16(attrs[NFULA_HWLEN])));
		nurs_output_set_u16(
			output, NFLOG_OUTPUT_RAW_TYPE,
			ntohs(mnl_attr_get_u16(attrs[NFULA_HWTYPE])));
	}

	if (attrs[NFULA_HWADDR]) {
		struct nfulnl_msg_packet_hw *hw
			= mnl_attr_get_payload(attrs[NFULA_HWADDR]);
		nurs_output_set_pointer(output, NFLOG_OUTPUT_RAW_MAC_SADDR,
					hw->hw_addr);
		nurs_output_set_u16(output, NFLOG_OUTPUT_RAW_MAC_ADDRLEN,
				    ntohs(hw->hw_addrlen));
	}

	if (attrs[NFULA_PAYLOAD]) {
		/* include pointer to raw packet */
		nurs_output_set_pointer(
			output, NFLOG_OUTPUT_RAW_PCKT,
			mnl_attr_get_payload(attrs[NFULA_PAYLOAD]));
		nurs_output_set_u32(
			output, NFLOG_OUTPUT_RAW_PCKTLEN,
			mnl_attr_get_payload_len(attrs[NFULA_PAYLOAD]));
	}

	/* number of packets */
	nurs_output_set_u32(output, NFLOG_OUTPUT_RAW_PCKTCOUNT, 1);

	if (attrs[NFULA_PREFIX])
		nurs_output_set_string(
			output, NFLOG_OUTPUT_OOB_PREFIX,
			mnl_attr_get_payload(attrs[NFULA_PREFIX]));

	if (attrs[NFULA_TIMESTAMP]) {
		struct nfulnl_msg_packet_timestamp *ts
			= mnl_attr_get_payload(attrs[NFULA_TIMESTAMP]);
		nurs_output_set_u32(output, NFLOG_OUTPUT_OOB_TIME_SEC,
				    ts->sec & 0xffffffff);
		nurs_output_set_u32(output, NFLOG_OUTPUT_OOB_TIME_USEC,
				    ts->usec & 0xffffffff);
	}

	if (attrs[NFULA_MARK])
		nurs_output_set_u32(
			output, NFLOG_OUTPUT_OOB_MARK,
			ntohl(mnl_attr_get_u32(attrs[NFULA_MARK])));
	if (attrs[NFULA_IFINDEX_INDEV])
		nurs_output_set_u32(
			output, NFLOG_OUTPUT_OOB_IFINDEX_IN,
			ntohl(mnl_attr_get_u32(attrs[NFULA_IFINDEX_INDEV])));
	if (attrs[NFULA_IFINDEX_OUTDEV])
		nurs_output_set_u32(
			output, NFLOG_OUTPUT_OOB_IFINDEX_OUT,
			ntohl(mnl_attr_get_u32(attrs[NFULA_IFINDEX_OUTDEV])));
	if (attrs[NFULA_UID])
		nurs_output_set_u32(
			output, NFLOG_OUTPUT_OOB_UID,
			ntohl(mnl_attr_get_u32(attrs[NFULA_UID])));
	if (attrs[NFULA_GID])
		nurs_output_set_u32(
			output, NFLOG_OUTPUT_OOB_GID,
			ntohl(mnl_attr_get_u32(attrs[NFULA_GID])));
	if (attrs[NFULA_SEQ])
		nurs_output_set_u32(
			output, NFLOG_OUTPUT_OOB_SEQ_LOCAL,
			ntohl(mnl_attr_get_u32(attrs[NFULA_SEQ])));
	if (attrs[NFULA_SEQ_GLOBAL])
		nurs_output_set_u32(
			output, NFLOG_OUTPUT_OOB_SEQ_GLOBAL,
			ntohl(mnl_attr_get_u32(attrs[NFULA_SEQ_GLOBAL])));
	return MNL_CB_OK;
}

static enum nurs_return_t
nflog_read_cb(struct nurs_fd *nfd, uint16_t when)
{
        struct nurs_producer *producer = nurs_fd_get_data(nfd);
        struct nflog_priv *priv = nurs_producer_context(producer);
        struct nurs_output *output = nurs_get_output(producer);
        ssize_t nrecv;
        void *buf;
        size_t buflen;
        int fd = nurs_fd_get_fd(nfd);

        if (!output) {
                nurs_log(NURS_ERROR, "failed to get output: %s\n",
                         strerror(errno));
                return NURS_RET_ERROR;
        }
        buf = nurs_output_pointer(output, NFLOG_OUTPUT_RECV_BUFFER);
        if (!buf) {
                nurs_log(NURS_ERROR, "failed to get recv buffer: %s\n",
                         strerror(errno));
                return NURS_RET_ERROR;
        }
        buflen = (size_t)nurs_output_size(output, NFLOG_OUTPUT_RECV_BUFFER);

        nrecv = recv(fd, buf, buflen, MSG_DONTWAIT);
        if (nrecv == -1) {
                nurs_log(NURS_ERROR, "failed to recv: %s\n",
                         strerror(errno));
                goto fail;
        }

        if (mnl_cb_run(buf, (size_t)nrecv, 0,
                       priv->portid, nflog_mnl_cb, output) == MNL_CB_ERROR) {
                nurs_log(NURS_ERROR, "failed to mnl_cb_run: %s\n",
                         strerror(errno));
                goto fail;
        }

	nurs_output_set_u8(output, NFLOG_OUTPUT_RAW_LABEL,
			   config_label(producer));

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

static int check_config_response(struct nflog_priv *priv)
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

static int become_system_logging(struct nurs_producer *producer, uint8_t family)
{
	struct nflog_priv *priv = nurs_producer_context(producer);
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	if (config_unbind(producer)) {
		nurs_log(NURS_NOTICE, "forcing unbind of existing log "
			 "handler for protocol %d\n", family);
		nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, family, 0);
		nlh->nlmsg_flags |= NLM_F_ACK;
		if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_PF_UNBIND) < 0) {
			nurs_log(NURS_ERROR, "nflog_attr_put_cfg_cmd: %s\n",
				 strerror(errno));
			return -1;
		}
		if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
			nurs_log(NURS_ERROR, "mnl_socket_sendto: %s\n",
				 strerror(errno));
			return -1;
		}
		if (check_config_response(priv)) {
			nurs_log(NURS_ERROR, "request PF_UNBIND: %s\n",
				 strerror(errno));
			return -1;
		}
	}

	nurs_log(NURS_DEBUG, "binding to protocol family %d\n", family);
	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, family, 0);
	nlh->nlmsg_flags |= NLM_F_ACK;
	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_PF_BIND) < 0) {
		nurs_log(NURS_ERROR, "nflog_attr_put_cfg_cmd: %s\n",
			 strerror(errno));
		return -1;
	}
	if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
		nurs_log(NURS_ERROR, "mnl_socket_sendto: %s\n",
			 strerror(errno));
		return -1;
	}
	if (check_config_response(priv)) {
		nurs_log(NURS_ERROR, "request command PF_BIND: %s\n",
			 strerror(errno));
		return -1;
	}

	return 0;
}

static int config_nflog(struct nurs_producer *producer)
{
	struct nflog_priv *priv = nurs_producer_context(producer);
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint16_t group = config_group(producer);
	const char *copy_mode = config_copy_mode(producer);
	uint16_t flags = 0;

        /* This is the system logging (conntrack, ...) facility */
	if (!group || config_bind(producer)) {
		if (become_system_logging(producer, AF_INET))
                        goto fail;
		if (become_system_logging(producer, AF_INET6))
                        goto fail;
		if (become_system_logging(producer, AF_BRIDGE))
                        goto fail;
	}

	nurs_log(NURS_DEBUG, "binding to log group %d\n", group);
	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, group);
	nlh->nlmsg_flags |= NLM_F_ACK;
	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_BIND) < 0) {
		nurs_log(NURS_ERROR, "nflog_attr_put_cfg_cmd: %s\n",
			 strerror(errno));
                goto fail;
	}
	if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
		nurs_log(NURS_ERROR, "mnl_socket_sendto: %s\n",
			 strerror(errno));
                goto fail;
	}
	if (check_config_response(priv)) {
		nurs_log(NURS_ERROR, "request command BIND: %s\n",
			 strerror(errno));
                goto fail;
	}

	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, group);
	nlh->nlmsg_flags |= NLM_F_ACK;
	if (!strcasecmp(copy_mode, "packet")) {
		uint32_t copy_range;
		copy_range = htonl(config_copy_range(producer));
		if (nflog_attr_put_cfg_mode(nlh, NFULNL_COPY_PACKET,
					    copy_range) < 0) {
			nurs_log(NURS_ERROR, "nflog_attr_put_cfg_mode: %s\n",
				 strerror(errno));
                        goto fail;
		}
	} else if (!strcasecmp(copy_mode, "meta")) {
		if (nflog_attr_put_cfg_mode(nlh, NFULNL_COPY_META, 0) < 0) {
			nurs_log(NURS_ERROR, "nflog_attr_put_cfg_mode: %s\n",
				 strerror(errno));
                        goto fail;
		}
	} else if (!strcasecmp(copy_mode, "none")) {
		if (nflog_attr_put_cfg_mode(nlh, NFULNL_COPY_NONE, 0) < 0) {
			nurs_log(NURS_ERROR, "nflog_attr_put_cfg_mode: %s\n",
				 strerror(errno));
                        goto fail;
		}
	} else {
		nurs_log(NURS_ERROR, "unknown copy_mode: %s\n", copy_mode);
                goto fail;
	}
	if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
		nurs_log(NURS_ERROR, "mnl_socket_sendto: %s\n",
			 strerror(errno));
                goto fail;
	}
	if (check_config_response(priv)) {
		nurs_log(NURS_ERROR, "request config COPY_PACKET: %s\n",
			 strerror(errno));
                goto fail;
	}

	if (config_qthresh(producer)) {
		nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG,
					     AF_UNSPEC, group);
		nlh->nlmsg_flags |= NLM_F_ACK;
		mnl_attr_put_u32(nlh, NFULA_CFG_QTHRESH,
				 htonl(config_qthresh(producer)));
		if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
			nurs_log(NURS_ERROR, "mnl_socket_sendto: %s\n",
				 strerror(errno));
                        goto fail;
		}
		if (check_config_response(priv)) {
			nurs_log(NURS_NOTICE,
				 "NFLOG netlink queue threshold can't "
				 "be set to %d: %s\n", config_qthresh(producer),
				 strerror(errno));
                        goto fail;
		}
	}

	if (config_qtimeout(producer)) {
		nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG,
					     AF_UNSPEC, group);
		nlh->nlmsg_flags |= NLM_F_ACK;
		mnl_attr_put_u32(nlh, NFULA_CFG_TIMEOUT,
				 htonl(config_qtimeout(producer)));
		if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
			nurs_log(NURS_ERROR, "mnl_socket_sendto: %s\n",
				 strerror(errno));
                        goto fail;
		}
		if (check_config_response(priv)) {
			nurs_log(NURS_NOTICE,
				 "NFLOG netlink queue timeout can't "
				 "be set to %d: %s\n",
				 config_qtimeout(producer),
				 strerror(errno));
                        goto fail;
		}
	}

	/* set log flags based on configuration */
	if (config_seq_local(producer))
		flags = NFULNL_CFG_F_SEQ;
	if (config_seq_global(producer))
		flags |= NFULNL_CFG_F_SEQ_GLOBAL;
	if (config_conntrack(producer))
		flags |= NFULNL_CFG_F_CONNTRACK;
	if (flags) {
		nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, group);
		nlh->nlmsg_flags |= NLM_F_ACK;
		mnl_attr_put_u16(nlh, NFULA_CFG_FLAGS, htons(flags));
		if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
			nurs_log(NURS_ERROR, "mnl_socket_sendto: %s\n",
				 strerror(errno));
                        goto fail;
		}
		if (check_config_response(priv)) {
			nurs_log(NURS_ERROR, "unable to set flags 0x%x: %s\n",
				 flags, strerror(errno));
                        goto fail;
		}
	}

	return 0;
fail:
        return -1;
}

static int nflog_pf_unbind(struct mnl_socket *nl)
{
	char buf[MNL_SOCKET_BUFFER_SIZE * 2];
	struct nlmsghdr *nlh;
	struct mnl_nlmsg_batch *b;
	int ret = -1;

	b = mnl_nlmsg_batch_start(buf, (size_t)MNL_SOCKET_BUFFER_SIZE);
	nlh = nflog_nlmsg_put_header(mnl_nlmsg_batch_current(b),
				     NFULNL_MSG_CONFIG, AF_INET, 0);
	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_PF_UNBIND) < 0) {
		nurs_log(NURS_ERROR, "nflog_attr_put_cfg_cmd: %s\n",
			 strerror(errno));
		goto batch_stop;
	}

	mnl_nlmsg_batch_next(b);
	nlh = nflog_nlmsg_put_header(mnl_nlmsg_batch_current(b),
				     NFULNL_MSG_CONFIG, AF_INET6, 0);
	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_PF_UNBIND) < 0) {
		nurs_log(NURS_ERROR, "nflog_attr_put_cfg_cmd: %s\n",
			 strerror(errno));
		goto batch_stop;
	}

	mnl_nlmsg_batch_next(b);
	nlh = nflog_nlmsg_put_header(mnl_nlmsg_batch_current(b),
				     NFULNL_MSG_CONFIG, AF_BRIDGE, 0);
	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_PF_UNBIND) < 0) {
		nurs_log(NURS_ERROR, "nflog_attr_put_cfg_cmd: %s\n",
			 strerror(errno));
		goto batch_stop;
	}

	mnl_nlmsg_batch_next(b);
	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		nurs_log(NURS_ERROR, "mnl_socket_sendto: %s\n",
			 strerror(errno));
		goto batch_stop;
	}
	ret = 0;

batch_stop:
	mnl_nlmsg_batch_stop(b);
	return ret;
}

static enum nurs_return_t nflog_organize(struct nurs_producer *producer)
{
	struct nflog_priv *priv = nurs_producer_context(producer);

	priv->nl = nurs_mnl_socket(config_namespace(producer), NETLINK_NETFILTER);
	if (!priv->nl) {
		nurs_log(NURS_FATAL, "mnl_socket_open: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}

	if (mnl_socket_bind(priv->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		nurs_log(NURS_FATAL, "mnl_socket_bind: %s\n",
			 strerror(errno));
		goto error_close;
	}
	priv->portid = mnl_socket_get_portid(priv->nl);

	if (config_reliable(producer)) {
		if (mnl_socket_set_reliable(priv->nl)) {
			nurs_log(NURS_ERROR, "mnl_socket_set_reliable: %s\n",
				 strerror(errno));
			goto error_close;
		}
	}

	return NURS_RET_OK;

error_close:
	mnl_socket_close(priv->nl);
	return NURS_RET_ERROR;
}

static enum nurs_return_t nflog_disorganize(struct nurs_producer *producer)
{
	struct nflog_priv *priv = nurs_producer_context(producer);
	int ret = 0;

	if (mnl_socket_close(priv->nl)) {
		nurs_log(NURS_ERROR, "mnl_socket_close: %s\n", strerror(errno));
		ret = -1;
	}

	if (ret)
		return NURS_RET_ERROR;
	return NURS_RET_OK;
}

static enum nurs_return_t nflog_start(struct nurs_producer *producer)
{
	struct nflog_priv *priv = nurs_producer_context(producer);

        priv -> fd = nurs_fd_register(
                mnl_socket_get_fd(priv->nl),  NURS_FD_F_READ,
                nflog_read_cb, producer);
	if (!priv->fd) {
		nurs_log(NURS_ERROR, "nurs_fd_register failed: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}

	if (config_nflog(producer)) {
		nurs_fd_unregister(priv->fd);
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static enum nurs_return_t nflog_stop(struct nurs_producer *producer)
{
	struct nflog_priv *priv = nurs_producer_context(producer);
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nurs_fd_unregister(priv->fd);

	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG,
				     AF_UNSPEC, config_group(producer));
	if (!nlh) {
		nurs_log(NURS_ERROR, "failed to put NFULNL_MSG_CONFIG\n");
		return NURS_RET_ERROR;
	}
	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_UNBIND)) {
		nurs_log(NURS_ERROR, "failed to put NFULNL_CFG_CMD_UNBIND\n");
		return NURS_RET_ERROR;
	}
	if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
		nurs_log(NURS_ERROR, "failed to mnl_socket_sendto: %s\n",
			 strerror(errno));
	}
	if (!config_group(producer) /* || config_bind(producer) */ &&
	    nflog_pf_unbind(priv->nl)) {
		nurs_log(NURS_ERROR, "failed to unbind nflog\n");
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static enum nurs_return_t
nflog_signal(struct nurs_producer *producer, uint32_t signal)
{
	switch (signal) {
	default:
		nurs_log(NURS_DEBUG, "receive signal: %d\n", signal);
		break;
	}
	return NURS_RET_OK;
}

static struct nurs_producer_def nflog_producer = {
	.version	= VERSION,
	.name		= "NFLOG",
	.context_size	= sizeof(struct nflog_priv),
	.config_def	= &nflog_config,
	.output_def	= &nflog_output,
	.organize	= nflog_organize,
	.disorganize	= nflog_disorganize,
	.start		= nflog_start,
	.stop		= nflog_stop,
	.signal		= nflog_signal,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	nurs_producer_register(&nflog_producer);
}

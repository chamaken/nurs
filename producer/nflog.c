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

#include <nurs/nurs.h>
#include <nurs/ring.h>
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
	NFLOG_CONFIG_BLOCK_SIZE	= 0,
	NFLOG_CONFIG_BLOCK_NR,
	NFLOG_CONFIG_FRAME_SIZE,
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
	NFLOG_CONFIG_MAX,
};

static struct nurs_config_def nflog_config = {
	.len = NFLOG_CONFIG_MAX,
	.keys = {
		[NFLOG_CONFIG_BLOCK_SIZE] = {
			.name	 = "block_size",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 8192,
		},
		[NFLOG_CONFIG_BLOCK_NR] = {
			.name	 = "block_nr",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 32,
		},
		[NFLOG_CONFIG_FRAME_SIZE] = {
			.name	 = "frame_size",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 8192,
		},
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
	}
};

#define block_size_ce(x)	(unsigned int)nurs_config_integer(nurs_producer_config(x), NFLOG_CONFIG_BLOCK_SIZE)
#define block_nr_ce(x)		(unsigned int)nurs_config_integer(nurs_producer_config(x), NFLOG_CONFIG_BLOCK_NR)
#define frame_size_ce(x)	(unsigned int)nurs_config_integer(nurs_producer_config(x), NFLOG_CONFIG_FRAME_SIZE)
#define oneshot_ce(x)		nurs_config_integer(nurs_producer_config(x), NFLOG_CONFIG_ONESHOT)
#define bind_ce(x)		nurs_config_boolean(nurs_producer_config(x), NFLOG_CONFIG_BIND)
#define unbind_ce(x)		nurs_config_boolean(nurs_producer_config(x), NFLOG_CONFIG_UNBIND)
#define group_ce(x)		(uint16_t)nurs_config_integer(nurs_producer_config(x), NFLOG_CONFIG_GROUP)
#define seq_ce(x)		nurs_config_boolean(nurs_producer_config(x), NFLOG_CONFIG_SEQ_LOCAL)
#define seq_global_ce(x)	nurs_config_boolean(nurs_producer_config(x), NFLOG_CONFIG_SEQ_GLOBAL)
#define label_ce(x)		(uint8_t)nurs_config_integer(nurs_producer_config(x), NFLOG_CONFIG_NUMLABEL)
#define qthresh_ce(x)		(uint32_t)nurs_config_integer(nurs_producer_config(x), NFLOG_CONFIG_QTHRESH)
#define qtimeout_ce(x)		(uint32_t)nurs_config_integer(nurs_producer_config(x), NFLOG_CONFIG_QTIMEOUT)
#define copy_mode_ce(x)		nurs_config_string(nurs_producer_config(x), NFLOG_CONFIG_COPY_MODE)
#define copy_range_ce(x)	(uint32_t)nurs_config_integer(nurs_producer_config(x), NFLOG_CONFIG_COPY_RANGE)
#define conntrack_ce(x)		nurs_config_boolean(nurs_producer_config(x), NFLOG_CONFIG_CONNTRACK)
#define reliable_ce(x)		nurs_config_boolean(nurs_producer_config(x), NFLOG_CONFIG_RELIABLE)

enum {
	NFLOG_OUTPUT_RAW_MAC = 0,
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
	NFLOG_OUTPUT_FRAME,
	NFLOG_OUTPUT_MAX,
};

static void frame_destructor(void *data);

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
			.flags	= NURS_OKEY_F_ACTIVE, /* from NFULA_PACKET_HDR */
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
			.flags	= NURS_OKEY_F_ACTIVE,
		},
		[NFLOG_OUTPUT_OOB_PROTOCOL] = {
			.name	= "oob.protocol",
			.type	= NURS_KEY_T_UINT16,
			.flags	= NURS_OKEY_F_ACTIVE, /* from NFULA_PACKET_HDR */
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
			.flags	= NURS_OKEY_F_ACTIVE,
			.len	= sizeof(struct nlattr *) * (NFULA_MAX + 1),
		},
		[NFLOG_OUTPUT_FRAME] = {
			/* only for set frame unused status */
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_OPTIONAL | NURS_OKEY_F_DESTRUCT,
			.name	= "nflog.frame",
			.destructor = frame_destructor,
		},
	}
};

static void frame_destructor(void *data)
{
	struct nl_mmap_hdr *frame = data;
	frame->nm_status = NL_MMAP_STATUS_UNUSED;
}

static int nflog_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	struct nurs_output *output = data;
	struct nlattr **attrs;
	struct nl_mmap_hdr *frame = MNL_NLMSG_FRAME(nlh);

	attrs = (struct nlattr **)
		nurs_output_pointer(output, NFLOG_OUTPUT_NLATTRS);
	if (nflog_nlmsg_parse(nlh, attrs) != MNL_CB_OK) {
		nurs_log(NURS_ERROR, "failed to parse nflog message: %s\n",
			 strerror(errno));
		return MNL_CB_ERROR;
	}
	nurs_output_set_valid(output, NFLOG_OUTPUT_NLATTRS);
	nurs_output_set_pointer(output, NFLOG_OUTPUT_FRAME, frame);

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
			output, NFLOG_OUTPUT_OOB_SEQ_LOCAL,
			ntohl(mnl_attr_get_u32(attrs[NFULA_SEQ_GLOBAL])));

	return MNL_CB_OK;
}

/* responsible for unused status */
static int handle_valid_frame(struct nurs_producer *producer,
			      struct nl_mmap_hdr *frame)
{
	struct nflog_priv *priv = nurs_producer_context(producer);
	struct nurs_output *output;
	int ret;

	if (!frame->nm_len) {
		frame->nm_status = NL_MMAP_STATUS_UNUSED;
		/* an error may occured in kernel */
		return NURS_RET_OK;
	}

	output = nurs_get_output(producer);
	ret = mnl_cb_run(MNL_FRAME_PAYLOAD(frame), frame->nm_len,
			 0, priv->portid, nflog_cb, output);
	/* __nfulnl_send set NLMSG_DONE, cause MNL_CB_STOP */
	if (ret == MNL_CB_ERROR) {
		frame->nm_status = NL_MMAP_STATUS_UNUSED;
		nurs_put_output(producer, output);
		return NURS_RET_ERROR;
	}
	nurs_output_set_u8(output, NFLOG_OUTPUT_RAW_LABEL, label_ce(producer));

	if (nurs_propagate(producer, output)) {
		frame->nm_status = NL_MMAP_STATUS_UNUSED;
		return NURS_RET_ERROR;
	}
	/* else key destructor will set status unused */

	return NURS_RET_OK;
}

/* callback called from nurs core when fd is readable */
static enum nurs_return_t
nflog_read_cb(int fd, uint16_t when, void *data)
{
	struct nurs_producer *producer = data;
	struct nflog_priv *priv = nurs_producer_context(producer);
	struct nl_mmap_hdr *frame;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	ssize_t rc, nrecv;
	static enum nurs_return_t ret = NURS_RET_ERROR;

	if (!(when & NURS_FD_F_READ))
		return NURS_RET_OK;

handle_frame:
	frame = mnl_ring_get_frame(priv->nlr);
	switch (frame->nm_status) {
	case NL_MMAP_STATUS_VALID:
		frame->nm_status = NL_MMAP_STATUS_SKIP;
		ret = handle_valid_frame(producer, frame);
		mnl_ring_advance(priv->nlr);
		break;
	case NL_MMAP_STATUS_COPY:
		/* only consuming message and report as error */
		nurs_log(NURS_ERROR, "exceeded the frame size: %d\n",
			 frame->nm_len);
		for (nrecv = 0; nrecv < frame->nm_len; ) {
			rc = recv(fd, buf,
				  (size_t)MNL_SOCKET_BUFFER_SIZE,
				  MSG_DONTWAIT);
			if (rc == -1) {
				nurs_log(NURS_ERROR, "failed to recv COPY"
					 " frame %s\n", strerror(errno));
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

static int check_config_response(struct nflog_priv *priv)
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
	errno = 0;
	ret = mnl_cb_run(buf, frame->nm_len, 0, priv->portid, NULL, NULL);
	frame->nm_status = NL_MMAP_STATUS_UNUSED;
	mnl_ring_advance(nlr);

	/* ACK message returns MNL_CB_STOP */
	if (ret == MNL_CB_ERROR)
		return -1;
	return 0;
}

static int become_system_logging(const struct nurs_producer *producer,
				 uint8_t family)
{
	struct nflog_priv *priv = nurs_producer_context(producer);
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	if (unbind_ce(producer)) {
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

static int config_nflog(const struct nurs_producer *producer)
{
	struct nflog_priv *priv = nurs_producer_context(producer);
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint16_t group = group_ce(producer);
	const char *copy_mode = copy_mode_ce(producer);
	uint16_t flags = 0;

	/* This is the system logging (conntrack, ...) facility */
	if (!group || bind_ce(producer)) {
		if (become_system_logging(producer, AF_INET))
			return -1;
		if (become_system_logging(producer, AF_INET6))
			return -1;
		if (become_system_logging(producer, AF_BRIDGE))
			return -1;
	}

	nurs_log(NURS_DEBUG, "binding to log group %d\n", group);
	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, group);
	nlh->nlmsg_flags |= NLM_F_ACK;
	if (nflog_attr_put_cfg_cmd(nlh, NFULNL_CFG_CMD_BIND) < 0) {
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
		nurs_log(NURS_ERROR, "request command BIND: %s\n",
			 strerror(errno));
		return -1;
	}

	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, group);
	nlh->nlmsg_flags |= NLM_F_ACK;
	if (!strcasecmp(copy_mode, "packet")) {
		uint32_t copy_range;
		if (frame_size_ce(producer) < copy_range_ce(producer))
			nurs_log(NURS_NOTICE, "may cause COPY status"
				 " - frame size: %d, copy_range: %d\n",
				 frame_size_ce(producer), copy_range_ce(producer));
		copy_range = htonl(copy_range_ce(producer));
		if (nflog_attr_put_cfg_mode(nlh, NFULNL_COPY_PACKET,
					    copy_range) < 0) {
			nurs_log(NURS_ERROR, "nflog_attr_put_cfg_mode: %s\n",
				 strerror(errno));
			return -1;
		}
	} else if (!strcasecmp(copy_mode, "meta")) {
		if (nflog_attr_put_cfg_mode(nlh, NFULNL_COPY_META, 0) < 0) {
			nurs_log(NURS_ERROR, "nflog_attr_put_cfg_mode: %s\n",
				 strerror(errno));
			return -1;
		}
	} else if (!strcasecmp(copy_mode, "none")) {
		if (nflog_attr_put_cfg_mode(nlh, NFULNL_COPY_NONE, 0) < 0) {
			nurs_log(NURS_ERROR, "nflog_attr_put_cfg_mode: %s\n",
				 strerror(errno));
			return -1;
		}
	} else {
		nurs_log(NURS_ERROR, "unknown copy_mode: %s\n", copy_mode);
		return -1;
	}
	if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
		nurs_log(NURS_ERROR, "mnl_socket_sendto: %s\n",
			 strerror(errno));
		return -1;
	}
	if (check_config_response(priv)) {
		nurs_log(NURS_ERROR, "request config COPY_PACKET: %s\n",
			 strerror(errno));
		return -1;
	}

	if (qthresh_ce(producer)) {
		nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, group);
		nlh->nlmsg_flags |= NLM_F_ACK;
		mnl_attr_put_u32(nlh, NFULA_CFG_QTHRESH, htonl(qthresh_ce(producer)));
		if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
			nurs_log(NURS_ERROR, "mnl_socket_sendto: %s\n",
				 strerror(errno));
			return -1;
		}
		if (check_config_response(priv)) {
			nurs_log(NURS_NOTICE,
				 "NFLOG netlink queue threshold can't "
				 "be set to %d: %s\n", qthresh_ce(producer),
				 strerror(errno));
			return -1;
		}
	}

	if (qtimeout_ce(producer)) {
		nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, group);
		nlh->nlmsg_flags |= NLM_F_ACK;
		mnl_attr_put_u32(nlh, NFULA_CFG_TIMEOUT, htonl(qtimeout_ce(producer)));
		if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
			nurs_log(NURS_ERROR, "mnl_socket_sendto: %s\n",
				 strerror(errno));
			return -1;
		}
		if (check_config_response(priv)) {
			nurs_log(NURS_NOTICE,
				 "NFLOG netlink queue timeout can't "
				 "be set to %d: %s\n", qtimeout_ce(producer),
				 strerror(errno));
			return -1;
		}
	}

	/* set log flags based on configuration */
	if (seq_ce(producer))
		flags = NFULNL_CFG_F_SEQ;
	if (seq_global_ce(producer))
		flags |= NFULNL_CFG_F_SEQ_GLOBAL;
	if (conntrack_ce(producer))
		flags |= NFULNL_CFG_F_CONNTRACK;
	if (flags) {
		nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG, AF_UNSPEC, group);
		nlh->nlmsg_flags |= NLM_F_ACK;
		mnl_attr_put_u16(nlh, NFULA_CFG_FLAGS, htons(flags));
		if (mnl_socket_sendto(priv->nl, nlh, nlh->nlmsg_len) < 0) {
			nurs_log(NURS_ERROR, "mnl_socket_sendto: %s\n",
				 strerror(errno));
			return -1;
		}
		if (check_config_response(priv)) {
			nurs_log(NURS_ERROR, "unable to set flags 0x%x: %s\n",
				 flags, strerror(errno));
			return -1;
		}
	}

	return 0;
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

static enum nurs_return_t
nflog_organize(const struct nurs_producer *producer)
{
	struct nflog_priv *priv = nurs_producer_context(producer);

	struct nl_mmap_req req = {
		.nm_block_size	= block_size_ce(producer),
		.nm_block_nr	= block_nr_ce(producer),
		.nm_frame_size	= frame_size_ce(producer),
		.nm_frame_nr	= block_size_ce(producer) / frame_size_ce(producer)
		* block_nr_ce(producer)
	};

	priv->nl = mnl_socket_open(NETLINK_NETFILTER);
	if (!priv->nl) {
		nurs_log(NURS_FATAL, "mnl_socket_open: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}
	nurs_log(NURS_INFO, "mmap - block_size: %d, block_nr: %d,"
		 " frame_size: %d, frame_nr: %d\n",
		 req.nm_block_size, req.nm_block_nr,
		 req.nm_frame_size, req.nm_frame_nr);
	priv->nlr = mnl_socket_rx_mmap(priv->nl, &req, MAP_SHARED);
	if (!priv->nlr) {
		nurs_log(NURS_FATAL, "mnl_socket_mmap: %s\n",
			 strerror(errno));
		goto error_close_sock;
	}
	if (mnl_socket_bind(priv->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		nurs_log(NURS_FATAL, "mnl_socket_bind: %s\n",
			 strerror(errno));
		goto error_unmap;
	}
	priv->portid = mnl_socket_get_portid(priv->nl);

	if (reliable_ce(producer)) {
		if (mnl_socket_set_reliable(priv->nl)) {
			nurs_log(NURS_ERROR, "mnl_socket_set_reliable: %s\n",
				 strerror(errno));
			goto error_unmap;
		}
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

static enum nurs_return_t
nflog_disorganize(const struct nurs_producer *producer)
{
	struct nflog_priv *priv = nurs_producer_context(producer);
	int ret = 0;

	nurs_fd_destroy(priv->fd);
	if (mnl_socket_unmap(priv->nlr)) {
		nurs_log(NURS_ERROR, "mnl_socket_unmap: %s\n", strerror(errno));
		ret = -1;
	}
	if (mnl_socket_close(priv->nl)) {
		nurs_log(NURS_ERROR, "mnl_socket_close: %s\n", strerror(errno));
		ret = -1;
	}

	if (ret)
		return NURS_RET_ERROR;
	return NURS_RET_OK;
}

static enum nurs_return_t
nflog_start(const struct nurs_producer *producer)
{
	struct nflog_priv *priv = nurs_producer_context(producer);
	void *cbdata = (void *)(uintptr_t)producer; /* remove const qual */

	if (nurs_fd_register(priv->fd, nflog_read_cb, cbdata)) {
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

static enum nurs_return_t
nflog_stop(const struct nurs_producer *producer)
{
	struct nflog_priv *priv = nurs_producer_context(producer);
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nurs_fd_unregister(priv->fd);

	nlh = nflog_nlmsg_put_header(buf, NFULNL_MSG_CONFIG,
				     AF_UNSPEC, group_ce(producer));
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
	if (!group_ce(producer) /* || bind_ce(producer) */ &&
	    nflog_pf_unbind(priv->nl)) {
		nurs_log(NURS_ERROR, "failed to unbind nflog\n");
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static enum nurs_return_t
nflog_signal(const struct nurs_producer *producer, uint32_t signal)
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

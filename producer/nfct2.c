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
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <nurs/nurs.h>
#include <nurs/ipfix_protocol.h>
#ifdef NLMMAP
#include <nurs/ring.h>
#else
#define mnl_socket_unmap(x)
#endif

#include "nfnl_common.h"

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC    1000000000L
#endif

/* flowEndReason
 *   (none)		0x01: idle timeout
 *   NFCT_T_UPDATE	0x02: active timeout
 *   NFCT_T_DESTROY	0x03: end of Flow detected
 *   (none)		0x04: forced end
 *   (none)		0x05: lack of resources
 */
static uint8_t flowReasons[] = {
	[NFCT_T_UPDATE]		= 0x02,
	[NFCT_T_DESTROY]	= 0x03,
};

struct nfct_priv {
#ifdef NLMMAP
	struct mnl_ring		*nlr;
#endif
	struct mnl_socket	*event_nl;
	struct nurs_fd		*event_fd;
	uint32_t		event_pid;
	int 			event_bufsize;
	int			event_bufmax;

	struct mnl_socket	*dump_nl;
	struct nurs_fd		*dump_fd;
	uint32_t		dump_pid;
	struct nlmsghdr		*dump_request;
	struct timeval		dump_prev;

	struct nurs_timer	*timer;
};

enum nfct_conf {
#ifdef NLMMAP
	NFCT_CONFIG_BLOCK_SIZE,		/* 8192 */
	NFCT_CONFIG_BLOCK_NR,		/* 128 */
	NFCT_CONFIG_FRAME_SIZE,		/* 8192 */
#endif
	NFCT_CONFIG_POLLINTERVAL,
	NFCT_CONFIG_RELIABLE,
	NFCT_CONFIG_MARK_FILTER,
	NFCT_CONFIG_DESTROY_ONLY,
	NFCT_CONFIG_SOCK_BUFSIZE,
	NFCT_CONFIG_SOCK_MAXBUF,
	NFCT_CONFIG_NAMESPACE,
	NFCT_CONFIG_MAX,
};

static struct nurs_config_def nfct_config = {
	.len     = NFCT_CONFIG_MAX,
	.keys = {
#ifdef NLMMAP
		[NFCT_CONFIG_BLOCK_SIZE] = {
			.name	 = "block_size",
			.type	 = NURS_CONFIG_T_INTEGER,
			.flags   = NURS_CONFIG_F_NONE,
			.integer = 8192,
		},
		[NFCT_CONFIG_BLOCK_NR] = {
			.name	 = "block_nr",
			.type	 = NURS_CONFIG_T_INTEGER,
			.flags   = NURS_CONFIG_F_NONE,
			.integer = 128,
		},
		[NFCT_CONFIG_FRAME_SIZE] = {
			.name	 = "frame_size",
			.type	 = NURS_CONFIG_T_INTEGER,
			.flags   = NURS_CONFIG_F_NONE,
			.integer = 8192,
		},
#endif
		[NFCT_CONFIG_POLLINTERVAL] = {
			.name	 = "pollinterval",
			.type	 = NURS_CONFIG_T_INTEGER,
			.flags	 = NURS_CONFIG_F_NONE,
			.integer = 300,
		},
		[NFCT_CONFIG_RELIABLE] = {
			.name	 = "reliable",
			.type	 = NURS_CONFIG_T_BOOLEAN,
			.flags   = NURS_CONFIG_F_NONE,
			.boolean = false,
		},
		[NFCT_CONFIG_MARK_FILTER] = {
			.name	 = "mark_filter",
			.type	 = NURS_CONFIG_T_STRING,
			.flags   = NURS_CONFIG_F_NONE,
		},
		[NFCT_CONFIG_DESTROY_ONLY] = {
			.name	 = "destroy_only",
			.type	 = NURS_CONFIG_T_BOOLEAN,
			.flags   = NURS_CONFIG_F_NONE,
			.boolean = false,
		},
		[NFCT_CONFIG_SOCK_BUFSIZE] = {
			.name	 = "netlink_socket_buffer_size",
			.type	 = NURS_CONFIG_T_INTEGER,
			.flags   = NURS_CONFIG_F_NONE,
			.integer = 0,
		},
		[NFCT_CONFIG_SOCK_MAXBUF] = {
			.name	 = "netlink_socket_buffer_maxsize",
			.type	 = NURS_CONFIG_T_INTEGER,
			.flags   = NURS_CONFIG_F_NONE,
			.integer = 0,
		},
		[NFCT_CONFIG_NAMESPACE] = {
			.name	 = "namespace",
			.type	 = NURS_CONFIG_T_STRING,
			.flags   = NURS_CONFIG_F_NONE,
			.string	 = "",
		},
	},
};

#ifdef NLMMAP
#define config_block_size(x)	(unsigned int)nurs_config_integer(nurs_producer_config(x), NFCT_CONFIG_BLOCK_SIZE)
#define config_block_nr(x)	(unsigned int)nurs_config_integer(nurs_producer_config(x), NFCT_CONFIG_BLOCK_NR)
#define config_frame_size(x)	(unsigned int)nurs_config_integer(nurs_producer_config(x), NFCT_CONFIG_FRAME_SIZE)
#endif
#define config_pollint(x)	(time_t)nurs_config_integer(nurs_producer_config(x), NFCT_CONFIG_POLLINTERVAL)
#define config_reliable(x)	nurs_config_boolean(nurs_producer_config(x), NFCT_CONFIG_RELIABLE)
#define config_mark_filter(x)	nurs_config_string (nurs_producer_config(x), NFCT_CONFIG_MARK_FILTER)
#define config_destroy_only(x)	nurs_config_boolean(nurs_producer_config(x), NFCT_CONFIG_DESTROY_ONLY)
#define config_nlsockbufsize(x)	nurs_config_integer(nurs_producer_config(x), NFCT_CONFIG_SOCK_BUFSIZE)
#define config_nlsockbufmaxsize(x)	nurs_config_integer(nurs_producer_config(x), NFCT_CONFIG_SOCK_MAXBUF)
#define config_namespace(x)	nurs_config_string(nurs_producer_config(x), NFCT_CONFIG_NAMESPACE)

#include "nfct.keydef"

enum nfct_output_keys {
	NFCT_OUTPUT_ENUM_DEFAULT,
	NFCT_CT,
	NFCT_FLOW_END_REASON,
	NFCT_OUTPUT_MAX,
};

static struct nurs_output_def nfct_output = {
	.len	= NFCT_OUTPUT_MAX,
	.keys	= {
		NFCT_OUTPUT_KEYS_DEFAULT,
		[NFCT_CT]	= {
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_ALWAYS | NURS_OKEY_F_DESTRUCT,
			.name	= "nfct",
			.destructor = (void (*)(void *))nfct_destroy,
		},
		[NFCT_FLOW_END_REASON]	= {
			.type	= NURS_KEY_T_UINT8,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "flow.end.reason",
			.ipfix	= {
				.vendor	  = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_flowEndReason,
			},
		},
	},
};

static int propagate_ct(struct nurs_producer *producer,
			uint32_t type, struct nf_conntrack *ct,
			struct timeval *recent)
{
	struct nurs_output *output = nurs_get_output(producer);
	struct nfct_priv *priv = nurs_producer_context(producer);
	uint64_t ts;
	uint32_t start_sec;

	nurs_output_set_u32(output, NFCT_CT_EVENT, type);
	nurs_output_set_u8(output, NFCT_OOB_FAMILY,
			   nfct_get_attr_u8(ct, ATTR_L3PROTO));

	switch (nfct_get_attr_u8(ct, ATTR_L3PROTO)) {
	case AF_INET:
		nurs_output_set_in_addr(
			output, NFCT_ORIG_IP_SADDR,
			nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC));
		nurs_output_set_in_addr(
			output, NFCT_ORIG_IP_DADDR,
			nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST));
		nurs_output_set_in_addr(
			output, NFCT_REPLY_IP_SADDR,
			nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC));
		nurs_output_set_in_addr(
			output, NFCT_REPLY_IP_DADDR,
			nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST));
		break;
	case AF_INET6:
		nurs_output_set_in6_addr(output, NFCT_ORIG_IP6_SADDR,
					 nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC));
		nurs_output_set_in6_addr(output, NFCT_ORIG_IP6_DADDR,
					 nfct_get_attr(ct, ATTR_ORIG_IPV6_DST));
		nurs_output_set_in6_addr(output, NFCT_REPLY_IP6_SADDR,
					 nfct_get_attr(ct, ATTR_REPL_IPV6_SRC));
		nurs_output_set_in6_addr(output, NFCT_REPLY_IP6_DADDR,
					 nfct_get_attr(ct, ATTR_REPL_IPV6_DST));
		break;
	default:
		nurs_log(NURS_NOTICE, "Unknown protocol family (%d)\n",
			 nfct_get_attr_u8(ct, ATTR_L3PROTO));
	}
	nurs_output_set_u8(output, NFCT_ORIG_IP_PROTOCOL,
			   nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO));
	nurs_output_set_u8(output, NFCT_REPLY_IP_PROTOCOL,
			   nfct_get_attr_u8(ct, ATTR_REPL_L4PROTO));

	switch (nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO)) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_SCTP:
	case IPPROTO_DCCP:
		nurs_output_set_u16(
			output, NFCT_ORIG_L4_SPORT,
			htons(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC)));
		nurs_output_set_u16(
			output, NFCT_ORIG_L4_DPORT,
			htons(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST)));
		break;
	case IPPROTO_ICMP:
		nurs_output_set_u8(output, NFCT_ICMP_CODE,
				   nfct_get_attr_u8(ct, ATTR_ICMP_CODE));
		nurs_output_set_u8(output, NFCT_ICMP_TYPE,
				   nfct_get_attr_u8(ct, ATTR_ICMP_TYPE));
		break;
	}

	switch (nfct_get_attr_u8(ct, ATTR_REPL_L4PROTO)) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_SCTP:
	case IPPROTO_DCCP:
		nurs_output_set_u16(
			output, NFCT_REPLY_L4_SPORT,
			htons(nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC)));
		nurs_output_set_u16(
			output, NFCT_REPLY_L4_DPORT,
			htons(nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST)));
	}

	nurs_output_set_u64(output, NFCT_ORIG_RAW_PKTLEN,
			    nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES));
	nurs_output_set_u64(output, NFCT_ORIG_RAW_PKTCOUNT,
			    nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS));
	nurs_output_set_u64(output, NFCT_REPLY_RAW_PKTLEN,
			    nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_BYTES));
	nurs_output_set_u64(output, NFCT_REPLY_RAW_PKTCOUNT,
			    nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_PACKETS));

	nurs_output_set_u32(output, NFCT_CT_MARK,
			    nfct_get_attr_u32(ct, ATTR_MARK));
	nurs_output_set_u32(output, NFCT_CT_ID,
			    nfct_get_attr_u32(ct, ATTR_ID));

	ts = nfct_get_attr_u64(ct, ATTR_TIMESTAMP_START);
	start_sec = (uint32_t)(ts / NSEC_PER_SEC);
	if (start_sec < priv->dump_prev.tv_sec) {
		nurs_output_set_u32(output, NFCT_FLOW_START_SEC,
				    (uint32_t)priv->dump_prev.tv_sec);
		nurs_output_set_u32(output, NFCT_FLOW_START_USEC,
				    (uint32_t)priv->dump_prev.tv_usec);
	} else {
		nurs_output_set_u32(output, NFCT_FLOW_START_SEC,
				    start_sec);
		nurs_output_set_u32(output, NFCT_FLOW_START_USEC,
				    (uint32_t)(ts % NSEC_PER_SEC / 1000));
	}

	ts = nfct_get_attr_u64(ct, ATTR_TIMESTAMP_STOP);
	if (ts) {
		nurs_output_set_u32(output, NFCT_FLOW_END_SEC,
				    (uint32_t)(ts / NSEC_PER_SEC));
		nurs_output_set_u32(output, NFCT_FLOW_END_USEC,
				    (uint32_t)(ts % NSEC_PER_SEC / 1000));
	} else {
		nurs_output_set_u32(output, NFCT_FLOW_END_SEC,
				    (uint32_t)recent->tv_sec);
		nurs_output_set_u32(output, NFCT_FLOW_END_USEC,
				    (uint32_t)recent->tv_usec);
	}

	nurs_output_set_pointer(output, NFCT_CT, ct);

	if (flowReasons[type])
		nurs_output_set_u8(output, NFCT_FLOW_END_REASON,
				   flowReasons[type]);

	switch (nurs_publish(output)) {
	case NURS_RET_OK:
		return MNL_CB_OK;
	case NURS_RET_STOP:
		nurs_log(NURS_NOTICE, "propagate returns STOP\n");
		return MNL_CB_STOP;
	default:
		nurs_log(NURS_NOTICE, "failed to propagate: %s\n",
			 strerror(errno));
		return MNL_CB_ERROR;
	}
	/* must not reach here */
	return MNL_CB_ERROR;
}

static uint32_t nfct_type(const struct nlmsghdr *nlh)
{
	switch(nlh->nlmsg_type & 0xFF) {
	case IPCTNL_MSG_CT_NEW:
		if (nlh->nlmsg_flags & (NLM_F_CREATE|NLM_F_EXCL))
			return NFCT_T_NEW;
		else
			return NFCT_T_UPDATE;
		break;
	case IPCTNL_MSG_CT_DELETE:
		return NFCT_T_DESTROY;
		break;
	}
	return NFCT_T_UNKNOWN;
}

struct mnl_cbarg {
	struct nurs_producer	*producer;
	struct timeval		*recent;
};

static int mnl_data_cb(const struct nlmsghdr *nlh, void *data)
{
	struct mnl_cbarg *cbarg = data;
	struct nf_conntrack *ct = nfct_new();

	if (!ct) {
		nurs_log(NURS_ERROR, "failed to alloc nf_conntrack: %s\n",
			 strerror(errno));
		return MNL_CB_ERROR;
	}

	if (nfct_nlmsg_parse(nlh, ct)) {
		nurs_log(NURS_ERROR, "nfct_nlmsg_parse: %s\n",
			 strerror(errno));
		nfct_destroy(ct);
		return MNL_CB_ERROR;
	}
	if (!nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES) &&
	    !nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_BYTES)) {
		nfct_destroy(ct);
		return MNL_CB_OK;
	}

	return propagate_ct(cbarg->producer,
			    nfct_type(nlh), ct, cbarg->recent);
}

static int setnlbufsiz(struct mnl_socket *nl, int size)
{
	int fd = mnl_socket_get_fd(nl);
	socklen_t socklen = sizeof(int);

	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, socklen)) {
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, socklen);
	}
	getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, &socklen);

	return size;
}

static int update_bufsize(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	int maxbufsiz = config_nlsockbufmaxsize(producer);
	int size;
	static int warned = 0;

	if (!maxbufsiz && !warned) {
		warned = 1;
		nurs_log(NURS_NOTICE,
			 "We are losing events. Please, "
			 "consider using the clauses "
			 "`event_buffer_size' and "
			 "`event_buffer_maxsize'\n");
		return 0;
	}

	size = priv->event_bufsize * 2;
	if (size > maxbufsiz) {
		if (warned)
			return 0;
		warned = 1;
		nurs_log(NURS_NOTICE,
			 "Maximum buffer size (%d) in NFCT has been "
			 "reached. Please, consider rising "
			 "`event_buffer_size` and "
			 "`event_buffer_maxsize` "
			 "clauses.\n", priv->event_bufsize);
		return 0;
	}
	priv->event_bufsize = setnlbufsiz(priv->event_nl, size);
	nurs_log(NURS_NOTICE, "update bufsize to: %d\n", priv->event_bufsize);
	return 1;
}

static enum nurs_return_t
nfct_event_cb(int fd, uint16_t when, void *data)
{
	struct nurs_producer *producer = data;
	struct nfct_priv *priv = nurs_producer_context(producer);
	char buf[MNL_SOCKET_BUFFER_SIZE];
	ssize_t nrecv;
	int ret;
	struct mnl_cbarg cbarg = {
		.producer	= producer,
		.recent		= NULL
	};

	if (!(when & NURS_FD_F_READ))
		return NURS_RET_OK;

	/* recv(mnl_socket_get_fd(priv->event_nl), buf, len, MSG_DONTWAIT); */
	nrecv = mnl_socket_recvfrom(priv->event_nl, buf, sizeof(buf));
	if (nrecv == -1) {
		if (errno == ENOBUFS) {
			update_bufsize(producer);
		} else {
			nurs_log(NURS_ERROR, "recv: %s\n",
				 strerror(errno));
		}
		return NURS_RET_ERROR;
	}

	ret = mnl_cb_run(buf, (size_t)nrecv, 0,
			 priv->event_pid, mnl_data_cb, &cbarg);
	if (ret == MNL_CB_ERROR) {
		nurs_log(NURS_ERROR, "mnl_cb_run: [%d]%s\n",
			 errno, strerror(errno));
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static enum nurs_return_t nurs_ret_from_mnl(int rc)
{
        switch (rc) {
        case MNL_CB_OK: return NURS_RET_OK;
        case MNL_CB_STOP: return NURS_RET_STOP;
        case MNL_CB_ERROR:
		nurs_log(NURS_ERROR, "mnl_cb_run: [%d]%s\n",
			 errno, strerror(errno));
		return NURS_RET_ERROR;
        default:
                nurs_log(NURS_ERROR, "mnl_cb_run - unknown code: %d\n", rc);
                return NURS_RET_ERROR;
        }

        return NURS_RET_ERROR;
}

static enum nurs_return_t
handle_copy_frame(int fd, void *arg)
{
	struct mnl_cbarg *cbarg = arg;
	struct nfct_priv *priv = nurs_producer_context(cbarg->producer);
        char buf[MNL_SOCKET_BUFFER_SIZE];
        ssize_t nrecv;

        nrecv = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (nrecv == -1) {
                nurs_log(NURS_ERROR, "failed to recv COPY frame: %s\n",
                         strerror(errno));
                return NURS_RET_ERROR;
        }

        return nurs_ret_from_mnl(
                mnl_cb_run(buf, (size_t)nrecv,
                           priv->dump_request->nlmsg_seq, priv->dump_pid,
                           mnl_data_cb, cbarg));
}

#ifdef NLMMAP
static enum nurs_return_t
handle_valid_frame(struct nl_mmap_hdr *frame, void *arg)
{
	struct mnl_cbarg *cbarg = arg;
        struct nfct_priv *priv = nurs_producer_context(cbarg->producer);

	if (!frame->nm_len) {
		/* an error may occured in kernel */
		return NURS_RET_OK;
	}

        return nurs_ret_from_mnl(
                mnl_cb_run(MNL_FRAME_PAYLOAD(frame), frame->nm_len,
                           priv->dump_request->nlmsg_seq, priv->dump_pid,
                           mnl_data_cb, cbarg));
}

static enum nurs_return_t
nfct_dump_cb(int fd, uint16_t when, void *data)
{
	struct nurs_producer *producer = data;
	struct nfct_priv *priv = nurs_producer_context(producer);
	struct timeval tv;
	enum nurs_return_t ret;
        struct mnl_cbarg cbarg = {
                .producer	= producer,
                .recent		= &tv,
        };

	if (!(when & NURS_FD_F_READ))
		return NURS_RET_OK;

	gettimeofday(&tv, NULL);
        do {
                ret = mnl_ring_cb_run(priv->nlr,
                                      handle_valid_frame, handle_copy_frame,
                                      &cbarg);
        } while (ret == NURS_RET_OK);

	priv->dump_prev = tv;
        if (ret == NURS_RET_STOP)
                return NURS_RET_OK;
	return ret;
}
#else
static enum nurs_return_t
nfct_dump_cb(int fd, uint16_t when, void *data)
{
	struct nurs_producer *producer = data;
	struct nfct_priv *priv = nurs_producer_context(producer);
	struct timeval tv;
	enum nurs_return_t ret;
        struct mnl_cbarg cbarg = {
                .producer	= producer,
                .recent		= &tv,
        };

	if (!(when & NURS_FD_F_READ))
		return NURS_RET_OK;

	gettimeofday(&tv, NULL);
        do {
                ret = handle_copy_frame(fd, &cbarg);
        } while (ret == NURS_RET_OK);

	priv->dump_prev = tv;
        if (ret == NURS_RET_STOP)
                return NURS_RET_OK;
	return ret;
}
#endif

static int clear_counters(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	struct mnl_socket *nl;
	ssize_t nrecv;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int ret;

	nl = nurs_mnl_socket(config_namespace(producer), NETLINK_NETFILTER);
	if (!nl) {
		nurs_log(NURS_ERROR, "failed to create socket: %s\n",
			 strerror(errno));
		return -1;
	}

	if (mnl_socket_sendto(nl, priv->dump_request,
			      priv->dump_request->nlmsg_len) == -1) {
		mnl_socket_close(nl);
		return -1;
	}
	/* below is needed for even just clearing counters */
	do {
		nrecv = mnl_socket_recvfrom(nl, buf, sizeof(buf));
		if (nrecv == -1) {
			mnl_socket_close(nl);
			return -1;
		}
		ret = mnl_cb_run(buf, (size_t)nrecv, 0,
				 priv->dump_pid, NULL, NULL);
	} while (ret == MNL_CB_OK);

	mnl_socket_close(nl);
	if (ret == MNL_CB_ERROR) {
		nurs_log(NURS_ERROR, "mnl_cb_run: %s\n", strerror(errno));
		return -1;
	}

	gettimeofday(&priv->dump_prev, NULL);

	return 0;
}

static enum nurs_return_t nfct_itimer_cb(struct nurs_timer *t, void *data)
{
	struct nurs_producer *producer = data;
	struct nfct_priv *priv = nurs_producer_context(producer);
	ssize_t ret;

	priv->dump_request->nlmsg_seq = (uint32_t)time(NULL);
	ret = mnl_socket_sendto(priv->dump_nl, priv->dump_request,
				priv->dump_request->nlmsg_len);
	if (ret == -1) {
		nurs_log(NURS_ERROR, "mnl_socket_sendto: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}
	return NURS_RET_OK;
}

static struct nlmsghdr *create_dump_request(uint32_t mark, uint32_t mask)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *ret, *nlh = mnl_nlmsg_put_header(buf);
	struct nfgenmsg *nfh;

	nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) |
		IPCTNL_MSG_CT_GET_CTRZERO;
	nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_DUMP;

	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = AF_UNSPEC;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	if (mark && mask) {
		mnl_attr_put_u32(nlh, CTA_MARK, htonl(mark));
		mnl_attr_put_u32(nlh, CTA_MARK_MASK, htonl(mask));
	}

	ret = calloc(1, nlh->nlmsg_len);
	if (!ret)
		return NULL;
	memcpy(ret, nlh, nlh->nlmsg_len);

	return ret;
}

static int create_mark_filter(const struct nurs_producer *producer,
			      struct nfct_filter *filter)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	uintmax_t v;
	const char *p;
	char *endptr;
	const char *filter_string = config_mark_filter(producer);
	struct nfct_filter_dump_mark attr;

	if (!strlen(filter_string)) {
		priv->dump_request = create_dump_request(0, 0);
		return 0;
	}

	errno = 0;
	for (p = filter_string; isspace(*p); ++p)
		;
	v = strtoumax(p, &endptr, 0);
	if (endptr == p)
		goto invalid_error;
	if ((errno == ERANGE && v == UINTMAX_MAX) || errno)
		goto invalid_error;
	attr.val = (uint32_t)v;

	if (*endptr != '\0') {
		for (p = endptr; isspace(*p); ++p)
			;
		if (*p++ != '/')
			goto invalid_error;
		for (; isspace(*p); ++p)
			;
		v = strtoumax(p, &endptr, 0);
		if (endptr == p)
			goto invalid_error;
		if ((errno == ERANGE && v == UINTMAX_MAX) || errno)
			goto invalid_error;
		attr.mask = (uint32_t)v;
		if (*endptr != '\0')
			goto invalid_error;
	} else {
		attr.mask = UINT32_MAX;
	}

	priv->dump_request = create_dump_request(attr.val, attr.mask);
	if (!priv->dump_request) {
		nurs_log(NURS_ERROR, "alloc_init_dump_request\n");
		return -1;
	}

	nfct_filter_add_attr(filter, NFCT_FILTER_MARK, &attr);
	nurs_log(NURS_NOTICE, "adding mark to event filter: \"%u/%u\"\n",
		 attr.val, attr.mask);

	return 0;

invalid_error:
	nurs_log(NURS_ERROR, "invalid val/mask %s\n", filter_string);
	return -1;
}

static int attach_filter(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	struct nfct_filter *filter = NULL;

	filter = nfct_filter_create();
	if (!filter) {
		nurs_log(NURS_FATAL, "error creating NFCT filter\n");
		goto err_init;
	}

	if (create_mark_filter(producer, filter)) {
		nurs_log(NURS_FATAL, "Unable to create mark filter\n");
		goto err_filter;
	}

	if (nfct_filter_attach(mnl_socket_get_fd(priv->event_nl), filter) == -1) {
		nurs_log(NURS_FATAL, "nfct_filter_attach");
		goto err_filter;
	}

	/* release the filter object, this does not detach the filter */
	nfct_filter_destroy(filter);

	return 0;

err_filter:
	nfct_filter_destroy(filter);
err_init:
	return -1;
}

static int open_event_socket(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);

	priv->event_nl = nurs_mnl_socket(config_namespace(producer),
					 NETLINK_NETFILTER);
	if (!priv->event_nl) {
		nurs_log(NURS_ERROR, "failed to create socket: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}

	if (mnl_socket_bind(priv->event_nl,
			    NF_NETLINK_CONNTRACK_DESTROY,
			    MNL_SOCKET_AUTOPID) == -1) {
		nurs_log(NURS_ERROR, "mnl_sockt_bind: %s\n",
			 strerror(errno));
		goto error_close;
	}
	priv->event_pid = mnl_socket_get_portid(priv->event_nl);

	if (config_reliable(producer)) {
		if (mnl_socket_set_reliable(priv->event_nl)) {
			nurs_log(NURS_ERROR, "mnl_socket_set_reliable: %s\n",
				 strerror(errno));
			goto error_close;
		}
	}

	priv->event_fd = nurs_fd_create(mnl_socket_get_fd(priv->event_nl),
					NURS_FD_F_READ);
	if (!priv->event_fd)
		goto error_close;

	return NURS_RET_OK;

error_close:
	mnl_socket_close(priv->event_nl);
	return NURS_RET_ERROR;
}

#ifdef NLMMAP
static int mmap_dump_socket(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	struct nl_mmap_req req = {
		.nm_block_size	= config_block_size(producer),
		.nm_block_nr	= config_block_nr(producer),
		.nm_frame_size	= config_frame_size(producer),
		.nm_frame_nr	= config_block_size(producer)
				  / config_frame_size(producer)
				  * config_block_nr(producer),
	};
	priv->nlr = mnl_socket_rx_mmap(priv->dump_nl, &req, MAP_SHARED);
	if (!priv->nlr) {
		nurs_log(NURS_FATAL, "mnl_socket_mmap: %s\n",
			 strerror(errno));
                return -1;
	}

        return 0;
}
#else
static int mmap_dump_socket(const struct nurs_producer *producer)
{
        return 0;
}
#endif

static int open_dump_socket(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	priv->dump_nl = nurs_mnl_socket(config_namespace(producer),
					NETLINK_NETFILTER);
	if (!priv->dump_nl) {
		nurs_log(NURS_ERROR, "failed to create socket: %s\n",
			 strerror(errno));
		goto error_close;
	}

        if (mmap_dump_socket(producer))
                goto error_close;

	if (mnl_socket_bind(priv->dump_nl, 0, MNL_SOCKET_AUTOPID) == -1) {
		nurs_log(NURS_ERROR, "mnl_sockt_bind: %s\n",
			 strerror(errno));
		goto error_unmap;
	}
	priv->dump_pid = mnl_socket_get_portid(priv->dump_nl);

	if (config_reliable(producer)) {
		if (mnl_socket_set_reliable(priv->dump_nl)) {
			nurs_log(NURS_ERROR, "set_reliable: %s\n",
				 strerror(errno));
			goto error_unmap;
		}
	}

	priv->dump_fd = nurs_fd_create(mnl_socket_get_fd(priv->dump_nl),
				       NURS_FD_F_READ);
	if (!priv->dump_fd)
		goto error_unmap;

	return NURS_RET_OK;

error_unmap:
	mnl_socket_unmap(priv->nlr);
error_close:
	mnl_socket_close(priv->dump_nl);
	return NURS_RET_ERROR;
}

static enum nurs_return_t nfct_organize(struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	int event_bufsiz, event_bufmax;
	socklen_t socklen = sizeof(int);

	if (open_event_socket(producer))
		return NURS_RET_ERROR;
	if (attach_filter(producer)) {
		nurs_log(NURS_FATAL, "error creating NFCT filter\n");
		goto error_close_event;
	}

	if (!config_destroy_only(producer)) {
		if (clear_counters(producer) == -1) {
			nurs_log(NURS_ERROR, "could not clear counters: %s\n",
				 strerror(errno));
			goto error_close_event;
		}
	}

	event_bufsiz = config_nlsockbufsize(producer);
	event_bufmax = config_nlsockbufmaxsize(producer);
	if (event_bufsiz) {
		if (event_bufsiz > event_bufmax) {
			nurs_log(NURS_INFO, "set event buffer size to: %d\n",
				 event_bufsiz);
			event_bufsiz = event_bufmax;
		}
		priv->event_bufsize = setnlbufsiz(priv->event_nl, event_bufsiz);
	} else {
		getsockopt(mnl_socket_get_fd(priv->event_nl),
			   SOL_SOCKET, SO_RCVBUF,
			   &priv->event_bufsize, &socklen);
	}

	if (config_destroy_only(producer))
		return NURS_RET_OK;

	if (open_dump_socket(producer))
		goto error_close_event;

	priv->timer = nurs_timer_create(&nfct_itimer_cb, producer);
	if (!priv->timer) {
		nurs_log(NURS_ERROR, "nurs_timer_create: %s\n",
			 strerror(errno));
		goto error_close_dump;
	}

	return NURS_RET_OK;

error_close_dump:
	mnl_socket_unmap(priv->nlr);
	mnl_socket_close(priv->dump_nl);
error_close_event:
	mnl_socket_close(priv->event_nl);

	return NURS_RET_ERROR;
}

static enum nurs_return_t nfct_disorganize(struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);

	if (!config_destroy_only(producer)) {
		nurs_timer_destroy(priv->timer);
		nurs_fd_destroy(priv->dump_fd);
		mnl_socket_unmap(priv->nlr);
		mnl_socket_close(priv->dump_nl);
	}

	free(priv->dump_request);
	nurs_fd_destroy(priv->event_fd);
	mnl_socket_close(priv->event_nl);

	return NURS_RET_OK;
}

static enum nurs_return_t nfct_start(struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	time_t interval = config_pollint(producer);

	if (nurs_fd_register(priv->event_fd, nfct_event_cb, producer)) {
		nurs_log(NURS_ERROR, "nurs_fd_register failed: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}

	if (config_destroy_only(producer))
		return NURS_RET_OK;

	if (nurs_fd_register(priv->dump_fd, nfct_dump_cb, producer)) {
		nurs_log(NURS_ERROR, "nurs_register_fd: %s\n",
			 strerror(errno));
		goto error_unregister_event;
	}

	if (nurs_itimer_add(priv->timer, interval, interval)) {
		nurs_log(NURS_ERROR, "nurs_add_itimer: %s\n",
			 strerror(errno));
		goto error_unregister_dump;
	}

	return NURS_RET_OK;

error_unregister_dump:
	nurs_fd_unregister(priv->dump_fd);
error_unregister_event:
	nurs_fd_unregister(priv->event_fd);

	return NURS_RET_ERROR;
}

static enum nurs_return_t nfct_stop(struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	int ret = NURS_RET_OK;

	if (!config_destroy_only(producer)) {
		if (nurs_timer_del(priv->timer)) {
			nurs_log(NURS_ERROR, "nurs_del_timer: %s\n",
				 strerror(errno));
			ret = NURS_RET_ERROR;
		}
		if (nurs_fd_unregister(priv->dump_fd)) {
			nurs_log(NURS_ERROR, "nurs_fd_unregister: %s\n",
				 strerror(errno));
			ret = NURS_RET_ERROR;
		}
	}
	if (nurs_fd_unregister(priv->event_fd)) {
		nurs_log(NURS_ERROR, "nurs_fd_unregister: %s\n",
			 strerror(errno));
		ret = NURS_RET_ERROR;
	}

	return ret;
}

static enum nurs_return_t
nfct_signal(struct nurs_producer *producer, uint32_t signal)
{
	switch (signal) {
	default:
		nurs_log(NURS_DEBUG, "receive signal: %d\n", signal);
		break;
	}
	return NURS_RET_OK;
}

static struct nurs_producer_def nfct_producer = {
	.version	= VERSION,
	.name		= "NFCT2",
	.context_size	= sizeof(struct nfct_priv),
	.config_def 	= &nfct_config,
	.output_def	= &nfct_output,
	.organize	= &nfct_organize,
	.disorganize	= &nfct_disorganize,
	.start		= &nfct_start,
	.stop		= &nfct_stop,
	.signal		= &nfct_signal,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	nurs_producer_register(&nfct_producer);
}

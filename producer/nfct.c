/* nurs_input_NFCT.c, Version $Revision$
 *
 * nurs input plugin for ctnetlink
 *
 * (C) 2005 by Harald Welte <laforge@netfilter.org>
 * (C) 2008-2010 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2016 by Ken-ichirou MATSUZAWA <chamas@h4.dion.ne.jp>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * 10 Jan 2005, Christian Hentschel <chentschel@people.netfilter.org>
 *      Added timestamp accounting support of the conntrack entries,
 *      reworked by Harald Welte.
 *
 * 11 May 2008, Pablo Neira Ayuso <pablo@netfilter.org>
 * 	Use a generic hashtable to store the existing flows
 * 	Add netlink overrun handling
 *
 * TODO:
 * 	- add nanosecond-accurate packet receive timestamp of event-changing
 * 	  packets to {ip,nf}_conntrack_netlink, so we can have accurate IPFIX
 *	  flowStart / flowEnd NanoSeconds.
 *	- SIGHUP for reconfiguration without loosing hash table contents, but
 *	  re-read of config and reallocation / rehashing of table, if required
 *	- Split hashtable code into separate [filter] plugin, so we can run
 * 	  small non-hashtable nurs installations on the firewall boxes, send
 * 	  the messages via IPFX to one aggregator who then runs nurs with a
 * 	  network wide connection hash table.
 */
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <nurs/nurs.h>
#include <nurs/list.h>
#include <nurs/ipfix_protocol.h>

#include "nfct_jhash.h"
#include "nfct_hash.h"


#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC    1000000000L
#endif

typedef enum TIMES_ { START, STOP, __TIME_MAX } TIMES;

struct ct_timestamp {
	struct hashtable_node hashnode;
	struct timeval time[__TIME_MAX];
	struct nf_conntrack *ct;
};

struct nfct_priv {
	struct nfct_handle *cth;
	struct nfct_handle *ovh;	/* overrun handler */
	struct nfct_handle *pgh;	/* purge handler */
	struct nurs_fd *nfct_fd;
	struct nurs_fd *nfct_ov;
	struct nurs_timer *timer;
	struct nurs_timer *ov_timer;	/* overrun retry timer */
	struct hashtable *ct_active;
	unsigned int nlbufsiz;		/* current netlink buffer size */
	struct nfct_filter_dump *filter_dump;
};

#define HTABLE_SIZE	(8192)
#define MAX_ENTRIES	(4 * HTABLE_SIZE)
#define EVENT_MASK	NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_DESTROY

enum {
	NFCT_CONFIG_POLLINTERVAL,
	NFCT_CONFIG_HASH_ENABLE,
	NFCT_CONFIG_HASH_BUCKETS,
	NFCT_CONFIG_HASH_MAX,
	NFCT_CONFIG_EVENT_MASK,
	NFCT_CONFIG_SOCK_BUFSIZE,
	NFCT_CONFIG_SOCK_MAXBUF,
	NFCT_CONFIG_RESYNC_TIMEOUT,
	NFCT_CONFIG_RELIABLE,
	NFCT_CONFIG_MARK_FILTER,
	NFCT_CONFIG_MAX,
};

static struct nurs_config_def nfct_config = {
	.len		= NFCT_CONFIG_MAX,
	.keys	= {
		[NFCT_CONFIG_POLLINTERVAL] = {
			.name	 = "pollinterval",
			.type	 = NURS_CONFIG_T_INTEGER,
		},
		[NFCT_CONFIG_HASH_ENABLE] = {
			.name	 = "hash_enable",
			.type	 = NURS_CONFIG_T_BOOLEAN,
			.boolean = true,
		},
		[NFCT_CONFIG_HASH_BUCKETS] = {
			.name	 = "hash_buckets",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = HTABLE_SIZE,
		},
		[NFCT_CONFIG_HASH_MAX] = {
			.name	 = "hash_max_entries",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = MAX_ENTRIES,
		},
		[NFCT_CONFIG_EVENT_MASK] = {
			.name	 = "event_mask",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = EVENT_MASK,
		},
		[NFCT_CONFIG_SOCK_BUFSIZE] = {
			.name	 = "netlink_socket_buffer_size",
			.type	 = NURS_CONFIG_T_INTEGER,
		},
		[NFCT_CONFIG_SOCK_MAXBUF] = {
			.name	 = "netlink_socket_buffer_maxsize",
			.type	 = NURS_CONFIG_T_INTEGER,
		},
		[NFCT_CONFIG_RESYNC_TIMEOUT] = {
			.name	 = "netlink_resync_timeout",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 60,
		},
		[NFCT_CONFIG_RELIABLE] = {
			.name	 = "reliable",
			.type	 = NURS_CONFIG_T_BOOLEAN,
		},
		[NFCT_CONFIG_MARK_FILTER] = {
			.name	 = "accept_mark_filter",
			.type	 = NURS_CONFIG_T_STRING,
		},
	},
};

#define config_pollint(x)	nurs_config_integer(nurs_producer_config(x), NFCT_CONFIG_POLLINTERVAL)
#define config_usehash(x)	nurs_config_boolean(nurs_producer_config(x), NFCT_CONFIG_HASH_ENABLE)
#define config_buckets(x)	(uint32_t)nurs_config_integer(nurs_producer_config(x), NFCT_CONFIG_HASH_BUCKETS)
#define config_maxentries(x) 	(uint32_t)nurs_config_integer(nurs_producer_config(x), NFCT_CONFIG_HASH_MAX)
#define config_eventmask(x) 	(unsigned int)nurs_config_integer(nurs_producer_config(x), NFCT_CONFIG_EVENT_MASK)
#define config_nlsockbufsize(x)	(unsigned int)nurs_config_integer(nurs_producer_config(x), NFCT_CONFIG_SOCK_BUFSIZE)
#define config_nlsockbufmaxsize(x)	(unsigned int)nurs_config_integer(nurs_producer_config(x), NFCT_CONFIG_SOCK_MAXBUF)
#define config_nlresynctimeout(x)	nurs_config_integer(nurs_producer_config(x), NFCT_CONFIG_RESYNC_TIMEOUT)
#define config_reliable(x)	nurs_config_boolean(nurs_producer_config(x), NFCT_CONFIG_RELIABLE)
#define config_mark_filter(x)	nurs_config_string(nurs_producer_config(x), NFCT_CONFIG_MARK_FILTER)

#include "nfct.keydef"

enum nfct_output_keys {
	NFCT_OUTPUT_ENUM_DEFAULT,
	NFCT_OOB_PROTOCOL,
	NFCT_CT,
	NFCT_DESTROY_CT,
	NFCT_OUTPUT_MAX,
};

static struct nurs_output_def nfct_output = {
	.len	= NFCT_OUTPUT_MAX,
	.keys	= {
		NFCT_OUTPUT_KEYS_DEFAULT,
		[NFCT_OOB_PROTOCOL]	= {
			.type	= NURS_KEY_T_UINT8,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "oob.protocol",
		},
		[NFCT_CT]	= {
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_ALWAYS,
			.name	= "nfct",
		},
		[NFCT_DESTROY_CT] = {
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_OPTIONAL | NURS_OKEY_F_DESTRUCT,
			.name	= "ct.destroy",
			.destructor = (void (*)(void *))nfct_destroy,
		},
	},
};

static uint32_t
__hash4(const struct nf_conntrack *ct, const struct hashtable *table)
{
	unsigned int a, b;

	a = jhash(nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC), sizeof(uint32_t),
		  (((uint32_t)nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO) << 16) |
		   (nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO))));

	b = jhash(nfct_get_attr(ct, ATTR_ORIG_IPV4_DST), sizeof(uint32_t),
		  (((uint32_t)nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC) << 16) |
		   (nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST))));

	/*
	 * Instead of returning hash % table->hashsize (implying a divide)
	 * we return the high 32 bits of the (hash * table->hashsize) that will
	 * give results between [0 and hashsize-1] and same hash distribution,
	 * but using a multiply, less expensive than a divide. See:
	 * http://www.mail-archive.com/netdev@vger.kernel.org/msg56623.html
	 */
	return (uint32_t)(((uint64_t)jhash_2words(a, b, 0) * table->hashsize) >> 32);
}

static uint32_t
__hash6(const struct nf_conntrack *ct, const struct hashtable *table)
{
	unsigned int a, b;

	a = jhash(nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC), sizeof(uint32_t)*4,
		  (((uint32_t)nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO) << 16) |
		   (nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO))));

	b = jhash(nfct_get_attr(ct, ATTR_ORIG_IPV6_DST), sizeof(uint32_t)*4,
		  (((uint32_t)nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC) << 16) |
		   (nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST))));

	return (uint32_t)(((uint64_t)jhash_2words(a, b, 0) * table->hashsize) >> 32);
}

static uint32_t hash(const void *data, const struct hashtable *table)
{
	uint32_t ret = 0;
	const struct nf_conntrack *ct = data;

	switch(nfct_get_attr_u8(ct, ATTR_L3PROTO)) {
		case AF_INET:
			ret = __hash4(ct, table);
			break;
		case AF_INET6:
			ret = __hash6(ct, table);
			break;
		default:
			break;
	}

	return ret;
}

static int compare(const void *data1, const void *data2)
{
	const struct ct_timestamp *u1 = data1;
	const struct nf_conntrack *ct = data2;

	return nfct_cmp(u1->ct, ct, NFCT_CMP_ORIG | NFCT_CMP_REPL);
}

/* only the main_producer plugin instance contains the correct private data. */
static int propagate_ct(struct nurs_producer *producer,
			struct nf_conntrack *ct,
			struct nf_conntrack *destroy_ct,
			uint32_t type,
			struct ct_timestamp *ts)
{
	struct nurs_output *output = nurs_get_output(producer);

	nurs_output_set_u32(output, NFCT_CT_EVENT, type);
	nurs_output_set_u8(output, NFCT_OOB_FAMILY, nfct_get_attr_u8(ct, ATTR_L3PROTO));
	nurs_output_set_u8(output, NFCT_OOB_PROTOCOL, 0); /* FIXME */

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
		nurs_output_set_in6_addr(
			output, NFCT_ORIG_IP6_SADDR,
			nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC));
		nurs_output_set_in6_addr(
			output, NFCT_ORIG_IP6_DADDR,
			nfct_get_attr(ct, ATTR_ORIG_IPV6_DST));
		nurs_output_set_in6_addr(
			output, NFCT_REPLY_IP6_SADDR,
			nfct_get_attr(ct, ATTR_REPL_IPV6_SRC));
		nurs_output_set_in6_addr(
			output, NFCT_REPLY_IP6_DADDR,
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
		nurs_output_set_u16(output, NFCT_ORIG_L4_SPORT,
			     htons(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC)));
		nurs_output_set_u16(output, NFCT_ORIG_L4_DPORT,
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
		nurs_output_set_u16(output, NFCT_REPLY_L4_SPORT,
			     htons(nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC)));
		nurs_output_set_u16(output, NFCT_REPLY_L4_DPORT,
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

	nurs_output_set_u32(output, NFCT_CT_MARK, nfct_get_attr_u32(ct, ATTR_MARK));
	nurs_output_set_u32(output, NFCT_CT_ID, nfct_get_attr_u32(ct, ATTR_ID));

	if (ts) {
		if (ts->time[START].tv_sec) {
			nurs_output_set_u32(output, NFCT_FLOW_START_SEC,
					    (uint32_t)ts->time[START].tv_sec);
			nurs_output_set_u32(output, NFCT_FLOW_START_USEC,
					    (uint32_t)ts->time[START].tv_usec);
		}
		if (ts->time[STOP].tv_sec) {
			nurs_output_set_u32(output, NFCT_FLOW_END_SEC,
					    (uint32_t)ts->time[STOP].tv_sec);
			nurs_output_set_u32(output, NFCT_FLOW_END_USEC,
					    (uint32_t)ts->time[STOP].tv_usec);
		}
	}
	nurs_output_set_pointer(output, NFCT_CT, ct);
	nurs_output_set_pointer(output, NFCT_DESTROY_CT, destroy_ct);
	nurs_propagate(producer, output);

	return 0;
}

static int set_timestamp_from_ct_try(struct ct_timestamp *ts,
				     struct nf_conntrack *ct, int name)
{
	int attr_name;

	if (name == START)
		attr_name = ATTR_TIMESTAMP_START;
	else
		attr_name = ATTR_TIMESTAMP_STOP;

	if (nfct_attr_is_set(ct, attr_name)) {
		ts->time[name].tv_sec = (time_t)
			nfct_get_attr_u64(ct, attr_name) / NSEC_PER_SEC;
		ts->time[name].tv_usec = (suseconds_t)
			(nfct_get_attr_u64(ct, attr_name) % NSEC_PER_SEC) / 1000;
		return 1;
	}
	return 0;
}

static void set_timestamp_from_ct(struct ct_timestamp *ts,
				   struct nf_conntrack *ct, int name)
{
	if (!set_timestamp_from_ct_try(ts, ct, name))
		gettimeofday(&ts->time[name], NULL);
}

static int
event_handler_hashtable(enum nf_conntrack_msg_type type,
			struct nf_conntrack *ct, void *data)
{
	struct nurs_producer *producer = data;
	struct nfct_priv *priv = nurs_producer_context(producer);
	struct ct_timestamp *ts;
	uint32_t id;
	int ret;

	switch(type) {
	case NFCT_T_NEW:
		ts = calloc(sizeof(struct ct_timestamp), 1);
		if (ts == NULL) {
			nurs_log(NURS_ERROR, "failed to alloc timestamp: %s\n",
				 strerror(errno));
			return NFCT_CB_CONTINUE;
		}
		ts->ct = ct;

		set_timestamp_from_ct(ts, ct, START);
		id = hashtable_hash(priv->ct_active, ct);
		ret = hashtable_add(priv->ct_active, &ts->hashnode, id);
		if (ret < 0) {
			nurs_log(NURS_ERROR, "failed to add to hashtable\n");
			free(ts);
			return NFCT_CB_CONTINUE;
		}
		return NFCT_CB_STOLEN;
	case NFCT_T_UPDATE:
		id = hashtable_hash(priv->ct_active, ct);
		ts = (struct ct_timestamp *)
			hashtable_find(priv->ct_active, ct, id);
		if (ts)
			nfct_copy(ts->ct, ct, NFCT_CP_META);
		else {
			ts = calloc(sizeof(struct ct_timestamp), 1);
			if (ts == NULL) {
				nurs_log(NURS_ERROR, "failed to alloc"
					 " timestamp: %s\n", strerror(errno));
				return NFCT_CB_CONTINUE;
			}
			ts->ct = ct;
			set_timestamp_from_ct(ts, ct, START);
			ret = hashtable_add(priv->ct_active, &ts->hashnode, id);
			if (ret < 0) {
				nurs_log(NURS_ERROR, "failed to add"
					 " hashtable\n");
				free(ts);
				return NFCT_CB_CONTINUE;
			}
			return NFCT_CB_STOLEN;
		}
		break;
	case NFCT_T_DESTROY:
		id = hashtable_hash(priv->ct_active, ct);
		ts = (struct ct_timestamp *)
			hashtable_find(priv->ct_active, ct, id);
		if (ts) {
			set_timestamp_from_ct(ts, ct, STOP);
			propagate_ct(producer, ct, ts->ct, type, ts);
			hashtable_del(priv->ct_active, &ts->hashnode);
			free(ts);
		} else {
			struct ct_timestamp tmp = {
				.ct = ct,
			};
			set_timestamp_from_ct(&tmp, ct, STOP);
			if (!set_timestamp_from_ct_try(&tmp, ct, START)) {
				tmp.time[START].tv_sec = 0;
				tmp.time[START].tv_usec = 0;
			}
			propagate_ct(producer, ct, NULL, type, &tmp);
		}
		break;
	default:
		nurs_log(NURS_NOTICE, "unknown netlink message type\n");
		break;
	}

	return NFCT_CB_CONTINUE;
}

static int
event_handler_no_hashtable(enum nf_conntrack_msg_type type,
			   struct nf_conntrack *ct, void *data)
{
	struct nurs_producer *producer = data;
	struct ct_timestamp tmp = {
		.ct = ct,
	};

	switch(type) {
	case NFCT_T_NEW:
		set_timestamp_from_ct(&tmp, ct, START);
		tmp.time[STOP].tv_sec = 0;
		tmp.time[STOP].tv_usec = 0;
		break;
	case NFCT_T_DESTROY:
		set_timestamp_from_ct(&tmp, ct, STOP);
		if (!set_timestamp_from_ct_try(&tmp, ct, START)) {
			tmp.time[START].tv_sec = 0;
			tmp.time[START].tv_usec = 0;
		}
		break;
	default:
		nurs_log(NURS_NOTICE, "unsupported message type\n");
		return NFCT_CB_CONTINUE;
	}
	propagate_ct(producer, ct, ct, type, &tmp);
	return NFCT_CB_STOLEN;
}

static int
polling_handler(enum nf_conntrack_msg_type type,
		struct nf_conntrack *ct, void *data)
{
	struct nurs_producer *producer = data;
	struct nfct_priv *priv = nurs_producer_context(producer);
	struct ct_timestamp *ts;
	uint32_t id;
	int ret;

	switch(type) {
	case NFCT_T_UPDATE:
		id = hashtable_hash(priv->ct_active, ct);
		ts = (struct ct_timestamp *)
			hashtable_find(priv->ct_active, ct, id);
		if (ts)
			nfct_copy(ts->ct, ct, NFCT_CP_META);
		else {
			ts = calloc(sizeof(struct ct_timestamp), 1);
			if (ts == NULL) {
				nurs_log(NURS_ERROR, "failed to alloc"
					 " timestamp: %s\n", strerror(errno));
				return NFCT_CB_CONTINUE;
			}

			ts->ct = ct;
			set_timestamp_from_ct(ts, ct, START);

			ret = hashtable_add(priv->ct_active, &ts->hashnode, id);
			if (ret < 0) {
				nurs_log(NURS_ERROR, "failed to add"
					 " hashtable\n");
				free(ts);
				return NFCT_CB_CONTINUE;
			}
			return NFCT_CB_STOLEN;
		}
		break;
	default:
		nurs_log(NURS_NOTICE, "unknown netlink message type\n");
		break;
	}

	return NFCT_CB_CONTINUE;
}

static int setnlbufsiz(const struct nurs_producer *producer, unsigned int size)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	static int warned = 0;

	if (size < config_nlsockbufmaxsize(producer)) {
		priv->nlbufsiz = nfnl_rcvbufsiz(nfct_nfnlh(priv->cth), size);
		return 1;
	}

	/* we have already warned the user, do not keep spamming */
	if (warned)
		return 0;

	warned = 1;
	nurs_log(NURS_NOTICE, "Maximum buffer size (%d) in NFCT has been "
		 "reached. Please, consider rising "
		 "`netlink_socket_buffer_size` and "
		 "`netlink_socket_buffer_maxsize` "
		 "clauses.\n", priv->nlbufsiz);
	return 0;
}

static int read_cb_nfct(int fd, uint16_t when, void *data)
{
	struct nurs_producer *producer = data;
	struct nfct_priv *priv = nurs_producer_context(producer);
	static int warned = 0;

	if (!(when & NURS_FD_F_READ))
		return 0;

	if (nfct_catch(priv->cth) == -1) {
		if (errno == ENOBUFS) {
			if (config_nlsockbufmaxsize(producer)) {
				unsigned int s = priv->nlbufsiz * 2;
				if (setnlbufsiz(producer, s)) {
					nurs_log(NURS_NOTICE,
						  "We are losing events, "
						  "increasing buffer size "
						  "to %d\n", priv->nlbufsiz);
				}
			} else if (!warned) {
				warned = 1;
				nurs_log(NURS_NOTICE,
					  "We are losing events. Please, "
					  "consider using the clauses "
					  "`netlink_socket_buffer_size' and "
					  "`netlink_socket_buffer_maxsize'\n");
			}

			/* internal hash can deal with refresh */
			if (config_usehash(producer) != 0) {
				/* schedule a resynchronization in N
				 * seconds, this parameter is configurable
				 * via config. Note that we don't re-schedule
				 * a resync if it's already in progress. */
				if (!nurs_timer_pending(priv->ov_timer)) {
					nurs_timer_add(priv->ov_timer,
						       config_nlresynctimeout(producer));
				}
			}
		}
	}

	return 0;
}

static int do_free(void *data1, void *data2)
{
	struct ct_timestamp *ts = data2;
	nfct_destroy(ts->ct);
	free(ts);
	return 0;
}


static int do_purge(void *data1, void *data2)
{
	int ret;
	struct nurs_producer *producer = data1;
	struct ct_timestamp *ts = data2;
	struct nfct_priv *priv = nurs_producer_context(producer);

	/* if it is not in kernel anymore, purge it */
	ret = nfct_query(priv->pgh, NFCT_Q_GET, ts->ct);
	if (ret == -1 && errno == ENOENT) {
		propagate_ct(producer, ts->ct, ts->ct, NFCT_T_DESTROY, ts);
		hashtable_del(priv->ct_active, &ts->hashnode);
		free(ts);
	}

	return 0;
}

static int overrun_handler(enum nf_conntrack_msg_type type,
			   struct nf_conntrack *ct,
			   void *data)
{
	struct nurs_producer *producer = data;
	struct nfct_priv *priv = nurs_producer_context(producer);
	struct ct_timestamp *ts;
	uint32_t id;
	int ret;

	id = hashtable_hash(priv->ct_active, ct);
	ts = (struct ct_timestamp *)
		hashtable_find(priv->ct_active, ct, id);
	if (!ts) {
		ts = calloc(sizeof(struct ct_timestamp), 1);
		if (!ts) {
			nurs_log(NURS_ERROR, "failed to alloc timestamp: %s\n",
				 strerror(errno));
			return NFCT_CB_CONTINUE;
		}

		ts->ct = ct;
		set_timestamp_from_ct(ts, ct, START);

		ret = hashtable_add(priv->ct_active, &ts->hashnode, id);
		if (ret < 0) {
			nurs_log(NURS_ERROR, "failed to add hashtable\n");
			free(ts);
			return NFCT_CB_CONTINUE;
		}
		return NFCT_CB_STOLEN;
	}

	return NFCT_CB_CONTINUE;
}

static int read_cb_ovh(int fd, uint16_t when, void *data)
{
	struct nurs_producer *producer = data;
	struct nfct_priv *priv = nurs_producer_context(producer);

	if (!(when & NURS_FD_F_READ))
		return 0;

	/* handle the resync request, update our hashtable */
	if (nfct_catch(priv->ovh) == -1) {
		/* enobufs in the overrun buffer? very rare */
		if (errno == ENOBUFS) {
			if (!nurs_timer_pending(priv->ov_timer)) {
				nurs_timer_add(priv->ov_timer,
					       config_nlresynctimeout(producer));
			}
		}
	}

	/* purge unexistent entries */
	hashtable_iterate(priv->ct_active, producer, do_purge);

	return 0;
}

static int
dump_reset_handler(enum nf_conntrack_msg_type type,
		   struct nf_conntrack *ct, void *data)
{
	struct nurs_producer *producer = data;
	struct nfct_priv *priv = nurs_producer_context(producer);
	uint32_t id;
	int ret = NFCT_CB_CONTINUE, rc;
	struct ct_timestamp *ts;

	switch(type) {
	case NFCT_T_UPDATE:
		id = hashtable_hash(priv->ct_active, ct);
		ts = (struct ct_timestamp *)
			hashtable_find(priv->ct_active, ct, id);
		if (ts)
			nfct_copy(ts->ct, ct, NFCT_CP_META);
		else {
			ts = calloc(sizeof(struct ct_timestamp), 1);
			if (ts == NULL) {
				nurs_log(NURS_ERROR, "failed to alloc"
					 " timestamp: %s\n", strerror(errno));
				return NFCT_CB_CONTINUE;
			}

			ts->ct = ct;
			set_timestamp_from_ct(ts, ct, START);

			rc = hashtable_add(priv->ct_active, &ts->hashnode, id);
			if (rc < 0) {
				nurs_log(NURS_ERROR, "failed to add"
					 " hashtable\n");
				free(ts);
				return NFCT_CB_CONTINUE;
			}
			ret = NFCT_CB_STOLEN;
		}
		propagate_ct(producer, ct, NULL, type, ts);
		break;
	default:
		nurs_log(NURS_NOTICE, "unknown netlink message type\n");
		break;
	}
	return ret;
}

static void get_ctr_zero(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	void *cbdata = (void *)((uintptr_t)producer);
	struct nfct_handle *h;

	h = nfct_open(CONNTRACK, 0);
	if (h == NULL) {
		nurs_log(NURS_FATAL, "Cannot dump and reset counters\n");
		return;
	}
	nfct_callback_register(h, NFCT_T_ALL, &dump_reset_handler, cbdata);
	if (nfct_query(h, NFCT_Q_DUMP_FILTER_RESET, priv->filter_dump) == -1)
		nurs_log(NURS_FATAL, "Cannot dump and reset counters\n");

	nfct_close(h);
}

static enum nurs_return_t
polling_timer_cb(struct nurs_timer *t, void *data)
{
	struct nurs_producer *producer = data;
	struct nfct_priv *priv = nurs_producer_context(producer);

	nfct_query(priv->pgh, NFCT_Q_DUMP_FILTER, priv->filter_dump);
	hashtable_iterate(priv->ct_active, producer, do_purge);
	nurs_timer_add(priv->timer, config_pollint(producer));

	return NURS_RET_OK;
}

static int set_mark_filter(struct nfct_handle *cth,
			   struct nfct_filter_dump *dump_filter,
			   const char* filter_string)
{
	struct nfct_filter_dump_mark mark_filter;
	const char *p;
	char *endptr;
	uintmax_t v;
	errno = 0;

	for (p = filter_string; isspace(*p); ++p)
		;
	v = (uintmax_t)strtoumax(p, &endptr, 0);
	if (endptr == p)
		goto invalid_error;
	if ((errno == ERANGE && v == UINTMAX_MAX) || errno != 0)
		goto invalid_error;
	mark_filter.val = (uint32_t)v;

	if (*endptr != '\0') {
		for (p = endptr; isspace(*p); ++p)
			;
		if (*p++ != '/')
			goto invalid_error;
		for (; isspace(*p); ++p)
			;
		v = (uintmax_t)strtoumax(p, &endptr, 0);
		if (endptr == p)
			goto invalid_error;
		if ((errno == ERANGE && v == UINTMAX_MAX) || errno != 0)
			goto invalid_error;
		mark_filter.mask = (uint32_t)v;
		if (*endptr != '\0')
			goto invalid_error;
	} else {
		mark_filter.mask = UINT32_MAX;
	}

	if (cth) {
		struct nfct_filter *filter = nfct_filter_create();
		nfct_filter_add_attr(filter, NFCT_FILTER_MARK, &mark_filter);
		if (nfct_filter_attach(nfct_fd(cth), filter)) {
			nurs_log(NURS_NOTICE, "failed to attach mark filter\n");
			nfct_filter_destroy(filter);
			return -1;
		}
		nurs_log(NURS_NOTICE, "adding mark filter to socket:"
			 " \"%u/%u\"\n", mark_filter.val, mark_filter.mask);
	}
	nfct_filter_dump_set_attr(dump_filter, NFCT_FILTER_DUMP_MARK,
				  &mark_filter);
	nurs_log(NURS_NOTICE, "adding mark dump filter: \"%u/%u\"\n",
		 mark_filter.val, mark_filter.mask);

	return 0;

invalid_error:
	nurs_log(NURS_FATAL, "invalid val/mask %s\n", filter_string);
	return -1;
}

static enum nurs_return_t
overrun_timeout(struct nurs_timer *a, void *data)
{
	struct nurs_producer *producer = data;
	struct nfct_priv *priv = nurs_producer_context(producer);

	nfct_send(priv->ovh, NFCT_Q_DUMP_FILTER, priv->filter_dump);
	return NURS_RET_OK;
}

static enum nurs_return_t
nfct_organize_events(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	void *cbdata = (void *)((uintptr_t)producer);
	int on = 1;

	priv->cth = nfct_open(NFNL_SUBSYS_CTNETLINK,
			      config_eventmask(producer));
	if (!priv->cth) {
		nurs_log(NURS_FATAL, "error opening ctnetlink\n");
		return NURS_RET_ERROR;
	}

	if (strlen(config_mark_filter(producer)) &&
	    set_mark_filter(priv->cth, priv->filter_dump,
			    config_mark_filter(producer))) {
		nurs_log(NURS_FATAL, "failed to create mark filter\n");
		goto close_cth;
	}

	if (config_nlsockbufsize(producer)) {
		setnlbufsiz(producer, config_nlsockbufsize(producer));
		nurs_log(NURS_NOTICE, "NFCT netlink buffer size has been "
			 "set to %d\n", priv->nlbufsiz);
	}

	if (config_reliable(producer)) {
		if (setsockopt(nfct_fd(priv->cth), SOL_NETLINK,
			NETLINK_BROADCAST_SEND_ERROR, &on, sizeof(int)) ||
		    setsockopt(nfct_fd(priv->cth), SOL_NETLINK,
			NETLINK_NO_ENOBUFS, &on, sizeof(int))) {
			nurs_log(NURS_FATAL, "failed to set reliable\n");
			goto close_cth;
		}
		nurs_log(NURS_NOTICE, "NFCT reliable logging "
			 "has been enabled.\n");
	}

	priv->nfct_fd = nurs_fd_create(nfct_fd(priv->cth), NURS_FD_F_READ);
	if (!priv->nfct_fd) {
		nurs_log(NURS_FATAL, "failed to create event nurs_fd\n");
		goto close_cth;
	}

	if (config_usehash(producer)) {
		/* we use a hashtable to cache entries in userspace. */
		priv->ct_active =
			hashtable_create(config_buckets(producer),
					 config_maxentries(producer),
					 hash,
					 compare);
		if (!priv->ct_active) {
			nurs_log(NURS_FATAL, "error allocating hash\n");
			goto destroy_cth;
		}
		priv->ovh = nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
		if (!priv->ovh) {
			nurs_log(NURS_FATAL, "error opening ctnetlink\n");
			goto destroy_hashtable;
		}

		priv->nfct_ov = nurs_fd_create(nfct_fd(priv->ovh), NURS_FD_F_READ);
		if (!priv->nfct_ov) {
			nurs_log(NURS_FATAL, "failed to create ov nurs_fd\n");
			goto close_ovh;
		}

		priv->ov_timer = nurs_timer_create(overrun_timeout, cbdata);
		if (!priv->ov_timer) {
			nurs_log(NURS_FATAL, "failed to create ov timer\n");
			goto destroy_ovh;
		}

		/* we use this to purge old entries during overruns.*/
		priv->pgh = nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
		if (!priv->pgh) {
			nurs_log(NURS_FATAL, "error opening ctnetlink\n");
			goto destroy_ovtimer;
		}
	}

	return NURS_RET_OK;

destroy_ovtimer:
	nurs_timer_destroy(priv->ov_timer);
destroy_ovh:
	nurs_fd_destroy(priv->nfct_ov);
close_ovh:
	nfct_close(priv->ovh);
destroy_hashtable:
	hashtable_destroy(priv->ct_active);
destroy_cth:
	nurs_fd_destroy(priv->nfct_fd);
close_cth:
	nfct_close(priv->cth);

	return NURS_RET_ERROR;
}

static enum nurs_return_t
nfct_organize_polling(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	void *cbdata = (void *)((uintptr_t)producer);

	if (!config_usehash(producer)) {
		nurs_log(NURS_FATAL, "NFCT polling mode requires "
			 "the hashtable\n");
		return NURS_RET_ERROR;
	}

	priv->pgh = nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
	if (!priv->pgh) {
		nurs_log(NURS_FATAL, "error opening ctnetlink\n");
		return NURS_RET_ERROR;
	}

	if (strlen(config_mark_filter(producer)) &&
	    set_mark_filter(priv->pgh, priv->filter_dump,
			    config_mark_filter(producer))) {
		nurs_log(NURS_FATAL, "failed to create mark filter\n");
		goto close_pgh;
	}

	priv->ct_active =
		hashtable_create(config_buckets(producer),
				 config_maxentries(producer),
				 hash,
				 compare);
	if (!priv->ct_active) {
		nurs_log(NURS_FATAL, "error allocating hash\n");
		goto close_pgh;
	}

	priv->timer = nurs_timer_create(polling_timer_cb, cbdata);
	if (!priv->timer) {
		nurs_log(NURS_FATAL, "failed to create polling timer\n");
		goto destroy_hashtable;
	}

	return NURS_RET_OK;

destroy_hashtable:
	hashtable_destroy(priv->ct_active);
close_pgh:
	nfct_close(priv->pgh);
	return NURS_RET_ERROR;
}

static enum nurs_return_t
nfct_organize(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	enum nurs_return_t ret;

	priv->filter_dump = nfct_filter_dump_create();
	if (priv->filter_dump == NULL) {
		nurs_log(NURS_FATAL, "could not create filter_dump\n");
		return NURS_RET_ERROR;
	}

	if (config_pollint(producer)) {
		/* poll from ctnetlink periodically. */
		ret = nfct_organize_polling(producer);
	} else {
		/* listen to ctnetlink events. */
		ret = nfct_organize_events(producer);
	}
	if (ret == NURS_RET_OK)
		return ret;

	nfct_filter_dump_destroy(priv->filter_dump);
	return NURS_RET_ERROR;
}

static enum nurs_return_t
nfct_disorganize_events(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	int ret = 0;

	if (config_usehash(producer)) {
		if (nfct_close(priv->pgh)) {
			nurs_log(NURS_ERROR, "failed to close pgh\n");
			ret = -1;
		}
		if (nurs_timer_destroy(priv->ov_timer)) {
			nurs_log(NURS_ERROR, "failed to destroy ov timer\n");
			ret = -1;
		}
		nurs_fd_destroy(priv->nfct_ov);
		if (nfct_close(priv->ovh)) {
			nurs_log(NURS_ERROR, "failed to close ovh\n");
			ret = -1;
		}
		hashtable_destroy(priv->ct_active);
	}
	nurs_fd_destroy(priv->nfct_fd);
	if (nfct_close(priv->cth)) {
		nurs_log(NURS_ERROR, "failed to close cth\n");
		ret = -1;
	}

	if (ret)
		return NURS_RET_ERROR;
	return NURS_RET_OK;
}

static enum nurs_return_t
nfct_disorganize_polling(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	int ret = 0;

	if (nurs_timer_destroy(priv->timer)) {
		nurs_log(NURS_ERROR, "failed to destroy timer\n");
		ret = -1;
	}
	hashtable_destroy(priv->ct_active);
	if (nfct_close(priv->pgh)) {
		nurs_log(NURS_ERROR, "failed to close pgh\n");
		ret = -1;
	}

	if (ret)
		return NURS_RET_ERROR;
	return NURS_RET_OK;
}

static enum nurs_return_t
nfct_disorganize(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	enum nurs_return_t ret;

	if (config_pollint(producer)) {
		ret = nfct_disorganize_polling(producer);
	} else {
		ret = nfct_disorganize_events(producer);
	}
	nfct_filter_dump_destroy(priv->filter_dump);

	return ret;
}

static enum nurs_return_t
nfct_start_events(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	void *cbdata = (void *)((uintptr_t)producer);

	if (config_usehash(producer) &&
	    nfct_callback_register(priv->cth, NFCT_T_ALL,
				   &event_handler_hashtable, cbdata)) {
		nurs_log(NURS_FATAL, "failed to register hashtable handler\n");
		return NURS_RET_ERROR;
	} else if (nfct_callback_register(priv->cth, NFCT_T_ALL,
					  &event_handler_no_hashtable,
					  cbdata)) {
		nurs_log(NURS_FATAL, "failed to register no hashtable handler\n");
		return NURS_RET_ERROR;
	}

	if (nurs_fd_register(priv->nfct_fd, &read_cb_nfct, cbdata)) {
		nurs_log(NURS_FATAL, "failed to register nurs fd\n");
		goto unregister_cth;
	}

	if (config_usehash(producer)) {
		struct nfct_handle *h;

		/* populate the hashtable: we use a disposable handler, we
		 * may hit overrun if we use priv->cth. This ensures that the
		 * initial dump is successful. */
		h = nfct_open(CONNTRACK, 0);
		if (!h) {
			nurs_log(NURS_FATAL, "error opening ctnetlink\n");
			goto unregister_nfd;
		}
		/* XXX: error check */
		nfct_callback_register(h, NFCT_T_ALL,
				       &event_handler_hashtable, cbdata);
		nfct_query(h, NFCT_Q_DUMP_FILTER, priv->filter_dump);
		nfct_close(h);

		/* the overrun handler only make sense with the hashtable,
		 * if we hit overrun, we resync with ther kernel table. */
		if (nfct_callback_register(priv->ovh, NFCT_T_ALL,
					   &overrun_handler, cbdata)) {
			nurs_log(NURS_FATAL, "failed to register overrun"
				 " handler\n");
			goto unregister_nfd;
		}

		if (nurs_fd_register(priv->nfct_ov, read_cb_ovh, cbdata)) {
			nurs_log(NURS_FATAL, "failed to register overrun"
				 " nurs fd\n");
			goto unregister_ovh;
		}
	}

	nurs_log(NURS_NOTICE, "NFCT plugin working in event mode\n");
	return NURS_RET_OK;

unregister_ovh:
	nfct_callback_unregister(priv->ovh);
unregister_nfd:
	nurs_fd_unregister(priv->nfct_fd);
unregister_cth:
	nfct_callback_unregister(priv->cth);

	return NURS_RET_ERROR;
}

static enum nurs_return_t
nfct_start_polling(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	void *cbdata = (void *)((uintptr_t)producer);

	if (nfct_callback_register(priv->pgh, NFCT_T_ALL,
				   &polling_handler, cbdata)) {
		nurs_log(NURS_FATAL, "failed to register pgh\n");
		return NURS_RET_ERROR;
	}

	if (config_pollint(producer) &&
	    nurs_timer_add(priv->timer, config_pollint(producer))) {
		nurs_log(NURS_FATAL, "failed to add timer\n");
		goto unregister_pgh;
	}

	nurs_log(NURS_NOTICE, "NFCT working in polling mode\n");
	return NURS_RET_OK;

unregister_pgh:
	nfct_callback_unregister(priv->pgh);
	return NURS_RET_ERROR;
}

static enum nurs_return_t
nfct_start(const struct nurs_producer *producer)
{
	if (config_pollint(producer) == 0) {
		/* listen to ctnetlink events. */
		return nfct_start_events(producer);
	} else {
		/* poll from ctnetlink periodically. */
		return nfct_start_polling(producer);
	}
	/* should not ever happen. */
	nurs_log(NURS_FATAL, "invalid NFCT configuration\n");
	return -1;
}

static enum nurs_return_t
nfct_stop_events(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);
	int ret = 0;

	if (nurs_fd_unregister(priv->nfct_fd)) {
		nurs_log(NURS_ERROR, "failed to unregister nurs_fd\n");
		ret = -1;
	}

	if (config_usehash(producer)) {
		if (nurs_fd_unregister(priv->nfct_ov)) {
			nurs_log(NURS_ERROR, "failed to unregister ovh nfd");
			ret = -1;
		}
		if (hashtable_iterate(priv->ct_active, NULL, do_free)) {
			nurs_log(NURS_ERROR, "failed to clean up hashtable\n");
			ret = -1;
		}
	}

	if (ret)
		return NURS_RET_ERROR;
	return NURS_RET_OK;
}

static enum nurs_return_t
nfct_stop_polling(const struct nurs_producer *producer)
{
	struct nfct_priv *priv = nurs_producer_context(producer);

	nfct_callback_unregister(priv->pgh);

	return NURS_RET_OK;
}

static enum nurs_return_t
nfct_stop(const struct nurs_producer *producer)
{
	if (config_pollint(producer))
		return nfct_stop_polling(producer);
	return nfct_stop_events(producer);
}

static enum nurs_return_t
nfct_signal(const struct nurs_producer *producer, uint32_t signal)
{
	switch (signal) {
	case SIGUSR2:
		get_ctr_zero(producer);
		break;
	}
	return NURS_RET_OK;
}

static struct nurs_producer_def nfct_producer = {
	.version	= VERSION,
	.name		= "NFCT",
	.context_size	= sizeof(struct nfct_priv),
	.config_def	= &nfct_config,
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

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
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <nurs/nurs.h>
#include <nurs/list.h>
#include <nurs/ipfix_protocol.h>
#include <nurs/utils.h>

/*
 * This implementation sends NetFlow v9 entry only if ORIG or REPLY counter is
 * greater than 0. Single NFCT entry contains duplex data, orig and reply but
 * NetFlow v9 can represents simplex entry only, so that sigle NFCT entry may
 * create two NetFlow v9 data entries. for example:
 *
 * 192.168.1.1 -> 172.16.1.1 will nat 1.1.1.1 -> 2.2.2.2
 *
 * NFCT:
 *	orig.ip.saddr		192.168.1.1
 *	orig.ip.daddr		172.16.1.1
 *	reply.ip.saddr		2.2.2.2
 *	reply.ip.daddr		1.1.1.1
 *	orig.raw.pktcount	111
 *	reply.raw.pktcount	222
 *
 * NFLOW9:
 *	SRC_ADDR		192.168.1.1	172.16.1.1
 *	DST_ADDR		172.16.1.1	192.168.1.1
 *	XLATE_SRC_ADDR		1.1.1.1		2.2.2.2
 *	XLATE_DST_ADDR		2.2.2.2		1.1.1.1
 *	IN_PKTS			111		222
 *
 * then:
 *	orig.raw.pktcount.delta > 0:	swap reply.*
 *	reply.raw.pktcount.delta > 0:	swap orig.* and ifindex.
 *					invert flowDirection
 *
 * This means a NetFlow v9 entry has only one conter and same can be said to
 * ip.protocol. corksets_max should be greater than 3 since added to
 * bidirectional handling, a template may be added.
 *
 * There are two assumption about NFCT:
 * - To use same template, assume the number of keys starting with "orig." and
 *   "reply." is the same.
 * - not propagate both Count and DeltaCount, only either of them.
 */

/* index for ikey which needs special handling */
enum {
	CII_ORIG_RAW_PKTLEN_DELTA,
	CII_ORIG_RAW_PKTCOUNT_DELTA,
	CII_REPLY_RAW_PKTLEN_DELTA,
	CII_REPLY_RAW_PKTCOUNT_DELTA,
	CII_REPLY_IP_PROTOCOL,	/* use only orig ip.protocol */
	CII_FAMILY,		/* illigal dirty hack */
	CII_MAX,
};

static char *counter_keys[] = {
	[CII_ORIG_RAW_PKTLEN_DELTA]	= "orig.raw.pktlen.delta",
	[CII_ORIG_RAW_PKTCOUNT_DELTA]	= "orig.raw.pktcount.delta",
	[CII_REPLY_RAW_PKTLEN_DELTA]	= "reply.raw.pktlen.delta",
	[CII_REPLY_RAW_PKTCOUNT_DELTA]	= "reply.raw.pktcount.delta",
	[CII_REPLY_IP_PROTOCOL]		= "reply.ip.protocol",
	[CII_FAMILY]			= "oob.family",
};

/* index for data field offset to swap by direction */
enum {
	FOI_ORIG_IP_SADDR = 0,
	FOI_ORIG_IP_DADDR,
	FOI_ORIG_IP6_SADDR,
	FOI_ORIG_IP6_DADDR,
	FOI_ORIG_L4_SPORT,
	FOI_ORIG_L4_DPORT,
	FOI_REPLY_IP_SADDR,
	FOI_REPLY_IP_DADDR,
	FOI_REPLY_IP6_SADDR,
	FOI_REPLY_IP6_DADDR,
	FOI_REPLY_L4_SPORT,
	FOI_REPLY_L4_DPORT,
	FOI_IF_INPUT,
	FOI_IF_OUTPUT,
	FOI_FLOW_DIR,
	FOI_IN_BYTES,
	FOI_IN_PKTS,
	FOI_MAX,
};

static char *dir_keys[] = {
	[FOI_ORIG_IP_SADDR]		= "orig.ip.saddr",
	[FOI_ORIG_IP_DADDR]		= "orig.ip.daddr",
	[FOI_ORIG_IP6_SADDR]		= "orig.ip6.saddr",
	[FOI_ORIG_IP6_DADDR]		= "orig.ip6.daddr",
	[FOI_ORIG_L4_SPORT]		= "orig.l4.sport",
	[FOI_ORIG_L4_DPORT]		= "orig.l4.dport",
	[FOI_REPLY_IP_SADDR]		= "reply.ip.saddr",
	[FOI_REPLY_IP_DADDR]		= "reply.ip.daddr",
	[FOI_REPLY_IP6_SADDR]		= "reply.ip6.saddr",
	[FOI_REPLY_IP6_DADDR]		= "reply.ip6.daddr",
	[FOI_REPLY_L4_SPORT]		= "reply.l4.sport",
	[FOI_REPLY_L4_DPORT]		= "reply.l4.dport",
	[FOI_IF_INPUT]			= "oob.ifindex_in",
	[FOI_IF_OUTPUT]			= "oob.ifindex_out",
	[FOI_FLOW_DIR]			= "flow.direction",
	[FOI_IN_BYTES]			= "orig.raw.pktlen.delta",
	[FOI_IN_PKTS]			= "orig.raw.pktcount.delta",
};

enum {
	NFLOW9_DIR_NONE		= 0,
	NFLOW9_DIR_ORIG		= 1,
	NFLOW9_DIR_REPLY	= 2,
	NFLOW9_DIR_BOTH		= NFLOW9_DIR_ORIG | NFLOW9_DIR_REPLY,
};

enum {
	NFLOW9_CONFIG_DEST = 0,
	NFLOW9_CONFIG_DOMAIN_ID,
	NFLOW9_CONFIG_NTH_TEMPLATE,
	NFLOW9_CONFIG_CORKSETS_MAX,
	NFLOW9_CONFIG_MAX,
};

static struct nurs_config_def nflow9_config = {
	.len		= NFLOW9_CONFIG_MAX,
	.keys	= {
		[NFLOW9_CONFIG_DEST]	= {
			.name	 = "dest",
			.type	 = NURS_CONFIG_T_STRING,
			.flags   = NURS_CONFIG_F_NONE,
			.string  = "udp://localhost:9996",
		},
		[NFLOW9_CONFIG_DOMAIN_ID]	= {
			.name	 = "domain_id",
			.type	 = NURS_CONFIG_T_INTEGER,
			.flags   = NURS_CONFIG_F_NONE,
			.integer = 0,
		},
		[NFLOW9_CONFIG_NTH_TEMPLATE] = {
			.name	 = "nth_template",
			.type	 = NURS_CONFIG_T_INTEGER,
			.flags   = NURS_CONFIG_F_NONE,
			.integer = 16,
		},
		[NFLOW9_CONFIG_CORKSETS_MAX] = {
			.name	 = "corksets_max",
			.type	 = NURS_CONFIG_T_INTEGER,
			.flags   = NURS_CONFIG_F_NONE,
			.integer = 3,
		},
	},
};

#define config_dest(x)		nurs_config_string(nurs_plugin_config(x), NFLOW9_CONFIG_DEST)
#define config_domain(x)		(uint32_t)nurs_config_integer(nurs_plugin_config(x), NFLOW9_CONFIG_DOMAIN_ID)
#define config_nth_template(x)	nurs_config_integer(nurs_plugin_config(x), NFLOW9_CONFIG_NTH_TEMPLATE)
#define config_corksets_max(x)	nurs_config_integer(nurs_plugin_config(x), NFLOW9_CONFIG_CORKSETS_MAX)

/* Section 5.1 */
struct nflow9_msghdr {
	uint16_t	version;
	uint16_t	count;
	uint32_t	sys_uptime;
	uint32_t	unix_secs;
	uint32_t	sequence_number;
	uint32_t	source_id;
};

/* Section 5.2, 5.3 */
struct nflow9_sethdr {
	uint16_t	set_id;
	uint16_t	length;
};
#define nflow9_data(x) (void *)((uintptr_t)(x) + sizeof(struct nflow9_sethdr))

/* Section 5.2 */
struct nflow9_tmpl_hdr {
	uint16_t	template_id;
	uint16_t	field_count;
};

/* Section 5.2 */
struct nflow9_tmpl_rec {
	uint16_t	type;
	uint16_t	length;
};

/* 8.  Field Type Definitions			octet (or default)*/
enum {
	NFLOW9_IN_BYTES			= 1,	/* (4)	octetDeltaCount			*/
	NFLOW9_IN_PKTS			= 2,	/* (4)	packetDeltaCount		*/
	NFLOW9_FLOWS			= 3,	/* (4) */
	NFLOW9_PROTOCOL			= 4,	/* 1	protocolIdentifier		*/
	NFLOW9_TOS			= 5,	/* 1	classOfServiceIPv4		*/
	NFLOW9_TCP_FLAGS		= 6,	/* 1	tcpControlBits			*/
	NFLOW9_L4_SRC_PORT		= 7,	/* 2	sourceTransportPort		*/
	NFLOW9_IPV4_SRC_ADDR		= 8,	/* 4	sourceIPv4Address		*/
	NFLOW9_SRC_MASK			= 9,	/* 1	sourceIPv4Mask			*/
	NFLOW9_INPUT_SNMP		= 10,	/* (2)	ingressInterface		*/
	NFLOW9_L4_DST_PORT		= 11,	/* 2	destinationTransportPort	*/
	NFLOW9_IPV4_DST_ADDR		= 12,	/* 4	destinationIPv4Address		*/
	NFLOW9_DST_MASK			= 13,	/* 1	destinationIPv4Mask		*/
	NFLOW9_OUTPUT_SNMP		= 14,	/* (2)	egressInterface			*/
	NFLOW9_IPV4_NEXT_HOP		= 15,	/* 4	ipNextHopIPv4Address		*/
	NFLOW9_SRC_AS			= 16,	/* (2)	bgpSourceAsNumber		*/
	NFLOW9_DST_AS			= 17,	/* (2)	bgpDestinationAsNumber		*/
	NFLOW9_BGP_IPV4_NEXT_HOP	= 18,	/* 4	bgpNextHopIPv4Address		*/
	NFLOW9_MUL_DST_PKTS		= 19,	/* (4)	postMCastPacketDeltaCount	*/
	NFLOW9_MUL_DST_BYTES		= 20,	/* (4)	postMCastOctetDeltaCount	*/
	NFLOW9_LAST_SWITCHED		= 21,	/* 4	flowEndSysUpTime		*/
	NFLOW9_FIRST_SWITCHED		= 22,	/* 4	flowStartSysUpTime		*/
	NFLOW9_OUT_BYTES		= 23,	/* (4)	postOctetDeltaCount		*/
	NFLOW9_OUT_PKTS			= 24,	/* (4)	postPacketDeltaCount		*/
	/* reserved */
	/* reserved */
	NFLOW9_IPV6_SRC_ADDR		= 27,	/* 16	sourceIPv6Address		*/
	NFLOW9_IPV6_DST_ADDR		= 28,	/* 16	destinationIPv6Address		*/
	NFLOW9_IPV6_SRC_MASK		= 29,	/* 1	sourceIPv6Mask			*/
	NFLOW9_IPV6_DST_MASK		= 30,	/* 1	destinationIPv6Mask		*/
	NFLOW9_FLOW_LABEL		= 31,	/* 3	flowLabelIPv6			*/
	NFLOW9_ICMP_TYPE		= 32,	/* 2	icmpTypeCodeIPv4		*/
	NFLOW9_MUL_IGMP_TYPE		= 33,	/* 1	igmpType			*/
	NFLOW9_SAMPLING_INTERVAL	= 34,	/* 4					*/
	/* reserved */
	NFLOW9_SAMPLING_ALGORITHM	= 35,	/* 1					*/
	NFLOW9_FLOW_ACTIVE_TIMEOUT	= 36,	/* 2	flowActiveTimeOut		*/
	NFLOW9_FLOW_INAVTIVE_TIMEOUT	= 37,	/* 2	flowInactiveTimeout		*/
	NFLOW9_ENGINE_TYPE		= 38,	/* 1					*/
	NFLOW9_ENGINE_ID		= 39,	/* 1					*/
	NFLOW9_TOTAL_BYTES_EXP		= 40,	/* (4)	exportedOctetTotalCount		*/
	NFLOW9_TOTAL_PKTS_EXP		= 41,	/* (4)	exportedMessageTotalCount	*/
	NFLOW9_TOTAL_FLOWS_EXP		= 42,	/* (4)	exportedFlowTotalCount		*/
	/* reserved */
	/* reserved */
	/* reserved */
	NFLOW9_MPLS_TOP_LABEL_TYPE	= 46,	/* 1	mplsTopLabelType		*/
	NFLOW9_MPLS_TOP_LABEL_IP_ADDR	= 47,	/* 4	mplsTopLabelIPv4Address		*/
	NFLOW9_FLOW_SAMPLER_ID		= 48,	/* 1					*/
	NFLOW9_FLOW_SAMPLER_MODE	= 49,	/* 1					*/
	NFLOW9_FLOW_SAMPLER_RANDOM_INTERVAL = 50,	/* 4				*/
	/* reserved */
	/* reserved */
	/* reserved */
	/* reserved */
	NFLOW9_DST_TOS			= 55,	/* 1	postClassOfServiceIPv4		*/
	NFLOW9_SRC_MAC			= 56,	/* 6	sourceMacAddress		*/
	NFLOW9_DST_MAC			= 57,	/* 6	postDestinationMacAddr		*/
	NFLOW9_SRC_VLAN			= 58,	/* 2	vlanId				*/
	NFLOW9_DST_VLAN			= 59,	/* 2	postVlanId			*/
	NFLOW9_IP_PROTOCOL_VERSION	= 60,	/* 1	ipVersion			*/
	NFLOW9_DIRECTION		= 61,	/* 1	flowDirection			*/
	NFLOW9_IPV6_NEXT_HOP		= 62,	/* 16	ipNextHopIPv6Address		*/
	NFLOW9_BGP_IPV6_NEXT_HOP	= 63,	/* 16	bgpNexthopIPv6Address		*/
	NFLOW9_IPV6_OPTION_HEADERS	= 64,	/* 4	ipv6ExtensionHeaders		*/
	/* reserved */
	/* reserved */
	/* reserved */
	/* reserved */
	/* reserved */
	NFLOW9_MPLS_LABEL_1		= 70,	/* 3	mplsTopLabelStackEntry		*/
	NFLOW9_MPLS_LABEL_2		= 71,	/* 3	mplsLabelStackEntry2		*/
	NFLOW9_MPLS_LABEL_3		= 72,	/* 3	mplsLabelStackEntry3		*/
	NFLOW9_MPLS_LABEL_4		= 73,	/* 3	mplsLabelStackEntry4		*/
	NFLOW9_MPLS_LABEL_5		= 74,	/* 3	mplsLabelStackEntry5		*/
	NFLOW9_MPLS_LABEL_6		= 75,	/* 3	mplsLabelStackEntry6		*/
	NFLOW9_MPLS_LABEL_7		= 76,	/* 3	mplsLabelStackEntry7		*/
	NFLOW9_MPLS_LABEL_8		= 77,	/* 3	mplsLabelStackEntry8		*/
	NFLOW9_MPLS_LABEL_9		= 78,	/* 3	mplsLabelStackEntry9		*/
	NFLOW9_MPLS_LABEL_10		= 79,	/* 3	mplsLabelStackEntry10		*/

	/* pick up usefuls from:
	 * http://www.cisco.com/c/en/us/td/docs/security/asa/special/netflow/guide/asa_netflow.html */
	NFLOW9_IPV4_XLATE_SRC_ADDR	= 225,	/* 4	NF_F_XLATE_SRC_ADDR_IPV4	*/
	NFLOW9_IPV4_XLATE_DST_ADDR	= 226,	/* 4	NF_F_XLATE_DST_ADDR_IPV4	*/
	NFLOW9_L4_XLATE_SRC_PORT	= 227,	/* 2	NF_F_XLATE_SRC_PORT		*/
	NFLOW9_L4_XLATE_DST_PORT	= 228,	/* 2	NF_F_XLATE_DST_PORT		*/
	NFLOW9_IPV6_XLATE_SRC_ADDR	= 281,	/* 16	NF_F_XLATE_SRC_ADDR_IPV6	*/
	NFLOW9_IPV6_XLATE_DST_ADDR	= 282,	/* 16	NF_F_XLATE_DST_ADDR_IPV6	*/

	NFLOW9_FIELD_MAX		= NFLOW9_IPV6_XLATE_DST_ADDR,
};

static int ipfix_map[] = {
	[IPFIX_octetDeltaCount]			= NFLOW9_IN_BYTES,
	[IPFIX_packetDeltaCount]		= NFLOW9_IN_PKTS,
	/* [3]					= NFLOW9_FLOWS,		*/
	[IPFIX_protocolIdentifier]		= NFLOW9_PROTOCOL,
	[IPFIX_classOfServiceIPv4]		= NFLOW9_TOS,
	[IPFIX_tcpControlBits]			= NFLOW9_TCP_FLAGS,
	[IPFIX_sourceTransportPort]		= NFLOW9_L4_SRC_PORT,
	[IPFIX_sourceIPv4Address]		= NFLOW9_IPV4_SRC_ADDR,
	[IPFIX_sourceIPv4Mask]			= NFLOW9_SRC_MASK,
	[IPFIX_ingressInterface]		= NFLOW9_INPUT_SNMP,
	[IPFIX_destinationTransportPort]	= NFLOW9_L4_DST_PORT,
	[IPFIX_destinationIPv4Address]		= NFLOW9_IPV4_DST_ADDR,
	[IPFIX_destinationIPv4Mask]		= NFLOW9_DST_MASK,
	[IPFIX_egressInterface]			= NFLOW9_OUTPUT_SNMP,
	[IPFIX_ipNextHopIPv4Address]		= NFLOW9_IPV4_NEXT_HOP,
	[IPFIX_bgpSourceAsNumber]		= NFLOW9_SRC_AS,
	[IPFIX_bgpDestinationAsNumber]		= NFLOW9_DST_AS,
	[IPFIX_bgpNextHopIPv4Address]		= NFLOW9_BGP_IPV4_NEXT_HOP,
	[IPFIX_postMCastPacketDeltaCount]	= NFLOW9_MUL_DST_PKTS,
	[IPFIX_postMCastOctetDeltaCount]	= NFLOW9_MUL_DST_BYTES,
	[IPFIX_flowEndSysUpTime]		= NFLOW9_LAST_SWITCHED,
	[IPFIX_flowStartSysUpTime]		= NFLOW9_FIRST_SWITCHED,
	[IPFIX_postOctetDeltaCount]		= NFLOW9_OUT_BYTES,
	[IPFIX_postPacketDeltaCount]		= NFLOW9_OUT_PKTS,
	[IPFIX_minimumPacketLength]		= 0,
	[IPFIX_maximumPacketLength]		= 0,
	[IPFIX_sourceIPv6Address]		= NFLOW9_IPV6_SRC_ADDR,
	[IPFIX_destinationIPv6Address]		= NFLOW9_IPV6_DST_ADDR,
	[IPFIX_sourceIPv6Mask]			= NFLOW9_IPV6_SRC_MASK,
	[IPFIX_destinationIPv6Mask]		= NFLOW9_IPV6_DST_MASK,
	[IPFIX_flowLabelIPv6]			= NFLOW9_FLOW_LABEL,
	[IPFIX_icmpTypeCodeIPv4]		= NFLOW9_ICMP_TYPE,
	[IPFIX_igmpType]			= NFLOW9_MUL_IGMP_TYPE,
	/* [34]					= [NFLOW9_SAMPLING_INTERVAL],	*/
	/* [35]					= [NFLOW9_SAMPLING_ALGORITHM],*/
	[IPFIX_flowActiveTimeOut]		= NFLOW9_FLOW_ACTIVE_TIMEOUT,
	[IPFIX_flowInactiveTimeout]		= NFLOW9_FLOW_INAVTIVE_TIMEOUT,
	/* [38]					= NFLOW9_ENGINE_TYPE,		*/
	/* [39]					= NFLOW9_ENGINE_ID,		*/
	[IPFIX_exportedOctetTotalCount]		= NFLOW9_TOTAL_BYTES_EXP,
	[IPFIX_exportedMessageTotalCount]	= NFLOW9_TOTAL_PKTS_EXP,
	[IPFIX_exportedFlowTotalCount]		= NFLOW9_TOTAL_FLOWS_EXP,
	/* [43]					= ,				*/
	[IPFIX_sourceIPv4Prefix]		= 0,
	[IPFIX_destinationIPv4Prefix]		= 0,
	[IPFIX_mplsTopLabelType]		= NFLOW9_MPLS_TOP_LABEL_TYPE,
	[IPFIX_mplsTopLabelIPv4Address]		= NFLOW9_MPLS_TOP_LABEL_IP_ADDR,
	/* [48]					= NFLOW9_FLOW_SAMPLER_ID,	*/
	/* [49]					= NFLOW9_FLOW_SAMPLER_MODE,	*/
	/* [50]					= NFLOW9_FLOW_SAMPLER_RANDOM_INTERVAL, */
	/* [51]					= ,				*/
	[IPFIX_minimumTtl]			= 0,
	[IPFIX_maximumTtl]			= 0,
	[IPFIX_identificationIPv4]		= 0,
	[IPFIX_postClassOfServiceIPv4]		= NFLOW9_DST_TOS,
	[IPFIX_sourceMacAddress]		= NFLOW9_SRC_MAC,
	[IPFIX_postDestinationMacAddr]		= NFLOW9_DST_MAC,
	[IPFIX_vlanId]				= NFLOW9_SRC_VLAN,
	[IPFIX_postVlanId]			= NFLOW9_DST_VLAN,
	[IPFIX_ipVersion]			= NFLOW9_IP_PROTOCOL_VERSION,
	[IPFIX_flowDirection]			= NFLOW9_DIRECTION,
	[IPFIX_ipNextHopIPv6Address]		= NFLOW9_IPV6_NEXT_HOP,
	[IPFIX_bgpNexthopIPv6Address]		= NFLOW9_BGP_IPV6_NEXT_HOP,
	[IPFIX_ipv6ExtensionHeaders]		= NFLOW9_IPV6_OPTION_HEADERS,
	/* [65]					= ,				*/
	/* [66]					= ,				*/
	/* [67]					= ,				*/
	/* [68]					= ,				*/
	/* [69]					= ,				*/
	[IPFIX_mplsTopLabelStackEntry]		= NFLOW9_MPLS_LABEL_1,
	[IPFIX_mplsLabelStackEntry2]		= NFLOW9_MPLS_LABEL_2,
	[IPFIX_mplsLabelStackEntry3]		= NFLOW9_MPLS_LABEL_3,
	[IPFIX_mplsLabelStackEntry4]		= NFLOW9_MPLS_LABEL_4,
	[IPFIX_mplsLabelStackEntry5]		= NFLOW9_MPLS_LABEL_5,
	[IPFIX_mplsLabelStackEntry6]		= NFLOW9_MPLS_LABEL_6,
	[IPFIX_mplsLabelStackEntry7]		= NFLOW9_MPLS_LABEL_7,
	[IPFIX_mplsLabelStackEntry8]		= NFLOW9_MPLS_LABEL_8,
	[IPFIX_mplsLabelStackEntry9]		= NFLOW9_MPLS_LABEL_9,
	[IPFIX_mplsLabelStackEntry10]		= NFLOW9_MPLS_LABEL_10,
	/* [80 - 224]				= ,				*/
	[IPFIX_postNATSourceIPv4Address]	= NFLOW9_IPV4_XLATE_SRC_ADDR,
	[IPFIX_postNATDestinationIPv4Address]	= NFLOW9_IPV4_XLATE_DST_ADDR,
	[IPFIX_postNAPTSourceTransportPort]	= NFLOW9_L4_XLATE_SRC_PORT,
	[IPFIX_postNAPTDestinationTransportPort]= NFLOW9_L4_XLATE_DST_PORT,
	[IPFIX_postNATSourceIPv6Address]	= NFLOW9_IPV6_XLATE_SRC_ADDR,
	[IPFIX_postNATDestinationIPv6Address]	= NFLOW9_IPV6_XLATE_DST_ADDR,
};

struct nflow9_template {
	struct list_head list;
	struct nfct_bitmask *bitmask;
	int until_template;		/* decide if it's time to retransmit our template */
	uintptr_t offset[FOI_MAX];	/* direction related field offset from data head */
	size_t tmplset_len, dataset_len;
	struct nflow9_sethdr *template;

	pthread_mutex_t sethdrs_mutex;
	pthread_cond_t sethdrs_condv;
	struct nflow9_sethdr *sethdrs;
	int sethdrs_max;
	int sethdrs_pos;
};

struct nflow9_priv {
	int fd;		/* socket that we use for sending NetFlow v9 data  */
	int uptime_fd;	/* /proc/uptime to set sysUpTime */

	uint16_t next_template_id;

	struct list_head tmpls;	/* nflow9_template */
	pthread_mutex_t tmpls_mutex;

	int nth_template;
	uint16_t cntidxs[CII_MAX];	/* ikey indexes to counter fields  */

	struct nflow9_msghdr msghdr;

	pthread_mutex_t vecs_mutex;	/* protect below */
	pthread_cond_t vecs_condv;
	struct iovec *iovecs;		/* index 0 is reserved for msghdr   */
	int iovcnt;
	int iovmax;
	size_t msglen;
	uint32_t seq;
};

/* +3 for sending template, orig and reply on next */
#define iovecs_full(x, w) (((w) && (x)->iovcnt + 3 >= (int)(x)->iovmax) || ((x)->iovcnt + 1 >= (int)(x)->iovmax))

#define UPTIME_FILE  "/proc/uptime"	/* for uptime_fd */
#define NURS_NFLOW9_TMPL_BASE 256	/* 5.2 Template FlowSet Format
					 * for next_template_id */

// #define DEBUG_TMMAP
#ifdef DEBUG_TMMAP
#include <sys/mman.h>
FILE *mmfd;
void *mmaddr;
static int nflow9_fprintf_header(FILE *fd, const struct nflow9_priv *priv);
#endif


static struct nflow9_template *
alloc_template(struct nflow9_priv *priv,
	       const struct nurs_input *input,
	       struct nfct_bitmask *bm)
{
	struct nflow9_template *tmpl;
	uint16_t i, input_len = nurs_input_len(input);
	size_t tmpl_len = 0, data_len = 0;

	for (i = 0; i < input_len; i++) {
		if (!nfct_bitmask_test_bit(bm, i))
			continue;

		/* ignore reply for unidirection */
		if (i == priv->cntidxs[CII_REPLY_RAW_PKTLEN_DELTA] ||
		    i == priv->cntidxs[CII_REPLY_RAW_PKTCOUNT_DELTA] ||
		    i == priv->cntidxs[CII_REPLY_IP_PROTOCOL])
			continue;

		tmpl_len += sizeof(struct nflow9_tmpl_rec);
		data_len += nurs_input_size(input, i);
	}

	tmpl = calloc(1, sizeof(struct nflow9_template));
	if (!tmpl)
		return NULL;

	for (i = 0; i < FOI_MAX; i++)
		tmpl->offset[i] = UINTPTR_MAX; /* as invalid */

	tmpl->bitmask = nfct_bitmask_clone(bm);
	if (!tmpl->bitmask)
		goto free_tmpl;

	tmpl->dataset_len = sizeof(struct nflow9_sethdr) + data_len;
	tmpl->tmplset_len = sizeof(struct nflow9_sethdr)
		+ sizeof(struct nflow9_tmpl_hdr) + tmpl_len;
	/* 5.3.	 Data FlowSet Format / Padding */
	tmpl->dataset_len = (tmpl->dataset_len + 3U) & ~3U;
	tmpl->tmplset_len = (tmpl->tmplset_len + 3U) & ~3U;

	tmpl->template = calloc(1, tmpl->tmplset_len);
	if (!tmpl->template)
		goto free_bitmask;
	tmpl->sethdrs_max = priv->iovmax - 1;
	tmpl->sethdrs = calloc((size_t)tmpl->sethdrs_max, tmpl->dataset_len);
	if (!tmpl->sethdrs)
		goto free_template;

	return tmpl;

free_template:
	free(tmpl->template);
free_bitmask:
	nfct_bitmask_destroy(tmpl->bitmask);
free_tmpl:
	free(tmpl);

	return NULL;
}

/* Build the NetFlow v9 template from the input keys */
static struct nflow9_template *
create_template(struct nflow9_priv *priv,
	       const struct nurs_input *input,
	       struct nfct_bitmask *bm)
{
	struct nflow9_template *tmpl;
	struct nflow9_tmpl_hdr *tmpl_hdr;
	struct nflow9_tmpl_rec *tmpl_rec;
	struct nflow9_sethdr *set_hdr;
	uint16_t field_id, field_count = 0;
	uintptr_t offset = 0;
	uint16_t i, j, input_size, input_len = nurs_input_len(input);
	const char *name;
        pthread_mutexattr_t attr;

	tmpl = alloc_template(priv, input, bm);
	if (!tmpl)
		return NULL;

        pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, NURS_MUTEX_ATTR);
	if (pthread_mutex_init(&tmpl->sethdrs_mutex, &attr)) {
		nurs_log(NURS_FATAL, "pthread_mutex_init: %s\n",
			 _sys_errlist[errno]);
		return NULL;
	}
	if (pthread_cond_init(&tmpl->sethdrs_condv, NULL)) {
		nurs_log(NURS_FATAL, "pthread_cond_init: %s\n",
			 _sys_errlist[errno]);
		return NULL;
	}

	/* build template records */
	tmpl_rec = (struct nflow9_tmpl_rec *)
		((uintptr_t)tmpl->template
		 + sizeof(struct nflow9_sethdr)
		 + sizeof(struct nflow9_tmpl_hdr));
	for (i = 0; i < input_len; i++) {
		if (!nfct_bitmask_test_bit(tmpl->bitmask, i))
			continue;

		if (i == priv->cntidxs[CII_REPLY_RAW_PKTLEN_DELTA] ||
		    i == priv->cntidxs[CII_REPLY_RAW_PKTCOUNT_DELTA] ||
		    i == priv->cntidxs[CII_REPLY_IP_PROTOCOL])
			continue;

		/* XXX: search swap related field and set its offset */
		name = nurs_input_name(input, i);
		for (j = 0; j < FOI_MAX; j++) {
			if (!strcmp(name, dir_keys[j])) {
				tmpl->offset[j] = offset;
				break;
			}
		}

		input_size = nurs_input_size(input, i);
		field_id = nurs_input_ipfix_field(input, i);
		tmpl_rec->type = htons(ipfix_map[field_id]);
		tmpl_rec->length = htons(input_size);
		tmpl_rec++;
		field_count++;
		offset += input_size;
	}

	/* initialize template set header */
	tmpl->template->set_id = htons(0); /* 5.2 Template FlowSet Format */
	tmpl->template->length = htons(tmpl->tmplset_len);

	/* initialize template record header */
	tmpl_hdr = (struct nflow9_tmpl_hdr *)((uintptr_t)tmpl->template
					      + sizeof(struct nflow9_sethdr));
	tmpl_hdr->template_id = htons(priv->next_template_id++);
	tmpl_hdr->field_count = htons(field_count);

	/* initialize data buffer */
	for (i = 0; i < priv->iovmax - 1; i++) {
		set_hdr = (struct nflow9_sethdr *)((uintptr_t)tmpl->sethdrs
						   + i * tmpl->dataset_len);
		set_hdr->set_id = tmpl_hdr->template_id;
		set_hdr->length = htons(tmpl->dataset_len);
	}

	return tmpl;
}

static struct nflow9_template *
find_template(struct nflow9_priv *priv, struct nfct_bitmask *bm)
{
	struct nflow9_template *tmpl;

	/* FIXME: this can be done more efficient! */
	list_for_each_entry(tmpl, &priv->tmpls, list)
		if (nfct_bitmask_equal(bm, tmpl->bitmask))
			return tmpl;

	return NULL;
}

static struct nflow9_template *
lookup_template(struct nflow9_priv *priv, const struct nurs_input *input,
		struct nfct_bitmask *bm)
{
	struct nflow9_template *tmpl;

	if (nurs_mutex_lock(&priv->tmpls_mutex))
		return NULL;

	tmpl = find_template(priv, bm);
	if (!tmpl) {
		tmpl = create_template(priv, input, bm);
		if (!tmpl) {
			nurs_log(NURS_ERROR, "failed to create template\n");
			goto exit;
		}
		list_add(&tmpl->list, &priv->tmpls);
	}
exit:
	if (nurs_mutex_unlock(&priv->tmpls_mutex))
		return NULL;

	return tmpl;
}

static struct nflow9_sethdr *get_sethdr(struct nflow9_template *tmpl)
{
	struct nflow9_sethdr *sethdr;
	void *data;

	if (nurs_mutex_lock(&tmpl->sethdrs_mutex))
		return NULL;
	while (tmpl->sethdrs_pos >= tmpl->sethdrs_max) {
		if (nurs_cond_wait(&tmpl->sethdrs_condv,
				   &tmpl->sethdrs_mutex)) {
			nurs_mutex_unlock(&tmpl->sethdrs_mutex);
			return NULL;
		}
	}

	sethdr = (struct nflow9_sethdr *)
		((uintptr_t)tmpl->sethdrs
		 + (uintptr_t)(tmpl->sethdrs_pos * (int)tmpl->dataset_len));
	data = nflow9_data(sethdr);
	memset(data, 0, tmpl->dataset_len - sizeof(struct nflow9_sethdr));
	tmpl->sethdrs_pos++;

	if (nurs_mutex_unlock(&tmpl->sethdrs_mutex))
		return NULL;

	return sethdr;
}

static struct nflow9_sethdr *
build_sethdr(struct nflow9_priv *priv, const struct nurs_input *input,
	     struct nflow9_template *tmpl)
{
	struct nflow9_sethdr *sethdr = get_sethdr(tmpl);
	void *buf = nflow9_data(sethdr);
	size_t buflen = tmpl->dataset_len;
	uint16_t i, input_len = nurs_input_len(input);
	int ret;

	if (!sethdr) return NULL;

	for (i = 0; i < input_len; i++) {
		if (!nfct_bitmask_test_bit(tmpl->bitmask, i))
			continue;

		/* store orig temporarily to (unidirectional) counter */
		if (i == priv->cntidxs[CII_REPLY_RAW_PKTLEN_DELTA] ||
		    i == priv->cntidxs[CII_REPLY_RAW_PKTCOUNT_DELTA] ||
		    i == priv->cntidxs[CII_REPLY_IP_PROTOCOL])
			continue;

		ret = nurs_key_putn(input, i, buf, buflen);
		if (ret < 0)
			return NULL;

		buf = (void *)((uintptr_t)buf + (uintptr_t)ret);
		buflen -= (size_t)ret;
	}

	return sethdr;
}

static void swap(void *data, size_t size, uintptr_t pos1, uintptr_t pos2)
{
	uint8_t tmp[16] = {}; /* 16: ip6 addr len */
	memcpy(tmp, (void *)((uintptr_t)data + pos1), size);
	memcpy((void *)((uintptr_t)data + pos1),
	       (void *)((uintptr_t)data + pos2), size);
	memcpy((void *)((uintptr_t)data + pos2), tmp, size);
}

#define TOF(i)	tmpl->offset[(i)]

static int orig_swap(struct nflow9_template *tmpl,
		     uint8_t family, void *buf)
{
	switch (family) {
	case AF_INET:
		swap(buf, sizeof(struct in_addr ),
		     TOF(FOI_REPLY_IP_SADDR), TOF(FOI_REPLY_IP_DADDR));
		break;
	case AF_INET6:
		swap(buf, sizeof(struct in6_addr ),
		     TOF(FOI_REPLY_IP6_SADDR), TOF(FOI_REPLY_IP6_DADDR));
		break;
	default:
		nurs_log(NURS_ERROR, "unknown family: %d", family);
		return -1;
	}
	if (TOF(FOI_REPLY_L4_SPORT) < UINTPTR_MAX &&
	    TOF(FOI_REPLY_L4_DPORT) < UINTPTR_MAX)
		swap(buf, sizeof(uint16_t),
		     TOF(FOI_REPLY_L4_SPORT), TOF(FOI_REPLY_L4_DPORT));

	return 0;
}

static int reply_swap(struct nflow9_template *tmpl,
		      uint8_t family, void *buf)
{
	switch (family) {
	case AF_INET:
		swap(buf, sizeof(struct in_addr),
		     TOF(FOI_ORIG_IP_SADDR), TOF(FOI_ORIG_IP_DADDR));
		break;
	case AF_INET6:
		swap(buf, sizeof(struct in6_addr ),
		     TOF(FOI_ORIG_IP_SADDR), TOF(FOI_ORIG_IP_DADDR));
		break;
	default:
		nurs_log(NURS_ERROR, "unknown family: %d", family);
		return -1;
	}
	if (TOF(FOI_ORIG_L4_SPORT) < UINTPTR_MAX &&
	    TOF(FOI_ORIG_L4_DPORT) < UINTPTR_MAX)
		swap(buf, sizeof(uint16_t),
		     TOF(FOI_ORIG_L4_SPORT), TOF(FOI_ORIG_L4_DPORT));
	if (TOF(FOI_IF_INPUT) < UINTPTR_MAX &&
	    TOF(FOI_IF_OUTPUT) < UINTPTR_MAX)
		swap(buf, sizeof(uint32_t),
		     TOF(FOI_IF_INPUT), TOF(FOI_IF_OUTPUT));
	if (TOF(FOI_FLOW_DIR) < UINTPTR_MAX)
		*(uint8_t *)((uintptr_t)buf + TOF(FOI_FLOW_DIR))
			= !*(uint8_t *)((uintptr_t)buf + TOF(FOI_FLOW_DIR));

	return 0;
}

static int swap_by_dir(struct nflow9_template *tmpl,
		       void *buf, uint8_t family, int direction,
		       uint64_t bytes, uint64_t packets)
{
	switch (direction) {
	case NFLOW9_DIR_ORIG:
		if (orig_swap(tmpl, family, buf) < 0)
			return -1;
		break;

	case NFLOW9_DIR_REPLY:
		if (reply_swap(tmpl, family, buf) < 0)
			return -1;
		break;
	default:
		nurs_log(NURS_ERROR, "unknown dir: %d", direction);
		return -1;
	}

	if (TOF(FOI_IN_BYTES) < UINTPTR_MAX)
		*(uint64_t *)((uintptr_t)buf + TOF(FOI_IN_BYTES))
			= __cpu_to_be64(bytes);
	if (TOF(FOI_IN_PKTS) < UINTPTR_MAX)
		*(uint64_t *)((uintptr_t)buf + TOF(FOI_IN_PKTS))
			= __cpu_to_be64(packets);

	return 0;
}
#undef TOF

static int nflow9_direction(struct nflow9_priv *priv,
			    const struct nurs_input *input, uint8_t *family,
			    uint64_t *obytes, uint64_t *opkts,
			    uint64_t *rbytes, uint64_t *rpkts)
{
	int ret = 0;
	uint16_t obytes_idx = priv->cntidxs[CII_ORIG_RAW_PKTLEN_DELTA],
		opkts_idx = priv->cntidxs[CII_ORIG_RAW_PKTCOUNT_DELTA],
		rbytes_idx = priv->cntidxs[CII_REPLY_RAW_PKTLEN_DELTA],
		rpkts_idx = priv->cntidxs[CII_REPLY_RAW_PKTCOUNT_DELTA],
		family_idx = priv->cntidxs[CII_FAMILY];

	if (obytes_idx < UINT16_MAX &&
	    nurs_input_is_valid(input, obytes_idx)) {
		*obytes = nurs_input_u64(input, obytes_idx);
		if (*obytes > 0) {
			*opkts = nurs_input_u64(input, opkts_idx);
			ret |= NFLOW9_DIR_ORIG;
		}
	}
	if (rbytes_idx != UINT16_MAX &&
	    nurs_input_is_valid(input, rbytes_idx)) {
		*rbytes = nurs_input_u64(input, rbytes_idx);
		if (*rbytes > 0) {
			*rpkts = nurs_input_u64(input, rpkts_idx);
			ret |= NFLOW9_DIR_REPLY;
		}
	}
	*family = nurs_input_u8(input, family_idx);

	return ret;
}

static int add_iovec(struct nflow9_priv *priv, struct nflow9_template *tmpl,
		     struct nflow9_sethdr *sethdr, bool wait)
{
	int ret = 0;

	if ((ret = nurs_mutex_lock(&priv->vecs_mutex)))
		return ret;
	while (iovecs_full(priv, wait)) {
		ret = nurs_cond_wait(&priv->vecs_condv, &priv->vecs_mutex);
		if (ret) goto unlock;
	}

	if (!tmpl->until_template) {
		tmpl->until_template = priv->nth_template;

		priv->iovecs[priv->iovcnt].iov_base = tmpl->template;
		priv->iovecs[priv->iovcnt].iov_len = tmpl->tmplset_len;
		priv->msglen += tmpl->tmplset_len;
		priv->iovcnt++;
	}
	tmpl->until_template--;
	priv->iovecs[priv->iovcnt].iov_base = sethdr;
	priv->iovecs[priv->iovcnt].iov_len = tmpl->dataset_len;
	priv->msglen += tmpl->dataset_len;
	priv->iovcnt++;

unlock:
	ret = nurs_mutex_unlock(&priv->vecs_mutex);
	return ret;
}

static int add_sethdr(struct nflow9_priv *priv, const struct nurs_input *input,
		      struct nflow9_template *tmpl)
{
	struct nflow9_sethdr *sethdr = build_sethdr(priv, input, tmpl);
	void *buf = nflow9_data(sethdr);
	uint8_t family = 0;
	uint64_t obytes = 0, opackets = 0;
	uint64_t rbytes = 0, rpackets = 0;
	int dir;

	if (!sethdr) {
		nurs_log(NURS_ERROR, "could not build netflow v9 dataset\n");
		return -1;
	}

	dir = nflow9_direction(priv, input, &family,
			       &obytes, &opackets, &rbytes, &rpackets);
	switch (dir) {
	case NFLOW9_DIR_ORIG:
		swap_by_dir(tmpl, buf, family, dir, obytes, opackets);
		add_iovec(priv, tmpl, sethdr, true);
		break;

	case NFLOW9_DIR_REPLY:
		swap_by_dir(tmpl, buf, family, dir, rbytes, rpackets);
		add_iovec(priv, tmpl, sethdr, true);
		break;

	case NFLOW9_DIR_BOTH:
		swap_by_dir(tmpl, buf, family, NFLOW9_DIR_ORIG,
			    obytes, opackets);
		add_iovec(priv, tmpl, sethdr, true);

		sethdr = build_sethdr(priv, input, tmpl);
		if (!sethdr) {
			nurs_log(NURS_ERROR,
				  "could not build netflow v9 dataset");
			return -1;
		}
		buf = nflow9_data(sethdr);
		swap_by_dir(tmpl, buf, family, NFLOW9_DIR_REPLY,
			    rbytes, rpackets);
		add_iovec(priv, tmpl, sethdr, false);
		break;

	case NFLOW9_DIR_NONE:
		nurs_log(NURS_DEBUG, "receive zero counter data\n");
		return 0;
		break;

	default:
		nurs_log(NURS_ERROR, "nflow9_direction() returns invalid");
		return -1;
		break;
	}

	return 0;
}

static uint32_t uptime_millis(struct nflow9_priv *priv)
{
	char buf[1024] = {0};
	double up;
	ssize_t nread;

	lseek(priv->uptime_fd, 0, SEEK_SET);
	nread = read(priv->uptime_fd, buf, sizeof(buf) - 1);
	if (nread == -1)
		return 0;
	if (sscanf(buf, "%lf", &up) != 1)
		return 0;
	return (uint32_t)(up * 1000);
}

static ssize_t send_nflow9(struct nflow9_priv *priv, bool force)
{
	ssize_t nsent, ret = 0;
	struct nflow9_template *tmpl;

	if ((ret = nurs_mutex_lock(&priv->vecs_mutex)))
		goto exit;
	if (!iovecs_full(priv, true) && !force)
		goto unlock;

	priv->msghdr.sys_uptime = htonl(uptime_millis(priv));
	priv->msghdr.unix_secs = htonl((uint32_t)time(NULL));
	priv->msghdr.count = htons(priv->iovcnt - 1); /* except header */
	priv->msghdr.sequence_number = htonl(++priv->seq);
	priv->msglen += sizeof(struct nflow9_msghdr);

#ifdef DEBUG_TMMAP
	nflow9_fprintf_header(stdout, priv);
	fflush(stdout);
#endif
	nsent = writev(priv->fd, priv->iovecs, priv->iovcnt);
	if (nsent == -1) {
		nurs_log(NURS_ERROR, "failed to send: %s\n",
			 _sys_errlist[errno]);
	} else if (nsent != (ssize_t)priv->msglen) {
		nurs_log(NURS_ERROR, "could not send all - attempt: %d,"
			 " but: %d\n", priv->msglen, nsent);
	}
	ret = nsent - (ssize_t)priv->msglen;
	priv->msglen = 0;
	priv->iovcnt = 1;

	/* XXX: not neat */
	if ((ret = nurs_mutex_lock(&priv->tmpls_mutex)))
		goto unlock;
	list_for_each_entry(tmpl, &priv->tmpls, list) {
		nurs_mutex_lock(&tmpl->sethdrs_mutex);
		tmpl->sethdrs_pos = 0;
		nurs_cond_broadcast(&tmpl->sethdrs_condv);
		nurs_mutex_unlock(&tmpl->sethdrs_mutex);
	}
	if ((ret = nurs_mutex_unlock(&priv->tmpls_mutex)))
		goto unlock;
	if ((ret = nurs_cond_broadcast(&priv->vecs_condv)))
		goto unlock;
unlock:
	ret = nurs_mutex_unlock(&priv->vecs_mutex);
exit:
	return ret;
}

static enum nurs_return_t
nflow9_interp(const struct nurs_plugin *plugin, const struct nurs_input *input)
{
	struct nflow9_priv *priv = nurs_plugin_context(plugin);
	struct nflow9_template *tmpl;
	struct nfct_bitmask *validmask;
	uint16_t i, field_id, input_len = nurs_input_len(input);
	enum nurs_return_t ret = NURS_RET_ERROR;

	/* FIXME: it would be more cache efficient if the IS_VALID
	 * flags would be a separate bitmask outside of the array.
	 * nurs core could very easily flush it after every packet,
	 * too. */
	validmask = nfct_bitmask_new(input_len); /* can be a TLS */
	if (!validmask) {
		nurs_log(NURS_ERROR, "failed to create nfct_bitmask\n");
		return NURS_RET_ERROR;
	}

	for (i = 0; i < input_len; i++) {
		if (!nurs_input_is_valid(input, i))
			continue;
		field_id = nurs_input_ipfix_field(input, i);
		if (!field_id)
			continue;
		if (!ipfix_map[field_id])
			continue;
		nfct_bitmask_set_bit(validmask, i);
	}

	tmpl = lookup_template(priv, input, validmask);
	if (!tmpl) {
		nurs_log(NURS_ERROR, "failed to lookup template\n");
		goto destroy_bitmask;
	}

	if (add_sethdr(priv, input, tmpl)) {
		nurs_log(NURS_ERROR, "failed to build message\n");
		/* reset_counters(priv); XXX: ? */
		goto destroy_bitmask;
	}

	if (!send_nflow9(priv, false))
		ret = NURS_RET_OK;

destroy_bitmask:
	nfct_bitmask_destroy(validmask);
	return ret;
}

static enum nurs_return_t
nflow9_signal(const struct nurs_plugin *plugin, uint32_t signum)
{
	switch (signum) {
	default:
		nurs_log(NURS_DEBUG, "receive signal: %d\n", signum);
		break;
	}
	return NURS_RET_OK;
}

static enum nurs_return_t
nflow9_organize(const struct nurs_plugin *plugin,
		const struct nurs_input *input)
{
	struct nflow9_priv *priv = nurs_plugin_context(plugin);
        pthread_mutexattr_t attr;
	uint16_t i, j, input_len = nurs_input_len(input);
	int ret;

	ret = config_corksets_max(plugin);
	if (ret < 3) {
		nurs_log(NURS_ERROR, "corksets_max should be more than 3"
			 " from implementation perspective\n");
		return NURS_RET_ERROR;
	}
	priv->iovmax = ret + 1;	/* +1 for msghdr */

	ret = config_nth_template(plugin);
	if (ret < 1) {
		nurs_log(NURS_ERROR, "invalid nth_template: %d\n", ret);
		return NURS_RET_ERROR;
	}
	priv->nth_template = ret;

	priv->iovecs = calloc((size_t)priv->iovmax, sizeof(struct iovec));
	if (!priv->iovecs) {
		nurs_log(NURS_ERROR, "failed to alloc iovecs: %s\n",
			 _sys_errlist[errno]);
		return NURS_RET_ERROR;
	}

	priv->uptime_fd = open(UPTIME_FILE, O_RDONLY);
	if (priv->uptime_fd == -1) {
		nurs_log(NURS_ERROR, "failed to open uptime fd: %s\n",
			 _sys_errlist[errno]);
		goto free_iovecs;
	}

	priv->fd = open_connect_descriptor(config_dest(plugin));
	if (priv->fd < 0) {
		nurs_log(NURS_ERROR, "failed to open descriptor: %s\n",
			 _sys_errlist[errno]);
		goto close_uptime_fd;
	}

	/* search key index for direction conditions and converts */
	for (i = 0; i < CII_MAX; i++)
		priv->cntidxs[i] = UINT16_MAX; /* as invalid */
	for (i = 0; i < input_len; i++) {
		if (!nurs_input_is_active(input, i))
			continue;
		for (j = 0; j < CII_MAX; j++) {
			if (!strcmp(nurs_input_name(input, i),
				    counter_keys[j])) {
				priv->cntidxs[j] = i;
				break;
			}
		}
	}
	/* check all CII has gotten */
	for (i = 0; i < CII_MAX; i++) {
		if (priv->cntidxs[i] == UINT16_MAX) {
			nurs_log(NURS_ERROR, "could not find counter key: %s\n",
				 counter_keys[i]);
			goto close_connection;
		}
	}

	/* initialize netflow v9 message header */
	priv->msghdr.version = htons(9);
	priv->msghdr.source_id = htonl(config_domain(plugin));
	priv->iovecs[0].iov_base = &priv->msghdr;
	priv->iovecs[0].iov_len = sizeof(priv->msghdr);
	priv->iovcnt = 1;
	priv->next_template_id = NURS_NFLOW9_TMPL_BASE;
	init_list_head(&priv->tmpls);

        pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, NURS_MUTEX_ATTR);
	if ((ret = pthread_mutex_init(&priv->tmpls_mutex, &attr))) {
		nurs_log(NURS_FATAL, "pthread_mutex_init: %s\n",
			 _sys_errlist[errno]);
		goto close_connection;
	}
	if ((ret = pthread_mutex_init(&priv->vecs_mutex, &attr))) {
		nurs_log(NURS_FATAL, "pthread_mutex_init: %s\n",
			 _sys_errlist[errno]);
		goto destroy_tmpls_mutex;
	}
	if ((ret = pthread_cond_init(&priv->vecs_condv, NULL))) {
		nurs_log(NURS_FATAL, "pthread_cond_init: %s\n",
			 _sys_errlist[errno]);
		goto destroy_vecs_mutex;
	}

#ifdef DEBUG_TMMAP
	mmfd = tmpfile();
	if (!mmfd) {
		nurs_log(NURS_ERROR, "failed to open debug file\n");
		goto destroy_vecs_mutex;
	}
	mmaddr = mmap(NULL, 65507, PROT_READ | PROT_WRITE, MAP_PRIVATE, fileno(mmfd), 0);
	if (mmaddr == MAP_FAILED) {
		nurs_log(NURS_ERROR, "failed to mmap debug file\n");
		fclose(mmfd);
		goto destroy_vecs_mutex;
	}
#endif
	return NURS_RET_OK;

destroy_vecs_mutex:
	pthread_mutex_destroy(&priv->vecs_mutex);
destroy_tmpls_mutex:
	pthread_mutex_destroy(&priv->tmpls_mutex);
close_connection:
	close(priv->fd);
close_uptime_fd:
	close(priv->uptime_fd);
free_iovecs:
	free(priv->iovecs);
	return NURS_RET_ERROR;
}

static enum nurs_return_t
nflow9_disorganize(const struct nurs_plugin *plugin)
{
	struct nflow9_priv *priv = nurs_plugin_context(plugin);
	int ret = 0;

#ifdef DEBUG_TMMAP
	ret |= munmap(mmaddr, 65507);
	ret |= fclose(mmfd);
#endif
	ret |= close(priv->fd);
	ret |= close(priv->uptime_fd);
	ret |= pthread_cond_destroy(&priv->vecs_condv);
	ret |= pthread_mutex_destroy(&priv->vecs_mutex);
	ret |= pthread_mutex_destroy(&priv->tmpls_mutex);

	/* XXX: release templates buf? */
	free(priv->iovecs);
	if (ret)
		return NURS_RET_ERROR;
	return NURS_RET_OK;
}

static enum nurs_return_t nflow9_stop(const struct nurs_plugin *plugin)
{
	struct nflow9_priv *priv = nurs_plugin_context(plugin);
	struct nflow9_template *tmpl, *tmp;

	if (priv->iovcnt)
		send_nflow9(priv, true);

	list_for_each_entry_safe(tmpl, tmp, &priv->tmpls, list) {
		nfct_bitmask_destroy(tmpl->bitmask);
		free(tmpl->template);
		free(tmpl->sethdrs);
		pthread_mutex_destroy(&tmpl->sethdrs_mutex);
		pthread_cond_destroy(&tmpl->sethdrs_condv);
		list_del(&tmpl->list);
		free(tmpl);
	}

	return NURS_RET_OK;
}

static struct nurs_coveter_def nflow9_coveter = {
	.name		= "NFLOW9",
	.version	= VERSION,
	.context_size	= sizeof(struct nflow9_priv),
	.mtsafe		= true,
	.config_def	= &nflow9_config,
	.organize	= nflow9_organize,
	.disorganize	= nflow9_disorganize,
	.stop		= nflow9_stop,
	.interp		= nflow9_interp,
	.signal		= nflow9_signal,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	nurs_coveter_register(&nflow9_coveter);
}

#ifdef DEBUG_TMMAP
static char *nflow9_field_name[] = {
	[NFLOW9_IN_BYTES]			= "IN_BYTES",
	[NFLOW9_IN_PKTS]			= "IN_PKTS",
	[NFLOW9_FLOWS]				= "FLOWS",
	[NFLOW9_PROTOCOL]			= "PROTOCOL",
	[NFLOW9_TOS]				= "TOS",
	[NFLOW9_TCP_FLAGS]			= "TCP_FLAGS",
	[NFLOW9_L4_SRC_PORT]			= "L4_SRC_PORT",
	[NFLOW9_IPV4_SRC_ADDR]			= "IPV4_SRC_ADDR",
	[NFLOW9_SRC_MASK]			= "SRC_MASK",
	[NFLOW9_INPUT_SNMP]			= "INPUT_SNMP",
	[NFLOW9_L4_DST_PORT]			= "L4_DST_PORT",
	[NFLOW9_IPV4_DST_ADDR]			= "IPV4_DST_ADDR",
	[NFLOW9_DST_MASK]			= "DST_MASK",
	[NFLOW9_OUTPUT_SNMP]			= "OUTPUT_SNMP",
	[NFLOW9_IPV4_NEXT_HOP]			= "IPV4_NEXT_HOP",
	[NFLOW9_SRC_AS]				= "SRC_AS",
	[NFLOW9_DST_AS]				= "DST_AS",
	[NFLOW9_BGP_IPV4_NEXT_HOP]		= "BGP_IPV4_NEXT_HOP",
	[NFLOW9_MUL_DST_PKTS]			= "MUL_DST_PKTS",
	[NFLOW9_MUL_DST_BYTES]			= "MUL_DST_BYTES",
	[NFLOW9_LAST_SWITCHED]			= "LAST_SWITCHED",
	[NFLOW9_FIRST_SWITCHED]			= "FIRST_SWITCHED",
	[NFLOW9_OUT_BYTES]			= "OUT_BYTES",
	[NFLOW9_OUT_PKTS]			= "OUT_PKTS",
	[NFLOW9_IPV6_SRC_ADDR]			= "IPV6_SRC_ADDR",
	[NFLOW9_IPV6_DST_ADDR]			= "IPV6_DST_ADDR",
	[NFLOW9_IPV6_SRC_MASK]			= "IPV6_SRC_MASK",
	[NFLOW9_IPV6_DST_MASK]			= "IPV6_DST_MASK",
	[NFLOW9_FLOW_LABEL]			= "FLOW_LABEL",
	[NFLOW9_ICMP_TYPE]			= "ICMP_TYPE",
	[NFLOW9_MUL_IGMP_TYPE]			= "MUL_IGMP_TYPE",
	[NFLOW9_SAMPLING_INTERVAL]		= "SAMPLING_INTERVAL",
	[NFLOW9_SAMPLING_ALGORITHM]		= "SAMPLING_ALGORITHM",
	[NFLOW9_FLOW_ACTIVE_TIMEOUT]		= "FLOW_ACTIVE_TIMEOUT",
	[NFLOW9_FLOW_INAVTIVE_TIMEOUT]		= "FLOW_INAVTIVE_TIMEOUT",
	[NFLOW9_ENGINE_TYPE]			= "ENGINE_TYPE",
	[NFLOW9_ENGINE_ID]			= "ENGINE_ID",
	[NFLOW9_TOTAL_BYTES_EXP]		= "TOTAL_BYTES_EXP",
	[NFLOW9_TOTAL_PKTS_EXP]			= "TOTAL_PKTS_EXP",
	[NFLOW9_TOTAL_FLOWS_EXP]		= "TOTAL_FLOWS_EXP",
	[NFLOW9_MPLS_TOP_LABEL_TYPE]		= "MPLS_TOP_LABEL_TYPE",
	[NFLOW9_MPLS_TOP_LABEL_IP_ADDR]		= "MPLS_TOP_LABEL_IP_ADDR",
	[NFLOW9_FLOW_SAMPLER_ID]		= "FLOW_SAMPLER_ID",
	[NFLOW9_FLOW_SAMPLER_MODE]		= "FLOW_SAMPLER_MODE",
	[NFLOW9_FLOW_SAMPLER_RANDOM_INTERVAL] 	= "FLOW_SAMPLER_RANDOM_INTERVAL",
	[NFLOW9_DST_TOS]			= "DST_TOS",
	[NFLOW9_SRC_MAC]			= "SRC_MAC",
	[NFLOW9_DST_MAC]			= "DST_MAC",
	[NFLOW9_SRC_VLAN]			= "SRC_VLAN",
	[NFLOW9_DST_VLAN]			= "DST_VLAN",
	[NFLOW9_IP_PROTOCOL_VERSION]		= "IP_PROTOCOL_VERSION",
	[NFLOW9_DIRECTION]			= "DIRECTION",
	[NFLOW9_IPV6_NEXT_HOP]			= "IPV6_NEXT_HOP",
	[NFLOW9_BGP_IPV6_NEXT_HOP]		= "BGP_IPV6_NEXT_HOP",
	[NFLOW9_IPV6_OPTION_HEADERS]		= "IPV6_OPTION_HEADERS",
	[NFLOW9_MPLS_LABEL_1]			= "MPLS_LABEL_1",
	[NFLOW9_MPLS_LABEL_2]			= "MPLS_LABEL_2",
	[NFLOW9_MPLS_LABEL_3]			= "MPLS_LABEL_3",
	[NFLOW9_MPLS_LABEL_4]			= "MPLS_LABEL_4",
	[NFLOW9_MPLS_LABEL_5]			= "MPLS_LABEL_5",
	[NFLOW9_MPLS_LABEL_6]			= "MPLS_LABEL_6",
	[NFLOW9_MPLS_LABEL_7]			= "MPLS_LABEL_7",
	[NFLOW9_MPLS_LABEL_8]			= "MPLS_LABEL_8",
	[NFLOW9_MPLS_LABEL_9]			= "MPLS_LABEL_9",
	[NFLOW9_MPLS_LABEL_10]			= "MPLS_LABEL_10",
	[NFLOW9_IPV4_XLATE_SRC_ADDR]		= "IPV4_XLATE_SRC_ADDR",
	[NFLOW9_IPV4_XLATE_DST_ADDR]		= "IPV4_XLATE_DST_ADDR",
	[NFLOW9_L4_XLATE_SRC_PORT]		= "L4_XLATE_SRC_PORT",
	[NFLOW9_L4_XLATE_DST_PORT]		= "L4_XLATE_DST_PORT",
	[NFLOW9_IPV6_XLATE_SRC_ADDR]		= "IPV6_XLATE_SRC_ADDR",
	[NFLOW9_IPV6_XLATE_DST_ADDR]		= "IPV6_XLATE_DST_ADDR",
};

static int nflow9_fprintf_field(FILE *fd, const struct nflow9_tmpl_rec *field, size_t len)
{
	int ret;
	void *ptr;

	if (len < sizeof(*field)) {
		fprintf(fd, "ERROR ietf field: too short buflen: %lu\n", len);
		return -1;
	}

	fprintf(fd, "+---------------------------------+---------------------------------+\n");
	fprintf(fd, "| Field Type: %19s |             Field Length: %5d |\n",
		nflow9_field_name[ntohs(field->type)], ntohs(field->length));

	if (len <= sizeof(*field))
		return sizeof(*field);
	len -= (int)sizeof(*field);

	ptr = (void *)((uintptr_t)field + sizeof(*field));
	ret = nflow9_fprintf_field(fd, ptr, len);
	if (ret == -1)
		return -1;
	return ret + (int)sizeof(*field);
}

static int nflow9_fprintf_data_records(FILE *fd, const void *data, size_t len)
{
	uintptr_t i;
	int over;

	fprintf(fd, "+-------------------------------------------------------------------+\n");
	/* don't say messy...*/
	for (i = 0; i < len; i += 4) {
		over = (int)len - (int)i - 4;
		switch (over) {
		case -3:
			fprintf(fd, "|          0x%02x                                                   |\n",
				*(uint8_t *)((uintptr_t)data + i));
			break;
		case -2:
			fprintf(fd, "|          0x%02x           0x%02x                                     |\n",
				*(uint8_t *)((uintptr_t)data + i),
				*(uint8_t *)((uintptr_t)data + i + 1));
			break;
		case -1:
			fprintf(fd, "|          0x%02x           0x%02x          0x%02x                       |\n",
				*(uint8_t *)((uintptr_t)data + i),
				*(uint8_t *)((uintptr_t)data + i + 1),
				*(uint8_t *)((uintptr_t)data + i + 2));
			break;
		default:
			fprintf(fd, "|          0x%02x           0x%02x          0x%02x           0x%02x         |\n",
				*(uint8_t *)((uintptr_t)data + i),
				*(uint8_t *)((uintptr_t)data + i + 1),
				*(uint8_t *)((uintptr_t)data + i + 2),
				*(uint8_t *)((uintptr_t)data + i + 3));
			break;
		}
	}

	return (int)len;
}

static int nflow9_fprintf_template_records(FILE *fd, const struct nflow9_tmpl_hdr *hdr, size_t len)
{
	int ret;
	void *field;

	if (len < (int)sizeof(*hdr)) {
		fprintf(fd, "ERROR template records: too short buflen for template record: %lu\n", len);
		return -1;
	}

	fprintf(fd, "+---------------------------------+---------------------------------+\n");
	fprintf(fd, "|              Template ID: %5d |              Field Count: %5d |\n",
		ntohs(hdr->template_id), ntohs(hdr->field_count));

	len -= sizeof(*hdr);
	if (len == 0)
		return sizeof(*hdr);

	field = (void *)((uintptr_t)hdr + sizeof(*hdr));
	ret = nflow9_fprintf_field(fd, field, len);
	if (ret == -1)
		return -1;
	return ret + (int)sizeof(*hdr);
}

static int nflow9_fprintf_set_header(FILE *fd, const struct nflow9_sethdr *hdr, size_t len)
{
	int ret;
	size_t setlen, total_len;
	void *ptr;

	if (len < (int)sizeof(*hdr)) {
		fprintf(fd, "ERROR set header: too short buflen for set header: %lu\n", len);
		return -1;
	}
	setlen = (size_t)ntohs(hdr->length);
	if (len < setlen) {
		fprintf(fd, "ERROR set header: buflen: %lu is smaller than set length field: %lu\n", len, setlen);
		/* return -1; */
	}
	if (setlen < (int)sizeof(*hdr)) {
		fprintf(fd, "ERROR set header: too short set length field: %lu\n", setlen);
		return -1;
	}

	fprintf(fd, "+---------------------------------+---------------------------------+\n");
	fprintf(fd, "|                   Set ID: %5d |                   Length: %5lu |\n",
		ntohs(hdr->set_id), setlen);

	setlen -= sizeof(*hdr);
	ptr = (void *)((uintptr_t)hdr + sizeof(*hdr));
	total_len = sizeof(*hdr);

	switch (ntohs(hdr->set_id)) {
	case 0:
		ret = nflow9_fprintf_template_records(fd, ptr, setlen);
		break;
	case 1:
		/* XXX: ret = nflow9_fprintf_options_template_records(fd, ptr, setlen); */
		fprintf(fd, "ERROR: options template is not implemented yet, sorry");
		ret = (int)setlen;
		break;
	default:
		ret = nflow9_fprintf_data_records(fd, ptr, setlen);
		break;
	}

	if (ret == -1 || ret != (int)setlen)
		return -1;

	fprintf(fd, "+-------------------------------------------------------------------+\n");
	return ret + (int)total_len;
}

static int _nflow9_fprintf_header(FILE *fd, const struct nflow9_msghdr *hdr, size_t msglen)
{
	int len, ret;
	char outstr[20];
	void *ptr;
	time_t t = (time_t)(ntohl(hdr->unix_secs));
	struct tm *tmp = localtime(&t);

	/* XXX: tmp == NULL and strftime == 0 */
	strftime(outstr, sizeof(outstr), "%F %T", tmp);

	fprintf(fd, "+---------------------------------+---------------------------------+\n");
	fprintf(fd, "|           Version Number: %5d |                    Count: %5d | (Length: %lu) \n",
		ntohs(hdr->version), ntohs(hdr->count), msglen);
	fprintf(fd, "+-------------------------------------------------------------------+\n");
	fprintf(fd, "|                        sysUpTime: %10u                      |\n",
		ntohl(hdr->sys_uptime));
	fprintf(fd, "+---------------------------------+---------------------------------+\n");
	fprintf(fd, "|                        UNIX Secs: %10u                      |\t%s\n",
		ntohl(hdr->unix_secs), outstr);
	fprintf(fd, "+-------------------------------------------------------------------+\n");
	fprintf(fd, "|                  Sequence Number: %10d                      |\n",
		ntohl(hdr->sequence_number));
	fprintf(fd, "+-------------------------------------------------------------------+\n");
	fprintf(fd, "|                        Source ID: %10d                      |\n",
		ntohl(hdr->source_id));
	fprintf(fd, "+-------------------------------------------------------------------+\n");

	len = (int)msglen - (int)sizeof(*hdr);
	ptr = (void *)((uintptr_t)hdr + sizeof(*hdr));

	while (len > 0) {
		ret = nflow9_fprintf_set_header(fd, ptr, (size_t)len);
		if (ret == -1)
			return -1;
		len -= ret;
		ptr = (void *)((uintptr_t)ptr + (uintptr_t)ret);
	}

	return (int)msglen - len;
}

static int nflow9_fprintf_header(FILE *fd, const struct nflow9_priv *priv)
{
	fseek(mmfd, 0, SEEK_SET);
	writev(fileno(mmfd), priv->iovecs, priv->iovcnt);
	return _nflow9_fprintf_header(fd, mmaddr, priv->msglen);
}
#endif

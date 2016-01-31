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
#define NFCT_OUTPUT_ENUM_DEFAULT \
	NFCT_ORIG_IP_SADDR = 0,			\
	NFCT_ORIG_IP_DADDR,			\
	NFCT_ORIG_IP_PROTOCOL,		    	\
	NFCT_ORIG_L4_SPORT,			\
	NFCT_ORIG_L4_DPORT,			\
	NFCT_ORIG_RAW_PKTLEN,			\
	NFCT_ORIG_RAW_PKTCOUNT,		    	\
	NFCT_REPLY_IP_SADDR,			\
	NFCT_REPLY_IP_DADDR,			\
	NFCT_REPLY_IP_PROTOCOL,		    	\
	NFCT_REPLY_L4_SPORT,			\
	NFCT_REPLY_L4_DPORT,			\
	NFCT_REPLY_RAW_PKTLEN,		    	\
	NFCT_REPLY_RAW_PKTCOUNT,		\
	NFCT_ICMP_CODE,			    	\
	NFCT_ICMP_TYPE,			    	\
	NFCT_CT_MARK,				\
	NFCT_CT_ID,				\
	NFCT_CT_EVENT,			    	\
	NFCT_FLOW_START_SEC,			\
	NFCT_FLOW_START_USEC,			\
	NFCT_FLOW_END_SEC,			\
	NFCT_FLOW_END_USEC,			\
	NFCT_OOB_FAMILY,			\
	NFCT_CT,				\
	NFCT_ORIG_IP6_SADDR,			\
	NFCT_ORIG_IP6_DADDR,			\
	NFCT_REPLY_IP6_SADDR,			\
	NFCT_REPLY_IP6_DADDR,			\
	NFCT_FLOW_END_REASON


#define NFCT_OUTPUT_KEYS_DEFAULT				\
	[NFCT_ORIG_IP_SADDR]	= {				\
		.type 	= NURS_KEY_T_INADDR,			\
		.flags 	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "orig.ip.saddr",			\
		.ipfix	= {					\
			.vendor	  = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_sourceIPv4Address,	\
		},						\
	},							\
	[NFCT_ORIG_IP_DADDR]	= {			     	\
		.type	= NURS_KEY_T_INADDR,		     	\
		.flags	= NURS_OKEY_F_OPTIONAL,		     	\
		.name	= "orig.ip.daddr",		     	\
		.ipfix	= {					\
			.vendor   = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_destinationIPv4Address, \
		},						\
	},							\
	[NFCT_ORIG_IP_PROTOCOL]	= {				\
		.type	= NURS_KEY_T_UINT8,			\
		.flags	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "orig.ip.protocol",			\
		.ipfix	= {					\
			.vendor   = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_protocolIdentifier,	\
		},						\
	},							\
	[NFCT_ORIG_L4_SPORT]	= {				\
		.type	= NURS_KEY_T_UINT16,			\
		.flags 	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "orig.l4.sport",			\
		.ipfix	= {					\
			.vendor   = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_sourceTransportPort,	\
		},						\
	},							\
	[NFCT_ORIG_L4_DPORT]	= {				\
		.type	= NURS_KEY_T_UINT16,			\
		.flags 	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "orig.l4.dport",			\
		.ipfix	= {					\
			.vendor   = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_destinationTransportPort, \
		},						\
	},							\
	[NFCT_ORIG_RAW_PKTLEN]	= {				\
		.type	= NURS_KEY_T_UINT64,			\
		.flags	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "orig.raw.pktlen.delta",		\
		.ipfix	= {					\
			.vendor   = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_octetDeltaCount,	\
		},						\
	},							\
	[NFCT_ORIG_RAW_PKTCOUNT]	= {			\
		.type	= NURS_KEY_T_UINT64,			\
		.flags	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "orig.raw.pktcount.delta",		\
		.ipfix	= {					\
			.vendor   = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_packetDeltaCount,	\
		},						\
	},							\
	[NFCT_REPLY_IP_SADDR]	= {				\
		.type 	= NURS_KEY_T_INADDR,			\
		.flags 	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "reply.ip.saddr",			\
		.ipfix	= {					\
			.vendor	  = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_postNATSourceIPv4Address, \
		},						\
	},							\
	[NFCT_REPLY_IP_DADDR]	= {				\
		.type	= NURS_KEY_T_INADDR,			\
		.flags	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "reply.ip.daddr",			\
		.ipfix	= {					\
			.vendor	  = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_postNATDestinationIPv4Address, \
		},						\
	},							\
	[NFCT_REPLY_IP_PROTOCOL]	= {			\
		.type	= NURS_KEY_T_UINT8,			\
		.flags	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "reply.ip.protocol",			\
		/* dup to "orig.ip.protocol"			\
		 * .ipfix	= {				\
		 *	.vendor	  = IPFIX_VENDOR_IETF,		\
		 *	.field_id = IPFIX_protocolIdentifier,	\
		 *},						\
		 */						\
	},							\
	[NFCT_REPLY_L4_SPORT]	= {				\
		.type	= NURS_KEY_T_UINT16,			\
		.flags 	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "reply.l4.sport",			\
		.ipfix	= {					\
			.vendor   = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_postNAPTSourceTransportPort, \
		},						\
	},							\
	[NFCT_REPLY_L4_DPORT]	= {				\
		.type	= NURS_KEY_T_UINT16,			\
		.flags 	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "reply.l4.dport",			\
		.ipfix	= {					\
			.vendor   = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_postNAPTDestinationTransportPort, \
		},						\
	},							\
	[NFCT_REPLY_RAW_PKTLEN]	= {				\
		.type	= NURS_KEY_T_UINT64,			\
		.flags	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "reply.raw.pktlen.delta",		\
		.ipfix	= {					\
			.vendor   = IPFIX_VENDOR_REVERSE,	\
			.field_id = IPFIX_octetDeltaCount,	\
		},						\
	},							\
	[NFCT_REPLY_RAW_PKTCOUNT]	= {			\
		.type	= NURS_KEY_T_UINT64,			\
		.flags	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "reply.raw.pktcount.delta",		\
		.ipfix	= {					\
			.vendor   = IPFIX_VENDOR_REVERSE,	\
			.field_id = IPFIX_packetDeltaCount,	\
		},						\
	},							\
	[NFCT_ICMP_CODE]	= {				\
		.type	= NURS_KEY_T_UINT8,			\
		.flags	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "icmp.code",				\
		.ipfix	= {					\
			.vendor	  = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_icmpCodeIPv4,		\
		},						\
	},							\
	[NFCT_ICMP_TYPE]	= {				\
		.type	= NURS_KEY_T_UINT8,			\
		.flags	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "icmp.type",				\
		.ipfix	= {					\
			.vendor	  = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_icmpTypeIPv4,		\
		},						\
	},							\
	[NFCT_CT_MARK]	= {					\
		.type	= NURS_KEY_T_UINT32,			\
		.flags	= NURS_OKEY_F_OPTIONAL, 		\
		.name	= "ct.mark",				\
		.ipfix	= {				    	\
			.vendor	  = IPFIX_VENDOR_NETFILTER, 	\
			.field_id = IPFIX_NF_mark,	    	\
		},					    	\
	},						    	\
	[NFCT_CT_ID]	= {				    	\
		.type	= NURS_KEY_T_UINT32,		    	\
		.flags	= NURS_OKEY_F_OPTIONAL,		    	\
		.name	= "ct.id",			    	\
		.ipfix	= {				    	\
			.vendor	  = IPFIX_VENDOR_NETFILTER, 	\
			.field_id = IPFIX_NF_conntrack_id,  	\
		},					    	\
	},						    	\
	[NFCT_CT_EVENT]	= {				    	\
		.type	= NURS_KEY_T_UINT32,		    	\
		.flags	= NURS_OKEY_F_OPTIONAL,		    	\
		.name	= "ct.event",			    	\
	},						    	\
	[NFCT_FLOW_START_SEC]	= {			    	\
		.type 	= NURS_KEY_T_UINT32,		    	\
		.flags 	= NURS_OKEY_F_OPTIONAL,		    	\
		.name	= "flow.start.sec",		    	\
		.ipfix	= {				    	\
			.vendor	  = IPFIX_VENDOR_IETF,	    	\
			.field_id = IPFIX_flowStartSeconds, 	\
		},					    	\
	},						    	\
	[NFCT_FLOW_START_USEC]	= {			    	\
		.type 	= NURS_KEY_T_UINT32,		    	\
		.flags 	= NURS_OKEY_F_OPTIONAL,		    	\
		.name	= "flow.start.usec",		    	\
	},						    	\
	[NFCT_FLOW_END_SEC]	= {			    	\
		.type	= NURS_KEY_T_UINT32,		    	\
		.flags	= NURS_OKEY_F_OPTIONAL,		    	\
		.name	= "flow.end.sec",		    	\
		.ipfix	= {				    	\
			.vendor	  = IPFIX_VENDOR_IETF,	    	\
			.field_id = IPFIX_flowEndSeconds,   	\
		},					    	\
	},						    	\
	[NFCT_FLOW_END_USEC]	= {			    	\
		.type	= NURS_KEY_T_UINT32,		    	\
		.flags	= NURS_OKEY_F_OPTIONAL,		    	\
		.name	= "flow.end.usec",		    	\
	},						    	\
	[NFCT_OOB_FAMILY]	= {			    	\
		.type	= NURS_KEY_T_UINT8,		    	\
		.flags	= NURS_OKEY_F_OPTIONAL,		    	\
		.name	= "oob.family",			    	\
	},						    	\
	[NFCT_CT]	= {				    	\
		.type	= NURS_KEY_T_POINTER,			\
		.flags	= NURS_OKEY_F_OPTIONAL | NURS_OKEY_F_DESTRUCT, \
		.name	= "nfct",				\
		.destructor = (void (*)(void *))nfct_destroy,	\
	},							\
	[NFCT_ORIG_IP6_SADDR]	= {				\
		.type 	= NURS_KEY_T_IN6ADDR,			\
		.flags 	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "orig.ip6.saddr",			\
		.ipfix	= {					\
			.vendor	  = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_sourceIPv6Address,	\
		},						\
	},							\
	[NFCT_ORIG_IP6_DADDR]	= {				\
		.type	= NURS_KEY_T_IN6ADDR,			\
		.flags	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "orig.ip6.daddr",			\
		.ipfix	= {					\
			.vendor	  = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_destinationIPv6Address, \
		},						\
	},							\
	[NFCT_REPLY_IP6_SADDR]	= {				\
		.type 	= NURS_KEY_T_IN6ADDR,			\
		.flags 	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "reply.ip6.saddr",			\
		.ipfix	= {					\
			.vendor	  = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_postNATSourceIPv6Address, \
		},						\
	},							\
	[NFCT_REPLY_IP6_DADDR]	= {				\
		.type	= NURS_KEY_T_IN6ADDR,			\
		.flags	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "reply.ip6.daddr",			\
		.ipfix	= {					\
			.vendor	  = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_postNATDestinationIPv6Address, \
		},						\
	},							\
	[NFCT_FLOW_END_REASON]	= {				\
		.type	= NURS_KEY_T_UINT8,			\
		.flags	= NURS_OKEY_F_OPTIONAL,			\
		.name	= "flow.end.reason",			\
		.ipfix	= {					\
			.vendor	  = IPFIX_VENDOR_IETF,		\
			.field_id = IPFIX_flowEndReason,	\
		},						\
	}

enum nfct_output_keys {
	NFCT_ORIG_IP_SADDR = 0,
	NFCT_ORIG_IP_DADDR,
	NFCT_ORIG_IP_PROTOCOL,
	NFCT_ORIG_L4_SPORT,
	NFCT_ORIG_L4_DPORT,
	NFCT_ORIG_RAW_PKTLEN,
	NFCT_ORIG_RAW_PKTCOUNT,
	NFCT_REPLY_IP_SADDR,
	NFCT_REPLY_IP_DADDR,
	NFCT_REPLY_IP_PROTOCOL,
	NFCT_REPLY_L4_SPORT,
	NFCT_REPLY_L4_DPORT,
	NFCT_REPLY_RAW_PKTLEN,
	NFCT_REPLY_RAW_PKTCOUNT,
	NFCT_ICMP_CODE,
	NFCT_ICMP_TYPE,
	NFCT_CT_MARK,
	NFCT_CT_ID,
	NFCT_CT_EVENT,
	NFCT_FLOW_START_SEC,
	NFCT_FLOW_START_USEC,
	NFCT_FLOW_END_SEC,
	NFCT_FLOW_END_USEC,
	NFCT_OOB_FAMILY,
	NFCT_CT,
	NFCT_ORIG_IP6_SADDR,
	NFCT_ORIG_IP6_DADDR,
	NFCT_REPLY_IP6_SADDR,
	NFCT_REPLY_IP6_DADDR,
	NFCT_FLOW_END_REASON,
	NFCT_OUTPUT_MAX,
};

static struct nurs_output_def nfct_output = {
	.len	= NFCT_OUTPUT_MAX,
	.keys	= {
		[NFCT_ORIG_IP_SADDR]	= {
			.type 	= NURS_KEY_T_INADDR,
			.flags 	= NURS_OKEY_F_OPTIONAL,
			.name	= "orig.ip.saddr",
			.ipfix	= {
				.vendor	  = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_sourceIPv4Address,
			},
		},
		[NFCT_ORIG_IP_DADDR]	= {
			.type	= NURS_KEY_T_INADDR,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "orig.ip.daddr",
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_destinationIPv4Address,
			},
		},
		[NFCT_ORIG_IP_PROTOCOL]	= {
			.type	= NURS_KEY_T_UINT8,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "orig.ip.protocol",
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_protocolIdentifier,
			},
		},
		[NFCT_ORIG_L4_SPORT]	= {
			.type	= NURS_KEY_T_UINT16,
			.flags 	= NURS_OKEY_F_OPTIONAL,
			.name	= "orig.l4.sport",
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_sourceTransportPort,
			},
		},
		[NFCT_ORIG_L4_DPORT]	= {
			.type	= NURS_KEY_T_UINT16,
			.flags 	= NURS_OKEY_F_OPTIONAL,
			.name	= "orig.l4.dport",
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_destinationTransportPort,
			},
		},
		[NFCT_ORIG_RAW_PKTLEN]	= {
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "orig.raw.pktlen.delta",
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_octetDeltaCount,
			},
		},
		[NFCT_ORIG_RAW_PKTCOUNT]	= {
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "orig.raw.pktcount.delta",
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_packetDeltaCount,
			},
		},
		[NFCT_REPLY_IP_SADDR]	= {
			.type 	= NURS_KEY_T_INADDR,
			.flags 	= NURS_OKEY_F_OPTIONAL,
			.name	= "reply.ip.saddr",
			.ipfix	= {
				.vendor	  = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_postNATSourceIPv4Address,
			},
		},
		[NFCT_REPLY_IP_DADDR]	= {
			.type	= NURS_KEY_T_INADDR,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "reply.ip.daddr",
			.ipfix	= {
				.vendor	  = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_postNATDestinationIPv4Address,
			},
		},
		[NFCT_REPLY_IP_PROTOCOL]	= {
			.type	= NURS_KEY_T_UINT8,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "reply.ip.protocol",
			/* dup to "orig.ip.protocol"
			 * .ipfix	= {
			 *	.vendor	  = IPFIX_VENDOR_IETF,
			 *	.field_id = IPFIX_protocolIdentifier,
			 *},
			 */
		},
		[NFCT_REPLY_L4_SPORT]	= {
			.type	= NURS_KEY_T_UINT16,
			.flags 	= NURS_OKEY_F_OPTIONAL,
			.name	= "reply.l4.sport",
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_postNAPTSourceTransportPort,
			},
		},
		[NFCT_REPLY_L4_DPORT]	= {
			.type	= NURS_KEY_T_UINT16,
			.flags 	= NURS_OKEY_F_OPTIONAL,
			.name	= "reply.l4.dport",
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_postNAPTDestinationTransportPort,
			},
		},
		[NFCT_REPLY_RAW_PKTLEN]	= {
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "reply.raw.pktlen.delta",
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_REVERSE,
				.field_id = IPFIX_octetDeltaCount,
			},
		},
		[NFCT_REPLY_RAW_PKTCOUNT]	= {
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "reply.raw.pktcount.delta",
			.ipfix	= {
				.vendor   = IPFIX_VENDOR_REVERSE,
				.field_id = IPFIX_packetDeltaCount,
			},
		},
		[NFCT_ICMP_CODE]	= {
			.type	= NURS_KEY_T_UINT8,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "icmp.code",
			.ipfix	= {
				.vendor	  = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_icmpCodeIPv4,
			},
		},
		[NFCT_ICMP_TYPE]	= {
			.type	= NURS_KEY_T_UINT8,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "icmp.type",
			.ipfix	= {
				.vendor	  = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_icmpTypeIPv4,
			},
		},
		[NFCT_CT_MARK]	= {
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "ct.mark",
			.ipfix	= {
				.vendor	  = IPFIX_VENDOR_NETFILTER,
				.field_id = IPFIX_NF_mark,
			},
		},
		[NFCT_CT_ID]	= {
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "ct.id",
			.ipfix	= {
				.vendor	  = IPFIX_VENDOR_NETFILTER,
				.field_id = IPFIX_NF_conntrack_id,
			},
		},
		[NFCT_CT_EVENT]	= {
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "ct.event",
		},
		[NFCT_FLOW_START_SEC]	= {
			.type 	= NURS_KEY_T_UINT32,
			.flags 	= NURS_OKEY_F_OPTIONAL,
			.name	= "flow.start.sec",
			.ipfix	= {
				.vendor	  = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_flowStartSeconds,
			},
		},
		[NFCT_FLOW_START_USEC]	= {
			.type 	= NURS_KEY_T_UINT32,
			.flags 	= NURS_OKEY_F_OPTIONAL,
			.name	= "flow.start.usec",
		},
		[NFCT_FLOW_END_SEC]	= {
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "flow.end.sec",
			.ipfix	= {
				.vendor	  = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_flowEndSeconds,
			},
		},
		[NFCT_FLOW_END_USEC]	= {
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "flow.end.usec",
		},
		[NFCT_OOB_FAMILY]	= {
			.type	= NURS_KEY_T_UINT8,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "oob.family",
		},
		[NFCT_CT]	= {
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_OPTIONAL | NURS_OKEY_F_DESTRUCT,
			.name	= "nfct",
			.destructor = (void (*)(void *))nfct_destroy,
		},
		[NFCT_ORIG_IP6_SADDR]	= {
			.type 	= NURS_KEY_T_IN6ADDR,
			.flags 	= NURS_OKEY_F_OPTIONAL,
			.name	= "orig.ip6.saddr",
			.ipfix	= {
				.vendor	  = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_sourceIPv6Address,
			},
		},
		[NFCT_ORIG_IP6_DADDR]	= {
			.type	= NURS_KEY_T_IN6ADDR,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "orig.ip6.daddr",
			.ipfix	= {
				.vendor	  = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_destinationIPv6Address,
			},
		},
		[NFCT_REPLY_IP6_SADDR]	= {
			.type 	= NURS_KEY_T_IN6ADDR,
			.flags 	= NURS_OKEY_F_OPTIONAL,
			.name	= "reply.ip6.saddr",
			.ipfix	= {
				.vendor	  = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_postNATSourceIPv6Address,
			},
		},
		[NFCT_REPLY_IP6_DADDR]	= {
			.type	= NURS_KEY_T_IN6ADDR,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "reply.ip6.daddr",
			.ipfix	= {
				.vendor	  = IPFIX_VENDOR_IETF,
				.field_id = IPFIX_postNATDestinationIPv6Address,
			},
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

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
#include <stdio.h>
#include <string.h>

#include <jansson.h>

#include <nurs/nurs.h>
#include <nurs/ipfix_protocol.h>

#include "internal.h"

/**
 * \defgroup nurs plugin registeration by json
 * @{
 *
 * Plugins can be registered not only C struct but also JSON string. Nurs is
 * aimed to access its input and output from other language. This JSON
 * registeration is introduced since it's bothersome to write struct type for
 * each other languages.
 *
 */

#define ccmp(s, t) do { if (strncmp(s, (#t), strlen(#t)) == 0) return (t); } while (0)

static int key_type(const char *const type)
{
	/* return -1 on error or can be casted to uint16_t */
	if (!type) {
		errno = EINVAL;
		return -1;
	}

	ccmp(type, NURS_KEY_T_BOOL);
	ccmp(type, NURS_KEY_T_INT8);
	ccmp(type, NURS_KEY_T_INT16);
	ccmp(type, NURS_KEY_T_INT32);
	ccmp(type, NURS_KEY_T_INT64);
	ccmp(type, NURS_KEY_T_UINT8);
	ccmp(type, NURS_KEY_T_UINT16);
	ccmp(type, NURS_KEY_T_UINT32);
	ccmp(type, NURS_KEY_T_UINT64);
	ccmp(type, NURS_KEY_T_INADDR);
	ccmp(type, NURS_KEY_T_IN6ADDR);
	ccmp(type, NURS_KEY_T_STRING);
	ccmp(type, NURS_KEY_T_POINTER);
	ccmp(type, NURS_KEY_T_EMBED);
	/* NURS_KEY_T_NONE is an error */

	errno = EINVAL;
	return -1;
}

static int output_key_flag(const char *const flag)
{
	/* return -1 on error or can be casted to uint16_t */
	if (!flag) {
		errno = EINVAL;
		return -1;
	}

	ccmp(flag, NURS_OKEY_F_ACTIVE);
	ccmp(flag, NURS_OKEY_F_FREE);
	ccmp(flag, NURS_OKEY_F_DESTRUCT);
	ccmp(flag, NURS_OKEY_F_OPTIONAL);

	errno = EINVAL;
	return -1;
}

static int input_key_flag(const char *const flag)
{
	/* return -1 on error or can be casted to uint16_t */
	if (!flag) {
		errno = EINVAL;
		return -1;
	}

	ccmp(flag, NURS_IKEY_F_REQUIRED);
	ccmp(flag, NURS_IKEY_F_OPTIONAL);

	errno = EINVAL;
	return -1;
}

static int config_type(const char *const type)
{
	/* return -1 on error or can be casted to uint8_t */
	if (!type) {
		errno = EINVAL;
		return -1;
	}

	ccmp(type, NURS_CONFIG_T_INTEGER);
	ccmp(type, NURS_CONFIG_T_STRING);
	ccmp(type, NURS_CONFIG_T_BOOLEAN);
	ccmp(type, NURS_CONFIG_T_CALLBACK);

	errno = EINVAL;
	return -1;
}

static int config_flag(const char *const flag)
{
	/* return -1 on error or can be casted to uint8_t */
	if (!flag) {
		errno = EINVAL;
		return -1;
	}

	ccmp(flag, NURS_CONFIG_F_NONE);
	ccmp(flag, NURS_CONFIG_F_MULTI);
	ccmp(flag, NURS_CONFIG_F_MANDATORY);

	errno = EINVAL;
	return -1;
}

static int ipfix_vendor(const char *const vendor)
{
	if (!vendor) {
		errno = EINVAL;
		return -1;
	}

	ccmp(vendor, IPFIX_VENDOR_IETF);
	ccmp(vendor, IPFIX_VENDOR_NETFILTER);
	ccmp(vendor, IPFIX_VENDOR_REVERSE);

	errno = EINVAL;
	return -1;
}

/* XXX: use gperf? */
static int ipfix_field_id(const char *const field_id)
{
	if (!field_id) {
		errno = EINVAL;
		return -1;
	}

	ccmp(field_id, IPFIX_octetDeltaCount);
	ccmp(field_id, IPFIX_packetDeltaCount);
	ccmp(field_id, IPFIX_protocolIdentifier);
	ccmp(field_id, IPFIX_classOfServiceIPv4);
	ccmp(field_id, IPFIX_tcpControlBits);
	ccmp(field_id, IPFIX_sourceTransportPort);
	ccmp(field_id, IPFIX_sourceIPv4Address);
	ccmp(field_id, IPFIX_sourceIPv4Mask);
	ccmp(field_id, IPFIX_ingressInterface);
	ccmp(field_id, IPFIX_destinationTransportPort);
	ccmp(field_id, IPFIX_destinationIPv4Address);
	ccmp(field_id, IPFIX_destinationIPv4Mask);
	ccmp(field_id, IPFIX_egressInterface);
	ccmp(field_id, IPFIX_ipNextHopIPv4Address);
	ccmp(field_id, IPFIX_bgpSourceAsNumber);
	ccmp(field_id, IPFIX_bgpDestinationAsNumber);
	ccmp(field_id, IPFIX_bgpNextHopIPv4Address);
	ccmp(field_id, IPFIX_postMCastPacketDeltaCount);
	ccmp(field_id, IPFIX_postMCastOctetDeltaCount);
	ccmp(field_id, IPFIX_flowEndSysUpTime);
	ccmp(field_id, IPFIX_flowStartSysUpTime);
	ccmp(field_id, IPFIX_postOctetDeltaCount);
	ccmp(field_id, IPFIX_postPacketDeltaCount);
	ccmp(field_id, IPFIX_minimumPacketLength);
	ccmp(field_id, IPFIX_maximumPacketLength);
	ccmp(field_id, IPFIX_sourceIPv6Address);
	ccmp(field_id, IPFIX_destinationIPv6Address);
	ccmp(field_id, IPFIX_sourceIPv6Mask);
	ccmp(field_id, IPFIX_destinationIPv6Mask);
	ccmp(field_id, IPFIX_flowLabelIPv6);
	ccmp(field_id, IPFIX_icmpTypeCodeIPv4);
	ccmp(field_id, IPFIX_igmpType);
	ccmp(field_id, IPFIX_flowActiveTimeOut);
	ccmp(field_id, IPFIX_flowInactiveTimeout);
	ccmp(field_id, IPFIX_exportedOctetTotalCount);
	ccmp(field_id, IPFIX_exportedMessageTotalCount);
	ccmp(field_id, IPFIX_exportedFlowTotalCount);
	ccmp(field_id, IPFIX_sourceIPv4Prefix);
	ccmp(field_id, IPFIX_destinationIPv4Prefix);
	ccmp(field_id, IPFIX_mplsTopLabelType);
	ccmp(field_id, IPFIX_mplsTopLabelIPv4Address);
	ccmp(field_id, IPFIX_minimumTtl);
	ccmp(field_id, IPFIX_maximumTtl);
	ccmp(field_id, IPFIX_identificationIPv4);
	ccmp(field_id, IPFIX_postClassOfServiceIPv4);
	ccmp(field_id, IPFIX_sourceMacAddress);
	ccmp(field_id, IPFIX_postDestinationMacAddr);
	ccmp(field_id, IPFIX_vlanId);
	ccmp(field_id, IPFIX_postVlanId);
	ccmp(field_id, IPFIX_ipVersion);
	ccmp(field_id, IPFIX_flowDirection);
	ccmp(field_id, IPFIX_ipNextHopIPv6Address);
	ccmp(field_id, IPFIX_bgpNexthopIPv6Address);
	ccmp(field_id, IPFIX_ipv6ExtensionHeaders);
	ccmp(field_id, IPFIX_mplsTopLabelStackEntry);
	ccmp(field_id, IPFIX_mplsLabelStackEntry2);
	ccmp(field_id, IPFIX_mplsLabelStackEntry3);
	ccmp(field_id, IPFIX_mplsLabelStackEntry4);
	ccmp(field_id, IPFIX_mplsLabelStackEntry5);
	ccmp(field_id, IPFIX_mplsLabelStackEntry6);
	ccmp(field_id, IPFIX_mplsLabelStackEntry7);
	ccmp(field_id, IPFIX_mplsLabelStackEntry8);
	ccmp(field_id, IPFIX_mplsLabelStackEntry9);
	ccmp(field_id, IPFIX_mplsLabelStackEntry10);
	ccmp(field_id, IPFIX_destinationMacAddress);
	ccmp(field_id, IPFIX_postSourceMacAddress);
	ccmp(field_id, IPFIX_octetTotalCount);
	ccmp(field_id, IPFIX_packetTotalCount);
	ccmp(field_id, IPFIX_fragmentOffsetIPv4);
	ccmp(field_id, IPFIX_bgpNextAdjacentAsNumber);
	ccmp(field_id, IPFIX_bgpPrevAdjacentAsNumber);
	ccmp(field_id, IPFIX_exporterIPv4Address);
	ccmp(field_id, IPFIX_exporterIPv6Address);
	ccmp(field_id, IPFIX_droppedOctetDeltaCount);
	ccmp(field_id, IPFIX_droppedPacketDeltaCount);
	ccmp(field_id, IPFIX_droppedOctetTotalCount);
	ccmp(field_id, IPFIX_droppedPacketTotalCount);
	ccmp(field_id, IPFIX_flowEndReason);
	ccmp(field_id, IPFIX_classOfServiceIPv6);
	ccmp(field_id, IPFIX_postClassOFServiceIPv6);
	ccmp(field_id, IPFIX_icmpTypeCodeIPv6);
	ccmp(field_id, IPFIX_mplsTopLabelIPv6Address);
	ccmp(field_id, IPFIX_lineCardId);
	ccmp(field_id, IPFIX_portId);
	ccmp(field_id, IPFIX_meteringProcessId);
	ccmp(field_id, IPFIX_exportingProcessId);
	ccmp(field_id, IPFIX_templateId);
	ccmp(field_id, IPFIX_wlanChannelId);
	ccmp(field_id, IPFIX_wlanSsid);
	ccmp(field_id, IPFIX_flowId);
	ccmp(field_id, IPFIX_sourceId);
	ccmp(field_id, IPFIX_flowStartSeconds);
	ccmp(field_id, IPFIX_flowEndSeconds);
	ccmp(field_id, IPFIX_flowStartMilliSeconds);
	ccmp(field_id, IPFIX_flowEndMilliSeconds);
	ccmp(field_id, IPFIX_flowStartMicroSeconds);
	ccmp(field_id, IPFIX_flowEndMicroSeconds);
	ccmp(field_id, IPFIX_flowStartNanoSeconds);
	ccmp(field_id, IPFIX_flowEndNanoSeconds);
	ccmp(field_id, IPFIX_flowStartDeltaMicroSeconds);
	ccmp(field_id, IPFIX_flowEndDeltaMicroSeconds);
	ccmp(field_id, IPFIX_systemInitTimeMilliSeconds);
	ccmp(field_id, IPFIX_flowDurationMilliSeconds);
	ccmp(field_id, IPFIX_flowDurationMicroSeconds);
	ccmp(field_id, IPFIX_observedFlowTotalCount);
	ccmp(field_id, IPFIX_ignoredPacketTotalCount);
	ccmp(field_id, IPFIX_ignoredOctetTotalCount);
	ccmp(field_id, IPFIX_notSentFlowTotalCount);
	ccmp(field_id, IPFIX_notSentPacketTotalCount);
	ccmp(field_id, IPFIX_notSentOctetTotalCount);
	ccmp(field_id, IPFIX_destinationIPv6Prefix);
	ccmp(field_id, IPFIX_sourceIPv6Prefix);
	ccmp(field_id, IPFIX_postOctetTotalCount);
	ccmp(field_id, IPFIX_postPacketTotalCount);
	ccmp(field_id, IPFIX_flowKeyIndicator);
	ccmp(field_id, IPFIX_postMCastPacketTotalCount);
	ccmp(field_id, IPFIX_postMCastOctetTotalCount);
	ccmp(field_id, IPFIX_icmpTypeIPv4);
	ccmp(field_id, IPFIX_icmpCodeIPv4);
	ccmp(field_id, IPFIX_icmpTypeIPv6);
	ccmp(field_id, IPFIX_icmpCodeIPv6);
	ccmp(field_id, IPFIX_udpSourcePort);
	ccmp(field_id, IPFIX_udpDestinationPort);
	ccmp(field_id, IPFIX_tcpSourcePort);
	ccmp(field_id, IPFIX_tcpDestinationPort);
	ccmp(field_id, IPFIX_tcpSequenceNumber);
	ccmp(field_id, IPFIX_tcpAcknowledgementNumber);
	ccmp(field_id, IPFIX_tcpWindowSize);
	ccmp(field_id, IPFIX_tcpUrgentPointer);
	ccmp(field_id, IPFIX_tcpHeaderLength);
	ccmp(field_id, IPFIX_ipHeaderLength);
	ccmp(field_id, IPFIX_totalLengthIPv4);
	ccmp(field_id, IPFIX_payloadLengthIPv6);
	ccmp(field_id, IPFIX_ipTimeToLive);
	ccmp(field_id, IPFIX_nextHeaderIPv6);
	ccmp(field_id, IPFIX_ipClassOfService);
	ccmp(field_id, IPFIX_ipDiffServCodePoint);
	ccmp(field_id, IPFIX_ipPrecedence);
	ccmp(field_id, IPFIX_fragmentFlagsIPv4);
	ccmp(field_id, IPFIX_octetDeltaSumOfSquares);
	ccmp(field_id, IPFIX_octetTotalSumOfSquares);
	ccmp(field_id, IPFIX_mplsTopLabelTtl);
	ccmp(field_id, IPFIX_mplsLabelStackLength);
	ccmp(field_id, IPFIX_mplsLabelStackDepth);
	ccmp(field_id, IPFIX_mplsTopLabelExp);
	ccmp(field_id, IPFIX_ipPayloadLength);
	ccmp(field_id, IPFIX_udpMessageLength);
	ccmp(field_id, IPFIX_isMulticast);
	ccmp(field_id, IPFIX_internetHeaderLengthIPv4);
	ccmp(field_id, IPFIX_ipv4Options);
	ccmp(field_id, IPFIX_tcpOptions);
	ccmp(field_id, IPFIX_paddingOctets);
	ccmp(field_id, IPFIX_headerLengthIPv4);
	ccmp(field_id, IPFIX_mplsPayloadLength);
	ccmp(field_id, IPFIX_postNATSourceIPv4Address);
	ccmp(field_id, IPFIX_postNATDestinationIPv4Address);
	ccmp(field_id, IPFIX_postNAPTSourceTransportPort);
	ccmp(field_id, IPFIX_postNAPTDestinationTransportPort);
	ccmp(field_id, IPFIX_firewallEvent);
	ccmp(field_id, IPFIX_postNATSourceIPv6Address);
	ccmp(field_id, IPFIX_postNATDestinationIPv6Address);

	/* XXX: not classified by vendor id */
	ccmp(field_id, IPFIX_NF_rawpacket);
	ccmp(field_id, IPFIX_NF_rawpacket_length);
	ccmp(field_id, IPFIX_NF_prefix);
	ccmp(field_id, IPFIX_NF_mark);
	ccmp(field_id, IPFIX_NF_hook);
	ccmp(field_id, IPFIX_NF_conntrack_id);
	ccmp(field_id, IPFIX_NF_seq_local);
	ccmp(field_id, IPFIX_NF_seq_global);

	errno = EINVAL;
	return -1;
};
#undef ccmp

/*
 * struct nurs_config_entry_def
 *   name: string (< NURS_NAME_LEN), required
 *   type: string (by config_type()), required
 *   flags: [string,] (by config_flag()), optional
 *   u .integer: integer, optional
 *   u .string: string (< NURS_STRING_LEN), optional
 *   u .parser: string, optional
 * {s:s%, s:s,  s?[s], s?o}
 * {s:s%, s:s,  s?o, s?o} - no wildcard array element
 *  name, type, flags, value
 */
static int parse_config_entry_def(json_t *json, char *pname, size_t index,
				  struct nurs_config_entry_def *def)
{
	json_t *jflags = NULL, *jvalue = NULL;
	json_error_t error;
	char *name, *stype, *parser;
	const char *sflag;
	int type, flag;
	size_t namelen, parser_len = 0, i;

	if (json_unpack_ex(json, &error, JSON_STRICT,
			   "{s:s%, s:s, s?o, s?s%, s?o}",
			   "name", &name, &namelen,
			   "type", &stype,
			   "flags", &jflags,
			   "parser", &parser, &parser_len,
			   "value", &jvalue) < 0) {
		nurs_log(NURS_ERROR, "plugin %s config[%d] error: %s\n",
			 pname, index, &error.text);
		errno = EINVAL;
		return -1;
	}

	if (namelen > NURS_NAME_LEN) {
		nurs_log(NURS_ERROR, "too long config name: %s\n", name);
		errno = ENAMETOOLONG;
		return -1;
	}
	strncpy(def->name, name, NURS_NAME_LEN);

	if (parser_len > NURS_NAME_LEN) {
		nurs_log(NURS_ERROR, "too long parser name: %s\n", name);
		errno = ENAMETOOLONG;
		return -1;
	} else if (parser_len > 0) {
		strncpy(def->parser_cb_s, parser, NURS_NAME_LEN);
		def->resolve_parser = true;
	}

	if ((type = config_type(stype)) < 0) {
		nurs_log(NURS_ERROR, "invalid config type: %s\n", stype);
		return -1;
	}
	def->type = (uint16_t)type;
	if (jflags && !json_is_array(jflags)) {
		nurs_log(NURS_ERROR, "config flags [%d] must be an array\n", index);
		errno = EINVAL;
		return -1;
	}
	/* 0 if array is NULL or not a JSON array */
	for (i = 0; i < json_array_size(jflags); i++) {
		if (!json_is_string(json_array_get(jflags, i))) {
			nurs_log(NURS_ERROR, "flags [%d] must be a string\n",
				 i);
			errno = EINVAL;
			return -1;
		}
		sflag = json_string_value(json_array_get(jflags, i));
		flag = config_flag(sflag);
		if (flag < 0) {
			nurs_log(NURS_ERROR,
				 "invalid config flag: %s\n", sflag);
			errno = EINVAL;
			return -1;
		}
		def->flags |= (uint16_t)flag;
	}

	if (!jvalue)
		return 0;

	switch(def->type) {
	case NURS_CONFIG_T_INTEGER:
		if (!json_is_integer(jvalue)) {
			nurs_log(NURS_ERROR,
				 "plugin config require int value: %s\n",
				 name);
			errno = EINVAL;
			return -1;
		}
		def->integer = (int)json_integer_value(jvalue);
		break;
	case NURS_CONFIG_T_STRING:
		if (!json_is_string(jvalue)) {
			nurs_log(NURS_ERROR,
				 "plugin config require string value: %s\n",
				 name);
			errno = EINVAL;
			return -1;
		}
		strncpy(def->string, json_string_value(jvalue), NURS_NAME_LEN);
		break;
	case NURS_CONFIG_T_BOOLEAN:
		if (!json_is_boolean(jvalue)) {
			nurs_log(NURS_ERROR,
				 "plugin config requires boolean value: %s\n",
				 name);
			errno = EINVAL;
			return -1;
		}
		def->boolean = json_boolean_value(jvalue);
		break;
	case NURS_CONFIG_T_CALLBACK:
		nurs_log(NURS_ERROR,
			 "plugin config does not allow value: %s\n", name);
		errno = EINVAL;
		return -1;
	default:
		nurs_log(NURS_ERROR, "invalid config type: %s, %d\n",
			 name, def->type);
		errno = EINVAL;
		return -1;
	}

	return 0;
}

/*
 * strucr nurs_output_key_def
 *   type: string (by output_type()), required
 *   flags: [string,] (by output_flag()), required
 *   name: string (< NURS_NANE_LEN), required
 *   len: integer, optional (will check at raw register() call)
 *   ipfix_vendor: string (by ipfix_vendor()), optional
 *   ipfix_field_id: string (by ipfix_field_id()), optional
 *   cim_name: string (< NURS_NAME_LEN), optional
 *   destructor: string (< NURS_NAME_LEN), optional
 * {s:s%, s:s,  s:o,   s?i, s?s,          s?s,            s?s%,     s?s%}
 *  name, type, flags, len, ipfix_vendor, ipfix_field_id, cim_name, destuctor
 */
static int parse_output_key_def(json_t *json, char *pname, size_t index,
				struct nurs_output_key_def *def)
{
	json_t *jflags;
	json_error_t error;
	char *name, *stype;
	const char *sflag;
	char *sipfix_vendor = NULL, *sipfix_field_id = NULL;
	char *cim_name = NULL, *destructor = NULL;
	size_t namelen, len = 0, cim_namelen, destructor_len, i;
	int type, flag, vendor, field_id;

	if (json_unpack_ex(json, &error, JSON_STRICT,
			   "{s:s%, s:s, s:o, s?i, s?s, s?s, s?s%, s?s%}",
			   "name", &name, &namelen,
			   "type", &stype,
			   "flags", &jflags,
			   "len", &len,
			   "ipfix_vendor", &sipfix_vendor,
			   "ipfix_field", &sipfix_field_id,
			   "cim_name", &cim_name, &cim_namelen,
			   "destructor", &destructor, &destructor_len) < 0) {
		nurs_log(NURS_ERROR, "plugin %s output[%d] error: %s\n",
			 pname, index, error.text);
		errno = EINVAL;
		return -1;
	}

	if (namelen > NURS_NAME_LEN) {
		nurs_log(NURS_ERROR, "too long output keyname: %s\n", name);
		errno = ENAMETOOLONG;
		return -1;
	}
	strncpy(def->name, name, NURS_NAME_LEN);
	if ((type = key_type(stype)) < 0) {
		nurs_log(NURS_ERROR, "invalid key type: %s, %s\n", name, stype);
		return -1;
	}
	def->type = (uint16_t)type;
	if (!json_is_array(jflags)) {
		nurs_log(NURS_ERROR,
			 "output flags must be an array: %s\n", name);
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < json_array_size(jflags); i++) {
		if (!json_is_string(json_array_get(jflags, i))) {
			nurs_log(NURS_ERROR,
				 "output flag must be a string: %s\n", name);
			errno = EINVAL;
			return -1;
		}
		sflag = json_string_value(json_array_get(jflags, i));
		flag = output_key_flag(sflag);
		if (flag < 0) {
			nurs_log(NURS_ERROR,
				 "invalid output flag: %s, %s\n", name, sflag);
			errno = EINVAL;
			return -1;
		}
		def->flags |= (uint16_t)flag;
	}
	def->len = (uint16_t)len;
	if (sipfix_vendor && strlen(sipfix_vendor)) {
		vendor = ipfix_vendor(sipfix_vendor);
		if (vendor < 0) {
			nurs_log(NURS_ERROR, "invalid ipfix vendor: %s, %s\n",
				 name, sipfix_vendor);
			return -1;
		}
		def->ipfix.vendor = (uint32_t)vendor;
	}
	if (sipfix_field_id && strlen(sipfix_field_id)) {
		field_id = ipfix_field_id(sipfix_field_id);
		if (field_id < 0) {
			nurs_log(NURS_ERROR, "invalid ipfix field id: %s, %s\n",
				 name, sipfix_field_id);
			return -1;
		}
		def->ipfix.field_id = (uint16_t)field_id;
	}
	if (cim_name && strlen(cim_name)) {
		strncpy(def->cim_name, cim_name, NURS_NAME_LEN);
		if (cim_namelen > NURS_NAME_LEN) {
			errno = ENAMETOOLONG;
			nurs_log(NURS_ERROR, "too long cim_name: %s, %s\n",
				 name, cim_name);
			return -1;
		}
	}
	if (destructor) {
		if (destructor_len > NURS_NAME_LEN) {
			nurs_log(NURS_ERROR, "too long destructor: %s, %s\n",
				 name, destructor);
			errno = ENAMETOOLONG;
			return -1;
		}
		strncpy(def->destructor_cb_s, destructor, NURS_NAME_LEN);
		/* XXX: fixed */
		def->resolve_destructor = true;
	}

	return 0;
}

/*
 * struct nurs_input_key_def
 *   type: string (by input_type()), required
 *   flags: [string,] (by input_flag()), required
 *   name: string (< NURS_NAME_LEN), required
 * {s:s%, s:s,  s:o}
 *  name, type, flags
 */
static int parse_input_key_def(json_t *json, char *pname, size_t index,
			       struct nurs_input_key_def *def)
{
	json_t *jflags;
	json_error_t error;
	char *name, *stype;
	const char *sflag;
	size_t namelen, i;
	int type, flag;

	if (json_unpack_ex(json, &error, JSON_STRICT,
			   "{s:s%, s:s, s:o}",
			   "name", &name, &namelen,
			   "type", &stype,
			   "flags", &jflags) < 0) {
		nurs_log(NURS_ERROR, "plugin %s input[%s] error: %s\n",
			 pname, index, error.text);
		errno = EINVAL;
		return -1;
	}

	if (namelen > NURS_NAME_LEN) {
		nurs_log(NURS_ERROR, "too long input keyname: %s\n", name);
		errno = ENAMETOOLONG;
		return -1;
	}
	strncpy(def->name, name, NURS_NAME_LEN);
	if ((type = key_type(stype)) < 0) {
		nurs_log(NURS_ERROR, "invalid key type: %s, %s\n", name, stype);
		return -1;
	}
	def->type = (uint16_t)type;
	if (!json_is_array(jflags)) {
		nurs_log(NURS_ERROR,
			 "input flags must be an array: %s\n", name);
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < json_array_size(jflags); i++) {
		if (!json_is_string(json_array_get(jflags, i))) {
			nurs_log(NURS_ERROR,
				 "input flag must be a string: %s\n", name);
			errno = EINVAL;
			return -1;
		}
		sflag = json_string_value(json_array_get(jflags, i));
		flag = input_key_flag(sflag);
		if (flag < 0) {
			nurs_log(NURS_ERROR,
				 "invalid input flag: %s, %s\n", name, sflag);
			errno = EINVAL;
			return -1;
		}
		def->flags |= (uint16_t)flag;
	}

	return 0;
}


/*
 * string nurs_config_def
 *   [nurs_config_entry_def]
 *
 * struct nurs_input_def
 *   u [nurs_input_key_def]
 *
 * struct nurs_output_def
 *   [nurs_output_key_def]
 */

#define set_cb_s(_v)							\
	do {								\
	if (_v) {							\
		if (_v##_len > NURS_NAME_LEN) {				\
			nurs_log(NURS_ERROR, "too long " #_v " cb:"	\
				 "%s, len: %d\n", _v, _v##_len);	\
			errno = ENAMETOOLONG;				\
			goto fail_free;					\
		}							\
		strncpy(def->_v##_cb_s, _v, NURS_NAME_LEN);		\
	}								\
	} while (0)

/*
 * struct nurs_producer_def: "producer"
 *   version: string (< NURS_NAME_LEN), required
 *   name: string (< NURS_NAME_LEN), required
 *   context_size: integer, optional
 *   config: <nurs_config_def>, optional
 *   output: <nurs_output_def>, required
 *   organize: string, optional
 *   disorganize: string, optional
 *   start: string, optional
 *   stop: string, optional
 *   signal: string, optional
 * {s:s%,    s:s%,    s?i,          s?o,    s:o,    s?s%,     s?s%,        s?s%,  s?s%  s?s%}
 *  version, name,    context_size, config, output, organize, disorganize, start, stop, signal
 */

/**
 * nurs_producer_register_json - register a producer by JSON, jansson object
 * \param json jansson json object
 * \param context_size context size in byte for this producer
 * \param enlist register this producer or just check json representation
 *
 * This function registers a producer by JSON jansson object and returns
 * producer definition on success, or NULL on error. Or just returns producer
 * definition in case of enlist param is false.
 */
struct nurs_producer_def *
nurs_producer_register_json(json_t *json, uint16_t context_size, bool enlist)
{
	struct nurs_producer_def *def;
	json_t *jconfig = NULL, *joutput;
	json_error_t error;
	char *version, *name;
	char *organize = NULL, *disorganize = NULL;
	char *start = NULL, *stop = NULL, *signal = NULL;
	size_t verlen, namelen, i;
	size_t jconfig_size = 0, joutput_size = 0;
	size_t organize_len = 0, disorganize_len = 0;
	size_t start_len = 0, stop_len = 0, signal_len = 0;

	if (json_unpack_ex(json, &error, JSON_STRICT,
			   "{s:s%, s:s%, s?i, s?o, s:o, s?s%, s?s%, s?s%, s?s%, s?s%}",
			   "version", &version, &verlen,
			   "name", &name, &namelen,
			   "context_size", &context_size,
			   "config", &jconfig,
			   "output", &joutput,
			   "organize", &organize, &organize_len,
			   "disorganize", &disorganize, &disorganize_len,
			   "start", &start, &start_len,
			   "stop", &stop, &stop_len,
			   "signal", &signal, &signal_len) < 0) {
		nurs_log(NURS_ERROR, "producer plugin error on line %d: %s\n",
			  error.line, error.text);
		errno = EINVAL;
		return NULL;
	}

	if (jconfig && !json_is_array(jconfig)) {
		nurs_log(NURS_ERROR, "config must be an array\n");
		errno = EINVAL;
		return NULL;
	}
	if (jconfig)
		jconfig_size = json_array_size(jconfig);

	if (!json_is_array(joutput)) {
		nurs_log(NURS_ERROR, "output must be an array\n");
		errno = EINVAL;
		return NULL;
	}
	joutput_size = json_array_size(joutput);

	/* plugin / config / output */
	def = calloc(1, sizeof(struct nurs_producer_def)
		        + sizeof(struct nurs_config_def)
		        + sizeof(struct nurs_config_entry_def) * jconfig_size
		        + sizeof(struct nurs_output_def)
		        + sizeof(struct nurs_output_key_def) * joutput_size);
	if (!def)
		return NULL;

	def->config_def = (struct nurs_config_def *)
		((uintptr_t)def + sizeof(struct nurs_producer_def));
	def->config_def->len = (uint8_t)jconfig_size;
	def->output_def = (struct nurs_output_def *)
		((uintptr_t)def->config_def
		 + sizeof(struct nurs_config_def)
		 + sizeof(struct nurs_config_entry_def) * jconfig_size);
	def->output_def->len = (uint16_t)joutput_size;

	strncpy(def->version, version, NURS_NAME_LEN);
	strncpy(def->name, name, NURS_NAME_LEN);
	def->context_size = context_size;
	for (i = 0; i < jconfig_size; i++) {
		if (parse_config_entry_def(json_array_get(jconfig, i), name, i,
					   &def->config_def->keys[i]))
			goto fail_free;
	}
	for (i = 0; i < joutput_size; i++) {
		if (parse_output_key_def(json_array_get(joutput, i), name, i,
					 &def->output_def->keys[i]))
			goto fail_free;
	}

	set_cb_s(organize);
	set_cb_s(disorganize);
	set_cb_s(start);
	set_cb_s(stop);
	set_cb_s(signal);

	if (enlist && nurs_producer_register(def))
		goto fail_free;

	def->dynamic = true;
	def->resolve_callback = true;
	return def;
fail_free:
	free(def);
	return NULL;
}
EXPORT_SYMBOL(nurs_producer_register_json);

/*
 * struct nurs_filter_def: "filter"
 *   version: string (< NURS_NAME_LEN), required
 *   name: string (< NURS_NAME_LEN), required
 *   context_size: integer, optional
 *   mtsafe: bool, optional (default false)
 *   config: [nurs_config_def], optional
 *   input: [nurs_input_def], required
 *   output: [nurs_output_def], required
 *   organize: string, optional
 *   disorganize: string, optional
 *   start: string, optional
 *   stop: string, optional
 *   interp: string, required
 *   signal: string, optional
 * {s:s%,    s:s%,    s?i,          s?b,    s?o,    s:o,   s:o,    s?s%,     s?s%,        s?s%,  s?s%, s?s%    s?s%}
 *  version, name,    context_size, mtsafe, config, input, output, organize, disorganize, start, stop, interp, signal
 */
/**
 * nurs_filter_register_json - register filter by JSON, jansson object
 * \param json jansson json object
 * \param context_size context size in byte for this filter
 * \param enlist register this filter or just check json representation
 *
 * This function registers a filter by JSON jansson object and returns filter
 * definition on success, or NULL on error. Or just returns filter definition in
 * case of enlist param is false.
 */
struct nurs_filter_def *
nurs_filter_register_json(json_t *json, uint16_t context_size, bool enlist)
{
	struct nurs_filter_def *def;
	json_t *jconfig = NULL, *jinput, *joutput;
	json_error_t error;
	char *version, *name;
	char *organize = NULL, *disorganize = NULL;
	char *start = NULL, *stop = NULL;
	char *interp = NULL, *signal = NULL;
	bool mtsafe = false;
	size_t verlen, namelen, i;
	size_t jconfig_size = 0, jinput_size = 0, joutput_size = 0;
	size_t organize_len = 0, disorganize_len = 0;
	size_t start_len = 0, stop_len = 0, signal_len = 0, interp_len = 0;

	if (json_unpack_ex(json, &error, JSON_STRICT,
			   "{s:s%, s:s%, s?i, s?b, s?o, s:o, s:o"
			   " s?s%, s?s%, s?s%, s?s%, s?s%, s?s%}",
			   "version", &version, &verlen,
			   "name", &name, &namelen,
			   "context_size", &context_size,
			   "mtsafe", &mtsafe,
			   "config", &jconfig,
			   "input", &jinput,
			   "output", &joutput,
			   "organize", &organize, &organize_len,
			   "disorganize", &disorganize, &disorganize_len,
			   "start", &start, &start_len,
			   "interp", &interp, &interp_len,
			   "stop", &stop, &stop_len,
			   "signal", &signal, &signal_len) < 0) {
		nurs_log(NURS_ERROR, "filter plugin error on line %d: %s\n",
			  error.line, error.text);
		errno = EINVAL;
		return NULL;
	}

	if (jconfig && !json_is_array(jconfig)) {
		nurs_log(NURS_ERROR, "config must be an array\n");
		errno = EINVAL;
		return NULL;
	}
	if (jconfig)
		jconfig_size = json_array_size(jconfig);

	if (!json_is_array(jinput)) {
		nurs_log(NURS_ERROR, "input must be an array\n");
		errno = EINVAL;
		return NULL;
	}
	jinput_size = json_array_size(jinput);

	if (!json_is_array(joutput)) {
		nurs_log(NURS_ERROR, "output must be an array\n");
		errno = EINVAL;
		return NULL;
	}
	joutput_size = json_array_size(joutput);

	/* plugin / config / input / output */
	def = calloc(1, sizeof(struct nurs_filter_def)
		        + sizeof(struct nurs_config_def)
		        + sizeof(struct nurs_config_entry_def) * jconfig_size
		        + sizeof(struct nurs_input_def)
		        + sizeof(struct nurs_input_key_def) * jinput_size
		        + sizeof(struct nurs_output_def)
		 	+ sizeof(struct nurs_output_key_def) * joutput_size);
	if (!def)
		return NULL;

	def->config_def = (struct nurs_config_def *)
		((uintptr_t)def + sizeof(struct nurs_filter_def));
	def->config_def->len = (uint8_t)jconfig_size;
	def->input_def = (struct nurs_input_def *)
		((uintptr_t)def->config_def
		 + sizeof(struct nurs_config_def)
		 + sizeof(struct nurs_config_entry_def) * jconfig_size);
	def->input_def->len = (uint16_t)jinput_size;
	def->output_def = (struct nurs_output_def *)
		((uintptr_t)def->input_def
		 + sizeof(struct nurs_input_def)
		 + sizeof(struct nurs_input_key_def) * jinput_size);
	def->output_def->len = (uint16_t)joutput_size;

	strncpy(def->version, version, NURS_NAME_LEN);
	strncpy(def->name, name, NURS_NAME_LEN);
	def->context_size = context_size;
	def->mtsafe = mtsafe;
	for (i = 0; i < jconfig_size; i++) {
		if (parse_config_entry_def(json_array_get(jconfig, i), name, i,
					   &def->config_def->keys[i]))
			goto fail_free;
	}
	for (i = 0; i < jinput_size; i++) {
		if (parse_input_key_def(json_array_get(jinput, i), name, i,
					&def->input_def->keys[i]))
			goto fail_free;
	}
	for (i = 0; i < joutput_size; i++) {
		if (parse_output_key_def(json_array_get(joutput, i), name, i,
					 &def->output_def->keys[i]))
			goto fail_free;
	}

	set_cb_s(organize);
	set_cb_s(disorganize);
	set_cb_s(start);
	set_cb_s(interp);
	set_cb_s(stop);
	set_cb_s(signal);

	if (enlist && nurs_filter_register(def))
		goto fail_free;

	def->dynamic = true;
	def->resolve_callback = true;
	return def;
fail_free:
	free(def);
	return NULL;
}
EXPORT_SYMBOL(nurs_filter_register_json);

/*
 * struct nurs_consumer_def: "consumer"
 *   version: string (< NURS_NAME_LEN), required
 *   name: string (< NURS_NAME_LEN), required
 *   context_size: integer, optional
 *   mtsafe: bool, optional (default false)
 *   config: [nurs_config_def], optional
 *   input: [nurs_input_def], required
 *   organize: string, optional
 *   disorganize: string, optional
 *   start: string, optional
 *   stop: string, optional
 *   interp: string, required
 *   signal: string, optional
 * {s:s%,    s:s%,    s?i,          s?b,    s?o,    s:o,   s?s,      s?s,         s?s,   s?s,  s?s,    s?s}
 *  version, name,    context_size, mtsafe, config, input, organize, disorganize, start, stop, interp, signal
 */
/**
 * nurs_consumer_register_json - register consumer by JSON, jansson object
 * \param json jansson json object
 * \param context_size context size in byte for this consumer
 * \param enlist register this consumer or just check json representation
 *
 * This function registers a consumer by JSON jansson object and returns
 * consumer definition on success, or NULL on error. Or just returns consumer
 * definition in case of enlist param is false.
 */
struct nurs_consumer_def *
nurs_consumer_register_json(json_t *json, uint16_t context_size, bool enlist)
{
	struct nurs_consumer_def *def;
	json_t *jconfig = NULL, *jinput;
	json_error_t error;
	char *version, *name;
	char *organize = NULL, *disorganize = NULL;
	char *start = NULL, *stop = NULL;
	char *interp = NULL, *signal = NULL;
	bool mtsafe = false;
	size_t verlen, namelen, i;
	size_t jconfig_size = 0, jinput_size = 0;
	size_t organize_len = 0, disorganize_len = 0;
	size_t start_len = 0, stop_len = 0, signal_len = 0, interp_len = 0;

	if (json_unpack_ex(json, &error, JSON_STRICT,
			   "{s:s%, s:s%, s?i, s?b, s?o, s:o"
			   " s?s%, s?s%, s?s%, s?s%, s?s%, s?s%}",
			   "version", &version, &verlen,
			   "name", &name, &namelen,
			   "context_size", &context_size,
			   "mtsafe", &mtsafe,
			   "config", &jconfig,
			   "input", &jinput,
			   "organize", &organize, &organize_len,
			   "disorganize", &disorganize, &disorganize_len,
			   "start", &start, &start_len,
			   "interp", &interp, &interp_len,
			   "stop", &stop, &stop_len,
			   "signal", &signal, &signal_len) < 0) {
		nurs_log(NURS_ERROR, "consumer plugin error on line %d: %s\n",
			  error.line, error.text);
		errno = EINVAL;
		return NULL;
	}

	if (jconfig && !json_is_array(jconfig)) {
		nurs_log(NURS_ERROR, "config must be an array\n");
		errno = EINVAL;
		return NULL;
	}
	if (jconfig)
		jconfig_size = json_array_size(jconfig);

	if (!json_is_array(jinput)) {
		nurs_log(NURS_ERROR, "input must be an array\n");
		errno = EINVAL;
		return NULL;
	}
	jinput_size = json_array_size(jinput);

	/* plugin / config / input */
	def = calloc(1, sizeof(struct nurs_consumer_def)
		        + sizeof(struct nurs_config_def)
		        + sizeof(struct nurs_config_entry_def) * jconfig_size
		        + sizeof(struct nurs_input_def)
		     	+ sizeof(struct nurs_input_key_def) * jinput_size);
	if (!def)
		return NULL;

	def->config_def = (struct nurs_config_def *)
		((uintptr_t)def + sizeof(struct nurs_consumer_def));
	def->config_def->len = (uint8_t)jconfig_size;
	def->input_def = (struct nurs_input_def *)
		((uintptr_t)def->config_def
		 + sizeof(struct nurs_config_def)
		 + sizeof(struct nurs_config_entry_def) * jconfig_size);
	def->input_def->len = (uint16_t)jinput_size;

	strncpy(def->version, version, NURS_NAME_LEN);
	strncpy(def->name, name, NURS_NAME_LEN);
	def->context_size = context_size;
	def->mtsafe = mtsafe;
	for (i = 0; i < jconfig_size; i++) {
		if (parse_config_entry_def(json_array_get(jconfig, i), name, i,
					   &def->config_def->keys[i]))
			goto fail_free;
	}
	for (i = 0; i < jinput_size; i++) {
		if (parse_input_key_def(json_array_get(jinput, i), name, i,
					&def->input_def->keys[i]))
			goto fail_free;
	}

	set_cb_s(organize);
	set_cb_s(disorganize);
	set_cb_s(start);
	set_cb_s(interp);
	set_cb_s(stop);
	set_cb_s(signal);

	if (enlist && nurs_consumer_register(def))
		goto fail_free;

	def->dynamic = true;
	def->resolve_callback = true;

	return def;
fail_free:
	free(def);
	return NULL;
}
EXPORT_SYMBOL(nurs_consumer_register_json);

/*
 * struct nurs_coveter_def: "coveter"
 *   version: string (< NURS_NAME_LEN), required
 *   name: string (< NURS_NAME_LEN), required
 *   context_size: integer, optional
 *   mtsafe: bool, optional (default false)
 *   config: [nurs_config_def], optional
 *   organize: string, optional
 *   disorganize: string, optional
 *   start: string, optional
 *   stop: string, optional
 *   interp: string, required
 *   signal: string, optional
 * {s:s%,    s:s%,    s?i,          s?b,    s?o,    s?s%      s?s%         s?s%   s?s%, s?s%,   s?s%}
 *  version, name,    context_size, mtsafe, config, organize, disorganize, start, stop, interp, signal
 */
/**
 * nurs_coveter_register_json - register coveter by JSON, jansson object
 * \param json jansson json object
 * \param context_size context size in byte for this coveter
 * \param enlist register this coveter or just check json representation
 *
 * This function registers a coveter by JSON jansson object and returns coveter
 * definition on success, or NULL on error. Or just returns coveter definition
 * in case of enlist param is false.
 */
struct nurs_coveter_def *
nurs_coveter_register_json(json_t *json, uint16_t context_size, bool enlist)
{
	struct nurs_coveter_def *def;
	json_t *jconfig = NULL;
	json_error_t error;
	char *version, *name;
	char *organize = NULL, *disorganize = NULL;
	char *start = NULL, *stop = NULL;
	char *interp = NULL, *signal = NULL;
	bool mtsafe = false;
	size_t verlen, namelen, i;
	size_t organize_len = 0, disorganize_len = 0, jconfig_size = 0;
	size_t start_len = 0, stop_len = 0, signal_len = 0, interp_len = 0;

	if (json_unpack_ex(json, &error, JSON_STRICT,
			   "{s:s%, s:s%, s?i, s?b, s?o"
			   " s?s%, s?s%, s?s%, s?s%, s?s%, s?s%}",
			   "version", &version, &verlen,
			   "name", &name, &namelen,
			   "context_size", &context_size,
			   "mtsafe", &mtsafe,
			   "config", &jconfig,
			   "organize", &organize, &organize_len,
			   "disorganize", &disorganize, &disorganize_len,
			   "start", &start, &start_len,
			   "interp", &interp, &interp_len,
			   "stop", &stop, &stop_len,
			   "signal", &signal, &signal_len) < 0) {
		nurs_log(NURS_ERROR, "coveter plugin error on line %d: %s\n",
			  error.line, error.text);
		errno = EINVAL;
		return NULL;
	}

	if (jconfig && !json_is_array(jconfig)) {
		nurs_log(NURS_ERROR, "config must be an array\n");
		errno = EINVAL;
		return NULL;
	}
	if (jconfig)
		jconfig_size = json_array_size(jconfig);

	/* plugin / config */
	def = calloc(1, sizeof(struct nurs_coveter_def)
		     + sizeof(struct nurs_config_def)
		     + sizeof(struct nurs_config_entry_def) * jconfig_size);
	if (!def)
		return NULL;

	def->config_def = (struct nurs_config_def *)
		((uintptr_t)def + sizeof(struct nurs_coveter_def));
	def->config_def->len = (uint8_t)jconfig_size;

	strncpy(def->version, version, NURS_NAME_LEN);
	strncpy(def->name, name, NURS_NAME_LEN);
	def->context_size = context_size;
	def->mtsafe = mtsafe;
	for (i = 0; i < jconfig_size; i++) {
		if (parse_config_entry_def(json_array_get(jconfig, i), name, i,
					   &def->config_def->keys[i]))
			goto fail_free;
	}

	set_cb_s(organize);
	set_cb_s(disorganize);
	set_cb_s(start);
	set_cb_s(interp);
	set_cb_s(stop);
	set_cb_s(signal);

	if (enlist && nurs_coveter_register(def))
		goto fail_free;

	def->dynamic = true;
	def->resolve_callback = true;
	return def;
fail_free:
	free(def);
	return NULL;
}
EXPORT_SYMBOL(nurs_coveter_register_json);

#undef set_cb_s

static json_t *json_from_string(const char *input)
{
	json_t *root;
	json_error_t error;

	root = json_loads(input, JSON_REJECT_DUPLICATES, &error);
	if (!root) {
		nurs_log(NURS_ERROR, "error on line %d: %s\n",
			  error.line, error.text);
		errno = EINVAL;
		return NULL;
	}

	return root;
}

static json_t *json_from_file(const char *fname)
{
	json_t *root;
	json_error_t error;

	root = json_load_file(fname, JSON_REJECT_DUPLICATES, &error);
	if (!root) {
		nurs_log(NURS_ERROR, "error on line %d: %s\n",
			  error.line, error.text);
		errno = EINVAL;
		goto fail_decref;
	}

	return root;

fail_decref:
	return NULL;
}

#define register_plugin_json(_source, _type, _ctxsz, _arg)		\
	({								\
		json_t *root;						\
		struct nurs_ ##_type## _def *def = NULL;		\
		root = json_from_##_source (_arg);			\
		if (root) {						\
			def = nurs_ ##_type## _register_json(root, _ctxsz, true); \
			/* save errno? */				\
			json_decref(root);				\
		}							\
		def;							\
	})

/**
 * nurs_producer_register_jsons - register producer by JSON encoded string.
 * \param JSON encoded string
 * \param context_size context size in byte for this coveter
 *
 * This function registers a producer by JSON string and returns producer
 * definition on success, or NULL on error. It's a wrapper of
 * nurs_producer_register_json()
 */
struct nurs_producer_def *
nurs_producer_register_jsons(const char *input, uint16_t context_size)
{
	return register_plugin_json(string, producer, context_size, input);
}
EXPORT_SYMBOL(nurs_producer_register_jsons);

/**
 * nurs_filter_register_jsons - register filter by JSON encoded string.
 * \param JSON encoded string
 * \param context_size context size in byte for this filter
 *
 * This function registers a filter by JSON string and returns filter definition
 * on success, or NULL on error. It's a wrapper of nurs_filter_register_json()
 */
struct nurs_filter_def *
nurs_filter_register_jsons(const char *input, uint16_t context_size)
{
	return register_plugin_json(string, filter, context_size, input);
}
EXPORT_SYMBOL(nurs_filter_register_jsons);

/**
 * nurs_consumer_register_jsons - register consumer by JSON encoded string.
 * \param JSON encoded string
 * \param context_size context size in byte for this consumer
 *
 * This function registers a consumer by JSON string and returns consumer
 * definition on success, or NULL on error. It's a wrapper of
 * nurs_consumer_register_json()
 */
struct nurs_consumer_def *
nurs_consumer_register_jsons(const char *input, uint16_t context_size)
{
	return register_plugin_json(string, consumer, context_size, input);
}
EXPORT_SYMBOL(nurs_consumer_register_jsons);

/**
 * nurs_coveter_register_jsons - register coveter by JSON encoded string.
 * \param JSON encoded string
 * \param context_size context size in byte for this consumer
 *
 * This function registers a coveter by JSON string and returns coveter
 * definition on success, or NULL on error. It's a wrapper of
 * nurs_coveter_register_json()
 */
struct nurs_coveter_def *
nurs_coveter_register_jsons(const char *input, uint16_t context_size)
{
	return register_plugin_json(string, coveter, context_size, input);
}
EXPORT_SYMBOL(nurs_coveter_register_jsons);

/**
 * nurs_producer_register_jsons - register producer from JSON file
 * \param fname file name
 * \param context_size context size in byte for this consumer
 *
 * This function registers a producer from a file and returns producer
 * definition on success, or NULL on error. It's a wrapper of
 * nurs_producer_register_json()
 */
struct nurs_producer_def *
nurs_producer_register_jsonf(const char *fname, uint16_t context_size)
{
	return register_plugin_json(file, producer, context_size, fname);
}
EXPORT_SYMBOL(nurs_producer_register_jsonf);

/**
 * nurs_filter_register_jsons - register filter from JSON file
 * \param fname file name
 * \param context_size context size in byte for this consumer
 *
 * This function registers a filter from a file and returns filter definition on
 * success, or NULL on error. It's a wrapper of nurs_filter_register_json()
 */
struct nurs_filter_def *
nurs_filter_register_jsonf(const char *fname, uint16_t context_size)
{
	return register_plugin_json(file, filter, context_size, fname);
}
EXPORT_SYMBOL(nurs_filter_register_jsonf);

/**
 * nurs_consumer_register_jsons - register consumer from JSON file
 * \param fname file name
 * \param context_size context size in byte for this consumer
 *
 * This function registers a consumer from a file and returns consumer
 * definition on success, or NULL on error. It's a wrapper of
 * nurs_consumer_register_json()
 */
struct nurs_consumer_def *
nurs_consumer_register_jsonf(const char *fname, uint16_t context_size)
{
	return register_plugin_json(file, consumer, context_size, fname);
}
EXPORT_SYMBOL(nurs_consumer_register_jsonf);

/**
 * nurs_coveter_register_jsons - register coveter from JSON file
 * \param fname file name
 * \param context_size context size in byte for this consumer
 *
 * This function registers a coveter from a file and returns coveter definition
 * on success, or NULL on error. It's a wrapper of nurs_coveter_register_json()
 */
struct nurs_coveter_def *
nurs_coveter_register_jsonf(const char *fname, uint16_t context_size)
{
	return register_plugin_json(file, coveter, context_size, fname);
}
EXPORT_SYMBOL(nurs_coveter_register_jsonf);

#undef register_plugin_json

static const char *name_in_json(json_t *json)
{
	json_error_t error;
	char *name;

	if (json_unpack_ex(json, &error, 0, "{s:s}", "name", &name)) {
		nurs_log(NURS_ERROR, "producer plugin error on line %d: %s\n",
			 error.line, error.text);
		errno = EINVAL;
		return NULL;
	}

	return name;
}

/**
 * nurs_producer_unregister_json - unregister producer by jansson JSON
 * \param json jansson JSON object
 *
 * This function unregisters a producer by jansson JSON object, looks only its
 * name. Returns 0 on success or -1 on error.
 */
int nurs_producer_unregister_json(json_t *json)
{
	return nurs_producer_unregister_name(name_in_json(json));
}
EXPORT_SYMBOL(nurs_producer_unregister_json);

/**
 * nurs_filter_unregister_json - unregister filter by jansson JSON
 * \param json jansson JSON object
 *
 * This function unregisters a filter by jansson JSON object, looks only its
 * name. Returns 0 on success or -1 on error.
 */
int nurs_filter_unregister_json(json_t *json)
{
	return nurs_filter_unregister_name(name_in_json(json));
}
EXPORT_SYMBOL(nurs_filter_unregister_json);

/**
 * nurs_consumer_unregister_json - unregister consumer by jansson JSON
 * \param json jansson JSON object
 *
 * This function unregisters a consumer by jansson JSON object, looks only its
 * name. Returns 0 on success or -1 on error.
 */
int nurs_consumer_unregister_json(json_t *json)
{
	return nurs_consumer_unregister_name(name_in_json(json));
}
EXPORT_SYMBOL(nurs_consumer_unregister_json);

/**
 * nurs_coveter_unregister_json - unregister coveter by jansson JSON
 * \param json jansson JSON object
 *
 * This function unregisters a coveter by jansson JSON object, looks only its
 * name. Returns 0 on success or -1 on error.
 */
int nurs_coveter_unregister_json(json_t *json)
{
	return nurs_coveter_unregister_name(name_in_json(json));
}
EXPORT_SYMBOL(nurs_coveter_unregister_json);

struct json_op {
	char *name;
	enum nurs_plugin_type type;
	void *(*register_f)(json_t *json, uint16_t, bool);
	int (*unregister_f)(json_t *json);
} json_ops[] = {
	{
		"producer", NURS_PLUGIN_T_PRODUCER,
		(void *(*)(json_t *, uint16_t, bool))nurs_producer_register_json,
		nurs_producer_unregister_json
	},
	{
		"filter",   NURS_PLUGIN_T_FILTER,
		(void *(*)(json_t *, uint16_t, bool))nurs_filter_register_json,
		nurs_filter_unregister_json
	},
	{
		"consumer", NURS_PLUGIN_T_CONSUMER,
		(void *(*)(json_t *, uint16_t, bool))nurs_consumer_register_json,
		nurs_consumer_unregister_json
	},
	{
		"coveter",  NURS_PLUGIN_T_COVETER,
		(void *(*)(json_t *, uint16_t, bool))nurs_coveter_register_json,
		nurs_coveter_unregister_json
	},
	{NULL, 0, NULL, NULL}
};

/* XXX: no atomicity
 * means just only return in the middle of op on failure */
static int nurs_plugins_op_jsonf(bool enlist, const char *fname)
{
	json_t *root, *object, *array;
	size_t index;
	int nregister = 0, ret = -1;
	struct json_op *op;

	root = json_from_file(fname);
	if (!root)
		goto decref;

	if (!json_is_object(root)) {
		nurs_log(NURS_ERROR, "not a json object(dictionary)\n");
		errno = EINVAL;
		goto decref;
	}

	for (op = json_ops; op->name; op++) {
		array = json_object_get(root, op->name);
		if (!array)
			continue;

		if (!json_is_array(array)) {
			nurs_log(NURS_ERROR, "%s is not an array\n",
				 op->name);
			errno = EINVAL;
			goto decref;
		}
		json_array_foreach(array, index, object) {
			if (!json_is_object(object)) {
				nurs_log(NURS_ERROR, "not an object -"
					 " %s[%d]\n", op->name, index);
				errno = EINVAL;
				goto decref;
			}
			if (enlist) {
				if (!op->register_f(object, 0, true)) {
					nurs_log(NURS_ERROR, "failed to register"
						 " %s[%d]\n", op->name, index);
					goto decref;
				}
			} else {
				if (op->unregister_f(object)) {
					nurs_log(NURS_ERROR, "failed to unregister"
						 " %s[%d]\n", op->name, index);
					goto decref;
				}
			}
			nregister++;
		}
	}
	if (!nregister)
		nurs_log(NURS_NOTICE, "empty or useless json file?"
			 " no entry registered\n");
	else
		ret = 0;

decref:
	json_decref(root);
	return ret;
}

/**
 * nurs_plugins_register_json - register plugins by JSON file.
 * \param fname JSON file name
 *
 * This function registers plugins by jansson JSON object. Each plugin is
 * represented by key, named 'producer', 'filter', 'consumer' and 'coveter'.
 */
int nurs_plugins_register_jsonf(const char *fname)
{
	return nurs_plugins_op_jsonf(true, fname);
}
EXPORT_SYMBOL(nurs_plugins_register_jsonf);

/**
 * nurs_plugins_unregister_json - unregister plugins by JSON file.
 * \param fname JSON file name
 *
 * This function unregisters plugins by jansson JSON object. Each plugin is
 * represented by key, named 'producer', 'filter', 'consumer' and 'coveter'.
 */
int nurs_plugins_unregister_jsonf(const char *fname)
{
	return nurs_plugins_op_jsonf(false, fname);
}
EXPORT_SYMBOL(nurs_plugins_unregister_jsonf);

/**
 * @}
 */

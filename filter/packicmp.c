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

#include <nurs/nurs.h>
#include <nurs/ipfix_protocol.h>

enum {
	PACKICMP_INPUT_ICMP_CODE,
	PACKICMP_INPUT_ICMP_TYPE,
	PACKICMP_INPUT_MAX,
};

static struct nurs_input_def packicmp_input = {
	.len	= PACKICMP_INPUT_MAX,
	.keys	= {
		[PACKICMP_INPUT_ICMP_CODE] = {
			.name	= "icmp.code",
			.type	= NURS_KEY_T_UINT8,
			.flags	= NURS_IKEY_F_OPTIONAL,
		},
		[PACKICMP_INPUT_ICMP_TYPE] = {
			.name	= "icmp.type",
			.type	= NURS_KEY_T_UINT8,
			.flags	= NURS_IKEY_F_OPTIONAL,
		},
	},
};

enum {
	PACKICMP_OUTPUT_V4,
	PACKICMP_OUTPUT_MAX,
};

static struct nurs_output_def packicmp_output = {
	.len	= PACKICMP_OUTPUT_MAX,
	.keys	= {
		[PACKICMP_OUTPUT_V4] = {
			.name	= "icmp.typecode4",
			.type	= NURS_KEY_T_UINT16,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor		= IPFIX_VENDOR_IETF,
				.field_id	= IPFIX_icmpTypeCodeIPv4,
			},
		},
	},
};

static enum nurs_return_t
packicmp_interp(const struct nurs_plugin *plugin,
		const struct nurs_input *input,
		struct nurs_output *output)
{
	uint8_t type, code;

	if (!nurs_input_is_valid(input, PACKICMP_INPUT_ICMP_TYPE)
	    || !nurs_input_is_valid(input, PACKICMP_INPUT_ICMP_CODE))
		return NURS_RET_OK;

	type = nurs_input_u8(input, PACKICMP_INPUT_ICMP_TYPE);
	code = nurs_input_u8(input, PACKICMP_INPUT_ICMP_CODE);
	nurs_output_set_u16(output, PACKICMP_OUTPUT_V4, (uint16_t)(type << 8 | code));

	return NURS_RET_OK;
}

static struct nurs_filter_def packicmp_filter = {
	.name		= "PACKICMP",
	.version	= VERSION,
	.input_def	= &packicmp_input,
	.output_def	= &packicmp_output,
	.mtsafe		= true,
	.interp		= &packicmp_interp,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	nurs_filter_register(&packicmp_filter);
}

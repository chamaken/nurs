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
#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <nurs/nurs.h>
#include <nurs/ipfix_protocol.h>

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC	((uint32_t)1000000000L)
#endif

enum {
	TIMECONV_CONFIG_USEC64,
	TIMECONV_CONFIG_MAX,
};

static struct nurs_config_def timeconv_config = {
	.len	 = TIMECONV_CONFIG_MAX,
	.keys = {
		[TIMECONV_CONFIG_USEC64] = {
			.name	 = "usec64",
			.type	 = NURS_CONFIG_T_BOOLEAN,
			.flags	 = NURS_CONFIG_F_NONE,
			.boolean = true,
		},
	},
};

#define config_usec64(x)	nurs_config_boolean(nurs_plugin_config(x), TIMECONV_CONFIG_USEC64)

enum {
	TIMECONV_INPUT_FLOW_START_SEC,
	TIMECONV_INPUT_FLOW_START_USEC,
	TIMECONV_INPUT_FLOW_END_SEC,
	TIMECONV_INPUT_FLOW_END_USEC,
	TIMECONV_INPUT_MAX,
};

static struct nurs_input_def timeconv_input = {
	.len	= TIMECONV_INPUT_MAX,
	.keys	= {
		[TIMECONV_INPUT_FLOW_START_SEC] = {
			.name	= "flow.start.sec",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_IKEY_F_OPTIONAL,
		},
		[TIMECONV_INPUT_FLOW_START_USEC] = {
			.name	= "flow.start.usec",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_IKEY_F_OPTIONAL,
		},
		[TIMECONV_INPUT_FLOW_END_SEC] = {
			.name	= "flow.end.sec",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_IKEY_F_OPTIONAL,
		},
		[TIMECONV_INPUT_FLOW_END_USEC] = {
			.name	= "flow.end.usec",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_IKEY_F_OPTIONAL,
		},
	},
};

enum {
	TIMECONV_OUTPUT_FLOW_START_USEC64,
	TIMECONV_OUTPUT_FLOW_END_USEC64,
	TIMECONV_OUTPUT_MAX,
};

/* output value will already be BE encoded, so that
 * .type is NURS_KEY_T_EMBED not to encode more.
 */
static struct nurs_output_def timeconv_output = {
	.len	= TIMECONV_OUTPUT_MAX,
	.keys	= {
		[TIMECONV_OUTPUT_FLOW_START_USEC64] = {
			.name	= "flow.start.useconds",
			.type	= NURS_KEY_T_EMBED,
                        .len	= sizeof(uint64_t),
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor		= IPFIX_VENDOR_IETF,
				.field_id	= IPFIX_flowStartMicroSeconds,
			},
		},
		[TIMECONV_OUTPUT_FLOW_END_USEC64] = {
			.name	= "flow.end.useconds",
			.type	= NURS_KEY_T_EMBED,
                        .len	= sizeof(uint64_t),
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor		= IPFIX_VENDOR_IETF,
				.field_id	= IPFIX_flowEndMicroSeconds,
			},
		},
	},
};

struct tm MSB1BASE = {
        .tm_year = 0,
        .tm_mon = 0,
        .tm_mday = 1,
        .tm_hour = 0,
        .tm_min = 0,
        .tm_sec = 0,
};
struct tm MSB0BASE = {
        .tm_year = 2036 - 1900,
        .tm_mon = 1,
        .tm_mday = 7,
        .tm_hour = 6,
        .tm_min = 28,
        .tm_sec = 16,
};
static time_t msb1base_time, msb0base_time;
const time_t MSB1BASE_TIME = -2209021200;
const time_t MSB0BASE_TIME = 2085946096;

static inline uint64_t conv_ntp_us(uint32_t sec, uint32_t usec)
{
        int use_base1 = sec < msb0base_time;
        uint32_t fraction;

        if (use_base1)
                sec -= msb1base_time;
        else
                sec -= msb0base_time;

        fraction = usec * 0x100000000 / 1000000;

        if (use_base1)
                sec |= 0x80000000;

	return (uint64_t)htonl((uint32_t)sec) << 32 | htonl(fraction);
}

static void set_ntp(struct nurs_output *output,
		    uint32_t start_sec, uint32_t start_usec,
		    uint32_t end_sec, uint32_t end_usec)
{
	nurs_output_set_u64(output, TIMECONV_OUTPUT_FLOW_START_USEC64,
			    conv_ntp_us(start_sec, start_usec));
	nurs_output_set_u64(output, TIMECONV_OUTPUT_FLOW_END_USEC64,
			    conv_ntp_us(end_sec, end_usec));
}

static enum nurs_return_t
timeconv_organize(const struct nurs_plugin *plugin)
{
        msb1base_time = mktime(&MSB1BASE);
        msb0base_time = mktime(&MSB0BASE);

	return NURS_RET_OK;
}

static enum nurs_return_t
timeconv_interp(const struct nurs_plugin *plugin,
		const struct nurs_input *input,
		struct nurs_output *output)
{
	char buf[4096];

	if (!nurs_input_is_valid(input, TIMECONV_INPUT_FLOW_START_SEC)
	    || !nurs_input_is_valid(input, TIMECONV_INPUT_FLOW_START_USEC)
	    || !nurs_input_is_valid(input, TIMECONV_INPUT_FLOW_END_SEC)
	    || !nurs_input_is_valid(input, TIMECONV_INPUT_FLOW_END_USEC)) {
		snprintf(buf, sizeof(buf), "%s%s%s%s",
			 nurs_input_is_valid(input,
					     TIMECONV_INPUT_FLOW_START_SEC)
			 ? "" : " flow.start.sec",
			 nurs_input_is_valid(input,
					     TIMECONV_INPUT_FLOW_START_USEC)
			 ? "" : " flow.start.usec",
			 nurs_input_is_valid(input,
					     TIMECONV_INPUT_FLOW_END_SEC)
			 ? "" : " flow.end.sec",
			 nurs_input_is_valid(input,
					     TIMECONV_INPUT_FLOW_END_USEC)
			 ? "" : " flow.end.usec");

		nurs_log(NURS_NOTICE, "could not find key(s):%s\n", buf);
		return NURS_RET_OK;
	}

	set_ntp(output,
                nurs_input_u32(input, TIMECONV_INPUT_FLOW_START_SEC),
                nurs_input_u32(input, TIMECONV_INPUT_FLOW_START_USEC),
                nurs_input_u32(input, TIMECONV_INPUT_FLOW_END_SEC),
                nurs_input_u32(input, TIMECONV_INPUT_FLOW_END_USEC));

	return NURS_RET_OK;
}

static struct nurs_filter_def timeconv_filter = {
	.name		= "TIMECONV",
	.version	= VERSION,
	.config_def	= &timeconv_config,
	.input_def	= &timeconv_input,
	.output_def	= &timeconv_output,
	.mtsafe		= true,
	.organize	= &timeconv_organize,
	.interp		= &timeconv_interp,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	nurs_filter_register(&timeconv_filter);
}

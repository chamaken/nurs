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

#define PROC_TIMER_LIST "/proc/timer_list"

struct timeconv_priv {
	uint64_t rtoffset;		/* in ns */
	void (*setfunc)(struct nurs_output *, uint64_t,
			uint32_t, uint32_t, uint32_t, uint32_t);
};

enum {
	TIMECONV_CONFIG_USEC64,
	TIMECONV_CONFIG_UPTIME,
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
		[TIMECONV_CONFIG_UPTIME] = {
			.name	 = "uptime",
			.type	 = NURS_CONFIG_T_BOOLEAN,
			.flags   = NURS_CONFIG_F_NONE,
			.boolean = true,
		},
	},
};

#define config_usec64(x)	nurs_config_boolean(nurs_plugin_config(x), TIMECONV_CONFIG_USEC64)
#define config_uptime(x)	nurs_config_boolean(nurs_plugin_config(x), TIMECONV_CONFIG_UPTIME)

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
	TIMECONV_OUTPUT_FLOW_START_UPTIME,
	TIMECONV_OUTPUT_FLOW_END_UPTIME,
	TIMECONV_OUTPUT_MAX,
};

static struct nurs_output_def timeconv_output = {
	.len	= TIMECONV_OUTPUT_MAX,
	.keys	= {
		[TIMECONV_OUTPUT_FLOW_START_USEC64] = {
			.name	= "flow.start.useconds",
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor		= IPFIX_VENDOR_IETF,
				.field_id	= IPFIX_flowStartMicroSeconds,
			},
		},
		[TIMECONV_OUTPUT_FLOW_END_USEC64] = {
			.name	= "flow.end.useconds",
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor		= IPFIX_VENDOR_IETF,
				.field_id	= IPFIX_flowEndMicroSeconds,
			},
		},
		[TIMECONV_OUTPUT_FLOW_START_UPTIME] = {
			.name	= "flow.start.uptime",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor		= IPFIX_VENDOR_IETF,
				.field_id	= IPFIX_flowStartSysUpTime,
			},
		},
		[TIMECONV_OUTPUT_FLOW_END_UPTIME] = {
			.name	= "flow.end.uptime",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.ipfix	= {
				.vendor		= IPFIX_VENDOR_IETF,
				.field_id	= IPFIX_flowEndSysUpTime,
			},
		},
	},
};

static inline uint64_t conv_ntp_us(uint32_t sec, uint32_t usec)
{
	/* RFC7011 - 6.1.10. dateTimeMicroseconds */
	return (((uint64_t) sec << 32)
		+ ((uint64_t) usec << 32) / (NSEC_PER_SEC / 1000))
		& (uint64_t)~0x07ff;
}

static void set_ntp(struct nurs_output *output, uint64_t offset,
		    uint32_t start_sec, uint32_t start_usec,
		    uint32_t end_sec, uint32_t end_usec)
{
	nurs_output_set_u64(output, TIMECONV_OUTPUT_FLOW_START_USEC64,
			    conv_ntp_us(start_sec, start_usec));
	nurs_output_set_u64(output, TIMECONV_OUTPUT_FLOW_END_USEC64,
			    conv_ntp_us(end_sec, end_usec));
}

static inline uint32_t conv_uptime(uint64_t offset, uint32_t sec, uint32_t usec)
{
	return (sec - (uint32_t)(offset / NSEC_PER_SEC)) * 1000
		+ usec / 1000 - (uint32_t)(offset % NSEC_PER_SEC) / 1000000;
}

static void set_uptime(struct nurs_output *output, uint64_t offset,
		       uint32_t start_sec, uint32_t start_usec,
		       uint32_t end_sec, uint32_t end_usec)
{
	nurs_output_set_u32(output, TIMECONV_OUTPUT_FLOW_START_UPTIME,
			    conv_uptime(offset, start_sec, start_usec));
	nurs_output_set_u32(output, TIMECONV_OUTPUT_FLOW_END_UPTIME,
			    conv_uptime(offset, end_sec, end_usec));
}

static void set_ntp_uptime(struct nurs_output *output, uint64_t offset,
			   uint32_t start_sec, uint32_t start_usec,
			   uint32_t end_sec, uint32_t end_usec)
{
	set_ntp(output, offset, start_sec, start_usec, end_sec, end_usec);
	set_uptime(output, offset, start_sec, start_usec, end_sec, end_usec);
}

static enum nurs_return_t
timeconv_organize(const struct nurs_plugin *plugin)
{
	struct timeconv_priv *priv = nurs_plugin_context(plugin);
	int fd;
	ssize_t nread, n;
	char buf[4096]; /* XXX: MAGIC NUMBER */
	char *s = "ktime_get_real\n  .offset: ";
	void *p;
	size_t slen = strlen(s);

	/* get rt offset */
	fd = open(PROC_TIMER_LIST, O_RDONLY);
	if (fd == -1) {
		nurs_log(NURS_ERROR, "open: %s\n", _sys_errlist[errno]);
		return NURS_RET_ERROR;
	}

	nread = 0;
	do {
		n = read(fd, buf + nread, sizeof(buf) - (size_t)nread);
		nread += n;
	} while (n > 0 && nread < 4096);
	close(fd);
	if (n == -1) {
		nurs_log(NURS_ERROR, "read: %s\n", _sys_errlist[errno]);
		return NURS_RET_ERROR;
	}

	p = memmem(buf, (size_t)nread, s, slen);
	if (p == NULL) {
		nurs_log(NURS_ERROR, "no ktime_get_real entry in %s\n",
			  PROC_TIMER_LIST);
		return NURS_RET_ERROR;
	}
	buf[nread] = '\0';
	if (sscanf((char *)((uintptr_t)p + slen),
		   " %"PRIu64, &priv->rtoffset) == EOF) {
		nurs_log(NURS_ERROR, "sscanf: %s\n", _sys_errlist[errno]);
		return NURS_RET_ERROR;
	}

	/* select set function */
	if (config_usec64(plugin))
		if (config_uptime(plugin))
			priv->setfunc = &set_ntp_uptime;
		else
			priv->setfunc = &set_ntp;
	else if (config_uptime(plugin))
		priv->setfunc = &set_uptime;
	else {
		nurs_log(NURS_ERROR, "no convertion?\n");
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static enum nurs_return_t
timeconv_interp(const struct nurs_plugin *plugin,
		const struct nurs_input *input,
		struct nurs_output *output)
{
	struct timeconv_priv *priv = nurs_plugin_context(plugin);
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

	priv->setfunc(output, priv->rtoffset,
		      nurs_input_u32(input, TIMECONV_INPUT_FLOW_START_SEC),
		      nurs_input_u32(input, TIMECONV_INPUT_FLOW_START_USEC),
		      nurs_input_u32(input, TIMECONV_INPUT_FLOW_END_SEC),
		      nurs_input_u32(input, TIMECONV_INPUT_FLOW_END_USEC));

	return NURS_RET_OK;
}

static struct nurs_filter_def timeconv_filter = {
	.name		= "TIMECONV",
	.version	= VERSION,
	.context_size	= sizeof(struct timeconv_priv),
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

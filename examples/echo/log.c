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
#include <nurs/nurs.h>

enum log_input_keys {
        LOG_INPUT_MESSAGE,
	LOG_INPUT_MAX,
};

static struct nurs_input_def log_input = {
	.len  = LOG_INPUT_MAX,
	.keys = {
		[LOG_INPUT_MESSAGE] = {
			.type  = NURS_KEY_T_EMBED,
			.flags = NURS_IKEY_F_REQUIRED,
			.name  = "message",
		},
	},
};

static int log_interp(const struct nurs_plugin *plugin,
		      const struct nurs_input *input)
{
        const char *s = nurs_input_pointer(input, LOG_INPUT_MESSAGE);
        nurs_log(NURS_INFO, "message: %s\n", s);
	return NURS_RET_OK;
}

static struct nurs_consumer_def log_consumer = {
	.name		= "LOG",
	.version	= VERSION,
	.context_size	= 0,
	.mtsafe		= true,
	.config_def	= NULL,
	.input_def	= &log_input,
	.organize	= NULL,
	.disorganize	= NULL,
	.start		= NULL,
	.stop		= NULL,
	.interp		= &log_interp,
	.signal		= NULL,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	nurs_consumer_register(&log_consumer);
}

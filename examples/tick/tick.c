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

enum tick_config {
	TICK_CONFIG_MYNAME,
	TICK_CONFIG_MAX,
};

static struct nurs_config_def tick_config = {
	.len	= TICK_CONFIG_MAX,
	.keys	= {
		[TICK_CONFIG_MYNAME] = {
			.name	= "myname",
			.type	= NURS_CONFIG_T_STRING,
			.flags	= NURS_CONFIG_F_MANDATORY,
		},
	},
};

enum tick_output_keys {
	TICK_OUTPUT_COUNTER,
	TICK_OUTPUT_MYNAME,
	TICK_OUTPUT_MAX,
};

static struct nurs_output_def tick_output = {
	.len = TICK_OUTPUT_MAX,
	.keys = {
		[TICK_OUTPUT_COUNTER] = {
			.name	= "counter",
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_ALWAYS,
		},
		[TICK_OUTPUT_MYNAME] = {
			.name	= "producer.name",
			.type	= NURS_KEY_T_STRING,
			.flags	= NURS_OKEY_F_ALWAYS,
			.len	= 32,
		},
	},
};

struct tick_priv {
	uint64_t counter;
	struct nurs_timer *timer;
	const char *myname;
};

static enum nurs_return_t
tick_timer_cb(struct nurs_timer *timer, void *data)
{
	struct nurs_producer *producer = data;
	struct tick_priv *priv = nurs_producer_context(producer);
	struct nurs_output *output = nurs_get_output(producer);

	nurs_output_set_u64(output, TICK_OUTPUT_COUNTER,
			    priv->counter++);
	nurs_output_set_string(output, TICK_OUTPUT_MYNAME, priv->myname);

	return nurs_publish(output);
}

static enum nurs_return_t tick_organize(struct nurs_producer *producer)
{
	struct tick_priv *priv = nurs_producer_context(producer);

	priv->timer = nurs_timer_create(tick_timer_cb, producer);
	if (!priv->timer) {
		nurs_log(NURS_ERROR, "failed to create timer\n");
		return NURS_RET_ERROR;
	}
	priv->myname = nurs_config_string(nurs_producer_config(producer), 0);

	return NURS_RET_OK;
}

static enum nurs_return_t
tick_disorganize(struct nurs_producer *producer)
{
	struct tick_priv *priv = nurs_producer_context(producer);

	if (nurs_timer_destroy(priv->timer)) {
		nurs_log(NURS_ERROR, "failed to destroy timer\n");
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static enum nurs_return_t tick_start(struct nurs_producer *producer)
{
	struct tick_priv *priv = nurs_producer_context(producer);

	if (nurs_itimer_add(priv->timer, 1, 1)) {
		nurs_log(NURS_ERROR, "failed to add itimer\n");
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static enum nurs_return_t tick_stop(struct nurs_producer *producer)
{
	struct tick_priv *priv = nurs_producer_context(producer);

	if (nurs_timer_del(priv->timer)) {
		nurs_log(NURS_ERROR, "failed to del timer\n");
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}


static struct nurs_producer_def tick_producer = {
	.version	= "0.1",
	.name		= "TICK",
	.context_size	= sizeof(struct tick_priv),
	.config_def	= &tick_config,
	.output_def	= &tick_output,
	.organize	= tick_organize,
	.disorganize	= tick_disorganize,
	.start		= tick_start,
	.stop		= tick_stop,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	nurs_producer_register(&tick_producer);
}

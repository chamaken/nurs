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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nurs/nurs.h>
#include <nurs/list.h>

#include "internal.h"

static struct nurs_plugin *
producer_create(struct nurs_plugin_def *defbase, const char *id)
{
	struct nurs_producer_def *def
		= (struct nurs_producer_def *)defbase;
	struct nurs_producer *pl;
	pthread_mutexattr_t attr; /* = {{0}}; */
	memset(&attr, 0, sizeof(pthread_mutexattr_t));

	pl = calloc(1, sizeof(struct nurs_producer) + def->context_size);
	if (pl == NULL) {
		nurs_log(NURS_ERROR, "failed to calloc: %s\n", strerror(errno));
		return NULL;
	}

	init_list_head(&pl->iosets);
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, NURS_MUTEX_ATTR);
	pthread_mutex_init(&pl->iosets_mutex, &attr);
	pthread_cond_init(&pl->iosets_condv, NULL);
	init_list_head(&pl->stacks);

	return (struct nurs_plugin *)pl;
}

static int producer_destroy(struct nurs_plugin *plugin)
{
	struct nurs_producer *producer = (struct nurs_producer *)plugin;
	int ret;

	if (ioset_destroy(producer)) { /* :: ioset.c */
		nurs_log(NURS_ERROR, "failed to destroy ioset %s: %s\n",
			 producer->id, strerror(errno));
		return -1;
	}

	if ((ret = pthread_mutex_destroy(&producer->iosets_mutex))) {
		nurs_log(NURS_FATAL, "pthread_mutex_destroy: %s\n",
			 strerror(ret));
		return -1;
	}
	if ((ret = pthread_cond_destroy(&producer->iosets_condv))) {
		nurs_log(NURS_FATAL, "pthread_cond_destroy: %s\n",
			 strerror(ret));
		return -1;
	}

	free(producer->config);

	return 0;
}

static int producer_resolve(struct nurs_plugin_def *defbase)
{
	struct nurs_producer_def *producer
		= (struct nurs_producer_def *)defbase;

	if (plugin_resolve_output_destructor(producer->dlh->h,
					     producer->output_def))
		return -1;
	if (!producer->resolve_callback)
		return 0;

	if (plugin_resolve_cbsym(defbase,
				 producer->organize_cb_s,
				 (void **)&producer->organize))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 producer->disorganize_cb_s,
				 (void **)&producer->disorganize))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 producer->start_cb_s,
				 (void **)&producer->start))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 producer->stop_cb_s,
				 (void **)&producer->stop))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 producer->signal_cb_s,
				 (void **)&producer->signal))
		return -1;

	return 0;
}

static int producer_check(const struct nurs_plugin_def *defbase)
{
	const struct nurs_producer_def *def
		= (const struct nurs_producer_def *)defbase;
	int ret = 0;

	if (!def->organize) {
		nurs_log(NURS_ERROR, "plugin: %s, no organize cb\n",
			 def->name);
		ret = -1;
	}
	if (!def->output_def || !def->output_def->len) {
		nurs_log(NURS_ERROR, "plugin: %s, no output\n", def->name);
		ret = -1;
	} else if (plugin_check_output(def->name, def->output_def)) {
		ret = -1;
	}

	return ret;
}

static int producer_show(const struct nurs_plugin_def *defbase)
{
	const struct nurs_producer_def *def
		= (const struct nurs_producer_def *)defbase;
	int ret;

	ret = plugin_show_output(def->output_def);
	if (ret)
		return ret;

	printf("callback:\n");
	if (def->resolve_callback) {
		if (def->organize_cb_s)
			printf("  organize: %s\n", def->organize_cb_s);
		if (def->disorganize_cb_s)
			printf("  disorganize: %s\n", def->disorganize_cb_s);
		if (def->start_cb_s)
			printf("  start: %s\n", def->start_cb_s);
		if (def->stop_cb_s)
			printf("  stop: %s\n", def->stop_cb_s);
		if (def->signal_cb_s)
			printf("  signal: %s\n", def->signal_cb_s);
	} else {
		if (def->organize)
			printf("  organize: %p\n", def->organize);
		if (def->disorganize)
			printf("  disorganize: %p\n", def->disorganize);
		if (def->start)
			printf("  start: %p\n", def->start);
		if (def->stop)
			printf("  stop: %p\n", def->stop);
		if (def->signal)
			printf("  signal: %p\n", def->signal);
	}

	return 0;
}

struct nurs_plugin_ops producer_ops = {
	.type		= NURS_PLUGIN_T_PRODUCER,
	.create		= &producer_create,
	.destroy	= &producer_destroy,
	.resolve_cb	= &producer_resolve,
	.check		= &producer_check,
	.show		= &producer_show,
};

int producer_init(void)
{
	return register_plugin_ops(&producer_ops);
}

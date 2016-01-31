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
consumer_create(struct nurs_plugin_def *defbase, const char *id)
{
	struct nurs_consumer_def *def = (struct nurs_consumer_def *)defbase;
	struct nurs_consumer *pl;
	pthread_mutexattr_t attr; /* = {{0}}; */
	memset(&attr, 0, sizeof(pthread_mutexattr_t));

	pl = calloc(1, sizeof(struct nurs_consumer) + def->context_size);
	if (pl == NULL) {
		nurs_log(NURS_ERROR, "failed to calloc: %s\n", strerror(errno));
		return NULL;
	}

	if (!def->mtsafe) {
		pthread_mutexattr_settype(&attr, NURS_MUTEX_ATTR);
		pthread_mutex_init(&pl->mutex, &attr);
	}

	return (struct nurs_plugin *)pl;
}

static int consumer_destroy(struct nurs_plugin *plugin)
{
	struct nurs_consumer *consumer = (struct nurs_consumer *)plugin;
	int ret;

	if (!consumer->def->mtsafe) {
		if ((ret = pthread_mutex_destroy(&consumer->mutex))) {
			nurs_log(NURS_FATAL, "pthread_mutex_destroy: %s\n",
				 strerror(ret));
			return -1;
		}
	}

	free(consumer->config);

	return 0;
}

static int consumer_resolve(struct nurs_plugin_def *defbase)
{
	struct nurs_consumer_def *consumer = (struct nurs_consumer_def *)defbase;

	if (!consumer->resolve_callback)
		return 0;

	if (plugin_resolve_cbsym(defbase,
				 consumer->organize_cb_s,
				 (void **)&consumer->organize))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 consumer->disorganize_cb_s,
				 (void **)&consumer->disorganize))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 consumer->start_cb_s,
				 (void **)&consumer->start))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 consumer->stop_cb_s,
				 (void **)&consumer->stop))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 consumer->interp_cb_s,
				 (void **)&consumer->interp))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 consumer->signal_cb_s,
				 (void **)&consumer->signal))
		return -1;

	return 0;
}

static int consumer_check(const struct nurs_plugin_def *defbase)
{
	const struct nurs_consumer_def *def
		= (const struct nurs_consumer_def *)defbase;
	int ret = 0;

	if (!def->interp) {
		nurs_log(NURS_ERROR, "plugin: %s, no interp cb\n", def->name);
		ret = -1;
	}
	if (!def->input_def || !def->input_def->len) {
		nurs_log(NURS_ERROR, "plugin: %s, no input\n", def->name);
		ret = -1;
	} else if (plugin_check_input(def->name, def->input_def)) {
		ret = -1;
	}

	return ret;
}

static int consumer_show(const struct nurs_plugin_def *defbase)
{
	const struct nurs_consumer_def *def
		= (const struct nurs_consumer_def *)defbase;
	int ret;

	printf("MT-safe: %s\n", def->mtsafe ? "true" : "false");

	ret = plugin_show_input(def->input_def);
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
		if (def->interp_cb_s)
			printf("  interp: %s\n", def->interp_cb_s);
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
		if (def->interp)
			printf("  interp: %p\n", def->interp);
		if (def->signal)
			printf("  signal: %p\n", def->signal);
	}

	return 0;
}

struct nurs_plugin_ops consumer_ops = {
	.type		= NURS_PLUGIN_T_CONSUMER,
	.create		= &consumer_create,
	.destroy	= &consumer_destroy,
	.resolve_cb	= &consumer_resolve,
	.check		= &consumer_check,
	.show		= &consumer_show,
};

int consumer_init(void)
{
	return register_plugin_ops(&consumer_ops);
}

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

#include "internal.h"

static struct nurs_plugin *
filter_create(struct nurs_plugin_def *defbase, const char *id)
{
	struct nurs_filter_def *def = (struct nurs_filter_def *)defbase;
	struct nurs_filter *pl;
	pthread_mutexattr_t attr; /* = {{0}}; */
	memset(&attr, 0, sizeof(pthread_mutexattr_t));

	pl = calloc(1, sizeof(struct nurs_filter) + def->context_size);
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

static int filter_destroy(struct nurs_plugin *plugin)
{
	struct nurs_filter *filter = (struct nurs_filter *)plugin;
	int ret;

	if (!filter->def->mtsafe) {
		if ((ret = pthread_mutex_destroy(&filter->mutex))) {
			nurs_log(NURS_FATAL, "pthread_mutex_destroy: %s\n",
				 strerror(ret));
			return -1;
		}
	}

	if (filter->config)
		free(filter->config);

	return 0;
}

static int filter_resolve(struct nurs_plugin_def *defbase)
{
	struct nurs_filter_def *filter = (struct nurs_filter_def *)defbase;

	if (plugin_resolve_output_destructor(filter->dlh->h, filter->output_def))
		return -1;
	if (!filter->resolve_callback)
		return 0;

	if (plugin_resolve_cbsym(defbase,
				 filter->organize_cb_s,
				 (void **)&filter->organize))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 filter->disorganize_cb_s,
				 (void **)&filter->disorganize))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 filter->start_cb_s,
				 (void **)&filter->start))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 filter->stop_cb_s,
				 (void **)&filter->stop))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 filter->interp_cb_s,
				 (void **)&filter->interp))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 filter->signal_cb_s,
				 (void **)&filter->signal))
		return -1;

	return 0;
}

static int filter_check(const struct nurs_plugin_def *defbase)
{
	const struct nurs_filter_def *def
		= (const struct nurs_filter_def *)defbase;
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
	if (!def->output_def || !def->output_def->len) {
		nurs_log(NURS_ERROR, "plugin: %s, no output\n", def->name);
		ret = -1;
	} else if (plugin_check_output(def->name, def->output_def)) {
		ret = -1;
	}

	return ret;
}

static int filter_show(const struct nurs_plugin_def *defbase)
{
	const struct nurs_filter_def *def
		= (const struct nurs_filter_def *)defbase;
	int ret;

	printf("MT-safe: %s\n", def->mtsafe ? "true" : "false");

	ret = plugin_show_input(def->input_def);
	if (ret)
		return ret;
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

struct nurs_plugin_ops filter_ops = {
	.type		= NURS_PLUGIN_T_FILTER,
	.create		= &filter_create,
	.destroy	= &filter_destroy,
	.resolve_cb	= &filter_resolve,
	.check		= &filter_check,
	.show		= &filter_show,
};

int filter_init(void)
{
	return register_plugin_ops(&filter_ops);
}

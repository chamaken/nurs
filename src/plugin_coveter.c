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
coveter_create(struct nurs_plugin_def *defbase, const char *id)
{
	struct nurs_coveter_def *def = (struct nurs_coveter_def *)defbase;
	struct nurs_coveter *pl;
	pthread_mutexattr_t attr; /* = {{0}}; */
	memset(&attr, 0, sizeof(pthread_mutexattr_t));

	pl = calloc(1, sizeof(struct nurs_coveter) + def->context_size);
	if (pl == NULL) {
		nurs_log(NURS_ERROR, "failed to calloc: %s\n",
			 strerror(errno));
		return NULL;
	}

	if (!def->mtsafe) {
		pthread_mutexattr_settype(&attr, NURS_MUTEX_ATTR);
		pthread_mutex_init(&pl->mutex, &attr);
	}
	init_list_head(&pl->wildlist);

	return (struct nurs_plugin *)pl;
}

static int coveter_destroy(struct nurs_plugin *plugin)
{
	struct nurs_coveter *coveter = (struct nurs_coveter *)plugin;
	struct nurs_wildlist_element *we1, *we2;
	int ret;

	if (!coveter->def->mtsafe) {
		if ((ret = pthread_mutex_destroy(&coveter->mutex))) {
			nurs_log(NURS_FATAL, "pthread_mutex_destroy: %s\n",
				 strerror(ret));
			return -1;
		}
	}

	if (!list_empty(&coveter->wildlist)) {
		list_for_each_entry_safe(we1, we2, &coveter->wildlist, list) {
			list_del(&we1->list);
			free(we1);
		}
	}

	free(coveter->input_def);
	coveter->input_def = NULL;

	free(coveter->config);

	return 0;
}

static int coveter_resolve(struct nurs_plugin_def *defbase)
{
	struct nurs_coveter_def *coveter
		= (struct nurs_coveter_def *)defbase;

	if (!coveter->resolve_callback)
		return 0;

	if (plugin_resolve_cbsym(defbase,
				 coveter->organize_cb_s,
				 (void **)&coveter->organize))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 coveter->disorganize_cb_s,
				 (void **)&coveter->disorganize))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 coveter->start_cb_s,
				 (void **)&coveter->start))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 coveter->stop_cb_s,
				 (void **)&coveter->stop))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 coveter->interp_cb_s,
				 (void **)&coveter->interp))
		return -1;
	if (plugin_resolve_cbsym(defbase,
				 coveter->signal_cb_s,
				 (void **)&coveter->signal))
		return -1;

	return 0;
}

static int coveter_check(const struct nurs_plugin_def *defbase)
{
	const struct nurs_coveter_def *def
		= (const struct nurs_coveter_def *)defbase;

	if (!def->interp) {
		nurs_log(NURS_ERROR, "plugin: %s, no interp cb\n", def->name);
		return -1;
	}

	return 0;
}

static int coveter_show(const struct nurs_plugin_def *defbase)
{
	const struct nurs_coveter_def *def
		= (const struct nurs_coveter_def *)defbase;

	printf("MT-safe: %s\n", def->mtsafe ? "true" : "false");

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

struct nurs_plugin_ops coveter_ops = {
	.type		= NURS_PLUGIN_T_COVETER,
	.create		= &coveter_create,
	.destroy	= &coveter_destroy,
	.resolve_cb	= &coveter_resolve,
	.check		= &coveter_check,
	.show		= &coveter_show,
};

int coveter_init(void)
{
	return register_plugin_ops(&coveter_ops);
}

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
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nurs/list.h>
#include "internal.h"

/**
 * \defgroup nurs plugin interface
 * @{
 * Plugin type is classified in three:
 *
 * - Producer
 *   This plugin acts data source. They get data from somewhere outside of
 *   nursd, and convert it into a input for succeeding plugins.
 *
 * - Filter
 *   Filter plugins interpret and/or filter data that was received from the
 *   Producer or Filter Plugin and create a input for succeeding plugins.
 *
 * - Consumer / Coveter
 *   This plugins describe how and where to put the information gained by the
 *   Producer Plugin and processed by one or more Filter Plugins. Coveter is
 *   special Consumer, which is not specify input but accepts all inputs in a
 *   stack sequense as optional. i.e. handles wildcard input.
 *
 * Plugins are defined by struct named with suffix _def, its common fields are:
 *
 * - version: current nurs version string
 * - name: the name, can be seemed as class name
 * - context_size: the mem size which nurs allocating for each plugin instance.
 * - config_def: its configuration definition.
 *
 * Additionaly, plugin has callbacks which nursd core calls. These callback
 * arguments vary depending on plugin type. It will be called:
 *
 * - organize
 *   The first function which nursd will call. Plugins may open socket, files to
 *   prepare start callback will be called.
 *
 * - disorganize
 *   The last callback, will be called just before nurs will exit. Resources
 *   allocated at organize needs to be released.
 *
 * - start
 *   It will be called literally to start. Producer may register their fds and
 *   timers.
 *
 * - stop
 *   This will be called before disorganize callback. It's not implemented but
 *   restart faculty may call it combined with start.
 *
 * - signal
 *   This callback will be called when signal arrived. Signals currently
 *   delivered is - SIGCHLD, SIGALRM, SIGUSR1 and SIGUSR2. And SIGINT and
 *   SIGTERM will be delivered just before nursd will exit.
 *
 * - interp (filter, consumer and coveter only)
 *   Main callback for filter and consumer. Producer propagates its output, then
 *   filter and consumer accept it as argument of this callback.
 */

bool nurs_show_pluginfo; /* main.c */

static LIST_HEAD(nurs_plugins);
static LIST_HEAD(nurs_producers);
static LIST_HEAD(nurs_plugin_defs);

static char *plugin_type_string[NURS_PLUGIN_T_MAX] = {
	[NURS_PLUGIN_T_PRODUCER]	= "producer",
	[NURS_PLUGIN_T_FILTER]		= "filter",
	[NURS_PLUGIN_T_CONSUMER]	= "consumer",
	[NURS_PLUGIN_T_COVETER]		= "coveter",
};

static struct nurs_plugin_ops *plugin_ops[NURS_PLUGIN_T_MAX];

/* set just before dlopen and unset just after dlopen in
 * plugin_config_parser to set nurs_dl_handle.plugin */
static struct nurs_dl_handle *dlh_context = NULL;

int register_plugin_ops(struct nurs_plugin_ops *op)
{
	if (!op ||
	    op->type <= NURS_PLUGIN_T_NONE ||
	    op->type >= NURS_PLUGIN_T_MAX) {
		nurs_log(NURS_ERROR, "invalid plugin op type\n");
		return -1;
	}

	if (!op->create ||
	    !op->destroy ||
	    !op->resolve_cb ||
	    !op->check ||
	    !op->show) {
		nurs_log(NURS_ERROR, "insufficient plugin op callback\n");
		return -1;
	}

	plugin_ops[op->type] = op;
	return 0;
}

int plugin_init(void)
{
	if (producer_init())	return -1;
	if (filter_init())	return -1;
	if (consumer_init())	return -1;
	if (coveter_init())	return -1;
	return 0;
}

static struct nurs_plugin_def *find_plugin_def(const char *name)
{
	struct nurs_plugin_def *def;

	list_for_each_entry(def, &nurs_plugin_defs, list)
		if (!strncmp(def->name, name, NURS_NAME_LEN))
			return def;

	return NULL;
}

static struct nurs_plugin *find_plugin(const char *id)
{
	struct nurs_plugin *plugin;

	list_for_each_entry(plugin, &nurs_plugins, list)
		if (!strncmp(plugin->id, id, NURS_NAME_LEN))
			return plugin;

	return NULL;
}

/**
 * nurs_producer_context - obtail private data
 * \param producer passed by callbacks
 *
 * This function returns allocated memory, specific for a instance and its size
 * is specified in definition struct, context_size field.
 */
void *nurs_producer_context(const struct nurs_producer *producer)
{
	/* plugin NULL check? */
	return plugin_context(producer);
}
EXPORT_SYMBOL(nurs_producer_context);

/**
 * nurs_plugin_context - obtail private data
 * \param plugin passed by callbacks
 *
 * This function returns allocated memory, specific for a instance and its size
 * is specified in definition struct, context_size field.
 */
void *nurs_plugin_context(const struct nurs_plugin *plugin)
{
	/* plugin NULL check? */
	switch (plugin->type) {
	case NURS_PLUGIN_T_PRODUCER:
		return plugin_context((const struct nurs_producer *)plugin);
	case NURS_PLUGIN_T_FILTER:
		return plugin_context((const struct nurs_filter *)plugin);
	case NURS_PLUGIN_T_CONSUMER:
		return plugin_context((const struct nurs_consumer *)plugin);
	case NURS_PLUGIN_T_COVETER:
		return plugin_context((const struct nurs_coveter *)plugin);
	default:
		nurs_log(NURS_FATAL, "invalid plugin type %s: %d\n",
			 plugin->id, plugin->type);
		return NULL;
	}
	return NULL;
}
EXPORT_SYMBOL(nurs_plugin_context);

/**
 * nurs_producer_context - obtail private data
 * \param producer passed by callbacks
 *
 * This function returns struct nurs_config from producer.
 */
const struct nurs_config *
nurs_producer_config(const struct nurs_producer *producer)
{
	/* plugin NULL check? */
	return producer->config;
}
EXPORT_SYMBOL(nurs_producer_config);

/**
 * nurs_producer_context - obtail private data
 * \param plugin passed by callbacks
 *
 * This function returns struct nurs_config from plugin.
 */
const struct nurs_config *
nurs_plugin_config(const struct nurs_plugin *plugin)
{
	/* plugin NULL check? */
	return plugin->config;
}
EXPORT_SYMBOL(nurs_plugin_config);

/*
 * show
 */
static int show_config(const struct nurs_config_def *config)

{
	const struct nurs_config_entry_def *entry;
	int ret = 0;
	uint8_t i;

	if (!config || !config->len) {
		printf("no config\n");
		return 0;
	}
	printf("config options: %d\n", config->len);
	for (i = 0; i < config->len; i++) {
		entry = &config->keys[i];

		printf("  name: %s, type:", entry->name);
		switch (entry->type) {
		case NURS_CONFIG_T_INTEGER:
			printf(" integer, default: %d",
			       entry->integer);
			break;
		case NURS_CONFIG_T_STRING:
			printf(" string, default: %s",
			       entry->string);
			break;
		case NURS_CONFIG_T_CALLBACK:
			if (entry->resolve_parser) {
				printf(" callback: %s", entry->parser_cb_s);
				break;
			}
			printf(" callback: %p", entry->parser);
			break;
		default:
			printf(" invalid confg type...");
			ret = -1;
			break;
		}

		printf(", flags:");
		if (entry->flags & NURS_CONFIG_F_MANDATORY)
			printf(" MANDATORY");
		if (entry->flags & NURS_CONFIG_F_MULTI)
			printf(" MULTI");
		/*
		 * if (entry->flags & NURS_CONFIG_F_PROTECTED)
		 *	printf(" PROTECTED");
		 */
		printf("\n");
	}

	return ret;
}

static int show_keyinfo(const struct nurs_key_def *key, bool input)
{
	uint16_t t = key->type, f = key->flags;

	if (key->name == NULL)
		return -1;

	printf("  name: %s, type:", key->name);
	if (t == NURS_KEY_T_BOOL)
		printf(" bool");
	else if (t == NURS_KEY_T_INT8)
		printf(" int8");
	else if (t == NURS_KEY_T_INT16)
		printf(" int16");
	else if (t == NURS_KEY_T_INT32)
		printf(" int32");
	else if (t == NURS_KEY_T_INT64)
		printf(" int64");
	else if (t == NURS_KEY_T_UINT8)
		printf(" uint8");
	else if (t == NURS_KEY_T_UINT16)
		printf(" uint16");
	else if (t == NURS_KEY_T_UINT32)
		printf(" uint32");
	else if (t == NURS_KEY_T_UINT64)
		printf(" uint64");
	else if (t == NURS_KEY_T_INADDR)
		printf(" in_addr_t");
	else if (t == NURS_KEY_T_IN6ADDR)
		printf(" in6_addr");
	else if (t == NURS_KEY_T_STRING)
		if (input)
			printf(" string");
		else
			printf(" string, len: %d",
			       ((const struct nurs_output_key_def *)key)->len);
	else if (t == NURS_KEY_T_POINTER)
		printf(" pointer");
	else if (t == NURS_KEY_T_EMBED)
		if (input)
			printf(" raw data");
		else
			printf(" raw data, len: %d",
			       ((const struct nurs_output_key_def *)key)->len);
	else {
		printf(" invalid keytype: %d", t);
		return -1;
	}

	printf(", flags:");
	if (input) {
		if (f & NURS_IKEY_F_REQUIRED)
			printf(" REQUIRED");
		if (f & NURS_IKEY_F_OPTIONAL)
			printf(" OPTIONAL");
	} else {
		if (f & NURS_OKEY_F_ACTIVE)
			printf(" ACTIVE");
		if (f & NURS_OKEY_F_FREE)
			printf(" FREE");
		if (f & NURS_OKEY_F_DESTRUCT)
			printf(" DESTRUCT");
		if (f & NURS_OKEY_F_OPTIONAL)
			printf(" OPTIONAL");
	}
	printf("\n");
	return 0;
}

int plugin_show_input(const struct nurs_input_def *def)
{
	uint16_t i;
	int rc, ret = 0;
	const struct nurs_key_def *base;

	printf("input keys: %d\n", def->len);
	for (i = 0; i < def->len; i++) {
		base = (const struct nurs_key_def *)&def->keys[i];
		if ((rc = show_keyinfo(base, true)))
			printf("invalid input key - index: %d\n", i);
		ret |= rc;
	}

	return ret;
}

int plugin_show_output(const struct nurs_output_def *def)
{
	uint16_t i;
	int rc, ret = 0;
	const struct nurs_key_def *key;

	printf("output keys: %d\n", def->len);
	for (i = 0; i < def->len; i++) {
		key = (const struct nurs_key_def *)&def->keys[i];
		rc = show_keyinfo(key, false);
		if (rc)
			printf("invalid output key - index: %d\n", i);
		ret |= rc;
	}

	return ret;
}

/*
 * check
 */
/* -1 returns no key name, 1 is else error */
static int check_key(const char *plname,
		     const struct nurs_key_def *keys,
		     uint16_t num_keys,
		     const struct nurs_key_def *key)
{
	uint16_t i;

	/* name */
	if (!key->name || !strlen(key->name)) {
		nurs_log(NURS_ERROR, "plugin: %s, no key name, index: %d\n",
			 plname, num_keys);
		return -1;
	}
	for (i = 0; i < num_keys; i++) { /* linear... */
		if (!strncmp(keys[i].name, key->name, NURS_NAME_LEN)) {
			nurs_log(NURS_ERROR, "plugin: %s, dup key name: %s\n",
				 plname, key->name);
			return 1;
		}
	}

	/* type */
	if (!key->type) {
		nurs_log(NURS_ERROR, "plugin: %s, no key type: %s\n",
			 plname, key->name);
		return 1;
	}

	return 0;
}

static int check_config(const char *name, const struct nurs_config_def *config)
{
	uint8_t i;
	int ret = 0;

	for (i = 0; i < config->len; i++) {
		if (!config->keys[i].name
		    || !strlen(config->keys[i].name)) {
			nurs_log(NURS_ERROR, "plugin: %s, no config name: %d\n",
				 name, i);
			ret = -1;
		}
		if (!config->keys[i].type) {
			nurs_log(NURS_ERROR, "plugin: %s, no config type: %s\n",
				 name, config->keys[i].name);
			ret = -1;
		}
	}

	return ret;
}

int plugin_check_input(const char *plname, const struct nurs_input_def *input)
{
	uint16_t i;
	const struct nurs_input_key_def *k;
	int rc, ret = 0;
	const struct nurs_key_def *base
		= (const struct nurs_key_def *)input->keys;

	for (i = 0; i < input->len; i++) {
		k = &input->keys[i];

		rc = check_key(plname, base, i,
			       (const struct nurs_key_def *)k);
		if (rc == -1) { /* no key name */
			ret |= 1;
			continue;
		}

		if (!k->flags) {
			nurs_log(NURS_ERROR,
				 "plugin %s, no key flags specified: %s\n",
				 plname, k->name);
			ret |= 1;
		} else if (k->flags & NURS_IKEY_F_REQUIRED &&
			   k->flags & NURS_IKEY_F_OPTIONAL) {
			nurs_log(NURS_ERROR,
				 "plugin %s, both REQUIRED and OPTIONAL"
				 " flag: %s\n", plname, k->name);
			ret |= 1;
		}
	}

	if (ret) return -1;
	return 0;
}

int plugin_check_output(const char *plname,
			const struct nurs_output_def *output)
{
	uint16_t i, j, flag;
	const struct nurs_output_key_def *k;
	int rc, ret = 0;
	const struct nurs_key_def *base
		= (const struct nurs_key_def *)output->keys;

	for (i = 0; i < output->len; i++) {
		k = &output->keys[i];

		rc = check_key(plname, base, i,
			       (const struct nurs_key_def *)k);
		if (rc == -1) { /* no key name */
			ret |= 1;
			continue;
		}

		for (j = 0; j < i; j++) { /* linear... */
			if (strlen(k->cim_name) &&
			    !strncmp(output->keys[j].cim_name, k->cim_name,
				     NURS_NAME_LEN)) {
				nurs_log(NURS_ERROR, "plugin: %s, dup key cim"
					 " name: %s\n", plname, k->cim_name);
				ret |= 1;
			}
			if (k->ipfix.field_id &&
			    output->keys[j].ipfix.field_id
			    	== k->ipfix.field_id &&
			    output->keys[j].ipfix.vendor == k->ipfix.vendor) {
				nurs_log(NURS_ERROR, "plugin: %s, %s dup ipfix"
					 " vendor: %d and field id: %d\n",
					 plname, k->name, k->ipfix.vendor,
					 k->ipfix.field_id);
				ret |= 1;
			}
		}

		if (k->type == NURS_KEY_T_STRING ||
		    k->type == NURS_KEY_T_EMBED) {
			if (k->len == 0) {
				nurs_log(NURS_ERROR, "plugin: %s, requires"
					 " key len: %s\n", plname, k->name);
				ret |= 1;
			}
			if (k->flags & NURS_OKEY_F_DESTRUCT ||
			    k->flags & NURS_OKEY_F_FREE) {
				nurs_log(NURS_ERROR, "plugin: %s, lengthen"
					 " field has release flag: %s\n",
					 plname, k->name);
				ret |= 1;
			}
		} else if (k->len != 0) {
			nurs_log(NURS_ERROR, "plugin: %s, len shold be 0: %s\n",
				 plname, k->name);
			ret |= 1;
		}

		if (k->type == NURS_KEY_T_POINTER) {
			if (k->flags & NURS_OKEY_F_DESTRUCT) {
				if (k->destructor == NULL) {
					nurs_log(NURS_ERROR,
						 "plugin: %s, no destructor:"
						 " %s\n", plname, k->name);
					ret |= 1;
				}
				if (k->flags & NURS_OKEY_F_FREE) {
					nurs_log(NURS_ERROR,
						 "plugin: %s, both FREE and"
						 " DESTRUCT: %s\n",
						 plname, k->name);
					ret |= 1;
				}
			}
		} else if (k->flags & NURS_OKEY_F_FREE ||
			   k->flags & NURS_OKEY_F_DESTRUCT) {
			nurs_log(NURS_ERROR, "plugin: %s, invalid key"
				 " release flag: %s\n", plname, k->name);
			ret |= 1;
		}

		/* only one of them must be valid */
		flag = k->flags &
			(NURS_OKEY_F_ACTIVE |
			 NURS_OKEY_F_OPTIONAL);
		if (flag != NURS_OKEY_F_ACTIVE &&
		    flag != NURS_OKEY_F_OPTIONAL) {
			nurs_log(NURS_ERROR, "plugin: %s, invalid flags: %s\n",
				 plname, k->name);
			ret |= 1;
		}
	}

	if (ret) return -1;
	return 0;
}

static int check_name(const struct nurs_plugin_def *def)
{
	if (find_plugin_def(def->name)) {
		nurs_log(NURS_ERROR, "duplicate plugin name: %s\n", def->name);
		errno = EALREADY;
		return -1;
	}
	return 0;
}

/*
 * resolve
 */
static int resolve_config_parser(struct nurs_plugin_def *defbase)
{
	struct nurs_config_def *config;
	void *handle, *sym;
	uint8_t i;

	if (!defbase) return -1;
	if (!defbase->dlh) {
		nurs_log(NURS_NOTICE, "no dl handle: %s\n", defbase->name);
		return -1;
	}

	config = defbase->config_def;
	handle = defbase->dlh->h;

	if (!config) return 0;
	for (i = 0; i < config->len; i++) {
		if (!config->keys[i].resolve_parser)
			continue;
		sym = dlsym(handle, config->keys[i].parser_cb_s);
		if (sym == NULL) {
			nurs_log(NURS_ERROR, "could not resolve config parser:"
				 " %s\n", config->keys[i].parser_cb_s);
			return -1;
		}
		config->keys[i].parser = sym;
	}

	return 0;
}

int plugin_resolve_output_destructor(void *handle, struct nurs_output_def *output)
{
	void *sym;
	uint16_t i;

	for (i = 0; i < output->len; i++) {
		if (!output->keys[i].resolve_destructor)
			continue;
		sym = dlsym(handle, output->keys[i].destructor_cb_s);
		if (sym == NULL) {
			nurs_log(NURS_ERROR, "could not resolve destructor:"
				 " %s\n", output->keys[i].destructor_cb_s);
			return -1;
		}
		output->keys[i].destructor = sym;
	}

	return 0;
}

int plugin_resolve_cbsym(struct nurs_plugin_def *def, const char *name, void **p)
{
	void *sym;

	if (!name || !strlen(name)) {
		*p = NULL;
		return 0;
	}

	sym = dlsym(def->dlh->h, name);
	if (!sym) {
		nurs_log(NURS_ERROR, "could not resolve %s.%s: %s\n",
			 def->name, name, dlerror());
		return -1;
	}

	*p = sym;
	return 0;
}

static int plugin_show(enum nurs_plugin_type type,
		       struct nurs_plugin_def *def)
{
	int ret;

	if (!def) return -1;

	printf("name: %s\n", def->name);
	printf("version: %s\n", def->version);
	printf("context size: %d\n", def->context_size);

	show_config(def->config_def);

	ret = plugin_ops[type]->show(def);
	if (def->dynamic)
		free(def);

	return ret;
}

/* EINVAL:
 * EALREADY: duplicate name */
static int plugin_check(enum nurs_plugin_type type,
			const struct nurs_plugin_def *def)
{
	int ret = 0;

	if (!def) {
		errno = EINVAL;
		return -1;
	}
	if (!def->name || !strlen(def->name)) {
		nurs_log(NURS_ERROR, "no plugin name\n");
		errno = EINVAL;
		return -1;
	}
	if (check_name(def))
		ret = -1;

	if (!def->version || strncmp(def->version, VERSION, NURS_NAME_LEN)) {
		nurs_log(NURS_ERROR,
			 "plugin: %s has incompatible version %s\n",
			 def->name, def->version);
		errno = EINVAL;
		ret = -1;
	}

	/* move to config.c? */
	if (def->config_def)
		ret |= check_config(def->name, def->config_def);

	ret |= plugin_ops[type]->check(def);

	if (ret)
		errno = EINVAL;
	return ret;
}

static int plugin_register(enum nurs_plugin_type type,
			   struct nurs_plugin_def *def)
{
	/* hold just ref, not copy */
	def->refcnt = 1;
	def->dynamic = false;
	def->type = type;
	list_add(&def->list, &nurs_plugin_defs);

	/* global variable, set at config_parser_plugin() */
	if (dlh_context) {
		dlh_context->refcnt++;
		def->dlh = dlh_context;
	}

	nurs_log(NURS_DEBUG, "registered %s plugin: %s\n",
		 plugin_type_string[type], def->name);

	return 0;
}

/* ENOENT:
 * EINVAL:
 * EBUSY:
 * ???: dlclose
 */
static int plugin_unregister(int type, const char *name)
{
	struct nurs_plugin_def *def = find_plugin_def(name);
	struct nurs_dl_handle *handle = NULL;
	int ret = 0;

	if (!def) {
		nurs_log(NURS_ERROR, "could not found plugin def: %s\n", name);
		errno = ENOENT;
		return -1;
	}

	if (def->type != type) {
		nurs_log(NURS_ERROR, "invalid plugin type\n");
		errno = EINVAL;
		return -1;
	}

	if (def->refcnt > 1) {
		nurs_log(NURS_ERROR, "%s is in use: %d\n",
			 def->name, def->refcnt);
		errno = EBUSY;
		return -1;
	}

	handle = def->dlh;
	list_del(&def->list);
	if (def->dynamic)
		free(def);

	if (handle && handle->h) {
		handle->refcnt--;
		if (!handle->refcnt) {
			/* comment out below if use valgrind to trace funcs */
			if (dlclose(handle->h)) {
				nurs_log(NURS_ERROR, "failed to close dlh:"
					 " %s\n", dlerror());
				ret = -1;
			}
			free(handle);
		}
	}

	return ret;
}

static struct nurs_plugin *plugin_create(struct nurs_plugin_def *def, const char *id)
{
	struct nurs_plugin *plugin;

	if (!def ||
	    def->type <= NURS_PLUGIN_T_NONE || def->type >= NURS_PLUGIN_T_MAX) {
		nurs_log(NURS_ERROR, "invalid plugin type\n");
		return NULL;
	}

	plugin = plugin_ops[def->type]->create(def, id);
	if (!plugin)
		return NULL;

	plugin->type = (enum nurs_plugin_type)def->type;
	strncpy(plugin->id, id, NURS_NAME_LEN);
	plugin->def = def;
	return plugin;
}


struct nurs_plugin *plugin_get(enum nurs_plugin_type type,
			       const char *name, const char *id)
{
	struct nurs_plugin *plugin;
	struct nurs_plugin_def *def;

	if (!id) return NULL;
	if (!name) return NULL;

	plugin = find_plugin(id);
	if (plugin) {
		if (plugin->type == type &&
		    !strcmp(plugin->def->name, name)) {
			plugin->refcnt++;
			plugin->def->refcnt++;
			return plugin;
		}
		return NULL;
	}

	def = find_plugin_def(name);
	if (!def || def->type != (int)type)
		return NULL;

	plugin = plugin_create(def, id);
	if (!plugin)
		return NULL;

	list_add(&plugin->list, &nurs_plugins);
	/* sorry for messy. add new one to the list */
	if (type == NURS_PLUGIN_T_PRODUCER) {
		struct nurs_producer *producer
			= (struct nurs_producer *)plugin;
		list_add(&producer->plist, &nurs_producers);
	}

	plugin->refcnt++;
	plugin->def->refcnt++;

	return plugin;
}

static int plugin_destroy(struct nurs_plugin *plugin)
{
	if (!plugin)
		return -1;

	if (plugin->refcnt) {
		nurs_log(NURS_NOTICE, "refcnt > 0, can't destory %s:%s\n",
			 plugin->id, plugin->def->name);
		return -1;
	}

	if (plugin_ops[plugin->type]->destroy(plugin))
		return -1;

	list_del(&plugin->list);
	if (plugin->type == NURS_PLUGIN_T_PRODUCER) {
		struct nurs_producer *producer
			= (struct nurs_producer *)plugin;
		list_del(&producer->plist);
	}

	free(plugin);
	return 0;
}

/* return -1 on error, 1 on release, or 0 */
int plugin_put(struct nurs_plugin *plugin)
{
	if (!plugin)
		return -1;

	if (!find_plugin(plugin->id)) {
		nurs_log(NURS_ERROR, "could not found plugin: %s\n",
			 plugin->id);
		return -1;
	}

	plugin->refcnt--;
	plugin->def->refcnt--;
	if (plugin->refcnt)
		return 0;

	if (plugin_destroy(plugin))
		return -1;

	return 1;
}

static int plugin_resolve_cb(struct nurs_plugin_def *def)
{
	if (!def ||
	    def->type <= NURS_PLUGIN_T_NONE ||
	    def->type >= NURS_PLUGIN_T_MAX) {
		nurs_log(NURS_ERROR, "invalid plugin type\n");
		return -1;
	}

	if (resolve_config_parser(def))
		return -1;
	return plugin_ops[def->type]->resolve_cb(def);
}

/*
 * plugin specific
 */

/**
 * nurs_producer_register - register producer by definition
 * \param producer producer definition
 *
 * This function register producer class by struct nurs_producer_def, returns 0
 * on success or -1 on error.
 */
int nurs_producer_register(struct nurs_producer_def *producer)
{
	enum nurs_plugin_type type = NURS_PLUGIN_T_PRODUCER;
	struct nurs_plugin_def *defbase = (struct nurs_plugin_def *)producer;

	if (plugin_check(type, defbase))
		return -1;

	if (nurs_show_pluginfo)
		return plugin_show(type, defbase);

	return plugin_register(type, defbase);
}
EXPORT_SYMBOL(nurs_producer_register);

/**
 * nurs_producer_unregister - unregister producer by definition
 * \param producer producer definition
 *
 * This function unregister producer class by name in struct nurs_producer_def,
 * returns 0 on success or -1 on error.
 */
int nurs_producer_unregister(struct nurs_producer_def *def)
{
	if (!def) {
		errno = EINVAL;
		return -1;
	}
	return plugin_unregister(NURS_PLUGIN_T_PRODUCER, def->name);
}
EXPORT_SYMBOL(nurs_producer_unregister);

/**
 * nurs_producer_unregister_name - unregister producer by name
 * \param name producer name
 *
 * This function unregister producer class by name, returns 0 on success or -1
 * on error.
 */
int nurs_producer_unregister_name(const char *name)
{
	return plugin_unregister(NURS_PLUGIN_T_PRODUCER, name);
}
EXPORT_SYMBOL(nurs_filter_unregister_name);

/**
 * nurs_filter_register - register filter by definition
 * \param filter filter definition
 *
 * This function register filter class by struct nurs_filter_def, returns 0 on
 * success or -1 on error.
 */
int nurs_filter_register(struct nurs_filter_def *filter)
{
	enum nurs_plugin_type type = NURS_PLUGIN_T_FILTER;
	struct nurs_plugin_def *defbase = (struct nurs_plugin_def *)filter;

	if (plugin_check(type, defbase))
		return -1;

	if (nurs_show_pluginfo)
		return plugin_show(type, defbase);

	return plugin_register(type, defbase);
}
EXPORT_SYMBOL(nurs_filter_register);

/**
 * nurs_filter_unregister - unregister filter by definition
 * \param filter filter definition
 *
 * This function unregister filter class by name in struct nurs_filter_def,
 * returns 0 on success or -1 on error.
 */
int nurs_filter_unregister(struct nurs_filter_def *def)
{
	if (!def) return -1;
	return plugin_unregister(NURS_PLUGIN_T_FILTER, def->name);
}
EXPORT_SYMBOL(nurs_filter_unregister);

/**
 * nurs_filter_unregister_name - unregister filter by name
 * \param name filter name
 *
 * This function unregister filter class by name, returns 0 on success or -1 on
 * error.
 */
int nurs_filter_unregister_name(const char *name)
{
	return plugin_unregister(NURS_PLUGIN_T_FILTER, name);
}
EXPORT_SYMBOL(nurs_filter_unregister_name);

/**
 * nurs_consumer_register - register consumer by definition
 * \param consumer consumer definition
 *
 * This function register consumer class by struct nurs_consumer_def, returns 0
 * on success or -1 on error.
 */
int nurs_consumer_register(struct nurs_consumer_def *def)
{
	enum nurs_plugin_type type = NURS_PLUGIN_T_CONSUMER;
	struct nurs_plugin_def *defbase = (struct nurs_plugin_def *)def;

	if (plugin_check(type, defbase))
		return -1;

	if (nurs_show_pluginfo)
		return plugin_show(type, defbase);

	return plugin_register(type, defbase);
}
EXPORT_SYMBOL(nurs_consumer_register);

/**
 * nurs_consumer_unregister - unregister consumer by definition
 * \param consumer consumer definition
 *
 * This function unregister consumer class by name in struct nurs_consumer_def,
 * returns 0 on success or -1 on error.
 */
int nurs_consumer_unregister(struct nurs_consumer_def *def)
{
	if (!def) return -1;
	return plugin_unregister(NURS_PLUGIN_T_CONSUMER, def->name);
}
EXPORT_SYMBOL(nurs_consumer_unregister);

/**
 * nurs_consumer_unregister_name - unregister consumer by name
 * \param name consumer name
 *
 * This function unregister consumer class by name, returns 0 on success or -1
 * on error.
 */
int nurs_consumer_unregister_name(const char *name)
{
	return plugin_unregister(NURS_PLUGIN_T_CONSUMER, name);
}
EXPORT_SYMBOL(nurs_consumer_unregister_name);

/**
 * nurs_coveter_register - register coveter by definition
 * \param coveter coveter definition
 *
 * This function register covter class by struct nurs_coveter_def, returns 0 on
 * success or -1 on error.
 */
int nurs_coveter_register(struct nurs_coveter_def *def)
{
	enum nurs_plugin_type type = NURS_PLUGIN_T_COVETER;
	struct nurs_plugin_def *defbase = (struct nurs_plugin_def *)def;

	if (plugin_check(type, defbase))
		return -1;

	if (nurs_show_pluginfo)
		return plugin_show(type, defbase);

	return plugin_register(type, defbase);
}
EXPORT_SYMBOL(nurs_coveter_register);

/**
 * nurs_producer_unregister - unregister coveter by definition
 * \param coveter coveter definition
 *
 * This function unregister coveter class by name in struct nurs_coveter_def,
 * returns 0 on success or -1 on error.
 */
int nurs_coveter_unregister(struct nurs_coveter_def *def)
{
	if (!def) return -1;
	return plugin_unregister(NURS_PLUGIN_T_COVETER, def->name);
}
EXPORT_SYMBOL(nurs_coveter_unregister);

/**
 * nurs_coveter_unregister_name - unregister coveter by name
 * \param name coveter name
 *
 * This function unregister coveter class by name, returns 0 on success or -1 on
 * error.
 */
int nurs_coveter_unregister_name(const char *name)
{
	return plugin_unregister(NURS_PLUGIN_T_COVETER, name);
}
EXPORT_SYMBOL(nurs_consumer_unregister_name);

struct nurs_producer *
plugin_producer_get(const char *name, const char *id)
{
	struct nurs_producer *producer
		= (struct nurs_producer *)
		plugin_get(NURS_PLUGIN_T_PRODUCER, name, id);

	if (!producer)
		return producer;

	return producer;
}

struct nurs_filter *
plugin_filter_get(const char *name, const char *id)
{
	return (struct nurs_filter *)
		plugin_get(NURS_PLUGIN_T_FILTER, name, id);
}

struct nurs_consumer *
plugin_consumer_get(const char *name, const char *id)
{
	return (struct nurs_consumer *)
		plugin_get(NURS_PLUGIN_T_CONSUMER, name, id);
}

struct nurs_coveter *
plugin_coveter_get(const char *name, const char *id)
{
	return (struct nurs_coveter *)
		plugin_get(NURS_PLUGIN_T_COVETER, name, id);
}

int plugin_producer_put(struct nurs_producer *producer)
{
	if (!producer || producer->type != NURS_PLUGIN_T_PRODUCER)
		return -1;
	if (plugin_put((struct nurs_plugin *)producer) == -1)
		return -1;
	return 0;
}

int plugin_filter_put(struct nurs_filter *filter)
{
	if (!filter || filter->type != NURS_PLUGIN_T_FILTER)
		return -1;
	if (plugin_put((struct nurs_plugin *)filter) == -1)
		return -1;
	return 0;
}

int plugin_consumer_put(struct nurs_consumer *consumer)
{
	if (!consumer || consumer->type != NURS_PLUGIN_T_CONSUMER)
		return -1;
	if (plugin_put((struct nurs_plugin *)consumer) == -1)
		return -1;
	return 0;
}

int plugin_coveter_put(struct nurs_coveter *coveter)
{
	if (!coveter || !coveter->type == NURS_PLUGIN_T_COVETER)
		return -1;
	if (plugin_put((struct nurs_plugin *)coveter) == -1)
		return -1;
	return 0;
}

/*
 * nurs_config_parser_t
 */
static int resolve_dlh(struct nurs_dl_handle *dlh)
{
	struct nurs_plugin_def *def;

	list_for_each_entry(def, &nurs_plugin_defs, list) {
		if (def->dlh != dlh)
			continue;
		if (plugin_resolve_cb(def))
			return -1;
	}

	return 0;
}

/* assume being called in error path, not return in the middle
 * of the lists walk, even error occured. */
static int unresolve_dlh(struct nurs_dl_handle *dlh)
{
	struct nurs_plugin_def *def;
	int ret = 0;

	list_for_each_entry(def, &nurs_plugin_defs, list) {
		if (def->dlh != dlh)
			continue;
		ret |= plugin_unregister(def->type, def->name);
	}

	return ret;
}

int plugin_config_parser(const char *line)
{
	struct nurs_dl_handle *dlh;
	void (*gocb)(void);
	int ret = -1;

	/* a little bit hacky.
	 * add (invalid, just allocated) handle to global list here. */
	dlh = (struct nurs_dl_handle *)calloc(1, sizeof(struct nurs_dl_handle));
	if (!dlh) {
		nurs_log(NURS_ERROR, "failed to calloc - %s: %s\n",
			 line, strerror(errno));
		return -1;
	}

	dlh_context = dlh;
	dlh->h = dlopen(line, RTLD_NOW);
	/* dlh_context = NULL; */
	if (!dlh->h) {
		nurs_log(NURS_ERROR, "failed to dlopen - %s\n", dlerror());
		dlh_context = NULL;
		goto fail_free;
	}

	/* XXX: weird hack for go
	 * https://github.com/golang/go/issues/12639 */
	gocb = dlsym(dlh->h, "sync_init");
	if (gocb) gocb();
	dlh_context = NULL;

	if (!dlh->refcnt) {
		if (nurs_show_pluginfo)
			ret = 0;
		else
			nurs_log(NURS_ERROR, "register plugin in init"
				 " might fail\n");
		goto fail_close;
	}

	if (resolve_dlh(dlh)) {
		unresolve_dlh(dlh);
		/* ..._unregister() will close dl handle */
		goto fail_free;
	}

	return 0;

fail_close:
	dlclose(dlh->h);
fail_free:
	free(dlh);
	return ret;
}

/*
 * callbacks
 */
struct nurs_plugin *
plugin_cb(const struct nurs_plugin *till, const char *name,
	  enum nurs_return_t (*cb)(struct nurs_plugin *, void *),
	  void *data, bool force)
{
	struct nurs_plugin *plugin, *tmp, *ret = NULL;
	enum nurs_return_t cbret;

	list_for_each_entry_safe(plugin, tmp, &nurs_plugins, list) {
		if (plugin == till)
			break;
		cbret = cb(plugin, data);
		if (cbret != NURS_RET_OK) {
			nurs_log(NURS_ERROR, "cb %s failed %s:%s\n",
				 name, plugin->id, plugin->def->name);
			ret = plugin;
			if (!force) return ret;
		}
	}
	return ret;
}

struct nurs_producer *
producer_cb(const char *name,
	    enum nurs_return_t (*cb)(struct nurs_producer *, void *),
	    void *data, bool force)
{
	struct nurs_producer *producer, *tmp, *ret = NULL;
	enum nurs_return_t cbret;

	list_for_each_entry_safe(producer, tmp, &nurs_producers, plist) {
		cbret = cb(producer, data);
		if (cbret != NURS_RET_OK) {
			nurs_log(NURS_ERROR, "cb %s failed %s:%s\n",
				 name, producer->id, producer->def->name);
			ret = producer;
			if (!force) return ret;
		}
	}
	return ret;
}

static enum nurs_return_t
disorganize_cb(struct nurs_plugin *plugin, void *data)
{
	const struct nurs_producer *producer;	/* nurs_producer_disorganize_t */
	const struct nurs_filter *filter;	/* nurs_disorganize_t */
	const struct nurs_consumer *consumer;	/* nurs_disorganize_t */
	const struct nurs_coveter *coveter;	/* nurs_disorganize_t */
	nurs_producer_disorganize_t producer_disorganize;
	nurs_disorganize_t disorganize = NULL;
	enum nurs_return_t ret = NURS_RET_OK;

	switch (plugin->type) {
	case NURS_PLUGIN_T_PRODUCER:
		producer = (const struct nurs_producer *)plugin;
		producer_disorganize = producer->def->disorganize;
		if (!producer_disorganize)
			return NURS_RET_OK;
		return producer_disorganize(producer);
	case NURS_PLUGIN_T_FILTER:
		filter = (const struct nurs_filter *)plugin;
		disorganize = filter->def->disorganize;
		break;
	case NURS_PLUGIN_T_CONSUMER:
		consumer = (const struct nurs_consumer *)plugin;
		disorganize = consumer->def->disorganize;
		break;
	case NURS_PLUGIN_T_COVETER:
		coveter = (const struct nurs_coveter *)plugin;
		disorganize = coveter->def->disorganize;
		break;
	default:
		nurs_log(NURS_FATAL, "invalid plugin type: %d\n",
			 plugin->type);
		return NURS_RET_ERROR;
	}

	if (disorganize)
		ret = disorganize(plugin);

	return ret;
}

int plugins_disorganize(bool force)
{
	if (plugin_cb(NULL, "disorganize", disorganize_cb, NULL, force))
		return -1;
	return 0;
}

static enum nurs_return_t
organize_cb(struct nurs_plugin *plugin, void *data)
{
	const struct nurs_producer *producer;	/* nurs_producer_organize_t */
	const struct nurs_filter *filter;	/* nurs_organize_t */
	const struct nurs_consumer *consumer;	/* nurs_organize_t */
	const struct nurs_coveter *coveter;	/* nurs_coveter_organize_t */
	nurs_producer_organize_t producer_organize;
	nurs_organize_t organize;
	nurs_coveter_organize_t coveter_organize;

	switch (plugin->type) {
	case NURS_PLUGIN_T_PRODUCER:
		producer = (const struct nurs_producer *)plugin;
		producer_organize = producer->def->organize;
		if (!producer_organize)
			return NURS_RET_OK;
		return producer_organize(producer);
	case NURS_PLUGIN_T_FILTER:
		filter = (const struct nurs_filter *)plugin;
		organize = filter->def->organize;
		if (!organize)
			return NURS_RET_OK;
		return organize(plugin);
	case NURS_PLUGIN_T_CONSUMER:
		consumer = (const struct nurs_consumer *)plugin;
		organize = consumer->def->organize;
		if (!organize)
			return NURS_RET_OK;
		return organize(plugin);
	case NURS_PLUGIN_T_COVETER:
		coveter = (const struct nurs_coveter *)plugin;
		coveter_organize = coveter->def->organize;
		if (!coveter_organize)
			return NURS_RET_OK;
		return coveter_organize(plugin, coveter->input_template);
	default:
		nurs_log(NURS_FATAL, "invalid plugin type: %d\n",
			 plugin->type);
		return NURS_RET_ERROR;
	}

	return NURS_RET_ERROR;
}

int plugins_organize(const char *fname)
{
	struct nurs_plugin *plugin;
	const struct nurs_plugin *error;

	if (config_fopen(fname))
		return -1;
	list_for_each_entry(plugin, &nurs_plugins, list) {
		if (!plugin->def->config_def || !plugin->def->config_def->len)
			continue;
		plugin->config = config_parse_section(
			plugin->id, plugin->def->config_def);
		if (!plugin->config) {
			nurs_log(NURS_NOTICE, "failed to parse config: %s\n",
				 plugin->def->name);
			return -1;
		}
	}
	if (config_fclose())
		return -1;

	error = plugin_cb(NULL, "organize", organize_cb, NULL, false);
	if (error) {
		plugin_cb(error, "disorganize", disorganize_cb, NULL, true);
		return -1;
	}

	return 0;
}

static enum nurs_return_t
stop_cb(struct nurs_plugin *plugin, void *data)
{
	const struct nurs_producer *producer;
	const struct nurs_filter *filter;
	const struct nurs_consumer *consumer;
	const struct nurs_coveter *coveter;
	nurs_producer_stop_t producer_stop;
	nurs_stop_t stop = NULL;

	switch (plugin->type) {
	case NURS_PLUGIN_T_PRODUCER:
		producer = (const struct nurs_producer *)plugin;
		producer_stop = producer->def->stop;
		if (!producer_stop)
			return NURS_RET_OK;
		return producer_stop(producer);
	case NURS_PLUGIN_T_FILTER:
		filter = (const struct nurs_filter *)plugin;
		stop = filter->def->stop;
		break;
	case NURS_PLUGIN_T_CONSUMER:
		consumer = (const struct nurs_consumer *)plugin;
		stop = consumer->def->stop;
		break;
	case NURS_PLUGIN_T_COVETER:
		coveter = (const struct nurs_coveter *)plugin;
		stop = coveter->def->stop;
		break;
	default:
		nurs_log(NURS_FATAL, "invalid plugin type: %d\n",
			 plugin->type);
		return NURS_RET_ERROR;
	}

	if (!stop)
		return NURS_RET_OK;

	return stop(plugin);
}

int plugins_stop(bool force)
{
	if (plugin_cb(NULL, "stop", stop_cb, NULL, force))
		return -1;
	return 0;
}

static enum nurs_return_t
start_cb(struct nurs_plugin *plugin, void *data)
{
	const struct nurs_producer *producer;
	const struct nurs_filter *filter;
	const struct nurs_consumer *consumer;
	const struct nurs_coveter *coveter;
	nurs_producer_start_t producer_start;
	nurs_start_t start = NULL;

	switch (plugin->type) {
	case NURS_PLUGIN_T_PRODUCER:
		producer = (const struct nurs_producer *)plugin;
		producer_start = producer->def->start;
		if (!producer_start)
			return NURS_RET_OK;
		return producer_start(producer);
	case NURS_PLUGIN_T_FILTER:
		filter = (const struct nurs_filter *)plugin;
		start = filter->def->start;
		break;
	case NURS_PLUGIN_T_CONSUMER:
		consumer = (const struct nurs_consumer *)plugin;
		start = consumer->def->start;
		break;
	case NURS_PLUGIN_T_COVETER:
		coveter = (const struct nurs_coveter *)plugin;
		start = coveter->def->start;
		break;
	default:
		nurs_log(NURS_FATAL, "invalid plugin type: %d\n",
			 plugin->type);
		return NURS_RET_ERROR;
	}

	if (!start)
		return NURS_RET_OK;
	return start(plugin);
}

int plugins_start(void)
{
	struct nurs_plugin *plugin, *tmp;
	enum nurs_return_t cbret;
	int ret = 0;

	if (workers_suspend()) {
		nurs_log(NURS_FATAL, "failed to suspend workers\n");
		return -1;
	}

	list_for_each_entry_safe_reverse(plugin, tmp, &nurs_plugins, list) {
		cbret = start_cb(plugin, NULL);
		if (cbret != NURS_RET_OK) {
			nurs_log(NURS_ERROR, "cb start failed %s:%s returns: %d\n",
				 plugin->id, plugin->def->name, cbret);
			ret = -1;
			break;
		}
	}
	if (!ret)
		goto resume_workers;

	plugin = list_first_entry(&plugin->list, struct nurs_plugin, list);
	list_for_each_entry_safe_from(plugin, tmp, &nurs_plugins, list)
		stop_cb(plugin, NULL); /* ignore retval */

resume_workers:
	if (workers_resume()) {
		nurs_log(NURS_FATAL, "failed to resume workers\n");
		plugin_cb(NULL, "stop", stop_cb, NULL, true);
		ret = -1;
	}

	return ret;
}

static enum nurs_return_t
signal_cb(struct nurs_plugin *plugin, void *data)
{
	const struct nurs_producer *producer;
	const struct nurs_filter *filter;
	const struct nurs_consumer *consumer;
	const struct nurs_coveter *coveter;
	uint32_t signum = *(uint32_t *)data;
	nurs_producer_signal_t producer_signal;
	nurs_signal_t signal;

	switch (plugin->type) {
	case NURS_PLUGIN_T_PRODUCER:
		producer = (const struct nurs_producer *)plugin;
		producer_signal = producer->def->signal;
		if (!producer_signal)
			return NURS_RET_OK;
		return producer_signal(producer, signum);
	case NURS_PLUGIN_T_FILTER:
		filter = (const struct nurs_filter *)plugin;
		signal = filter->def->signal;
		if (!signal)
			return NURS_RET_OK;
		return signal(plugin, signum);
	case NURS_PLUGIN_T_CONSUMER:
		consumer = (const struct nurs_consumer *)plugin;
		signal = consumer->def->signal;
		if (!signal)
			return NURS_RET_OK;
		return signal(plugin, signum);
	case NURS_PLUGIN_T_COVETER:
		coveter = (const struct nurs_coveter *)plugin;
		signal = coveter->def->signal;
		if (!signal)
			return NURS_RET_OK;
		return signal(plugin, signum);
	default:
		nurs_log(NURS_FATAL, "invalid plugin type: %d\n",
			 plugin->type);
		return NURS_RET_ERROR;
	}

	return NURS_RET_ERROR;
}

int plugins_signal(uint32_t signum, bool force)
{
	if (plugin_cb(NULL, "signal", signal_cb, &signum, force))
		return -1;
	return 0;
}

const void *plugin_resolve_symbol(const char *name, const char *symbol)
{
	struct nurs_plugin_def *def;
	void *handler = NULL, *sym = NULL;
	char *error;

	error = dlerror();
	if (error != NULL) {
		nurs_log(NURS_ERROR, "dl error remainded: %s\n", error);
		return NULL;
	}

	if (name == NULL || !strcmp("global", name)) { /* from main */
		handler = dlopen(NULL, RTLD_NOW);
		if (!handler) {
			nurs_log(NURS_ERROR, "failed to open global handler:"
				 " %s\n", dlerror());
			return NULL;
		}
		sym = dlsym(handler, symbol);
		dlclose(handler); /* will just decrement? */
	} else {
		def = find_plugin_def(name);
		if (!def || !def->dlh) {
			nurs_log(NURS_ERROR, "could not found symbol: %s"
				 ", in %s\n", symbol, name);
			return NULL;
		}
		sym = dlsym(def->dlh->h, symbol);
	}
	if (sym == NULL) {
		error = dlerror();
		nurs_log(NURS_ERROR, "failed to dlsym - %s: %s\n",
			 symbol, error);
		return NULL;
	}

	return sym;
}

int plugin_unregister_all(void)
{
	struct nurs_plugin *plugin, *ptmp;
	struct nurs_plugin_def *def, *dtmp;
	int ret = 0;


	list_for_each_entry_safe(plugin, ptmp, &nurs_plugins, list)
		ret |= plugin_put(plugin);

	list_for_each_entry_safe(def, dtmp, &nurs_plugin_defs, list)
		ret |= plugin_unregister(def->type, def->name);

	return ret;
}

static void relist(struct list_head *tmplist, enum nurs_plugin_type type)
{
	struct nurs_plugin *plugin, *tmp;

	list_for_each_entry_safe(plugin, tmp, &nurs_plugins, list) {
		if (plugin->type == type) {
			list_del(&plugin->list);
			list_add_tail(&plugin->list, tmplist);
		}
	}
}

/* add this to call start / stop callbacks in sequence
 * might be better way */
void plugins_order_group(void)
{
	LIST_HEAD(ordered);
	enum nurs_plugin_type types[] = {
		NURS_PLUGIN_T_PRODUCER,
		NURS_PLUGIN_T_FILTER,
		NURS_PLUGIN_T_CONSUMER,
		NURS_PLUGIN_T_COVETER,
	};
	unsigned int i;

	for (i = 0; i < sizeof(types) / sizeof(types[0]); i++)
		relist(&ordered, types[i]);

	list_replace(&ordered, &nurs_plugins);
}

/**
 * @}
 */

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
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

static int check_input(const struct nurs_producer *producer,
		       const struct nurs_stack *stack,
		       const struct nurs_plugin *plugin)
{
	const struct nurs_filter *filter;
	const struct nurs_consumer *consumer;
	const struct nurs_coveter *coveter;
	struct nurs_stack_element *element;
	struct nurs_input_def *indef;
	struct nurs_input_key_def *inkey;
	struct nurs_output_def *outdef;
	struct nurs_output_key_def *outkey;
	char *name;
	uint8_t i, j;
	bool found;

	switch (plugin->type) {
	case NURS_PLUGIN_T_FILTER:
		filter = (const struct nurs_filter *)plugin;
		indef = filter->def->input_def;
		break;
	case NURS_PLUGIN_T_CONSUMER:
		consumer = (const struct nurs_consumer *)plugin;
		indef = consumer->def->input_def;
		break;
	case NURS_PLUGIN_T_COVETER:
		coveter = (const struct nurs_coveter *)plugin;
		indef = coveter->input_def;
		break;
	default:
		nurs_log(NURS_FATAL, "invalid plugin type: %s, %d\n",
			 plugin->id, plugin->type);
		return -1;
	}

	for (i = 0; i < indef->len; i++) {
		found = false;
		inkey = &indef->keys[i];

		/* resolve name */
		list_for_each_entry_reverse(element, &stack->elements, list) {
			/* sorry for mess...
			 * stack_config_parser calls excludeing the plugin, but
			 * settle_cb calls including the plugin int the stack */
			if (element->plugin->type == NURS_PLUGIN_T_CONSUMER ||
			    element->plugin->type == NURS_PLUGIN_T_COVETER)
				continue;

			filter = (struct nurs_filter *)element->plugin;
			name = filter->def->name;
			outdef = filter->def->output_def;
			for (j = 0; j < outdef->len; j++) {
				outkey = &outdef->keys[j];
				if (!strcmp(inkey->name, outkey->name)) {
					found = true;
					break;
				}
			}
		}
		if (!found) {
			name = producer->def->name;
			outdef = producer->def->output_def;
			for (j = 0; j < outdef->len; j++) {
				outkey = &outdef->keys[j];
				if (!strcmp(inkey->name, outkey->name)) {
					found = true;
					break;
				}
			}
		}

		if (!found) {
			if (inkey->flags & NURS_IKEY_F_ANY)
				continue;
			nurs_log(NURS_ERROR, "coud not found key in"
				 " stack: %s\n", inkey->name);
			return -1;
		}

		/* check type */
		if (inkey->type != outkey->type) {
			nurs_log(NURS_ERROR, "key type differ"
				 " %s in %s is a type: %d\n",
				 outkey->name, name, outkey->type);
			return -1;
		}

		/* check flags */
		if ((inkey->flags & NURS_IKEY_F_REQUIRED) &&
		    !(outkey->flags & NURS_OKEY_F_ALWAYS)) {
			nurs_log(NURS_ERROR, "not an active key: %s - %s\n",
				 outkey->name, name);
			return -1;
		}
		if ((inkey->flags & NURS_IKEY_F_OPTIONAL) &&
		    (!(outkey->flags & NURS_OKEY_F_ALWAYS) &&
		     !(outkey->flags & NURS_OKEY_F_OPTIONAL))) {
			nurs_log(NURS_ERROR, "not an optional key: %s - %s\n",
				 outkey->name, name);
			return -1;
		}
	}

	return 0;
}

static int add_wildinput(struct list_head *wildlist,
			 struct nurs_output_def *outdef)
{
	LIST_HEAD(list);
	struct nurs_wildlist_element *e, *element;
	bool found = false;
	uint16_t i;

	for (found = false, i = 0; i < outdef->len; i++) {
		list_for_each_entry(e, wildlist, list) {
			if (!strcmp(outdef->keys[i].name, e->keydef.name)) {
				if (outdef->keys[i].type != e->keydef.type) {
					nurs_log(NURS_ERROR, "key: %s has"
						 " different types %d and %d\n",
						 outdef->keys[i].type,
						 e->keydef.type);
					goto fail_free_list;
				}
				/* XXX: check flag? */
				found = true;
				break;
			}
		}
		if (found)
			continue;

		element = calloc(1, sizeof(struct nurs_wildlist_element));
		if (!element)
			goto fail_free_list;
		strcpy(element->keydef.name, outdef->keys[i].name);
		element->keydef.type = outdef->keys[i].type;
		element->keydef.flags = NURS_IKEY_F_ANY;
		list_add(&element->list, &list);
	}
	list_splice(&list, wildlist);
	return 0;

fail_free_list:
	list_for_each_entry_safe(element, e, &list, list)
		free(element);
	return -1;
}


/* nurs_config_parser_t */
int stack_config_parser(const char *line)
{
	struct nurs_producer *producer = NULL;
	struct nurs_plugin *plugin = NULL;
	struct nurs_filter *filter;
	struct nurs_coveter *coveter = NULL;
	struct nurs_stack *stack = NULL;
	struct nurs_stack_element *element, *e;
	char id[NURS_NAME_LEN + 1], *name;	/* instance represented id:name */
	LIST_HEAD(wildlist);			/* for coveter */
	struct nurs_wildlist_element *we1, *we2, *we3;
	const char *p = line;
	char *q;
	int n = 0;

	if (!line) return NURS_RET_ERROR;
	for (; isblank(*p); p++);
	while (*p) {
		p = get_word(p, ",", true, id, NURS_NAME_LEN);
		if (p == NULL) {
			nurs_log(NURS_ERROR, "found invalid word? %s\n", line);
			goto fail_free;
		}
		if (*p == ',')	p++;

		name = strchr(id, ':');
		if (!name) {
			nurs_log(NURS_ERROR, "invalid plugin id: %s\n", id);
			goto fail_free;
		}
		for (q = name - 1; isblank(*q); q--)
			*q = '\0';
		*name++ = '\0';
		for (; isblank(*name); name++)
			*name = '\0';

		if (n == 0) {	 	/* producer */
			producer = plugin_producer_get(name, id);
			if (!producer) {
				nurs_log(NURS_ERROR, "no producer plugin:"
					 " %s:%s\n", id, name);
				goto fail_free;
			}
			stack = calloc(1, sizeof(struct nurs_stack));
			if (!stack) {
				nurs_log(NURS_ERROR, "failed to calloc: %s\n",
					 strerror(errno));
				goto fail_free;
			}
			if (add_wildinput(&wildlist, producer->def->output_def))
				goto fail_free;

			list_add(&stack->list, &producer->stacks);
			init_list_head(&stack->elements);
			producer->nstacks++;
		} else {
			if (*p == '\0') { /* consumer */
				plugin = (struct nurs_plugin *)
					plugin_consumer_get(name, id);
				if (!plugin) {
					coveter = plugin_coveter_get(name, id);
					plugin = (struct nurs_plugin *)coveter;
				}
			} else {	/* filter */
				filter = plugin_filter_get(name, id);
				if (!filter) {
					nurs_log(NURS_ERROR, "faild to get"
						 " filter %s:%s\n", id, name);
					goto fail_free;
				}
				if (add_wildinput(&wildlist,
						  filter->def->output_def))
					goto fail_free;
				plugin = (struct nurs_plugin *)filter;
			}

			if (!plugin) {
				nurs_log(NURS_ERROR, "failed to get plugin:"
					 " %s:%s\n", id, name);
				goto fail_free;
			}

			/* coveter will check after all stack have created */
			if ((plugin->type == NURS_PLUGIN_T_FILTER ||
			     plugin->type == NURS_PLUGIN_T_CONSUMER) &&
			    check_input(producer, stack, plugin)) {
				nurs_log(NURS_ERROR, "failed to key check\n");
				goto fail_free;
			}

			element = calloc(1, sizeof(struct nurs_stack_element));
			if (!element) {
			  nurs_log(NURS_ERROR, "failed to calloc: %s\n",
				   strerror(errno));
				goto fail_free;
			}
			element->plugin = plugin;
			list_add_tail(&element->list, &stack->elements);
		}
		n++;
	}
	if (n < 2) {
		nurs_log(NURS_ERROR, "not enough stack element: %s\n", line);
		goto fail_free;
	}

	if (coveter) {
		list_for_each_entry(we1, &coveter->wildlist, list) {
			list_for_each_entry_safe(we2, we3, &wildlist, list) {
				if (!strcmp(we1->keydef.name,
					    we2->keydef.name)) {
					list_del(&we2->list);
					free(we2);
				}
			}
		}
		list_splice(&wildlist, &coveter->wildlist);
	} else {
		list_for_each_entry_safe(we1, we2, &wildlist, list) {
			list_del(&we1->list);
			free(we1);
		}
	}
	return NURS_RET_OK;

fail_free:
	if (stack) {
		list_del(&stack->list);
		list_for_each_entry_safe(element, e, &stack->elements, list) {
			plugin_put(element->plugin);
			free(element);
		}
		free(stack);
		plugin_producer_put(producer);
		if (plugin)
			plugin_put(plugin);
	}
	list_for_each_entry_safe(we1, we2, &wildlist, list) {
		list_del(&we1->list);
		free(we1);
	}
	return NURS_RET_ERROR;
}

static int create_coveter_input(struct nurs_coveter *coveter)
{
	struct nurs_wildlist_element *e, *tmp;
	uint16_t len = 0;

	list_for_each_entry(e, &coveter->wildlist, list)
		len++;

	coveter->input_def = calloc(1, sizeof(struct nurs_input_def)
				    + sizeof(struct nurs_input_key_def) * len);
	if (!coveter->input_def)
		return -1;

	coveter->input_def->len = len;
	len = 0;
	list_for_each_entry_safe(e, tmp, &coveter->wildlist, list) {
		memcpy(&coveter->input_def->keys[len++], &e->keydef,
		       sizeof(struct nurs_input_key_def));
		list_del(&e->list);
		free(e);
	}

	return 0;
}

static enum nurs_return_t coveter_cb(struct nurs_plugin *plugin, void *data)
{
	struct nurs_coveter *coveter = (struct nurs_coveter *)plugin;

	if (plugin->type != NURS_PLUGIN_T_COVETER)
		return NURS_RET_OK;

	if (create_coveter_input(coveter))
		return NURS_RET_ERROR;

	return NURS_RET_OK;
}

static enum nurs_return_t settle_cb(struct nurs_producer *producer, void *data)
{
	struct nurs_stack *stack;
	struct nurs_stack_element *e;
	struct nurs_ioset *ioset;
	size_t nioset = *((size_t *)data);

	/* is check_input for COVETER needed? */
	if (ioset_create(producer, nioset))
		return NURS_RET_ERROR;

	ioset = list_first_entry(&producer->iosets,
				 struct nurs_ioset, list);
	for_each_stack_element(producer, stack, e) {
		if (e->plugin->type != NURS_PLUGIN_T_COVETER)
			continue;
		((struct nurs_coveter *)e->plugin)->input_template
			= ioset_input(ioset, e->idx);
	}

	return NURS_RET_OK;
}

int stack_settle(size_t nioset)
{
	if (plugin_cb(NULL, "settle coveter", coveter_cb, NULL, false)) {
		nurs_log(NURS_ERROR, "failed to create coveter input def\n");
		return -1;
	}

	if (producer_cb("settle producer", settle_cb, &nioset, false)) {
		nurs_log(NURS_ERROR, "failed to settle producer\n");
		return -1;
	}

	return 0;
}

static enum nurs_return_t unsettle_cb(struct nurs_producer *producer, void *data)
{
	struct nurs_stack *stack, *tmps;
	struct nurs_stack_element *element, *tmpe;
	int refcnt, ret;

	for_each_stack_element_safe(producer, stack, element, tmpe) {
		switch (element->plugin->type) {
		case NURS_PLUGIN_T_FILTER:
			ret = plugin_filter_put(stack_element_filter(element));
			break;
		case NURS_PLUGIN_T_CONSUMER:
			ret = plugin_consumer_put(
				stack_element_consumer(element));
			break;
		case NURS_PLUGIN_T_COVETER:
			ret = plugin_coveter_put(
				stack_element_coveter(element));
			break;
		default:
			nurs_log(NURS_FATAL, "invalid plugin type: %d\n",
				 element->plugin->type);
			return NURS_RET_ERROR; /* XXX: return ? */
		}
		if (ret) {
			nurs_log(NURS_FATAL, "failed to put plugin: %s:%s\n",
				 element->plugin->id, element->plugin->def->name);
			return NURS_RET_ERROR; /* XXX: return ? */
		}
		list_del(&element->list);
		free(element);
	}

	list_for_each_entry_safe(stack, tmps, &producer->stacks, list) {
		list_del(&stack->list);
		free(stack);
	}

	for (refcnt = producer->nstacks; refcnt; refcnt--)
		if (plugin_producer_put(producer))
			return NURS_RET_ERROR;

	return NURS_RET_OK;
}

int stack_unsettle(void)
{
	if (producer_cb("unsettle producer", unsettle_cb, NULL, true)) {
		nurs_log(NURS_ERROR, "failed to unsettle producer\n");
		return -1;
	}
	return 0;
}

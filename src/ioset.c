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
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "internal.h"

static LIST_HEAD(nurs_iosets_factories);

struct nurs_input *
ioset_input(struct nurs_ioset *ioset, uint8_t idx)
{
	return (struct nurs_input *)&ioset->base[idx];
}

struct nurs_output *
ioset_output(struct nurs_ioset *ioset, uint8_t idx)
{
	return &ioset->base[idx];
}

/* types are already checked in check_input::stack.c */
static int element_resolve(const struct nurs_stack *stack,
			   const struct nurs_stack_element *element,
			   struct nurs_ioset *ioset)
{
	struct nurs_filter *filter;
	struct nurs_consumer *consumer;
	struct nurs_coveter *coveter;
	const struct nurs_stack_element *el;
	struct nurs_input *input;
	struct nurs_output *output;
	struct nurs_input_def *indef;
	uint16_t i, j;
	char *id, *name;
	bool found;

	id = element->plugin->id;
	name = element->plugin->def->name;
	switch (element->plugin->type) {
	case NURS_PLUGIN_T_FILTER:
		filter = stack_element_filter(element);
		indef = filter->def->input_def;
		break;
	case NURS_PLUGIN_T_CONSUMER:
		consumer = stack_element_consumer(element);
		indef = consumer->def->input_def;
		break;
	case NURS_PLUGIN_T_COVETER:
		coveter = stack_element_coveter(element);
		indef = coveter->input_def;
		break;
	default:
		nurs_log(NURS_FATAL, "invalid plugin type - %s: %d\n",
			 id, element->plugin->type);
		return -1;
	}

	input = ioset_input(ioset, element->idx);
	for (i = 0; i < indef->len; i++) {
		found = false;
		el = list_entry(element->list.prev, struct nurs_stack_element, list);
		list_for_each_entry_reverse_from(el, &stack->elements, list) {
			output = ioset_output(ioset, el->odx);
			for (j = 0; j < output->len; j++) {
				if (!strcmp(indef->keys[i].name,
					    output->keys[j].def->name)) {
					input->keys[i] = &output->keys[j];
					found = true;
					break;
				}
			}
			if (found) break;
		}
		if (found) continue;

		/* check producer */
		output = ioset->base;
		for (j = 0; j < output->len; j++) {
			if (!strcmp(indef->keys[i].name,
				    output->keys[j].def->name)) {
				input->keys[i] = &output->keys[j];
				found = true;
				break;
			}
		}
		if (found) continue;
		if (indef->keys[i].flags & NURS_IKEY_F_ANY) continue;

		nurs_log(NURS_ERROR, "could not found key: %s in %s:%s\n",
			 indef->keys[i].name, id, name);

		return -1;
	}

	return 0;
}

static int input_resolve(const struct nurs_producer *producer,
			 struct nurs_ioset *ioset)
{
	const struct nurs_stack *stack;
	const struct nurs_stack_element *element;
	int ret = 0;

	for_each_stack_element(producer, stack, element)
		ret |= element_resolve(stack, element, ioset);

	return ret;
}

/* XXX: too long */
static struct nurs_ioset *
ioset_create_template(struct nurs_producer *producer)
{
	struct nurs_filter *filter;
	struct nurs_consumer *consumer;
	struct nurs_coveter *coveter;
	struct nurs_stack *stack;
	struct nurs_stack_element *e;
	struct nurs_ioset *ioset;
	struct nurs_input *input;
	struct nurs_output *output;
	struct nurs_input_def *idef;
	struct nurs_output_def *odef;
	size_t s, size;
	void *ptr;		/* lengthen field */
	void *next_keys;
	uintptr_t keys_offset, ptr_offset;
	uint8_t ioset_len;
	uint16_t i;

	/* calc whole size */
	s = sizeof(struct nurs_ioset) + sizeof(struct nurs_output);
	size = keys_offset = ptr_offset = s;

	odef = producer->def->output_def;
	s = sizeof(struct nurs_output_key) * odef->len;
	size += s;
	ptr_offset += s;

	for (i = 0; i < odef->len; i++)
		size += (size_t)NURS_ALIGN(odef->keys[i].len);

	ioset_len = 1;
	for_each_stack_element(producer, stack, e) {
		switch (e->plugin->type) {
		case NURS_PLUGIN_T_FILTER:
			filter = stack_element_filter(e);

			e->idx = ioset_len++;
			s = sizeof(struct nurs_input);
			size += s;
			keys_offset += s;
			ptr_offset += s;

			idef = filter->def->input_def;
			s = sizeof(struct nurs_output_key *) * idef->len;
			size += s;
			ptr_offset += s;

			e->odx = ioset_len++;
			s = sizeof(struct nurs_output);
			size += s;
			keys_offset += s;
			ptr_offset += s;

			odef = filter->def->output_def;
			s = sizeof(struct nurs_output_key) * odef->len;
			size += s;
			ptr_offset += s;
			for (i = 0; i < odef->len; i++)
				size += (size_t)NURS_ALIGN(odef->keys[i].len);
			break;
		case NURS_PLUGIN_T_CONSUMER:
		case NURS_PLUGIN_T_COVETER:
			e->idx = ioset_len++;
			if (e->plugin->type == NURS_PLUGIN_T_CONSUMER) {
				consumer = stack_element_consumer(e);
				idef = consumer->def->input_def;
			} else {
				coveter = stack_element_coveter(e);
				idef = coveter->input_def;
			}

			s = sizeof(struct nurs_input);
			size += s;
			keys_offset += s;
			ptr_offset += s;

			s = sizeof(struct nurs_output_key *) * idef->len;
			size += s;
			ptr_offset += s;
			break;
		default:
			nurs_log(NURS_FATAL, "invalid plugin type - %s: %d\n",
				 e->plugin->id, e->plugin->type);
				return NULL;
		}
	}

	ioset = calloc(1, size);
	if (ioset == NULL)
		goto exit;

	ioset->size = size;
	ioset->len = ioset_len;
	ioset->producer = producer;

	ptr = (void *)((uintptr_t)ioset + ptr_offset);

	output = ioset->base;
	output->keys = (struct nurs_output_key *)
		((uintptr_t)ioset + keys_offset);
	odef = producer->def->output_def;
	output->len = odef->len;
	for (i = 0; i < odef->len; i++) {
		output->keys[i].def = &odef->keys[i];
		if (odef->keys[i].len) {
			uintptr_t len = (uintptr_t)
				NURS_ALIGN(odef->keys[i].len);
			output->keys[i].ptr = ptr;
			ptr = (void *)((uintptr_t)ptr + len);
		}
	}

	next_keys = (void *)((uintptr_t)output->keys
			     + sizeof(struct nurs_output_key) * output->len);
	for_each_stack_element(producer, stack, e) {
		switch (e->plugin->type) {
		case NURS_PLUGIN_T_FILTER:
			filter = stack_element_filter(e);

			idef = filter->def->input_def;
			input = ioset_input(ioset, e->idx);
			input->len = idef->len;
			input->keys = (struct nurs_output_key **)next_keys;

			odef = filter->def->output_def;
			output = ioset_output(ioset, e->odx);
			output->len = odef->len;
			output->keys = (struct nurs_output_key *)
				((uintptr_t)input->keys
				 + sizeof(struct nurs_output_key *)
				 * input->len);
			for (i = 0; i < odef->len; i++) {
				output->keys[i].def = &odef->keys[i];
				if (odef->keys[i].len) {
					uintptr_t len = (uintptr_t)
						NURS_ALIGN(odef->keys[i].len);
					output->keys[i].ptr = ptr;
					ptr = (void *)((uintptr_t)ptr + len);
				}
			}
			next_keys = (void *)
				((uintptr_t)output->keys
				 + sizeof(struct nurs_output_key) * output->len);
			break;
		case NURS_PLUGIN_T_CONSUMER:
		case NURS_PLUGIN_T_COVETER:
			if (e->plugin->type == NURS_PLUGIN_T_CONSUMER) {
				consumer = stack_element_consumer(e);
				idef = consumer->def->input_def;
			} else {
				coveter = stack_element_coveter(e);
				idef = coveter->input_def;
			}
			input = ioset_input(ioset, e->idx);
			input->len = idef->len;
			input->keys = (struct nurs_output_key **)next_keys;
			next_keys = (void *)
				((uintptr_t)input->keys
				 + sizeof(struct nurs_output_key *)
				 * input->len);
			break;
		default:
			nurs_log(NURS_FATAL, "invalid plugin type - %s: %d\n",
				 e->plugin->id, e->plugin->type);
			goto fail_free_ioset;
		}
	}

	if (input_resolve(producer, ioset))
		goto fail_free_ioset;

	goto exit;

fail_free_ioset:
	free(ioset);
	ioset = NULL;
exit:
	return ioset;
}

static void adjust_output(struct nurs_ioset *srcs, struct nurs_ioset *dsts,
			  uint8_t index, uintptr_t offset)
{
	struct nurs_output *src, *dst;
	uint16_t i;

	src = ioset_output(srcs, index);
	dst = ioset_output(dsts, index);
	dst->keys = (struct nurs_output_key *)((uintptr_t)src->keys + offset);
	for (i = 0; i < src->len; i++) {
		if (!src->keys[i].def->len)
			continue;
		dst->keys[i].ptr
			= (void *)((uintptr_t)src->keys[i].ptr + offset);
	}
}

static void adjust_input(struct nurs_ioset *srcs, struct nurs_ioset *dsts,
			 uint8_t index, uintptr_t offset)
{
	struct nurs_input *src, *dst;
	uint16_t i;

	src = ioset_input(srcs, index);
	dst = ioset_input(dsts, index);
	dst->keys = (struct nurs_output_key **)((uintptr_t)src->keys + offset);
	for (i = 0; i < src->len; i++) {
		if (!src->keys[i])
			continue;
		dst->keys[i] = (struct nurs_output_key *)
			((uintptr_t)src->keys[i] + offset);
	}
}

static int ioset_add_copy(struct nurs_producer *producer,
			  struct nurs_ioset *template,
			  size_t num)
{
	struct nurs_ioset *ioset, *iosets;
	struct nurs_stack *stack;
	struct nurs_stack_element *element;
	pthread_mutexattr_t attr;
	size_t i;
	uintptr_t offset;

	iosets = mmap(NULL, template->size * num, PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (iosets == MAP_FAILED) {
		nurs_log(NURS_ERROR, "mmap: %s\n", strerror(errno));
		return -1;
	}
	producer->iosets_size = template->size * num;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, NURS_MUTEX_ATTR);

	for (i = 0, ioset = iosets;
	     i < num;
	     i++, ioset = (void *)((uintptr_t)ioset + template->size)) {
		memcpy(ioset, template, template->size);
		offset = (uintptr_t)ioset - (uintptr_t)template;

		/* adjust producer - lengthen ptr field */
		adjust_output(template, ioset, 0, offset);

		for_each_stack_element(producer, stack, element) {
			adjust_input(template, ioset, element->idx, offset);
			if (element->plugin->type == NURS_PLUGIN_T_FILTER)
				adjust_output(template, ioset,
					      element->odx, offset);
		}

		pthread_mutex_init(&ioset->refcnt_mutex, &attr);
		pthread_cond_init(&ioset->refcnt_condv, NULL);
		list_add(&ioset->list, &producer->iosets);
	}

	return 0;
}

int ioset_create(struct nurs_producer *producer, size_t num)
{
	struct nurs_ioset *template;
	int ret;

	if (!num) {
		nurs_log(NURS_ERROR, "invalid #ioset: %d\n", num);
		return -1;
	}

	template = ioset_create_template(producer);
	if (!template)
		return -1;

	ret = ioset_add_copy(producer, template, num);
	free(template);

	return ret;
}

int ioset_destroy(struct nurs_producer *producer)
{
	struct nurs_ioset *b1, *b2, *xb;

	if (list_empty(&producer->iosets))
		return 0;

	xb = list_first_entry(&producer->iosets, struct nurs_ioset, list);
	list_for_each_entry_safe(b1, b2, &producer->iosets, list) {
		if ((uintptr_t)b1 < (uintptr_t)xb)
			xb = b1;
		list_del(&b1->list);
	}

	return munmap(xb, producer->iosets_size);
}

/* static - used in tests */
struct nurs_ioset *ioset_get(struct nurs_producer *producer)
{
	struct nurs_ioset *ioset;

	if (nurs_mutex_lock(&producer->iosets_mutex))
		return NULL;

	while (list_empty(&producer->iosets)) {
		nurs_log(NURS_NOTICE, "producer: %s consumes all iosets,"
			 " may need to increase its size\n", producer->id);
		if (nurs_cond_wait(&producer->iosets_condv,
				   &producer->iosets_mutex)) {
			nurs_mutex_unlock(&producer->iosets_mutex);
			return NULL;
		}
	}
	ioset = list_first_entry(&producer->iosets,
				  struct nurs_ioset, list);
	list_del(&ioset->list);
	if (nurs_mutex_unlock(&producer->iosets_mutex))
		return NULL;

	return ioset;
}

/* return errno */
int ioset_put(struct nurs_producer *producer, struct nurs_ioset *ioset)
{
	if (nurs_mutex_lock(&producer->iosets_mutex))
		return -1;

	list_add(&ioset->list, &producer->iosets);

	if (nurs_cond_broadcast(&producer->iosets_condv)) {
		nurs_mutex_unlock(&producer->iosets_mutex);
		return -1;
	}
	if (nurs_mutex_unlock(&producer->iosets_mutex))
		return -1;

	return 0;
}

/* return errno */
int ioset_clear(struct nurs_ioset *ioset)
{
	struct nurs_stack *stack;
	struct nurs_stack_element *e;
	struct nurs_output *output;
	struct nurs_output_key *key;
	uint16_t i;

        for_each_stack_element(ioset->producer, stack, e) {
                if (e->plugin->type != NURS_PLUGIN_T_PRODUCER &&
                    e->plugin->type != NURS_PLUGIN_T_FILTER)
                        continue;

		output = ioset_output(ioset, e->odx);
		for (i = 0; i < output->len; i++) {
			key = &output->keys[i];

			if (!(key->flags & NURS_KEY_F_VALID))
				continue;

			if (key->def->flags & NURS_OKEY_F_FREE) {
				free(key->ptr);
				key->ptr = NULL;
			} else if (key->def->flags & NURS_OKEY_F_DESTRUCT &&
				   key->def->destructor &&
				   key->ptr) {
				key->def->destructor(key->ptr);
                                key->ptr = NULL;
			}
			if (key->def->len) {
				memset(key->ptr, 0, key->def->len);
			} else {
				/* XXX: fixed magic */
				memset(key->umax, 0, sizeof(key->umax));
			}
			key->flags &= (uint16_t)~NURS_KEY_F_VALID;
		}
	}
	return 0;
}

/* set pthread related errno and returns NULL on error */
struct nurs_output *nurs_get_output(struct nurs_producer *producer)
{
	struct nurs_ioset *ioset = ioset_get(producer);

	if (ioset == NULL)
		return NULL;

	return ioset->base;
}
EXPORT_SYMBOL(nurs_get_output);

int nurs_put_output(struct nurs_output *output)
{
	struct nurs_ioset *ioset
		= container_of((struct nurs_output (*)[])output,
			       struct nurs_ioset, base);
	struct nurs_producer *producer = ioset->producer;

	return ioset_put(producer, ioset);
}
EXPORT_SYMBOL(nurs_put_output);

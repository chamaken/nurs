/*
 * (C) 2006-2009 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Description: generic hash table implementation
 */
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "nfct_hash.h"

struct hashtable *
hashtable_create(uint32_t hashsize, uint32_t limit,
		 uint32_t (*hash)(const void *data,
		 		  const struct hashtable *table),
		 int (*compare)(const void *data1, const void *data2))
{
	struct hashtable *h;
	size_t i, size = sizeof(struct hashtable)
		+ hashsize * sizeof(struct list_head);

	h = (struct hashtable *) calloc(1, size);
	if (h == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	for (i = 0; i < hashsize; i++)
		init_list_head(&h->members[i]);

	h->hashsize = hashsize;
	h->limit = limit;
	h->hash = hash;
	h->compare = compare;

	return h;
}

void hashtable_destroy(struct hashtable *h)
{
	free(h);
}

uint32_t hashtable_hash(const struct hashtable *table, const void *data)
{
	return table->hash(data, table);
}

struct hashtable_node *
hashtable_find(const struct hashtable *table, const void *data, uint32_t id)
{
	struct hashtable_node *n;

	list_for_each_entry(n, &table->members[id], head) {
		if (table->compare(n, data)) {
			return n;
		}
	}
	errno = ENOENT;
	return NULL;
}

int hashtable_add(struct hashtable *table, struct hashtable_node *n, uint32_t id)
{
	/* hash table is full */
	if (table->count >= table->limit) {
		errno = ENOSPC;
		return -1;
	}
	list_add(&n->head, &table->members[id]);
	table->count++;
	return 0;
}

void hashtable_del(struct hashtable *table, struct hashtable_node *n)
{
	list_del(&n->head);
	table->count--;
}

int hashtable_flush(struct hashtable *table)
{
	uint32_t i;
	struct hashtable_node *n, *tmp;

	for (i=0; i < table->hashsize; i++) {
		list_for_each_entry_safe(n, tmp, &table->members[i], head) {
			free(n);
		}
	}
	return 0;
}

/* returns -1 on error */
int
hashtable_iterate_limit(struct hashtable *table, void *data,
			uint32_t from, uint32_t steps,
		        int (*iterate)(void *data1, void *n))
{
	uint32_t i;
	struct hashtable_node *n, *tmp;

	for (i = from; i < table->hashsize && i < from + steps; i++) {
		list_for_each_entry_safe(n, tmp, &table->members[i], head) {
			if (iterate(data, n) == -1)
				return -1;
		}
	}
	return 0;
}

int hashtable_iterate(struct hashtable *table, void *data,
		      int (*iterate)(void *data1, void *n))
{
	return hashtable_iterate_limit(table, data, 0, UINT_MAX, iterate);
}

unsigned int hashtable_counter(const struct hashtable *table)
{
	return table->count;
}

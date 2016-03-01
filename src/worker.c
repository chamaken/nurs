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
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include <nurs/nurs.h>
#include "internal.h"

static LIST_HEAD(nurs_workers);
static size_t nurs_workers_size;

static pthread_mutex_t
nurs_runnable_workers_mutex = NURS_MUTEX_INITIALIZER;
static pthread_cond_t
nurs_runnable_workers_condv = PTHREAD_COND_INITIALIZER;
/* protected by aboves */
static LIST_HEAD(nurs_runnable_workers);
static size_t nurs_runnable_workers_size;
static enum nurs_workers_state nurs_runnable_workers_state;


static int no_validate_output(const char *id, const struct nurs_output *output);
static int(*validate_output)
(const char *id, const struct nurs_output *output) = no_validate_output;

#define STOPPED_WORKER ((struct nurs_worker *)-1)

/* XXX: set errno? caller clear errno before call? */
/* not static - for tests */
struct nurs_worker *worker_get(void)
{
	struct nurs_worker *worker;

	if (nurs_mutex_lock(&nurs_runnable_workers_mutex))
		return NULL;

check_status:
	switch (nurs_runnable_workers_state) {
	case NURS_WORKERS_STOP:
		if (nurs_mutex_unlock(&nurs_runnable_workers_mutex))
			return NULL;
		return STOPPED_WORKER;
	case NURS_WORKERS_RUNNABLE:
		if (!list_empty(&nurs_runnable_workers))
			break;
		nurs_log(NURS_NOTICE, "producer consumes all workers,"
			 " may need to increase its size from: %d\n",
			 nurs_workers_size);
		/* pass through */
	case NURS_WORKERS_SUSPEND:
		if (nurs_cond_wait(&nurs_runnable_workers_condv,
				   &nurs_runnable_workers_mutex))
			return NULL;
		goto check_status;
	}

	worker = list_entry(nurs_runnable_workers.next,
			    struct nurs_worker, runnable_list);
	list_del(nurs_runnable_workers.next);
	nurs_runnable_workers_size--;

	if (nurs_mutex_unlock(&nurs_runnable_workers_mutex))
		return NULL;

	return worker;
}

/* return errno */
/* static - for tests */
int worker_put(struct nurs_worker *worker)
{
	if (nurs_mutex_lock(&nurs_runnable_workers_mutex))
		return -1;

	list_add(&worker->runnable_list, &nurs_runnable_workers);
	nurs_runnable_workers_size++;

	if (nurs_cond_broadcast(&nurs_runnable_workers_condv)) {
		nurs_mutex_unlock(&nurs_runnable_workers_mutex);
		return -1;
	}
	if (nurs_mutex_unlock(&nurs_runnable_workers_mutex))
		return -1;

	return 0;
}

static enum nurs_return_t
exec_stack(struct nurs_stack *stack, struct nurs_ioset *ioset)
{
	struct nurs_stack_element *e;
	struct nurs_filter *filter;
	struct nurs_consumer *consumer;
	struct nurs_coveter *coveter;
	struct nurs_input *input;
	struct nurs_output *output;
	bool abort_stack = false;
	enum nurs_return_t ret;

	list_for_each_entry(e, &stack->elements, list) {
		input = ioset_input(ioset, e->idx);
		switch (e->plugin->type) {
		case NURS_PLUGIN_T_FILTER:
			filter = (struct nurs_filter *)e->plugin;
			if (!filter->def->mtsafe &&
			    nurs_mutex_lock(&filter->mutex))
				return NURS_RET_ERROR;
			output = ioset_output(ioset, e->odx);
			ret = filter->def->interp(e->plugin, input, output);
			if (!filter->def->mtsafe &&
			    nurs_mutex_unlock(&filter->mutex))
				return NURS_RET_ERROR;
			if (validate_output(e->plugin->id, output))
				ret = NURS_RET_ERROR;
			break;
		case NURS_PLUGIN_T_CONSUMER:
			consumer = (struct nurs_consumer *)e->plugin;
			if (!consumer->def->mtsafe &&
			    nurs_mutex_lock(&consumer->mutex))
				return NURS_RET_ERROR;
			ret = consumer->def->interp(e->plugin, input);
			if (!consumer->def->mtsafe &&
			    nurs_mutex_unlock(&consumer->mutex))
				return NURS_RET_ERROR;
			break;
		case NURS_PLUGIN_T_COVETER:
			coveter = (struct nurs_coveter *)e->plugin;
			if (!coveter->def->mtsafe &&
			    nurs_mutex_lock(&coveter->mutex))
				return NURS_RET_ERROR;
			ret = coveter->def->interp(e->plugin, input);
			if (!coveter->def->mtsafe &&
			    nurs_mutex_unlock(&coveter->mutex))
				return NURS_RET_ERROR;
			break;
		default:
			nurs_log(NURS_FATAL, "invalid plugin type: %d\n",
				 e->plugin->type);
			ret = NURS_RET_ERROR;
			break;
		}

		switch (ret) {
		case NURS_RET_ERROR:
		case NURS_RET_STOP:
			nurs_log(NURS_ERROR, "interp: %s, returns: %d\n",
				 e->plugin->id, ret);
			abort_stack = true;
			break;
		case NURS_RET_OK: /* 0 */
			continue;
		default:
			nurs_log(NURS_NOTICE,
				 "unknown return value: %d, from plugin: %s\n",
				 ret, e->plugin->id);
			abort_stack = true;
			break;
		}
		if (abort_stack)
			break;
	}

	return ret;
}

/* per ioset thread routine
 * retval error:
 *   interp: positive
 *   other:  negative */
static void *ioset_routine(void *arg)
{
	struct nurs_worker *worker = arg;
	struct nurs_producer *producer;
	struct nurs_ioset *ioset = NULL;
	struct nurs_stack *stack;
	enum nurs_return_t nret = 0;
	int ret = 0;

	while (worker->runnable) {
		/* get keys ioset */
		if ((ret = nurs_mutex_lock(&worker->mutex)))
			goto exit;
		while (worker->runnable && !worker->ioset)
			if ((ret = nurs_cond_wait(&worker->condv,
						  &worker->mutex)))
				goto fail_unlock;
		ioset = worker->ioset;
		producer = worker->producer;
		worker->ioset = NULL;
		worker->producer = NULL;
		if ((ret = nurs_mutex_unlock(&worker->mutex)))
			goto fail_unlock;

		if (!worker->runnable)
			break;

		list_for_each_entry(stack, &producer->stacks, list) {
			nurs_log(NURS_DEBUG, "exec stack [T%lu/D%p]\n",
				 worker->tid, ioset);
			nret = exec_stack(stack, ioset);
			if (nret != NURS_RET_OK) {
				nurs_log(NURS_ERROR, "[T%lu/D%p] stack: %s,"
					 " returned: %d\n",
					 worker->tid, ioset, stack->name, nret);
			}
			/* entire ioset is holded, no atomic op is needed? */
			ioset->refcnt--;
		}
		assert(ioset->refcnt == 0); /* TODO: remove? or if error */

		if ((ret = ioset_clear(ioset))) {
			nurs_log(NURS_ERROR, "failed to clear ioset: %s\n",
				 _sys_errlist[ret]);
			goto exit;
		}
		if ((ret = ioset_put(producer, ioset))) {
			nurs_log(NURS_ERROR, "failed to put ioset: %s\n",
				 _sys_errlist[ret]);
			goto exit;
		}

		/* notify to nurs_wait_consume() */
		if ((ret = nurs_mutex_lock(&ioset->refcnt_mutex)))
			goto exit;
		/* not broadcast, only one producer may waiting */
		if ((ret = nurs_cond_signal(&ioset->refcnt_condv)))
			goto fail_unlock_refcnt;
		if ((ret = nurs_mutex_unlock(&ioset->refcnt_mutex)))
			goto fail_unlock_refcnt;

		if ((ret = worker_put(worker))) {
			nurs_log(NURS_FATAL, "failed to put worker: %s\n",
				_sys_errlist[ret]);
			goto exit;
		}
		ioset = NULL;
	}
	if (ioset) {
		nurs_log(NURS_NOTICE, "discard ioset: %p"
			 " because of user stop request\n", ioset);
		ioset_clear(ioset);
		ioset_put(producer, ioset);
		worker_put(worker);
	}
	nret = NURS_RET_STOP;
	goto exit;

fail_unlock:
	nurs_mutex_unlock(&worker->mutex);
	goto exit;
fail_unlock_refcnt:
	nurs_mutex_unlock(&ioset->refcnt_mutex);
exit:
	if (nret)
		worker->retval = nret;
	else
		worker->retval = -ret;
	return &worker->retval;
}

/* per stack thread routine */
__attribute__ ((unused))
static void *stack_routine(void *arg)
{
	struct nurs_worker *worker = arg;
	struct nurs_producer *producer;
	struct nurs_ioset *ioset;
	struct nurs_stack *stack;
	enum nurs_return_t nret = 0;
	int ret = 0;

	while (worker->runnable) {
		if ((ret = nurs_mutex_lock(&worker->mutex)))
			goto exit;
		while (worker->runnable && !worker->ioset)
			if ((ret = nurs_cond_wait(&worker->condv,
						  &worker->mutex)))
				goto fail_unlock;
		ioset = worker->ioset;
		producer = worker->producer;
		stack = worker->stack;
		worker->ioset = NULL;
		worker->producer = NULL;
		worker->stack = NULL;
		if ((ret = nurs_mutex_unlock(&worker->mutex)))
			goto fail_unlock;

		if (!worker->runnable)
			break;

		nret = exec_stack(stack, ioset);
		if (nret != NURS_RET_OK) {
			nurs_log(NURS_ERROR, "[T%lu/D%p] stack: %s,"
				 "returned: %d\n",
				 worker->tid, ioset, stack->name, nret);
		}
		if (__sync_sub_and_fetch(&ioset->refcnt, 1) == 0) {
			if ((ret = ioset_clear(ioset)))
				nurs_log(NURS_ERROR, "failed to clear ioset:"
					 " %s\n", _sys_errlist[ret]);
			if ((ret = ioset_put(producer, ioset)))
				nurs_log(NURS_FATAL,
					 "failed to put ioset: %s\n",
					 _sys_errlist[ret]);
			if ((ret = nurs_mutex_lock(&ioset->refcnt_mutex)))
				goto exit;
			if ((ret = nurs_cond_signal(&ioset->refcnt_condv)))
				goto fail_unlock_refcnt;
			if ((ret = nurs_mutex_unlock(&ioset->refcnt_mutex)))
				goto fail_unlock_refcnt;
		}
		if ((ret = worker_put(worker))) {
			nurs_log(NURS_FATAL, "failed to put worker: %s\n",
				_sys_errlist[ret]);
			goto exit;
		}
	}
	if (ioset) {
		nurs_log(NURS_NOTICE, "discard ioset: %p"
			 "because of user stop request\n", ioset);
		ioset_clear(ioset);
		ioset_put(producer, ioset);
		worker_put(worker);
	}
	nret = NURS_RET_STOP;
	goto exit;

fail_unlock:
	nurs_mutex_unlock(&worker->mutex);
	goto exit;
fail_unlock_refcnt:
	nurs_mutex_unlock(&ioset->refcnt_mutex);
exit:
	if (nret)
		worker->retval = nret;
	else
		worker->retval = -ret;
	return &worker->retval;
}

/* set pthread related errno and returns NURS_RET_ERROR on error */
static enum nurs_return_t
nurs_publish_ioset(struct nurs_output *output)
{
	struct nurs_ioset *ioset
		= container_of((struct nurs_output (*)[])output,
			       struct nurs_ioset, base);
	struct nurs_producer *producer = ioset->producer;
	struct nurs_worker *worker;

	if (validate_output(producer->id, output)) {
		nurs_put_output(output);
		errno = EIO;
		return NURS_RET_ERROR;
	}

	worker = worker_get();
	if (!worker) {
		nurs_log(NURS_ERROR, "failed to get worker: %s\n",
			 _sys_errlist[errno]);
		return NURS_RET_ERROR;
	} else if (worker == STOPPED_WORKER) {
		nurs_log(NURS_NOTICE, "worker may be stopped\n");
		return NURS_RET_STOP;
	}

	if (nurs_mutex_lock(&worker->mutex))
		goto fail;

	ioset->refcnt = producer->nstacks;
	worker->ioset = ioset;
	worker->producer = producer;
	if (nurs_cond_signal(&worker->condv)) {
		nurs_mutex_unlock(&worker->mutex);
		goto fail;
	}
	if (nurs_mutex_unlock(&worker->mutex))
		goto fail;

	return NURS_RET_OK;
fail:
	worker_put(worker);
	return NURS_RET_ERROR;
}

/* set pthread related errno and returns NURS_RET_ERROR on error */
__attribute__ ((unused))
static enum nurs_return_t
nurs_publish_stack(struct nurs_output *output)
{
	struct nurs_ioset *ioset
		= container_of((struct nurs_output (*)[])output,
			       struct nurs_ioset, base);
	struct nurs_producer *producer = ioset->producer;
	struct nurs_stack *stack;
	struct nurs_worker *worker;

	if (validate_output(producer->id, output)) {
		nurs_put_output(output);
		errno = EIO;
		return NURS_RET_ERROR;
	}

	ioset->refcnt = producer->nstacks;
	list_for_each_entry(stack, &producer->stacks, list) {
		worker = worker_get();
		if (!worker) {
			nurs_log(NURS_ERROR, "failed to get worker: %s\n",
				 _sys_errlist[errno]);
			return NURS_RET_ERROR;
		} else if (worker == STOPPED_WORKER) {
			nurs_log(NURS_NOTICE, "worker may be stopped\n");
			return NURS_RET_STOP;
		}

		if (nurs_mutex_lock(&worker->mutex))
			goto fail;

		worker->ioset = ioset;
		worker->producer = producer;
		worker->stack = stack;

		if (nurs_cond_signal(&worker->condv)) {
			nurs_mutex_unlock(&worker->mutex);
			goto fail;
		}
		if (nurs_mutex_unlock(&worker->mutex))
			goto fail;
	}
	return NURS_RET_OK;
fail:
	worker_put(worker);
	return NURS_RET_ERROR;
}

#ifdef THREAD_PER_STACK
enum nurs_return_t
nurs_publish(struct nurs_output *output)
{
	return nurs_publish_stack(output);
}
static void *start_routine(void *arg)
{
	stack_routine(arg);
}
#else
enum nurs_return_t
nurs_publish(struct nurs_output *output)
{
	return nurs_publish_ioset(output);
}
static void *start_routine(void *arg)
{
	return ioset_routine(arg);
}
#endif
EXPORT_SYMBOL(nurs_publish);

/* allocate workers and start it
 * return negative errno on error */
int workers_start(size_t nthread)
{
	struct nurs_worker *workers, *cur, *tmp;
	pthread_mutexattr_t attr;
	size_t i;
	int ret;

	if (!nthread) {
		nurs_log(NURS_ERROR, "invalid #worker: %d\n", nthread);
		return -1;
	}

	if (nurs_workers_size) {
		errno = EALREADY;
		return -1;
	}

	workers = calloc(nthread, sizeof(struct nurs_worker));
	if (!workers) {
		nurs_log(NURS_FATAL, "failed to calloc: %s\n", strerror(errno));
		return -errno;
	}

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, NURS_MUTEX_ATTR);
	for (i = 0; i < nthread; i++) {
		/* XXX: any attr? err? */
		pthread_mutex_init(&workers[i].mutex, &attr);
		pthread_cond_init(&workers[i].condv, NULL);
		workers[i].ioset = NULL;
		workers[i].stack = NULL;
		workers[i].runnable = true;
		list_add(&workers[i].list, &nurs_workers);
		ret = pthread_create(&workers[i].tid, NULL,
				     start_routine, &workers[i]);
		if (ret) {
			nurs_log(NURS_FATAL, "pthread_create: %s\n",
				 _sys_errlist[ret]);
			goto fail_cancel;
		}
	}
	nurs_workers_size = nthread;

	/* may not need, but this makes helgrind happy */
	nurs_mutex_lock(&nurs_runnable_workers_mutex);
	list_for_each_entry(cur, &nurs_workers, list)
		list_add(&cur->runnable_list, &nurs_runnable_workers);
	nurs_runnable_workers_size = nurs_workers_size;
	nurs_mutex_unlock(&nurs_runnable_workers_mutex);

	return 0;

fail_cancel:
	for (--i; i != 0; i--) {
		/* must be canceled at waiting condv loop */
		if (pthread_cancel(workers[i].tid))
			nurs_log(NURS_FATAL, "pthread_cancel: %s\n",
				 _sys_errlist[ret]);
		if (pthread_join(workers[i].tid, NULL))
			nurs_log(NURS_FATAL, "pthread_join: %s\n",
				 _sys_errlist[ret]);
	}

	nurs_mutex_lock(&nurs_runnable_workers_mutex);
	list_for_each_entry_safe(cur, tmp, &nurs_workers, list) {
		/* XXX: no err check */
		pthread_mutex_destroy(&cur->mutex);
		pthread_cond_destroy(&cur->condv);
		list_del(&cur->list);
		list_del(&cur->runnable_list);
	}
	free(workers);

	return -ret;
}

/* return errno */
static int workers_wait(enum nurs_workers_state state)
{
	int ret = 0;

	if ((ret = nurs_mutex_lock(&nurs_runnable_workers_mutex)))
		return ret;

	nurs_runnable_workers_state = state;
	while (nurs_workers_size != nurs_runnable_workers_size)
		if ((ret = nurs_cond_wait(&nurs_runnable_workers_condv,
					  &nurs_runnable_workers_mutex)))
			break;

	ret |= pthread_mutex_unlock(&nurs_runnable_workers_mutex);
		return ret;

	return ret;
}

int workers_suspend(void)
{
	return workers_wait(NURS_WORKERS_SUSPEND);
}

/* returns errno */
int workers_resume(void)
{
	int ret = 0;

	if ((ret = nurs_mutex_lock(&nurs_runnable_workers_mutex)))
		return ret;
	nurs_runnable_workers_state = NURS_WORKERS_RUNNABLE;
	ret = nurs_cond_broadcast(&nurs_runnable_workers_condv);
	ret |= nurs_mutex_unlock(&nurs_runnable_workers_mutex);

	return ret;
}

/* stop workers and destroy
 * returns errno */
int workers_stop(void)
{
	struct nurs_worker *cur, *tmp, *head;
	int rc, ret = 0;
	int *retval; /* worker.retval */

	if ((ret = workers_wait(NURS_WORKERS_STOP)))
		return ret;

	if (list_empty(&nurs_workers)) {
		nurs_log(NURS_NOTICE, "no workers\n");
		return 0;
	}

	/* set runnable false and notify */
	list_for_each_entry(cur, &nurs_workers, list) {
		if ((ret = nurs_mutex_lock(&cur->mutex)))
			goto exit;
		cur->runnable = false;
		ret = pthread_cond_signal(&cur->condv);
		if (ret) {
			nurs_log(NURS_FATAL, "pthread_cond_signal: %s\n",
				 _sys_errlist[ret]);
			nurs_mutex_unlock(&cur->mutex);
			goto exit;
		}
		if ((ret = nurs_mutex_unlock(&cur->mutex)))
			goto exit;
	}

	/* join and release reproducer */
	head = list_entry(nurs_workers.next, struct nurs_worker, list);
	list_for_each_entry_safe(cur, tmp, &nurs_workers, list) {
		rc = pthread_join(cur->tid, (void **)&retval);
		if (rc) {
			nurs_log(NURS_FATAL, "pthread_join: %s\n",
				 _sys_errlist[ret]);
			ret = rc;
			goto exit;
		}
		if (*retval != NURS_RET_STOP) {
			nurs_log(NURS_ERROR, "join worker: T%lu returns: %d\n",
				 cur->tid, *retval);
			ret = -1;
		}

		rc = pthread_mutex_destroy(&cur->mutex);
		if (rc) {
			nurs_log(NURS_ERROR, "pthread_mutex_destroy: %s\n",
				 _sys_errlist[ret]);
			ret = -1;
		}
		rc = pthread_cond_destroy(&cur->condv);
		if (rc) {
			nurs_log(NURS_ERROR, "pthread_cond_destroy: %s\n",
				 _sys_errlist[ret]);
			ret = -1;
		}
		list_del(&cur->list);
		list_del(&cur->runnable_list);
		if (cur < head)
			head = cur;
	}
	free(head);
	nurs_workers_size = 0;
exit:
	return ret;
}

static int really_validate_output(const char *id,
				  const struct nurs_output *output)
{
	uint16_t i;
	int ret = 0;

	for (i = 0; i < output->len; i++) {
		if (!(output->keys[i].def->flags & NURS_OKEY_F_ALWAYS))
			continue;
		if (!(output->keys[i].flags & NURS_KEY_F_VALID)) {
			nurs_log(NURS_ERROR, "not valid active output: %s@%s\n",
				 output->keys[i].def->name, id);
			ret = -1;
		}
	}

	return ret;
}

static int no_validate_output(const char *id,
			      const struct nurs_output *output)
{
	return 0;
}

void nurs_output_set_validate(bool b)
{
	if (b) validate_output = really_validate_output;
}

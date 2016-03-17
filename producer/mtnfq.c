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
 *
 * XXX: less error check
 */
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/eventfd.h>

#include <nurs/nurs.h>
#include <nurs/ring.h>

#include "nfq_common.h"

extern struct nurs_config_def nfq_config;
extern struct nurs_output_def nfq_output;

enum thread_status {
	MTNFQ_STATUS_INVALID,
	MTNFQ_STATUS_RUNNING,
	MTNFQ_STATUS_SUSPEND,
	MTNFQ_STATUS_STOP,
};

struct mtnfq_priv {
	struct mnl_socket	*nl;
	uint32_t		portid;
#ifdef NLMMAP
	struct mnl_ring		*nlr;
#endif

	int			retval, statusfd;
	enum thread_status	status_req;
	pthread_t		tid;
	pthread_mutex_t		req_lock;
	pthread_cond_t		req_condv;
};

static void *start_routine(void *arg)
{
	struct nurs_producer *producer = arg;
	struct mtnfq_priv *priv = nurs_producer_context(producer);
	struct pollfd pfds[2];
	uint64_t u;

	pfds[0].fd = mnl_socket_get_fd(priv->nl);
	pfds[1].fd = priv->statusfd;
	pfds[0].events = pfds[1].events = POLLIN | POLLERR;
	pfds[0].revents = pfds[1].revents = 0;

	while (1) {
		if (poll(pfds, 2, -1) < 0 && errno != -EINTR) {
			nurs_log(NURS_ERROR, "poll: %s\n",
				  _sys_errlist[errno]);
			continue;
		}
		if (pfds[1].revents & POLLIN) {
			read(pfds[1].fd, &u, sizeof(uint64_t));
			pthread_mutex_lock(&priv->req_lock);
			while (priv->status_req != MTNFQ_STATUS_RUNNING) {
				if (priv->status_req == MTNFQ_STATUS_STOP) {
					priv->retval = EXIT_SUCCESS;
					pthread_mutex_unlock(&priv->req_lock);
					return &priv->retval;
				}
				pthread_cond_wait(&priv->req_condv,
						  &priv->req_lock);
			}
			pthread_mutex_unlock(&priv->req_lock);
		}
		if (pfds[0].revents & POLLIN) {
			nfq_read_cb(pfds[0].fd, NURS_FD_F_READ, producer);
		}
		if (pfds[0].revents & POLLERR || pfds[1].revents & POLLERR) {
			/* getsockopt(pfds[0], SOL_SOCKET, err, errlen) */
			nurs_log(NURS_ERROR, "receive POLLERR\n");
		}
	}
	priv->retval = EXIT_FAILURE;
	return &priv->retval;
}

static int suspend_routine(struct mtnfq_priv *priv)
{
	uint64_t u = 1; /* must not be 0, see eventfd(2) */

	if (nurs_mutex_lock(&priv->req_lock))
		return -1;
	priv->status_req = MTNFQ_STATUS_SUSPEND;
	if (nurs_cond_signal(&priv->req_condv))
		goto fail_unlock;
	if (nurs_mutex_unlock(&priv->req_lock))
		return -1;
	if (write(priv->statusfd, &u, sizeof(u)) != sizeof(u)) {
		nurs_log(NURS_ERROR, "write statusfd: %s\n",
			  _sys_errlist[errno]);
		return -1;
	}

	return 0;
fail_unlock:
	nurs_mutex_unlock(&priv->req_lock);
	return -1;
}

static int resume_routine(struct mtnfq_priv *priv)
{
	if (nurs_mutex_lock(&priv->req_lock))
		return -1;
	priv->status_req = MTNFQ_STATUS_RUNNING;
	if (nurs_cond_signal(&priv->req_condv))
		goto fail_unlock;
	nurs_mutex_unlock(&priv->req_lock);

	return 0;
fail_unlock:
	nurs_mutex_unlock(&priv->req_lock);
	return -1;
}

static int init_pthread(struct mtnfq_priv *priv)
{
	pthread_mutexattr_t attr;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, NURS_MUTEX_ATTR);
	pthread_mutex_init(&priv->req_lock, &attr);
	pthread_cond_init(&priv->req_condv, NULL);
	priv->statusfd = eventfd(0, 0);
	if (priv->statusfd == -1) {
		nurs_log(NURS_ERROR, "eventfd: %s\n",
			  _sys_errlist[errno]);
		return -1;
	}
	priv->status_req = MTNFQ_STATUS_RUNNING;

	return 0;
}

static int fini_pthread(struct mtnfq_priv *priv)
{
	int ret = 0;

	if (close(priv->statusfd)) {
		nurs_log(NURS_ERROR, "failed to close statusfd: %s\n",
			 strerror(errno));
		ret = -1;
	}
	pthread_cond_destroy(&priv->req_condv);
	pthread_mutex_destroy(&priv->req_lock);

	return ret;
}

static enum nurs_return_t mtnfq_organize(struct nurs_producer *producer)
{
	struct mtnfq_priv *priv = nurs_producer_context(producer);

	if (init_pthread(priv))
		return NURS_RET_ERROR;
	return nfq_common_organize(producer);
}

static enum nurs_return_t
mtnfq_disorganize(struct nurs_producer *producer)
{
	struct mtnfq_priv *priv = nurs_producer_context(producer);
	enum nurs_return_t ret = NURS_RET_OK;

	if (fini_pthread(priv))
		ret = NURS_RET_ERROR;
	if (nfq_common_disorganize(producer) != NURS_RET_OK)
		ret = NURS_RET_ERROR;

	return ret;
}

static enum nurs_return_t mtnfq_start(struct nurs_producer *producer)
{
	struct mtnfq_priv *priv = nurs_producer_context(producer);
	int ret;

	if (config_nfq(producer))
		return NURS_RET_ERROR;

	ret = pthread_create(&priv->tid, NULL, start_routine, producer);
	if (ret) {
		nurs_log(NURS_ERROR, "failed to pthread_create: %s\n",
			 strerror(ret));
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static enum nurs_return_t mtnfq_stop(struct nurs_producer *producer)
{
	struct mtnfq_priv *priv = nurs_producer_context(producer);
	uint64_t u = 1;
	void *retval;

	if (nurs_mutex_lock(&priv->req_lock))
		return NURS_RET_ERROR;

	priv->status_req = MTNFQ_STATUS_STOP;
	if (nurs_cond_signal(&priv->req_condv))
		goto fail_unlock;
	if (nurs_mutex_unlock(&priv->req_lock))
		return NURS_RET_ERROR;

	if (write(priv->statusfd, &u, sizeof(u)) == -1) {
		nurs_log(NURS_ERROR, "failed to write: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}

	pthread_join(priv->tid, &retval);
	if (retval == PTHREAD_CANCELED)
		nurs_log(NURS_INFO, "thread cancened\n");

	if (unbind_nfq(producer))
		return NURS_RET_ERROR;

	return NURS_RET_OK;
fail_unlock:
	nurs_mutex_unlock(&priv->req_lock);
	return NURS_RET_ERROR;
}

static enum nurs_return_t
mtnfq_signal(struct nurs_producer *producer, uint32_t signal)
{
	struct mtnfq_priv *priv = nurs_producer_context(producer);

	if (suspend_routine(priv)) {
		nurs_log(NURS_ERROR, "failed to suspend\n");
		return NURS_RET_ERROR;
	}

	switch (signal) {
	default:
		nurs_log(NURS_DEBUG, "receive signal: %d\n", signal);
	}

	if (resume_routine(priv)) {
		nurs_log(NURS_ERROR, "failed to resume\n");
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static struct nurs_producer_def mtnfq_producer = {
	.version	= VERSION,
	.name		= "MTNFQ",
	.context_size	= sizeof(struct mtnfq_priv),
	.config_def	= &nfq_config,
	.output_def	= &nfq_output,
	.organize	= mtnfq_organize,
	.disorganize	= mtnfq_disorganize,
	.start		= mtnfq_start,
	.stop		= mtnfq_stop,
	.signal		= mtnfq_signal,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	nurs_producer_register(&mtnfq_producer);
}

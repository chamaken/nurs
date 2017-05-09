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
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "internal.h"

#define NURS_FD_MAX_EVENTS 16

/* Yes, not MT-safe */
static int epollfd = -1;
static int cancelfd = -1;

int nfd_init(void)
{
	if (epollfd != -1) {
		errno = EALREADY;
		return -1;
	}

	epollfd = epoll_create1(0);
	if (epollfd == -1) {
		nurs_log(NURS_FATAL, "epoll_create: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int nfd_fini(void)
{
	int ret;

	if (epollfd == -1) {
		errno = EBADF;
		return -1;
	}

	ret = close(epollfd);
	if (ret == -1)
		return ret;

	epollfd = -1;
	return ret;
}

int nurs_fd_get_fd(const struct nurs_fd *nfd)
{
        return nfd->fd;
}
EXPORT_SYMBOL(nurs_fd_get_fd);

void *nurs_fd_get_data(const struct nurs_fd *nfd)
{
        return nfd->data;
}
EXPORT_SYMBOL(nurs_fd_get_data);

struct nurs_fd *nurs_fd_register(int fd, uint16_t when, nurs_fd_cb_t cb, void *data)
{
	struct nurs_fd *nfd;
	struct epoll_event ev = {0, {0}};
	int flags;

	/* make FD non blocking */
	flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		return NULL;

	flags |= O_NONBLOCK;
	flags = fcntl(fd, F_SETFL, flags);
	if (flags < 0)
		return NULL;

	if (when & NURS_FD_F_READ)
		ev.events |= EPOLLIN;
	if (when & NURS_FD_F_WRITE)
		ev.events |= EPOLLOUT;
	if (when & NURS_FD_F_EXCEPT) {
		/* intend to be a fd_set *exceptfds, right? */
		ev.events |= EPOLLRDHUP | EPOLLPRI | EPOLLERR;
	}

        nfd = calloc(1, sizeof(struct nurs_fd));
        if (!nfd)
                return NULL;

        nfd->fd = fd;
        nfd->when = when;
	nfd->cb = cb;
	nfd->data = data;
	ev.data.ptr = nfd;

	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
                free(nfd);
                return NULL;
        }

        return nfd;

}
EXPORT_SYMBOL(nurs_fd_register);

int nurs_fd_unregister(struct nurs_fd *nfd)
{
	struct epoll_event ev = {0, {0}};
        int ret;

	if (nfd->when & NURS_FD_F_READ)
		ev.events |= EPOLLIN;

	if (nfd->when & NURS_FD_F_WRITE)
		ev.events |= EPOLLOUT;

	if (nfd->when & NURS_FD_F_EXCEPT)
		ev.events |= EPOLLRDHUP | EPOLLPRI | EPOLLERR;

	ev.data.ptr = nfd;
        ret = epoll_ctl(epollfd, EPOLL_CTL_DEL, nfd->fd, &ev);
        if (ret == -1)
                return ret;

        free(nfd);
        return 0;
}
EXPORT_SYMBOL(nurs_fd_unregister);

int nfd_loop(void)
{
	struct nurs_fd *nfd;
	struct epoll_event cancelev = {0};
	struct epoll_event events[NURS_FD_MAX_EVENTS];
	enum nurs_return_t rc;
	uint16_t flags;
	int fds, i, err, ret = 0;
	socklen_t errlen = sizeof(int);

	cancelfd = eventfd(0, 0);
	if (cancelfd == -1)
		return -1;

	cancelev.data.fd = cancelfd;
	cancelev.events = EPOLLIN;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, cancelfd, &cancelev)) {
		i = errno;
		close(cancelfd);
		cancelfd = -1;
		errno = i;
		return -1;
	}

	while (1) {
		fds = epoll_wait(epollfd, events, NURS_FD_MAX_EVENTS, -1);
		if (fds == -1) {
			if (errno == EINTR)
				continue;
			ret = -1;
			goto exit;
		}

		for (i = 0; i < fds; i++) {
			if (events[i].data.fd == cancelfd)
				goto exit;

			flags = 0;
			nfd = events[i].data.ptr;

			if (events[i].events & EPOLLIN)
				flags |= NURS_FD_F_READ;

			if (events[i].events & EPOLLOUT)
				flags |= NURS_FD_F_WRITE;

			if (events[i].events
			    & (EPOLLRDHUP | EPOLLPRI | EPOLLERR)) {
				flags |= NURS_FD_F_EXCEPT;
				if (!errno &&
				    !getsockopt(nfd->fd, SOL_SOCKET, SO_ERROR,
						&err, &errlen))
					errno = err;
                                nurs_log(NURS_DEBUG, "might be a fd error"
                                         " event: %s\n", strerror(errno));
			}

			if (flags & nfd->when) {
				rc = nfd->cb(nfd, flags);
				if (rc != NURS_RET_OK)
					nurs_log(NURS_DEBUG, "callback is not OK"
						 ", but %d\n", rc);
			}
		}
	}

exit:
	close(cancelfd);
	cancelfd = -1;
	return ret;
}

static void *cancel_routine(void *arg)
{
	int *ret = arg;
	uint64_t val = 1;
	write(cancelfd, &val, sizeof(uint64_t));
	*ret = -errno;
	return ret;
}

int nfd_cancel(void)
{
	pthread_t tid;
	int ret, thret, *p = &thret;

	ret = pthread_create(&tid, NULL, cancel_routine, p);
	if (ret)
		return -1;
	ret = pthread_join(tid, (void **)&p);
	if (ret || thret == -1)
		return -1;

	return 0;
}

static enum nurs_return_t
timer_cb(struct nurs_fd *nfd, uint16_t when)
{
	struct nurs_timer *timer = nurs_fd_get_data(nfd);
	enum nurs_return_t ret;
	uint64_t exp;
        int fd = nurs_fd_get_fd(nfd);

	read(fd, &exp, sizeof(uint64_t)); /* just consuming */
	if (nurs_fd_unregister(timer->nfd)) {
		nurs_log(NURS_ERROR, "could not unregister fd: %s\n",
			 _sys_errlist[errno]);
		return NURS_RET_ERROR;
	}

	ret = timer->cb(timer);
	if (ret != NURS_RET_OK) {
		nurs_log(NURS_ERROR, "timer cb failed: %d\n", ret);
		return ret;
	}

	return NURS_RET_OK;
}

static enum nurs_return_t
itimer_cb(struct nurs_fd *nfd, uint16_t when)
{
	struct nurs_timer *timer = nurs_fd_get_data(nfd);
	enum nurs_return_t ret;
	uint64_t exp;
        int fd = nurs_fd_get_fd(nfd);

	read(fd, &exp, sizeof(uint64_t));
	ret = timer->cb(timer);
	if (ret != NURS_RET_OK) {
		nurs_log(NURS_ERROR, "timer cb failed: %d\n", ret);
		return ret;
	}

	return NURS_RET_OK;
}

static struct nurs_timer *
_nurs_timer_register(time_t ini, time_t per,
                     const nurs_timer_cb_t cb, void *data,
                     int (*stcb)(int, time_t, time_t),
                     nurs_fd_cb_t fdcb)
{
	struct nurs_timer *timer;
	int timerfd;

	timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (timerfd == -1)
		return NULL;

        if (stcb(timerfd, ini, per))
                goto error_close;

        timer = calloc(1, sizeof(struct nurs_timer));
        if (!timer)
                goto error_close;

	timer->nfd = nurs_fd_register(timerfd, NURS_FD_F_READ, fdcb, timer);
	if (timer->nfd == NULL)
		goto error_free;

        timer->cb = cb;
        timer->data = data;

        return timer;

error_free:
        free(timer);
error_close:
        close(timerfd);
        return NULL;
}

static int itimer_stcb(int timerfd, time_t ini, time_t per)
{
        /* XXX: check ini and per is 0 or disarm */
	struct itimerspec its = {{per, 0}, {ini, 0}};
        return timerfd_settime(timerfd, 0, &its, NULL);
}

struct nurs_timer *nurs_itimer_register(time_t ini, time_t per,
                                        const nurs_timer_cb_t cb, void *data)
{
        return _nurs_timer_register(ini, per, cb, data, itimer_stcb, itimer_cb);
}
EXPORT_SYMBOL(nurs_itimer_register);

static int timer_stcb(int timerfd, time_t ini, time_t per)
{
	struct itimerspec its = {{0, 0}, {ini, 0}}; /* interval, initial */

	/* caller want to be called just after now */
        if (ini == 0)
                its.it_value.tv_nsec = 1;
        else
                its.it_value.tv_nsec = 0;

        return timerfd_settime(timerfd, 0, &its, NULL);
}

struct nurs_timer *nurs_timer_register(time_t ini,
                                       const nurs_timer_cb_t cb, void *data)
{
        return _nurs_timer_register(ini, 0, cb, data, timer_stcb, timer_cb);
}
EXPORT_SYMBOL(nurs_timer_register);

int nurs_timer_unregister(struct nurs_timer *timer)
{
	struct itimerspec spec = {{0, 0}, {0, 0}};
        int ret;

        if (!timer) {
                nurs_log(NURS_NOTICE, "not a registered timer\n");
                return 0;
        }

        ret = timerfd_settime(timer->nfd->fd, 0, &spec, NULL);
        if (ret == -1)
                return ret;

	if (nurs_fd_unregister(timer->nfd))
		return -1;

        free(timer);
        return 0;
}
EXPORT_SYMBOL(nurs_timer_unregister);

bool nurs_timer_pending(const struct nurs_timer *timer)
{
        struct itimerspec its;

        if (!timer) {
                nurs_log(NURS_NOTICE, "not a registered timer\n");
                return false;
        }

        if (timerfd_gettime(timer->nfd->fd, &its)) {
                nurs_log(NURS_ERROR, "timerfd_gettime: %s\n",
                         strerror(errno));
                return false;
        }

        return its.it_interval.tv_sec > 0
                || its.it_interval.tv_nsec > 0
                || its.it_value.tv_sec > 0
                || its.it_value.tv_nsec > 0;
}
EXPORT_SYMBOL(nurs_timer_pending);

void *nurs_timer_get_data(const struct nurs_timer *timer)
{
        return timer->data;
}
EXPORT_SYMBOL(nurs_timer_get_data);

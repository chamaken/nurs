/*
 * (C) 2015 by Ken-ichirou MATSUZAWA <chamas@h4.dion.ne.jp>
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
#include <nurs/nurs.h>

#include "_cgo_export.h"
#include "helper.h"

void nurs_glog(int level, char *file, int line, char *msg)
{
	nurs_flog(level, file, line, "%s", msg);
}

struct nurs_fd *
nurs_fd_register_helper(int fd, uint16_t when, void *data)
{
        return nurs_fd_register(fd, when, (nurs_fd_cb_t)goFdCb, data);
}

struct nurs_timer *
nurs_timer_register_helper(time_t sc, void *data)
{
	return nurs_timer_register(sc, (nurs_timer_cb_t)goTimerCb, data);
}

struct nurs_timer *
nurs_itimer_register_helper(time_t ini, time_t per, void *data)
{
	return nurs_itimer_register(ini, per, (nurs_timer_cb_t)goTimerCb, data);
}

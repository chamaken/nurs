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
#ifndef _NURS_CGO_H
#define _NURS_CGO_H

void nurs_glog(int level, char *file, int line, char *msg);
struct nurs_fd *
nurs_fd_register_helper(int fd, uint16_t when, void *data);
struct nurs_timer *
nurs_timer_register_helper(time_t sc, void *data);
struct nurs_timer *
nurs_itimer_register_helper(time_t ini, time_t per, void *data);

#endif

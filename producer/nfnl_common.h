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
#ifndef _NURS_NFNL_COMMON_H
#define _NURS_NFNL_COMMON_H

#include <libmnl/libmnl.h>

int mnl_socket_set_reliable(struct mnl_socket *nl);
void frame_destructor(void *data);
struct mnl_socket *nurs_mnl_socket(const char *ns, int bus);

#endif

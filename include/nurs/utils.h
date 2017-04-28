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
#ifndef _NURS_UTILS_H_
#define _NURS_UTILS_H_

#include <byteswap.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#  ifndef __be64_to_cpu
#  define __be64_to_cpu(x)	(x)
#  endif
#  ifndef __cpu_to_be64
#  define __cpu_to_be64(x)	(x)
#  endif
# else
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  ifndef __be64_to_cpu
#  define __be64_to_cpu(x)	__bswap_64(x)
#  endif
#  ifndef __cpu_to_be64
#  define __cpu_to_be64(x)	__bswap_64(x)
#  endif
# endif
#endif

int open_connect_descriptor(const char *dest);
int open_listen_socket(const char *dest);
int nurs_key_putn(const struct nurs_input *input, uint16_t idx,
		  void *buf, size_t buflen);
uint8_t event_ct_to_firewall(uint32_t ct_event);
#endif

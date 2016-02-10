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
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <nurs/nurs.h>
#include <nurs/utils.h>

/*
 * This function returns file or connected socket descriptor
 * specified by URL like dest:
 *     <proto>://<filename or address>[:port]
 * proto is either one of tcp, udp, sctp and file. port is required
 * in case of socket. file will be stdout if proto is file and
 * no filename specified.
 */
int open_connect_descriptor(const char *dest)
{
	char *proto = NULL, *host, *port;
	struct addrinfo hint, *result = NULL, *rp = NULL;
	int ret, fd = -1;

	proto = strdup(dest);
	if (proto == NULL) {
		nurs_log(NURS_ERROR, "strdup: %s\n", strerror(errno));
		return -1;
	}
	host = strchr(proto, ':');
	if (host == NULL) {
		nurs_log(NURS_ERROR, "invalid dest\n");
		goto error;
	}
	*host++ = '\0';
	if (*host++ != '/') {
		nurs_log(NURS_ERROR, "invalid dest\n");
		goto error;
	}
	if (*host++ != '/') {
		nurs_log(NURS_ERROR, "invalid dest\n");
		goto error;
	}

	/* file */
	if (!strcasecmp(proto, "file")) {
		if (strlen(host) == 0)
			fd = STDOUT_FILENO;
		else
			fd = open(host, O_CREAT|O_WRONLY|O_APPEND, 0600);
		free(proto);
		return fd;
	}

	/* socket */
	port = strrchr(host, ':');
	if (port == NULL) {
		nurs_log(NURS_ERROR, "no destination port\n");
		goto error;
	}
	*port++ = '\0';

	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_UNSPEC;
	if (!strcasecmp(proto, "udp")) {
		hint.ai_socktype = SOCK_DGRAM;
		hint.ai_protocol = IPPROTO_UDP;
	} else if (!strcasecmp(proto, "tcp")) {
		hint.ai_socktype = SOCK_STREAM;
		hint.ai_protocol = IPPROTO_TCP;
	} else {
		nurs_log(NURS_ERROR, "unknown protocol `%s'\n",
			  proto);
		goto error;
	}

	ret = getaddrinfo(host, port, &hint, &result);
	if (ret != 0) {
		nurs_log(NURS_ERROR, "can't resolve host/service: %s\n",
			  gai_strerror(ret));
		if (ret != EAI_SYSTEM)
			errno = EINVAL;
		goto error;
	}

	/* rp == NULL indicates could not get valid sockfd */
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		int on = 1;

		fd = socket(rp->ai_family, rp->ai_socktype,
			    rp->ai_protocol);
		if (fd == -1) {
			switch (errno) {
			case EACCES:
			case EAFNOSUPPORT:
			case EINVAL:
			case EPROTONOSUPPORT:
				/* try next result */
				continue;
			default:
				nurs_log(NURS_ERROR, "socket error: %s\n",
					  strerror(errno));
				rp = NULL;
				goto error;
			}
		}
		ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
				 (void *)&on, sizeof(on));
		if (ret < 0) {
			nurs_log(NURS_ERROR, "error on set SO_REUSEADDR: %s",
				  strerror(errno));
			close(fd);
			rp = NULL;
			break;
		}

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		close(fd);
	}

error:
	if (proto)
		free(proto);
	if (result)
		freeaddrinfo(result);

	if (rp == NULL) {
		nurs_log(NURS_ERROR, "could not connect\n");
		fd = -1;
	}

	return fd;
}

/*
 * This functions stores nurs key value, specifued by key into
 * buf. buflen means buf len and is checked exceeds. This function
 * returns the copied length or -1 on error.
 */
int nurs_key_putn(const struct nurs_input *input, uint16_t idx,
		  void *buf, size_t buflen)
{
	size_t ret;

	if (!nurs_input_is_valid(input, idx))
		return -1;

	switch (nurs_input_type(input, idx)) {
	case NURS_KEY_T_BOOL:
		ret = sizeof(bool);
		if (buflen < ret)
			return -1;
		*(bool *)buf = nurs_input_bool(input, idx);
	case NURS_KEY_T_INT8:
	case NURS_KEY_T_UINT8:
		ret = sizeof(uint8_t);
		if (buflen < ret)
			return -1;
		*(uint8_t *)buf = nurs_input_u8(input, idx);
		break;
	case NURS_KEY_T_INT16:
	case NURS_KEY_T_UINT16:
		ret = sizeof(uint16_t);
		if (buflen < ret)
			return -1;
		*(uint16_t *)buf = htons(nurs_input_u16(input, idx));
		break;
	case NURS_KEY_T_INT32:
	case NURS_KEY_T_UINT32:
		ret = sizeof(uint32_t);
		if (buflen < ret)
			return -1;
		*(uint32_t *)buf = htonl(nurs_input_u32(input, idx));
		break;
	case NURS_KEY_T_INADDR:
		ret = sizeof(in_addr_t);
		if (buflen < ret)
			return -1;
		*(in_addr_t *)buf = nurs_input_in_addr(input, idx);
		break;
	case NURS_KEY_T_INT64:
	case NURS_KEY_T_UINT64:
		ret = sizeof(uint64_t);
		if (buflen < ret)
			return -1;
		*(uint64_t *)buf = __be64_to_cpu(nurs_input_u64(input, idx));
		break;
	case NURS_KEY_T_IN6ADDR:
		ret = 16;
		if (buflen < ret)
			return -1;
		memcpy(buf, nurs_input_in6_addr(input, idx), 16);
		break;
	case NURS_KEY_T_STRING:
		ret = nurs_input_size(input, idx);
		if (buflen < ret)
			return -1;
		memcpy(buf, nurs_input_pointer(input, idx), ret);
		((char *)buf)[ret] = '\0';
		break;
	case NURS_KEY_T_EMBED:
		ret = nurs_input_size(input, idx);
		if (buflen < ret)
			return -1;
		memcpy(buf, nurs_input_pointer(input, idx), ret);
		break;
	case NURS_KEY_T_POINTER:
		ret = nurs_input_size(input, idx);
		if (buflen < ret)
			return -1;
		*(const void **)buf = nurs_input_pointer(input, idx);
		break;
	default:
		nurs_log(NURS_ERROR, "unknown size - key "
			 "`%s' type 0x%x\n", nurs_input_name(input, idx)
			 , nurs_input_type(input, idx));
		return -1;
		break;
	}

	return (int)ret;
}


uint8_t event_ct_to_firewall(uint32_t ct_event)
{
	/* 0 - Ignore (invalid)
	 * 1 - Flow Created
	 * 2 - Flow Deleted
	 * 3 - Flow Denied
	 * 4 - Flow Alert
	 * 5 - Flow Update */
	if (ct_event & NFCT_T_NEW)
		return 1;
	if (ct_event & NFCT_T_UPDATE)
		return 5;
	if (ct_event & NFCT_T_DESTROY)
		return 2;
	return 0;
}

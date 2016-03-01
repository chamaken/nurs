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
#include <Python.h>

#include <linux/netlink.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <libmnl/libmnl.h>

#include <nurs/nurs.h>
#include "pynurs.h"

char *pynurs_nlmsg_string[NURS_PYIPC_T_MAX + 1] = {
	[NURS_PYIPC_T_NONE] =			"PYIPC_T_NONE",

	[NURS_PYIPC_T_REQ_LOG] =		"REQ_LOG",

	[NURS_PYIPC_T_REQ_START] =		"REQ_START",
	[NURS_PYIPC_T_REQ_PRODUCER_START] =	"REQ_PRODUCER_START",
	[NURS_PYIPC_T_REQ_STOP] =		"REQ_STOP",
	[NURS_PYIPC_T_REQ_PRODUCER_STOP] =	"REQ_PRODUCER_STOP",
	[NURS_PYIPC_T_REQ_SIGNAL] =		"REQ_SIGNAL",
	[NURS_PYIPC_T_REQ_PRODUCER_SIGNAL] =	"REQ_PRODUCER_SIGNAL",
	[NURS_PYIPC_T_REQ_ORGANIZE] =		"REQ_ORGANIZE",
	[NURS_PYIPC_T_REQ_COVETER_ORGANIZE] =	"REQ_COVETER_ORGANIZE",
	[NURS_PYIPC_T_REQ_PRODUCER_ORGANIZE] =	"REQ_PRODUCER_ORGANIZE",
	[NURS_PYIPC_T_REQ_DISORGANIZE] =	"REQ_DISORGANIZE",
	[NURS_PYIPC_T_REQ_PRODUCER_DISORGANIZE] = "REQ_PRODUCER_DISORGANIZE",
	[NURS_PYIPC_T_REQ_FILTER_INTERP] =	"REQ_FILTER_INTERP",
	[NURS_PYIPC_T_REQ_CONSUMER_INTERP] =	"REQ_CONSUMER_INTERP",

	[NURS_PYIPC_T_REQ_FD_CREATE] =		"REQ_FD_CREATE",
	[NURS_PYIPC_T_REQ_FD_DESTROY] =		"REQ_FD_DESTROY",
	[NURS_PYIPC_T_REQ_FD_CALLBACK] =	"REQ_FD_CALLBACK",

	[NURS_PYIPC_T_REQ_TIMER_CREATE] =	"REQ_TIMER_CREATE",
	[NURS_PYIPC_T_REQ_TIMER_DESTROY] =	"REQ_TIMER_DESTROY",
	[NURS_PYIPC_T_REQ_TIMER_ADD] =		"REQ_TIMER_ADD",
	[NURS_PYIPC_T_REQ_ITIMER_ADD] =		"REQ_ITIMER_ADD",
	[NURS_PYIPC_T_REQ_TIMER_DEL] =		"REQ_TIMER_DEL",
	[NURS_PYIPC_T_REQ_TIMER_PENDING] =	"REQ_TIMER_PENDING",
	[NURS_PYIPC_T_REQ_TIMER_CALLBACK] =	"REQ_TIMER_CALLBACK",

	[NURS_PYIPC_T_REQ_PUBLISH] =		"REQ_PUBLISH",
	[NURS_PYIPC_T_REQ_GET_OUTPUT] =		"REQ_GET_OUTPUT",
	[NURS_PYIPC_T_REQ_PUT_OUTPUT] =		"REQ_PUT_OUTPUT",
	[NURS_PYIPC_T_REQ_FD_REGISTER] =		"REQ_FD_REGISTER",
	[NURS_PYIPC_T_REQ_FD_UNREGISTER] =	"REQ_FD_UNREGISTER",

	[NURS_PYIPC_T_REQ_MAX] =		"REQ_MAX",

	[NURS_PYIPC_T_ACK_PUBLISH] =		"ACK_PUBLISH",
	[NURS_PYIPC_T_ACK_GET_OUTPUT] =		"ACK_GET_OUTPUT",
	[NURS_PYIPC_T_ACK_PUT_OUTPUT] =		"ACK_PUT_OUTPUT",
	[NURS_PYIPC_T_ACK_FD_REGISTER] =		"ACK_FD_REGISTER",
	[NURS_PYIPC_T_ACK_FD_UNREGISTER] =	"ACK_FD_UNREGISTER",

	[NURS_PYIPC_T_ACK_INIT] =		"ACK_INIT",
	[NURS_PYIPC_T_ACK_ORGANIZE] =		"ACK_ORGANIZE",
	[NURS_PYIPC_T_ACK_COVETER_ORGANIZE] =	"ACK_COVETER_ORGANIZE",
	[NURS_PYIPC_T_ACK_PRODUCER_ORGANIZE] =	"ACK_PRODUCER_ORGANIZE",
	[NURS_PYIPC_T_ACK_DISORGANIZE] =	"ACK_DISORGANIZE",
	[NURS_PYIPC_T_ACK_PRODUCER_DISORGANIZE] = "ACK_PRODUCER_DISORGANIZE",
	[NURS_PYIPC_T_ACK_START] =		"ACK_START",
	[NURS_PYIPC_T_ACK_PRODUCER_START] =	"ACK_PRODUCER_START",
	[NURS_PYIPC_T_ACK_STOP] =		"ACK_STOP",
	[NURS_PYIPC_T_ACK_PRODUCER_STOP] =	"ACK_PRODUCER_STOP",
	[NURS_PYIPC_T_ACK_SIGNAL] =		"ACK_SIGNAL",
	[NURS_PYIPC_T_ACK_PRODUCER_SIGNAL] =	"ACK_PRODUCER_SIGNAL",
	[NURS_PYIPC_T_ACK_FILTER_INTERP] =	"ACK_FILTER_INTERP",
	[NURS_PYIPC_T_ACK_CONSUMER_INTERP] =	"ACK_CONSUMER_INTERP",

	[NURS_PYIPC_T_ACK_FD_CREATE] =		"ACK_FD_CREATE",
	[NURS_PYIPC_T_ACK_FD_DESTROY] =		"ACK_FD_DESTROY",
	[NURS_PYIPC_T_ACK_FD_CALLBACK] =	"ACK_FD_CALLBACK",

	[NURS_PYIPC_T_ACK_TIMER_CREATE] =	"ACK_TIMER_CREATE",
	[NURS_PYIPC_T_ACK_TIMER_DESTROY] =	"ACK_TIMER_DESTROY",
	[NURS_PYIPC_T_ACK_TIMER_ADD] =		"ACK_TIMER_ADD",
	[NURS_PYIPC_T_ACK_ITIMER_ADD] =		"ACK_ITIMER_ADD",
	[NURS_PYIPC_T_ACK_TIMER_DEL] =		"ACK_TIMER_DEL",
	[NURS_PYIPC_T_ACK_TIMER_PENDING] =	"ACK_TIMER_PENDING",
	[NURS_PYIPC_T_ACK_TIMER_CALLBACK] =	"ACK_TIMER_CALLBACK",

	[NURS_PYIPC_T_MAX] =			"PYIPC_T_MAX",
};

char *py_strerror(char *buf, size_t len)
{
	PyObject *type, *value, *trace;
	PyObject *frame, *code;
	PyObject *str = NULL, *line_no, *file_name;
	PyObject *fname_ascii = NULL, *msg_ascii = NULL;
	char *msg, *fname = NULL, *slash;
	long lineno = -1;

	PyErr_Fetch(&type, &value, &trace);
	PyErr_NormalizeException(&type, &value, &trace);

	/* message */
	str = PyObject_Str(value);
	if (str == NULL) {
		snprintf(buf, len, "(could not get message)");
		goto decref;
	}
	if (PyUnicode_Check(str)) {
		msg_ascii = PyUnicode_AsASCIIString(str);
		msg = PyBytes_AsString(msg_ascii);
	} else if (PyBytes_Check(str)) {
		msg = PyBytes_AsString(str);
	} else {
		snprintf(buf, len, "(could not decode message)");
		Py_DECREF(str);
		goto decref;
	}
	Py_DECREF(str);

	if (trace == NULL) {
		snprintf(buf, len, "(no trace) %s", msg);
		goto decref_msg_ascii;
	}

	/* file name */
	frame = PyObject_GetAttrString(trace, "tb_frame");
	if (frame == NULL) {
		snprintf(buf, len, "(could not get frame) %s", msg);
		goto decref_msg_ascii;
	}
	code = PyObject_GetAttrString(frame, "f_code");
	Py_DECREF(frame);
	if (code == NULL) {
		snprintf(buf, len, "(could not get frame code) %s", msg);
		goto decref_msg_ascii;
	}
	file_name = PyObject_GetAttrString(code, "co_filename");
	Py_DECREF(code);
	if (file_name == NULL) {
		snprintf(buf, len, "(could not get filename) %s", msg);
		goto decref_msg_ascii;
	}
	str = PyObject_Str(file_name);
	Py_DECREF(file_name);
	if (str == NULL) {
		snprintf(buf, len, "(could not get filename str) %s", msg);
		goto decref_msg_ascii;
	}
	fname_ascii = PyUnicode_AsASCIIString(str);
	Py_DECREF(str);
	if (fname_ascii == NULL) {
		snprintf(buf, len, "(could not get filename ascii) %s", msg);
		goto decref_msg_ascii;
	}
	fname = PyBytes_AsString(fname_ascii);
	if ((slash = strrchr(fname, '/')) != NULL)
		fname = slash + 1;

	/* line number */
	line_no = PyObject_GetAttrString(trace, "tb_lineno");
	if (line_no == NULL) {
		snprintf(buf, len, "%s: (could not get lineno) %s", fname, msg);
		goto decref_fname_ascii;
	}
	if (!PyLong_Check(line_no)) {
		snprintf(buf, len, "%s: (lineno is not an integer) %s",
			 fname, msg);
		Py_DECREF(line_no);
		goto decref_fname_ascii;;
	}
	lineno = PyLong_AsLong(line_no);
	Py_DECREF(line_no);

	snprintf(buf, len, "%s[%ld]: %s", fname, lineno, msg);

decref_fname_ascii:
	Py_XDECREF(fname_ascii);
decref_msg_ascii:
	Py_XDECREF(msg_ascii);
decref:
	buf[len - 1] = '\0';
	Py_DECREF(type);
	Py_DECREF(value);
	Py_XDECREF(trace); /* may be NULL? */

	return buf;
}

static struct nlmsghdr *pack_nlmsg(void *buf, int len, const char *format, va_list ap)
{
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	void *p;
	char *s;
	size_t slen;
	int remains;

	while (*format != '\0') {
		remains = len - (int)nlh->nlmsg_len
			- MY_ATTR_ALIGN(sizeof(struct nlattr));
		switch (*format) {
		case 'B': /* byte */
			if (MY_ATTR_ALIGN(sizeof(uint8_t)) > remains) {
				errno = EOVERFLOW;
				return NULL;
			}

			/* gcc warning: 'uint8_t' is promoted
			 * to 'int' when passed through '...' */
			mnl_attr_put_u8(nlh, MNL_TYPE_U8,
					(uint8_t)va_arg(ap, int));
			break;
		case 'H': /* 2byte */
			if (MY_ATTR_ALIGN(sizeof(uint16_t)) > remains) {
				errno = EOVERFLOW;
				return NULL;
			}

			/* gcc warning: 'uint16_t' is promoted
			 * to 'int' when passed through '...' */
			mnl_attr_put_u16(nlh, MNL_TYPE_U16,
					 (uint16_t)va_arg(ap, int));
			break;
		case 'I': /* 4byte */
			if (MY_ATTR_ALIGN(sizeof(uint32_t)) > remains) {
				errno = EOVERFLOW;
				return NULL;
			}

			mnl_attr_put_u32(nlh, MNL_TYPE_U32,
					 va_arg(ap, uint32_t));
			break;
		case 'K': /* 8byte */
			if (MY_ATTR_ALIGN(sizeof(uint64_t)) > remains) {
				errno = EOVERFLOW;
				return NULL;
			}

			mnl_attr_put_u64(nlh, MNL_TYPE_U64,
					 va_arg(ap, uint64_t));
			break;
		case 'p': /* pointer */
			if (MY_ATTR_ALIGN(sizeof(void *)) > remains) {
				errno = EOVERFLOW;
				return NULL;
			}

			p = va_arg(ap, void *);
			mnl_attr_put(nlh, MNL_TYPE_BINARY, sizeof(void *), &p);
			break;
		case 'z': /* null string */
			s = va_arg(ap, char *);
			slen = strlen(s);
			if (MY_ATTR_ALIGN(slen + 1) > remains) {
				errno = EOVERFLOW;
				return NULL;
			}

			mnl_attr_put(nlh, MNL_TYPE_NUL_STRING, slen + 1, s);
			break;
		case 'y': /* bytes with size */
			format++;
			if (*format != '#') {
				errno = EINVAL;
				return NULL;
			}
			p = va_arg(ap, void *);
			slen = va_arg(ap, size_t);
			if (MY_ATTR_ALIGN(slen) > remains) {
				errno = EOVERFLOW;
				return NULL;
			}

			mnl_attr_put(nlh, MNL_TYPE_STRING, slen, p);
			break;
		default:
			errno = EINVAL;
			return NULL;

		}
		format++;
	}

	return nlh;
}

/* returns negative on error
 * or returns remainded nlmsghdr length */
static int _unpack_nlmsg(const struct nlmsghdr *nlh,
		  const char *format, va_list ap)
{
	struct nlattr *attr = mnl_nlmsg_get_payload(nlh);
	int remains = (int)mnl_nlmsg_get_payload_len(nlh);
	size_t len;
	uint16_t atype, alen;
	void *p;

	while (*format != '\0' ) {
		if (!mnl_attr_ok(attr, remains)) {
			errno = EOVERFLOW;
			return -1;
		}

		remains -= MY_NLATTR_HDRLEN;
		atype = mnl_attr_get_type(attr);
		alen = mnl_attr_get_payload_len(attr);

		switch (*format) {
		case 'B': /* byte */
			if (atype != MNL_TYPE_U8 ||
			    alen != sizeof(uint8_t)) {
				errno =EINVAL;
				return -1;
			}
			*(va_arg(ap, uint8_t *)) = mnl_attr_get_u8(attr);
			break;
		case 'H': /* 2byte */
			if (atype != MNL_TYPE_U16 ||
			    alen != sizeof(uint16_t)) {
				errno = EINVAL;
				return -1;
			}
			*(va_arg(ap, uint16_t *)) = mnl_attr_get_u16(attr);
			break;
		case 'I': /* 4byte */
			if (atype != MNL_TYPE_U32 ||
			    alen != sizeof(uint32_t)) {
				errno = EINVAL;
				return -1;
			}
			*(va_arg(ap, uint32_t *)) = mnl_attr_get_u32(attr);
			break;
		case 'K': /* 8byte */
			if (atype  != MNL_TYPE_U64 ||
			    alen != sizeof(uint64_t)) {
				errno = EINVAL;
				return -1;
			}
			*(va_arg(ap, uint64_t *)) = mnl_attr_get_u64(attr);
			break;
		case 'p': /* pointer */
			if (atype != MNL_TYPE_BINARY ||
			    alen != sizeof(void *)) {
				errno = EINVAL;
				return -1;
			}
			*(va_arg(ap, void **))
				= *((void **)mnl_attr_get_payload(attr));
			break;
		case 'z': /* null string */
			if (atype != MNL_TYPE_NUL_STRING) {
				errno = EINVAL;
				return -1;
			}
			p = va_arg(ap, void *);
			if (*(format + 1) == '#') {
				format++;
				len = va_arg(ap, size_t);
				if (alen > len) {
					errno = EINVAL;
					return -1;
				}
			}
			strncpy(p, mnl_attr_get_payload(attr), alen);
			break;
		case 'y': /* bytes with size */
			format++;
			if (*format != '#') {
				errno = EINVAL;
				return -1;
			}
			p = va_arg(ap, void *);
			len = va_arg(ap, size_t);
			if (alen > len)
				return -EINVAL;

			memcpy(p, mnl_attr_get_payload(attr), alen);
			break;
		default:
			errno =EINVAL;
			return -1;
		}
		remains -= MY_ATTR_ALIGN(alen);
		format++;
		attr = mnl_attr_next(attr);
	}

	if (remains) {
		errno = EMSGSIZE;
		nurs_log(NURS_NOTICE, "unpack remains: %d\n", remains);
	}
	return remains;
}

int unpack_nlmsg(const struct nlmsghdr *nlh, const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = _unpack_nlmsg(nlh, format, ap);
	va_end(ap);

	return ret;
}

static void put_unaligned_int(void *d, int x)
{
	memcpy(d, &x, sizeof(x));
}

/* suppose cdata is a file descriptor */
/* not return sent size, but success: 0 or failure: -1 */
static int py_send_nlmsg(int fd, struct nlmsghdr *nlh, int cdata)
{
	struct msghdr msg = {0};
	struct iovec iov;
	size_t cmsglen = CMSG_SPACE(sizeof(int));
	char control[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	ssize_t nsent;

	iov.iov_base = nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (cdata) {
		msg.msg_control = control;
		msg.msg_controllen = cmsglen;
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		put_unaligned_int(CMSG_DATA(cmsg), cdata);
	}

	nsent = sendmsg(fd, &msg, MSG_NOSIGNAL);
	if (nsent == -1)
		return -1;
	if (nsent != nlh->nlmsg_len) {
		errno = EMSGSIZE;
		return -1;
	}

	return 0;
}

static int get_unaligned_int(const void *s)
{
	int x;
	memcpy(&x, s, sizeof(x));
	return x;
}

ssize_t py_recv(int fd, void *buf, size_t len, int *cdata)
{
	struct msghdr msg = {0};
	struct iovec iov = {0};
	size_t cmsglen = CMSG_SPACE(sizeof(int));
	char control[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	ssize_t ret;

	iov.iov_base = buf;
	iov.iov_len = len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (cdata != NULL) {
		msg.msg_control = control;
		msg.msg_controllen = cmsglen;
	}

	ret = recvmsg(fd, &msg, 0);
	if (ret == -1 || cdata == NULL) {
		return ret;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || cmsg->cmsg_len != CMSG_LEN(sizeof(int))
	    || cmsg->cmsg_level != SOL_SOCKET
	    || cmsg->cmsg_type != SCM_RIGHTS) {
		*cdata = -1;
	} else {
		*cdata = get_unaligned_int(CMSG_DATA(cmsg));
	}

	return ret;
}

/* return 0 on success, -1 on error */
int py_sendf(int sockfd, uint16_t type, uint16_t flags,
	     int cdata, const char *format, va_list ap)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = pack_nlmsg(buf, (int)MNL_SOCKET_BUFFER_SIZE, format, ap);
	if (!nlh)
		return -1;

	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = flags;
	return py_send_nlmsg(sockfd, nlh, cdata);
}

/* return 0 on success, -1 on error */
int py_recvf(int sockfd, uint16_t type, uint16_t flags,
	     int *cdata, const char *format, va_list ap)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	ssize_t nrecv;
	int ret;

	nrecv = py_recv(sockfd, buf, sizeof(buf), cdata);
	if (nrecv < 0)
		return -1;

	ret = _unpack_nlmsg(nlh, format, ap);
	if (ret < 0)
		return -1;
	if (nlh->nlmsg_type != type || nlh->nlmsg_flags != flags) {
		nurs_log(NURS_ERROR, "---- type: %d, %d, flags: %d, %d\n",
			 type, nlh->nlmsg_type, flags, nlh->nlmsg_flags);
		errno = ENOMSG;
		return -1;
	}

	return 0;
}

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

#include <stdarg.h>

#include <libmnl/libmnl.h>

#include <nurs/nurs.h>
#include "pynurs.h"

extern char *pynurs_nlmsg_string[];
static int sockfd;
static const char *modname;
static pid_t mypid;

__attribute__ ((noreturn))
static void pycli_exit(int status, const char *format, ...)
{
	va_list ap;

	if (format) {
		va_start(ap, format);
		vfprintf(stderr, format, ap);
		va_end(ap);
	}
	/* Py_Finalize(); */
	_exit(status);
	/* NOTREACHED */
}

static int pycli_sendf(const char *src, uint16_t type, uint16_t flags,
		       int cdata, const char *format, ...)
{
	va_list ap;
	int ret;

	nurs_log(NURS_DEBUG, "%s[%d] sending: %s\n",
		 modname, mypid, pynurs_nlmsg_string[type]);
	va_start(ap, format);
	ret = py_sendf(sockfd, type, flags, cdata, format, ap);
	va_end(ap);
	if (ret) {
		shutdown(sockfd, SHUT_RDWR);
		pycli_exit(EXIT_FAILURE, "%s - failed to py_sendf: %s\n",
			   src, _sys_errlist[errno]);
	}

	return ret;
}

static int pycli_recvf(const char *src, uint16_t type, uint16_t flags,
		       int *cdata, const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = py_recvf(sockfd, type, flags, cdata, format, ap);
	va_end(ap);
	if (ret < 0) {
		shutdown(sockfd, SHUT_RDWR);
		pycli_exit(EXIT_FAILURE, "%s - failed to py_recvf: %s\n",
			   src, _sys_errlist[errno]);
	}

	return ret;
}

static int pycli_recv(void *buf, size_t len, int *cdata)
{
	ssize_t ret;

	ret = py_recv(sockfd, buf, len, cdata);
	if (ret < 0) {
		shutdown(sockfd, SHUT_RDWR);
		pycli_exit(EXIT_FAILURE, "failed to py_recv: %s\n",
			   _sys_errlist[errno]);
	}

	return (int)ret;
}

void __pycli_log(int level, char *file, int line, char *format, ...)
{
	va_list ap;
	char buf[MNL_SOCKET_BUFFER_SIZE], *b;
	int n;

	n = snprintf(buf, sizeof(buf), "%s(%d) ", modname, mypid);
	b = (char *)((uintptr_t)buf + (uintptr_t)n);
	va_start(ap, format);
	vsnprintf(b, sizeof(buf) - (size_t)n, format, ap);
	va_end(ap);

	pycli_sendf("nurs_log", NURS_PYIPC_T_REQ_LOG, NLM_F_REQUEST, 0,
		    "IzIz", level, file, line, buf);
}

void __pynurs_log(int level, char *file, int line, char *format, ...)
{
	va_list ap;
	char buf[MNL_SOCKET_BUFFER_SIZE];

	va_start(ap, format);
	vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);

	pycli_sendf("nurs_log", NURS_PYIPC_T_REQ_LOG, NLM_F_REQUEST, 0,
		    "IzIz", level, file, line, buf);
}

#define _talk_passive(_nlh, _tx, _retcb, _format, _args...) ({		\
	int _ret = 0;							\
	if (unpack_nlmsg(_nlh, _format, ## _args)) {			\
		pycli_log(NURS_ERROR, "failed to unpack: %s\n", _sys_errlist[errno]); \
		_ret = -1;						\
	} else {							\
		pycli_sendf(__func__, _tx, NLM_F_ACK, 0, "I", (_retcb)); \
	} _ret; })

static int pycli_start(struct nlmsghdr *nlh, int fd)
{
	struct nurs_plugin *plugin;

	return _talk_passive(nlh,
			     NURS_PYIPC_T_ACK_START,
			     py_start(plugin),
			     "p", &plugin);
}

static int pycli_producer_start(struct nlmsghdr *nlh, int fd)
{
	struct nurs_producer *producer;

	return _talk_passive(nlh,
			     NURS_PYIPC_T_ACK_PRODUCER_START,
			     py_producer_start(producer),
			     "p", &producer);
}

static int pycli_stop(struct nlmsghdr *nlh, int fd)
{
	struct nurs_plugin *plugin;

	return _talk_passive(nlh,
			     NURS_PYIPC_T_ACK_STOP,
			     py_stop(plugin),
			     "p", &plugin);
}

static int pycli_producer_stop(struct nlmsghdr *nlh, int fd)
{
	struct nurs_producer *producer;

	return _talk_passive(nlh,
			     NURS_PYIPC_T_ACK_PRODUCER_STOP,
			     py_producer_stop(producer),
			     "p", &producer);
}

static int pycli_signal(struct nlmsghdr *nlh, int fd)
{
	struct nurs_plugin *plugin;
	uint32_t signum;

	return _talk_passive(nlh,
			     NURS_PYIPC_T_ACK_SIGNAL,
			     py_signal(plugin, signum),
			     "pI", &plugin, &signum);

}

static int pycli_producer_signal(struct nlmsghdr *nlh, int fd)
{
	struct nurs_producer *producer;
	uint32_t signum;

	return _talk_passive(nlh,
			     NURS_PYIPC_T_ACK_PRODUCER_SIGNAL,
			     py_producer_signal(producer, signum),
			     "pI", &producer, &signum);
}

static int pycli_organize(struct nlmsghdr *nlh, int fd)
{
	struct nurs_plugin *plugin;
	enum nurs_return_t ret = NURS_RET_ERROR;
	int rc;

	rc = _talk_passive(nlh,
			   NURS_PYIPC_T_ACK_ORGANIZE,
			   ret = py_organize(plugin),
			   "p", &plugin);
	if (ret != NURS_RET_OK)
		pycli_exit(EXIT_FAILURE, NULL); /* "failed to organize\n" */

	return rc;
}

static int pycli_coveter_organize(struct nlmsghdr *nlh, int fd)
{
	struct nurs_plugin *plugin;
	struct nurs_input *input;
	enum nurs_return_t ret = NURS_RET_ERROR;
	int rc;

	rc = _talk_passive(nlh,
			   NURS_PYIPC_T_ACK_COVETER_ORGANIZE,
			   ret = py_coveter_organize(plugin, input),
			   "pp", &plugin, &input);
	if (ret != NURS_RET_OK)
		pycli_exit(EXIT_FAILURE, NULL); /* "failed to organize\n" */

	return rc;
}

static int pycli_producer_organize(struct nlmsghdr *nlh, int fd)
{
	struct nurs_producer *producer;
	enum nurs_return_t ret = NURS_RET_ERROR;
	int rc;

	rc = _talk_passive(nlh,
			   NURS_PYIPC_T_ACK_PRODUCER_ORGANIZE,
			   ret = py_producer_organize(producer),
			   "p", &producer);
	if (ret != NURS_RET_OK)
		pycli_exit(EXIT_FAILURE, NULL); /* "failed to organize\n" */

	return rc;
}

static int pycli_disorganize(struct nlmsghdr *nlh, int fd)
{
	struct nurs_plugin *plugin;
	int ret = _talk_passive(nlh,
				NURS_PYIPC_T_ACK_DISORGANIZE,
				py_disorganize(plugin),
				"p", &plugin);
	pycli_exit(EXIT_SUCCESS, NULL); /* "exit by disorganize\n" */
	/* NOTREACHED */
	return ret;
}

static int pycli_producer_disorganize(struct nlmsghdr *nlh, int fd)
{
	struct nurs_producer *producer;

	int ret = _talk_passive(nlh,
				NURS_PYIPC_T_ACK_PRODUCER_DISORGANIZE,
				py_producer_disorganize(producer),
				"p", &producer);
	pycli_exit(EXIT_SUCCESS, NULL); /* "exit by disorganize\n" */
	/* NOTREACHED */
	return ret;
}

static int pycli_filter_interp(struct nlmsghdr *nlh, int fd)
{
	struct nurs_plugin *plugin;
	struct nurs_input *input;
	struct nurs_output *output;

	return _talk_passive(nlh,
			     NURS_PYIPC_T_ACK_FILTER_INTERP,
			     py_filter_interp(plugin, input, output),
			     "ppp", &plugin, &input, &output);
}

static int pycli_consumer_interp(struct nlmsghdr *nlh, int fd)
{
	struct nurs_plugin *plugin;
	struct nurs_input *input;

	return _talk_passive(nlh,
			     NURS_PYIPC_T_ACK_CONSUMER_INTERP,
			     py_consumer_interp(plugin, input),
			     "pp", &plugin, &input);
}

static int pycli_fd_callback(struct nlmsghdr *nlh, int fd)
{
	struct pynurs_fd *nfd;
	uint16_t when;

	if (unpack_nlmsg(nlh, "pH", &nfd, &when)) {
		pycli_log(NURS_ERROR, "failed to unpack fd callback: %s\n",
			 _sys_errlist[errno]);
		return -1;
	}

	return pycli_sendf(__func__,
			   NURS_PYIPC_T_ACK_FD_CALLBACK, NLM_F_ACK,
			   0, "I", py_fd_callback(nfd, when));
}

struct py_nfd *pycli_fd_register(int fd, uint16_t when, struct pynurs_fd *data)
{
        struct py_nfd *pfd;

	pycli_sendf(__func__,
		    NURS_PYIPC_T_REQ_FD_REGISTER, NLM_F_REQUEST,
		    fd, "Bp", when, data);
	pycli_recvf(__func__,
		    NURS_PYIPC_T_ACK_FD_REGISTER, NLM_F_ACK,
		    NULL, "p", &pfd);

	return pfd;
}

int pycli_fd_unregister(struct py_nfd *pfd)
{
	int ret;

	pycli_sendf(__func__,
		    NURS_PYIPC_T_REQ_FD_UNREGISTER, NLM_F_REQUEST,
		    0, "p", pfd);
	pycli_recvf(__func__,
		    NURS_PYIPC_T_ACK_FD_UNREGISTER, NLM_F_ACK,
		    NULL, "I", &ret);

	return ret;
}

static int pycli_timer_callback(struct nlmsghdr *nlh, int fd)
{
	struct py_timer *ptimer;

	if (unpack_nlmsg(nlh, "p", &ptimer)) {
		pycli_log(NURS_ERROR, "failed to unpack timer callback: %s\n",
			  _sys_errlist[errno]);
		return -1;
	}
	return pycli_sendf(__func__,
			   NURS_PYIPC_T_ACK_FD_CALLBACK, NLM_F_ACK,
			   0, "I", ptimer->cb(ptimer->timer));
}

struct py_timer *
pycli_timer_register(time_t sc, struct pynurs_timer *data)
{
        struct py_timer *ptimer;

	pycli_sendf(__func__,
		    NURS_PYIPC_T_REQ_TIMER_REGISTER, NLM_F_REQUEST,
		    0, "Ip", sc, data);
	pycli_recvf(__func__,
		    NURS_PYIPC_T_ACK_TIMER_REGISTER, NLM_F_ACK,
		    NULL, "p", &ptimer);

	return ptimer;
}

struct py_timer *
pycli_itimer_register(time_t ini, time_t per, struct pynurs_timer *data)
{
        struct py_timer *ptimer;

	pycli_sendf(__func__,
		    NURS_PYIPC_T_REQ_ITIMER_REGISTER, NLM_F_REQUEST,
		    0, "IIp", ini, per, data);
	pycli_recvf(__func__,
		    NURS_PYIPC_T_ACK_ITIMER_REGISTER, NLM_F_ACK,
		    NULL, "I", &ptimer);

	return ptimer;
}

int pycli_timer_unregister(struct py_timer *ptimer)
{
	int ret;

	pycli_sendf(__func__,
		    NURS_PYIPC_T_REQ_TIMER_UNREGISTER, NLM_F_REQUEST,
		    0, "pI", ptimer);
	pycli_recvf(__func__,
		    NURS_PYIPC_T_ACK_TIMER_UNREGISTER, NLM_F_ACK,
		    NULL, "I", &ret);

	return ret;
}

int pycli_timer_pending(struct py_timer *ptimer)
{
	int ret;

	pycli_sendf(__func__,
		    NURS_PYIPC_T_REQ_TIMER_PENDING, NLM_F_REQUEST,
		    0, "p", ptimer);
	pycli_recvf(__func__,
		    NURS_PYIPC_T_ACK_TIMER_PENDING, NLM_F_ACK,
		    NULL, "I", &ret);

	return ret;
}

int pycli_publish(struct nurs_output *output)
{
	int ret;

	pycli_sendf(__func__,
		    NURS_PYIPC_T_REQ_PUBLISH, NLM_F_REQUEST,
		    0, "p", output);
	pycli_recvf(__func__,
		    NURS_PYIPC_T_ACK_PUBLISH, NLM_F_ACK,
		    NULL, "I", &ret);

	return ret;
}

struct nurs_output *pycli_get_output(struct nurs_producer *producer)
{
	struct nurs_output *output;

	pycli_sendf(__func__,
		    NURS_PYIPC_T_REQ_GET_OUTPUT, NLM_F_REQUEST,
		    0, "p", producer);
	pycli_recvf(__func__,
		    NURS_PYIPC_T_ACK_GET_OUTPUT, NLM_F_ACK,
		    NULL, "p", &output);

	return output;
}

int pycli_put_output(struct nurs_output *output)
{
	int ret;

	pycli_sendf(__func__,
		    NURS_PYIPC_T_REQ_PUT_OUTPUT, NLM_F_REQUEST,
		    0, "p", output);
	pycli_recvf(__func__,
		    NURS_PYIPC_T_ACK_PUT_OUTPUT, NLM_F_ACK,
		    NULL, "I", &ret);

	return ret;
}

/*
 * main
 */
static void pycli_undef_handler(int signum)
{
	pycli_log(NURS_ERROR, "receive unusal signal: %d\n", signum);
	/* seems to be required to SOCK_SEQPACKET to invalidate sockfd */
	shutdown(sockfd, SHUT_RDWR);
	signal(signum, SIG_DFL);
	kill(getpid(), signum);
}

static void pycli_set_sighandler(void)
{
	signal(SIGBUS, pycli_undef_handler);
	signal(SIGFPE, pycli_undef_handler);
	signal(SIGILL, pycli_undef_handler);
	signal(SIGSEGV, pycli_undef_handler);
	signal(SIGABRT, pycli_undef_handler);
}

static int pycli_append_path(const char *path)
{
	PyObject *sys_path, *str;
	char ebuf[ERRBUF_SIZE];
	char *apath, *bpath, *tok;
	int ret = 0;

	sys_path = PySys_GetObject("path");
	if (sys_path == NULL) {
		pycli_log(NURS_ERROR, "could not get sys.path\n");
		return -1;
	}
	if (!PyList_Check(sys_path)) {
		pycli_log(NURS_ERROR, "sys.path is not a list\n");
		return -1;
	}
	apath = bpath = strdup(path);
	while ((tok = strtok(apath, ":"))) {
		str = PyUnicode_FromString(apath);
		if (!str) {
			pycli_log(NURS_ERROR, "%s\n",
				  py_strerror(ebuf, ERRBUF_SIZE));
			ret = -1;
			break;
		}
		if (PyList_Append(sys_path, str) < 0) {
			pycli_log(NURS_ERROR, "%s\n",
				  py_strerror(ebuf, ERRBUF_SIZE));
			Py_DECREF(str);
			ret = -1;
			break;
		}
		Py_DECREF(str);
		apath = NULL;
	}
	free(bpath);

	return ret;

}

static int (*passive_funcs[NURS_PYIPC_T_REQ_MAX])(struct nlmsghdr *, int) = {
	[NURS_PYIPC_T_REQ_START]		= pycli_start,
	[NURS_PYIPC_T_REQ_PRODUCER_START]	= pycli_producer_start,
	[NURS_PYIPC_T_REQ_STOP]			= pycli_stop,
	[NURS_PYIPC_T_REQ_PRODUCER_STOP]	= pycli_producer_stop,
	[NURS_PYIPC_T_REQ_SIGNAL]		= pycli_signal,
	[NURS_PYIPC_T_REQ_PRODUCER_SIGNAL]	= pycli_producer_signal,
	[NURS_PYIPC_T_REQ_ORGANIZE]		= pycli_organize,
	[NURS_PYIPC_T_REQ_COVETER_ORGANIZE]	= pycli_coveter_organize,
	[NURS_PYIPC_T_REQ_PRODUCER_ORGANIZE]	= pycli_producer_organize,
	[NURS_PYIPC_T_REQ_DISORGANIZE]		= pycli_disorganize,
	[NURS_PYIPC_T_REQ_PRODUCER_DISORGANIZE]	= pycli_producer_disorganize,
	[NURS_PYIPC_T_REQ_FILTER_INTERP]	= pycli_filter_interp,
	[NURS_PYIPC_T_REQ_CONSUMER_INTERP]	= pycli_consumer_interp,
	[NURS_PYIPC_T_REQ_FD_CALLBACK]		= pycli_fd_callback,
	[NURS_PYIPC_T_REQ_TIMER_CALLBACK]	= pycli_timer_callback,
};

static enum nurs_return_t pycli_session(void)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	int (*fn)(struct nlmsghdr *, int);
	int fd;

	while (true) {
		if (pycli_recv(buf, sizeof(buf), &fd) < MY_NLMSG_HDRLEN) {
			pycli_log(NURS_ERROR, "failed to receive nlmsg\n");
			return NURS_RET_ERROR;
		}
		pycli_log(NURS_DEBUG, "received: %s\n",
			  pynurs_nlmsg_string[nlh->nlmsg_type]);

		if (nlh->nlmsg_type >= NURS_PYIPC_T_REQ_MAX ||
		    !(fn = passive_funcs[nlh->nlmsg_type])) {
			pycli_log(NURS_ERROR, "receive unknown msgtype: %d\n",
				  nlh->nlmsg_type);
		} else if (fn(nlh, fd)) {
			pycli_log(NURS_ERROR, "failed to cb - type: %s\n",
				  pynurs_nlmsg_string[nlh->nlmsg_type]);
		}
	}
	return NURS_RET_ERROR;
}

/* use nurs_log instead of pycli_log before sending ACK_INIT */
void pycli_init(int fd, const char *path, const char *name)
{
	sigset_t mask;

	modname = name;
	mypid = getpid();
	sockfd = fd;

	sigprocmask(SIG_BLOCK, NULL, &mask);
	Py_Initialize();
	pycli_set_sighandler();
	sigprocmask(SIG_BLOCK, &mask, NULL);

	if (path && pycli_append_path(path)) {
		nurs_log(NURS_ERROR, "failed to append sys.path: %s\n", path);
		pycli_sendf(__func__, NURS_PYIPC_T_ACK_INIT, NLM_F_ACK,
			    0, "I", -1);
		pycli_exit(EXIT_FAILURE, NULL);
		/* NOTREACHED */
	}

	if (py_init(name)) {
		nurs_log(NURS_ERROR, "failed to load module: %s\n", name);
		pycli_sendf(__func__, NURS_PYIPC_T_ACK_INIT, NLM_F_ACK,
			    0, "I", -1);
		pycli_exit(EXIT_FAILURE, NULL);
		/* NOTREACHED */
	}

	pycli_sendf(__func__, NURS_PYIPC_T_ACK_INIT, NLM_F_ACK,
		    0, "I", 0);

	pycli_session();
}

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
#include <linux/netlink.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libmnl/libmnl.h>
#include <jansson.h>

#include <nurs/nurs.h>
#include "pynurs.h"

extern char *pynurs_nlmsg_string[];

struct py_priv {
	pid_t childpid;
	int sockfd;
	const char *modname;
	int (*sendf)(struct py_priv *priv, uint16_t type, uint16_t flags,
		     int cdata, const char *format, ...);
	int (*recvf)(struct py_priv *priv, uint16_t type, uint16_t flags,
		     int *cdata, const char *format, ...);
};

#define svr_log(level, priv, format, args...)				\
	__nurs_log(level, __FILE__, __LINE__, "%s " format, priv->modname, ## args)

static enum nurs_return_t pysvr_session(struct py_priv *priv, uint16_t fin_type,
					const char *format, ...);

static int pysvr_waitpid(struct py_priv *priv, int option)
{
	int status;

	switch (waitpid(priv->childpid, &status, option)) {
	case -1:
		svr_log(NURS_ERROR, priv, "waitpid: %s\n",
			strerror(errno));
		break;
	case 0:
		/* WNOHANG was specified and the child exist
                 * but have not yet changed state */
		svr_log(NURS_INFO, priv, "child have not yet changed state\n");
		return -1;
	default:
		svr_log(NURS_INFO, priv, "child: %d has exited: %d\n",
			priv->childpid, WEXITSTATUS(status));
		priv->childpid = 0;
	}

	return 0;
}

static int pysvr_error_sendf(struct py_priv *priv, uint16_t type, uint16_t flags,
			     int cdata, const char *format, ...)
{
	svr_log(NURS_FATAL, priv, "no child\n");
	errno = ESRCH;
	return -1;
}

static int pysvr_error_recvf(struct py_priv *priv, uint16_t type, uint16_t flags,
			     int *cdata, const char *format, ...)
{
	svr_log(NURS_FATAL, priv, "no child\n");
	errno = ESRCH;
	return -1;
}

static int pysvr_sendf(struct py_priv *priv, uint16_t type, uint16_t flags,
		       int cdata, const char *format, ...)
{
	va_list ap;
	int ret;

	svr_log(NURS_DEBUG, priv, "sending: %s\n", pynurs_nlmsg_string[type]);

	va_start(ap, format);
	ret = py_sendf(priv->sockfd, type, flags, cdata, format, ap);
	va_end(ap);
	if (ret != 0) {
		svr_log(NURS_ERROR, priv, "failed to pysvr_sendf: %s\n",
			strerror(errno));
		pysvr_waitpid(priv, 0); /* WNOHANG */
		close(priv->sockfd);
		priv->sockfd = -1;
		priv->sendf = pysvr_error_sendf;
		priv->recvf = pysvr_error_recvf;
	}

	return ret;
}

static int _pysvr_recvf(struct py_priv *priv, uint16_t type, uint16_t flags,
			int *cdata, const char *format, va_list ap)
{
	int ret = py_recvf(priv->sockfd, type, flags, cdata, format, ap);
	if (ret < 0) {
		svr_log(NURS_ERROR, priv, "failed to recvf: %s(%d)\n",
			strerror(errno), errno);
		pysvr_waitpid(priv, 0); /* WNOHANG */
		close(priv->sockfd);
		priv->sockfd = -1;
		priv->sendf = pysvr_error_sendf;
		priv->recvf = pysvr_error_recvf;
	}
	return ret;
}

static int pysvr_recvf(struct py_priv *priv, uint16_t type, uint16_t flags,
		       int *cdata, const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = _pysvr_recvf(priv, type, flags, cdata, format, ap);
	va_end(ap);

	return ret;
}

static int pysvr_recv(struct py_priv *priv, void *buf, size_t len, int *cdata)
{
	ssize_t ret;

	ret = py_recv(priv->sockfd, buf, len, cdata);
	/* ret == 0 means client shutdown the socket */
	if (ret <= 0) {
		if (ret < 0)
			svr_log(NURS_ERROR, priv, "failed to pysvr_recv: %s\n",
				strerror(errno));
		pysvr_waitpid(priv, 0); /* WNOHANG */
		close(priv->sockfd);
		priv->sockfd = -1;
		priv->sendf = pysvr_error_sendf;
		priv->recvf = pysvr_error_recvf;
	}

	return (int)ret;
}

/*
 * log
 */
static int pysvr_log(struct py_priv *priv, struct nlmsghdr *nlh, int fd)
{
	uint32_t level, line;
	char fname[MNL_SOCKET_BUFFER_SIZE];
	char buf[MNL_SOCKET_BUFFER_SIZE];

	if (unpack_nlmsg(nlh, "IzIz", &level, fname, &line, buf)) {
		svr_log(NURS_ERROR, priv, "failed to unpack log: %s\n",
			_sys_errlist[errno]);
		return 0;
	}
	nurs_flog((int)level, fname, (int)line, "%s", buf);
	return 0;
}

#define _talk_active(_ctx, _tx, _rx, _fd, _format, _args...) ({		\
	struct py_priv *_p = _ctx;					\
	enum nurs_return_t _r1, _r2 = NURS_RET_OK;			\
	if (_p->sendf(_p, _tx, NLM_F_REQUEST,				\
			_fd, _format, ## _args)) {			\
		svr_log(NURS_ERROR, _p, "%s - failed to sendf: %s\n",	\
			__func__, _sys_errlist[errno]);			\
		_r1 = NURS_RET_ERROR;					\
	} else {							\
		_r1 = pysvr_session(_p, _rx, "I", &_r2);		\
		if (!_r1) _r1 = _r2;					\
	}								\
	_r1; })

/*
 * plugin callback
 */
static enum nurs_return_t
pysvr_start(const struct nurs_plugin *plugin)
{
	return _talk_active(nurs_plugin_context(plugin),
			    NURS_PYIPC_T_REQ_START,
			    NURS_PYIPC_T_ACK_START,
			    0, "p", plugin);
}

static enum nurs_return_t
pysvr_producer_start(struct nurs_producer *producer)
{
	return _talk_active(nurs_producer_context(producer),
			    NURS_PYIPC_T_REQ_PRODUCER_START,
			    NURS_PYIPC_T_ACK_PRODUCER_START,
			    0, "p", producer);
}

static enum nurs_return_t
pysvr_stop(const struct nurs_plugin *plugin)
{
	return _talk_active(nurs_plugin_context(plugin),
			    NURS_PYIPC_T_REQ_STOP,
			    NURS_PYIPC_T_ACK_STOP,
			    0, "p", plugin);
}

static enum nurs_return_t
pysvr_producer_stop(struct nurs_producer *producer)
{
	return _talk_active(nurs_producer_context(producer),
			    NURS_PYIPC_T_REQ_PRODUCER_STOP,
			    NURS_PYIPC_T_ACK_PRODUCER_STOP,
			    0, "p", producer);
}

static enum nurs_return_t
pysvr_signal(const struct nurs_plugin *plugin, uint32_t signum)
{
	return _talk_active(nurs_plugin_context(plugin),
			    NURS_PYIPC_T_REQ_SIGNAL,
			    NURS_PYIPC_T_ACK_SIGNAL,
			    0, "pI", plugin, signum);
}

static enum nurs_return_t
pysvr_producer_signal(struct nurs_producer *producer, uint32_t signum)
{
	return _talk_active(nurs_producer_context(producer),
			    NURS_PYIPC_T_REQ_PRODUCER_SIGNAL,
			    NURS_PYIPC_T_ACK_PRODUCER_SIGNAL,
			    0, "pI", producer, signum);
}

static int create_child(struct py_priv *priv, const struct nurs_config *config)
{
	int sv[2], ret;
	uint8_t path_idx, modname_idx;
	const char *path = NULL;

	errno = 0;
	modname_idx = nurs_config_index(config, "module");
	if (!modname_idx && errno) {
		nurs_log(NURS_ERROR, "no module specified\n");
		return -1;
	}
	priv->modname = nurs_config_string(config, modname_idx);

	errno = 0;
	path_idx = nurs_config_index(config, "path");
	if (!errno) {
		path = nurs_config_string(config, path_idx);
		svr_log(NURS_DEBUG, priv, "appending path: %s\n", path);
	}

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == -1) {
		priv->sockfd = -1;
		svr_log(NURS_ERROR, priv, "socketpair: %s\n", strerror(errno));
		return -1;
	}
	priv->sockfd = sv[0];
	priv->childpid = fork();
	switch (priv->childpid) {
	case -1:
		svr_log(NURS_ERROR, priv, "fork: %s\n", strerror(errno));
		close(sv[0]);
		close(sv[1]);
		priv->sockfd = -1;
		return -1;
	case 0:
		pycli_init(sv[1], path, priv->modname);
		/* NOTREACHED */
		break;
	default:
		svr_log(NURS_INFO, priv, "child pid: %d\n", priv->childpid);
		break;
	}

	priv->sendf = pysvr_sendf;
	priv->recvf = pysvr_recvf;

	/* receive pycli_init retval */
	if (priv->recvf(priv, NURS_PYIPC_T_ACK_INIT, NLM_F_ACK, 0, "I", &ret) ||
	    ret) {
		svr_log(NURS_ERROR, priv, "failed to init child\n");
		pysvr_waitpid(priv, 0); /* WNOHANG */
		close(priv->sockfd);
		priv->sockfd = -1;
		priv->sendf = pysvr_error_sendf;
		priv->recvf = pysvr_error_recvf;
		return -1;
	}

	return 0;
}

static enum nurs_return_t
pysvr_organize(const struct nurs_plugin *plugin)
{
	const struct nurs_config *config = nurs_plugin_config(plugin);
	struct py_priv *priv = nurs_plugin_context(plugin);

	if (create_child(priv, config)) {
		svr_log(NURS_ERROR, priv, "failed to create child: %s\n",
			strerror(errno));
		return NURS_RET_ERROR;
	}

	return _talk_active(nurs_plugin_context(plugin),
			    NURS_PYIPC_T_REQ_ORGANIZE,
			    NURS_PYIPC_T_ACK_ORGANIZE,
			    0, "p", plugin);
}

static enum nurs_return_t
pysvr_coveter_organize(const struct nurs_plugin *plugin,
		       const struct nurs_input *input)
{
	const struct nurs_config *config = nurs_plugin_config(plugin);
	struct py_priv *priv = nurs_plugin_context(plugin);

	if (create_child(priv, config)) {
		svr_log(NURS_ERROR, priv, "failed to create child: %s\n",
			 _sys_errlist[errno]);
		return NURS_RET_ERROR;
	}

	return _talk_active(nurs_plugin_context(plugin),
			    NURS_PYIPC_T_REQ_COVETER_ORGANIZE,
			    NURS_PYIPC_T_ACK_COVETER_ORGANIZE,
			    0, "p", plugin, input);
}

static enum nurs_return_t
pysvr_producer_organize(struct nurs_producer *producer)
{
	const struct nurs_config *config = nurs_producer_config(producer);
	struct py_priv *priv = nurs_producer_context(producer);

	if (create_child(priv, config)) {
		svr_log(NURS_ERROR, priv, "failed to create child: %s\n",
			 _sys_errlist[errno]);
		return NURS_RET_ERROR;
	}

	return _talk_active(nurs_producer_context(producer),
			    NURS_PYIPC_T_REQ_PRODUCER_ORGANIZE,
			    NURS_PYIPC_T_ACK_PRODUCER_ORGANIZE,
			    0, "p", producer);
}

static enum nurs_return_t
pysvr_disorganize(const struct nurs_plugin *plugin)
{
	struct py_priv *priv = nurs_plugin_context(plugin); /* not use priv */
	enum nurs_return_t ret
		=  _talk_active(priv,
				NURS_PYIPC_T_REQ_DISORGANIZE,
				NURS_PYIPC_T_ACK_DISORGANIZE,
				0, "p", plugin);

	if (priv->sockfd != -1)
		pysvr_waitpid(priv, 0);

	return ret;
}

static enum nurs_return_t
pysvr_producer_disorganize(struct nurs_producer *producer)
{
	struct py_priv *priv = nurs_producer_context(producer);
	enum nurs_return_t ret
		= _talk_active(priv,
			       NURS_PYIPC_T_REQ_PRODUCER_DISORGANIZE,
			       NURS_PYIPC_T_ACK_PRODUCER_DISORGANIZE,
			       0, "p", producer);

	if (priv->sockfd != -1)
		pysvr_waitpid(priv, 0);

	return ret;
}

static enum nurs_return_t
pysvr_filter_interp(const struct nurs_plugin *plugin,
		    const struct nurs_input *input, struct nurs_output *output)
{
	return _talk_active(nurs_plugin_context(plugin),
			    NURS_PYIPC_T_REQ_FILTER_INTERP,
			    NURS_PYIPC_T_ACK_FILTER_INTERP,
			    0, "ppp", plugin, input, output);
}

static enum nurs_return_t
pysvr_consumer_interp(const struct nurs_plugin *plugin,
		      const struct nurs_input *input)
{
	return _talk_active(nurs_plugin_context(plugin),
			    NURS_PYIPC_T_REQ_CONSUMER_INTERP,
			    NURS_PYIPC_T_ACK_CONSUMER_INTERP,
			    0, "pp", plugin, input);
}

/*
 * fd
 */
static enum nurs_return_t
pysvr_fd_callback(int fd, uint16_t when, void *data)
{
	struct py_nfd *pfd = data;
	return _talk_active(pfd->priv,
			    NURS_PYIPC_T_REQ_FD_CALLBACK,
			    NURS_PYIPC_T_ACK_FD_CALLBACK,
			    fd, "Hp", when, pfd->data);
}

static int pysvr_fd_create(struct py_priv *priv, struct nlmsghdr *nlh, int fd)
{
	struct py_nfd *pfd;
	int ret;
	uint16_t when;

	if (unpack_nlmsg(nlh, "B", &when)) {
		svr_log(NURS_ERROR, priv, "failed to unpack fd_create: %s\n",
			_sys_errlist[errno]);
		return -1;
	}

	pfd = calloc(1, sizeof(struct py_nfd));
	if (!pfd) {
		svr_log(NURS_ERROR, priv, "failed to alloc fd for python: %s\n",
			_sys_errlist[errno]);
		goto sendf;
	}

	pfd->priv = priv;
	pfd->nfd = nurs_fd_create(fd, when);
	if (!pfd->nfd) {
		free(pfd);
		pfd = NULL;
	}

sendf:
	ret = priv->sendf(priv, NURS_PYIPC_T_ACK_FD_CREATE, NLM_F_ACK,
			  0, "p", pfd);
	if (ret && pfd) {
		nurs_fd_destroy(pfd->nfd);
		free(pfd);
		pfd = NULL;
	}

	return ret;
}

static int pysvr_fd_destroy(struct py_priv *priv, struct nlmsghdr *nlh, int fd)
{
	struct py_nfd *pfd;

	if (unpack_nlmsg(nlh, "p", &pfd)) {
		svr_log(NURS_ERROR, priv, "failed to unpack fd_destroy: %s\n",
			_sys_errlist[errno]);
		return -1;
	}

	if (pfd) {
		nurs_fd_destroy(pfd->nfd);
		free(pfd);
	}

	return 0;
}

static int pysvr_fd_register(struct py_priv *priv, struct nlmsghdr *nlh, int fd)
{
	struct py_nfd *pfd;
	void *data;
	enum nurs_return_t ret = NURS_RET_ERROR;

	if (unpack_nlmsg(nlh, "pp", &pfd, &data)) {
		svr_log(NURS_ERROR, priv, "failed to unpack fd_register: %s\n",
			_sys_errlist[errno]);
		return -1;
	}

	if (pfd) {
		ret = nurs_fd_register(pfd->nfd, pysvr_fd_callback, pfd);
		if (!ret) {
			pfd->priv = priv;
			pfd->data = data;
		}
	}
	return priv->sendf(priv, NURS_PYIPC_T_ACK_FD_REGISTER, NLM_F_ACK,
			   0, "I", ret);
}

static int pysvr_fd_unregister(struct py_priv *priv, struct nlmsghdr *nlh, int fd)
{
	struct py_nfd *pfd;

	if (unpack_nlmsg(nlh, "p", &pfd)) {
		svr_log(NURS_ERROR, priv, "failed to unpack fd unregister: %s\n",
			_sys_errlist[errno]);
		return -1;
	}

	return priv->sendf(priv, NURS_PYIPC_T_ACK_FD_UNREGISTER, NLM_F_ACK,
			   0, "I", nurs_fd_unregister(pfd->nfd));
}

static enum nurs_return_t
pysvr_timer_callback(struct nurs_timer *timer, void *data)
{
	struct py_timer *ptimer = data;

	return _talk_active(ptimer->priv,
			    NURS_PYIPC_T_REQ_TIMER_CALLBACK,
			    NURS_PYIPC_T_ACK_TIMER_CALLBACK,
			    0, "p", ptimer);
}

static int pysvr_timer_create(struct py_priv *priv, struct nlmsghdr *nlh, int fd)
{
	struct py_timer *ptimer;
	nurs_timer_cb_t timer_cb;
	void *data;
	int ret;

	if (unpack_nlmsg(nlh, "pp", &timer_cb, &data)) {
		svr_log(NURS_ERROR, priv, "failed to unpack timer create: %d\n",
			_sys_errlist[errno]);
		return -1;
	}

	ptimer = calloc(1, sizeof(struct py_timer));
	if (!ptimer) {
		svr_log(NURS_ERROR, priv,
			"failed to alloc timer for python: %s\n",
			_sys_errlist[errno]);
		goto sendf;
	}
	ptimer->priv = priv;
	ptimer->timer = nurs_timer_create(pysvr_timer_callback, ptimer);
	if (!ptimer->timer) {
		free(ptimer);
		ptimer = NULL;
	}
sendf:
	ret = priv->sendf(priv, NURS_PYIPC_T_ACK_TIMER_CREATE, NLM_F_ACK,
			  0, "p", ptimer);
	if (ret && ptimer) {
		nurs_timer_destroy(ptimer->timer);
		free(ptimer);
	}
	return ret;
}

static int pysvr_timer_destroy(struct py_priv *priv, struct nlmsghdr *nlh, int fd)
{
	struct py_timer *ptimer;
	int ret;

	if (unpack_nlmsg(nlh, "p", &ptimer)) {
		svr_log(NURS_ERROR, priv,
			"failed to unpack timer destroy: %s\n",
			_sys_errlist[errno]);
		return -1;
	}

	ret = nurs_timer_destroy(ptimer->timer);
	free(ptimer);

	return priv->sendf(priv, NURS_PYIPC_T_ACK_TIMER_DESTROY, NLM_F_ACK,
			   0, "I", ret);
}

static int pysvr_timer_add(struct py_priv *priv, struct nlmsghdr *nlh, int fd)
{
	struct py_timer *ptimer;
	time_t sc; /* XXX: as 32bit */

	if (unpack_nlmsg(nlh, "pI", &ptimer, &sc)) {
		svr_log(NURS_ERROR, priv, "failed to unpack timer add: %s\n",
			_sys_errlist[errno]);
		return -1;
	}

	return priv->sendf(priv, NURS_PYIPC_T_ACK_TIMER_ADD, NLM_F_ACK,
			   0, "I", nurs_timer_add(ptimer->timer, sc));
}

static int pysvr_itimer_add(struct py_priv *priv, struct nlmsghdr *nlh, int fd)
{
	struct py_timer *ptimer;
	time_t ini, sc; /* XXX: as 32bit */

	if (unpack_nlmsg(nlh, "pII", &ptimer, &ini, &sc)) {
		svr_log(NURS_ERROR, priv, "failed to unpack itimer add: %s\n",
			_sys_errlist[errno]);
		return -1;
	}

	return priv->sendf(priv, NURS_PYIPC_T_ACK_ITIMER_ADD, NLM_F_ACK,
			   0, "I", nurs_itimer_add(ptimer->timer, ini, sc));
}

static int pysvr_timer_del(struct py_priv *priv, struct nlmsghdr *nlh, int fd)
{
	struct py_timer *ptimer;

	if (unpack_nlmsg(nlh, "p", &ptimer)) {
		svr_log(NURS_ERROR, priv, "failed to unpack timer del: %s\n",
			_sys_errlist[errno]);
		return -1;
	}

	return priv->sendf(priv, NURS_PYIPC_T_ACK_TIMER_DEL, NLM_F_ACK,
			   0, "I", nurs_timer_del(ptimer->timer));
}

static int pysvr_timer_pending(struct py_priv *priv, struct nlmsghdr *nlh, int fd)
{
	struct py_timer *ptimer;

	if (unpack_nlmsg(nlh, "p", &ptimer)) {
		svr_log(NURS_ERROR, priv,
			"failed to unpack timer pending: %s\n",
			_sys_errlist[errno]);
		return -1;
	}

	return priv->sendf(priv, NURS_PYIPC_T_ACK_TIMER_PENDING, NLM_F_ACK,
			   0, "I", nurs_timer_pending(ptimer->timer));
}

static int pysvr_publish(struct py_priv *priv, struct nlmsghdr *nlh, int fd)
{
	struct nurs_output *output;
	int ret, rc;

	if (unpack_nlmsg(nlh, "p", &output)) {
		svr_log(NURS_ERROR, priv, "failed to unpack publish: %s\n",
			_sys_errlist[errno]);
		return -1;
	}

	rc = nurs_publish(output);
	ret = priv->sendf(priv, NURS_PYIPC_T_ACK_PUBLISH, NLM_F_ACK,
			  0, "I", rc);

	return ret;
}

static int pysvr_get_output(struct py_priv *priv, struct nlmsghdr *nlh, int fd)
{
	struct nurs_producer *producer;
	struct nurs_output *output;

	if (unpack_nlmsg(nlh, "p", &producer)) {
		svr_log(NURS_ERROR, priv, "failed to unpack get output: %s\n",
			_sys_errlist[errno]);
		return -1;
	}

	output = nurs_get_output(producer);
	return priv->sendf(priv, NURS_PYIPC_T_ACK_GET_OUTPUT, NLM_F_ACK,
			   0, "p", output);
}

static int pysvr_put_output(struct py_priv *priv, struct nlmsghdr *nlh, int fd)
{
	struct nurs_output *output;

	if (unpack_nlmsg(nlh, "p", &output)) {
		svr_log(NURS_ERROR, priv, "failed to unpack put producer: %s\n",
			_sys_errlist[errno]);
		return -1;
	}

	return priv->sendf(priv, NURS_PYIPC_T_ACK_PUT_OUTPUT, NLM_F_ACK,
			   0, "I", nurs_put_output(output));
}

static int (*passive_funcs[NURS_PYIPC_T_REQ_MAX])
	(struct py_priv *, struct nlmsghdr *, int)  = {
	[NURS_PYIPC_T_REQ_LOG]			= pysvr_log,
	[NURS_PYIPC_T_REQ_FD_CREATE]		= pysvr_fd_create,
	[NURS_PYIPC_T_REQ_FD_DESTROY]		= pysvr_fd_destroy,
	[NURS_PYIPC_T_REQ_FD_REGISTER]		= pysvr_fd_register,
	[NURS_PYIPC_T_REQ_FD_UNREGISTER]		= pysvr_fd_unregister,
	[NURS_PYIPC_T_REQ_TIMER_CREATE]		= pysvr_timer_create,
	[NURS_PYIPC_T_REQ_TIMER_DESTROY]	= pysvr_timer_destroy,
	[NURS_PYIPC_T_REQ_TIMER_ADD]		= pysvr_timer_add,
	[NURS_PYIPC_T_REQ_ITIMER_ADD]		= pysvr_itimer_add,
	[NURS_PYIPC_T_REQ_TIMER_DEL]		= pysvr_timer_del,
	[NURS_PYIPC_T_REQ_TIMER_PENDING]	= pysvr_timer_pending,
	[NURS_PYIPC_T_REQ_PUBLISH]		= pysvr_publish,
	[NURS_PYIPC_T_REQ_GET_OUTPUT]		= pysvr_get_output,
	[NURS_PYIPC_T_REQ_PUT_OUTPUT]		= pysvr_put_output,
};

/* handle message until receiving specified by fin_type */
static enum nurs_return_t pysvr_session(struct py_priv *priv, uint16_t fin_type,
					const char *format, ...)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	int (*fn)(struct py_priv *, struct nlmsghdr *, int);
	ssize_t nrecv;
	enum nurs_return_t ret;
	int fd;

	while (true) {
		memset(buf, 0, sizeof(buf));
		nrecv = pysvr_recv(priv, buf, sizeof(buf), &fd);
		if (nrecv < MY_NLMSG_HDRLEN) {
			svr_log(NURS_ERROR, priv, "failed to receive - type: %d"
				", size: %d\n", nlh->nlmsg_type, nrecv);
			/* XXX: release resources */
			return NURS_RET_ERROR;
		}
		svr_log(NURS_DEBUG, priv, "received: %s\n",
			pynurs_nlmsg_string[nlh->nlmsg_type]);

		if (nlh->nlmsg_type == fin_type) {
			if (nlh->nlmsg_flags != NLM_F_ACK) {
				svr_log(NURS_ERROR, priv,
					"response with invalid flag\n");
				return NURS_RET_ERROR;
			}
			if (unpack_nlmsg(nlh, "I", &ret)) {
				svr_log(NURS_ERROR, priv,
					"failed to unpack response\n");
				return NURS_RET_ERROR;
			}
			switch (ret) {
			case NURS_RET_OK:
			case NURS_RET_STOP:
			case NURS_RET_ERROR:
				return ret;
			default:
				return NURS_RET_ERROR;
			}
			return NURS_RET_ERROR;
		}

		if (nlh->nlmsg_type >= NURS_PYIPC_T_REQ_MAX ||
		    !(fn = passive_funcs[nlh->nlmsg_type])) {
			svr_log(NURS_ERROR, priv,
				"receive unknown msgtype: %d\n",
				nlh->nlmsg_type);
		} else if (fn(priv, nlh, fd)) {
			svr_log(NURS_ERROR, priv, "failed to cb - type: %d\n",
				nlh->nlmsg_type);
		}
	}
	return NURS_RET_ERROR;
}

/*
 * init
 */
void __attribute__ ((constructor)) init(void);

char *json_names[] = {
	"producer", "filter", "consumer", "coveter", NULL,
};

static struct nurs_config_def py_config = {
	.len		= PY_CONFIG_MAX,
	.keys	= {
		[PY_CONFIG_PATH]	= {
			.name	= "path",
			.type	= NURS_CONFIG_T_STRING,
		},
		[PY_CONFIG_MODULE]	= {
			.name	= "module",
			.type	= NURS_CONFIG_T_STRING,
			.flags	= NURS_CONFIG_F_MANDATORY,
		},
	},
};

static int register_producer(json_t *json)
{
	struct nurs_producer_def *producer
		= nurs_producer_register_json(json, 0, false);

	if (!producer)
		return -1;

	producer->resolve_callback = false;
	producer->context_size = sizeof(struct py_priv);
	if (!producer->config_def || !producer->config_def->len)
		producer->config_def = &py_config;
	producer->organize = pysvr_producer_organize;
	producer->disorganize = pysvr_producer_disorganize;
	producer->start = pysvr_producer_start;
	producer->stop = pysvr_producer_stop;
	producer->signal = pysvr_producer_signal;

	return nurs_producer_register(producer);
}

static int register_filter(json_t *json)
{
	struct nurs_filter_def *filter
		= nurs_filter_register_json(json, 0, false);
	if (!filter)
		return -1;

	filter->resolve_callback = false;
	filter->context_size = sizeof(struct py_priv);
	if (!filter->config_def || !filter->config_def->len)
		filter->config_def = &py_config;

	filter->organize = pysvr_organize;
	filter->disorganize = pysvr_disorganize;
	filter->start = pysvr_start;
	filter->stop = pysvr_stop;
	filter->signal = pysvr_signal;
	filter->interp = pysvr_filter_interp;

	return nurs_filter_register(filter);
}

static int register_consumer(json_t *json)
{
	struct nurs_consumer_def *consumer
		= nurs_consumer_register_json(json, 0, false);

	if (!consumer)
		return -1;

	consumer->resolve_callback = false;
	consumer->context_size = sizeof(struct py_priv);
	if (!consumer->config_def || !consumer->config_def->len)
		consumer->config_def = &py_config;

	consumer->organize = pysvr_organize;
	consumer->disorganize = pysvr_disorganize;
	consumer->start = pysvr_start;
	consumer->stop = pysvr_stop;
	consumer->signal = pysvr_signal;
	consumer->interp = pysvr_consumer_interp;

	return nurs_consumer_register(consumer);
}

static int register_coveter(json_t *json)
{
	struct nurs_coveter_def *coveter
		= nurs_coveter_register_json(json, 0, false);

	if (!coveter)
		return -1;

	coveter->resolve_callback = false;
	coveter->context_size = sizeof(struct py_priv);
	if (!coveter->config_def || !coveter->config_def->len)
		coveter->config_def = &py_config;

	coveter->organize = pysvr_coveter_organize;
	coveter->disorganize = pysvr_disorganize;
	coveter->start = pysvr_start;
	coveter->stop = pysvr_stop;
	coveter->signal = pysvr_signal;
	coveter->interp = pysvr_consumer_interp;

	return nurs_coveter_register(coveter);
}

static int register_by_json(const char *jfname)
{
	json_t *root, *object, *array;
	json_error_t error;
	size_t index;
	char **name;
	int ret = -1;

	root = json_load_file(jfname, JSON_REJECT_DUPLICATES, &error);
	if (!root) {
		nurs_log(NURS_ERROR, "failed to read json file: %s,"
			 " error on line %d: %s\n",
			 jfname, error.line, error.text);
		return ret;
	}

	if (!json_is_object(root)) {
		nurs_log(NURS_ERROR, "not a json object(dictionary)\n");
		goto decref;
	}

	for (name = json_names; *name; name++) {
		array = json_object_get(root, *name);
		if (!array)
			continue;

		if (!json_is_array(array)) {
			nurs_log(NURS_ERROR, "%s is not an array\n",
				 *name);
			goto decref;
		}
		json_array_foreach(array, index, object) {
			if (!json_is_object(object)) {
				nurs_log(NURS_ERROR, "not an json object -"
					 " %s[%d]\n", *name, index);
				goto decref;
			}

			if (!strcmp(*name, "producer")) {
				if (register_producer(object)) {
					nurs_log(NURS_ERROR, "failed to register"
						 " producer: %s\n",
						 strerror(errno));
					goto decref;
				}
			} else if (!strcmp(*name, "filter")) {
				if (register_filter(object)) {
					nurs_log(NURS_ERROR, "failed to register"
						 " filter% %s\n",
						 strerror(errno));
					goto decref;
				}
			} else if (!strcmp(*name, "consumer")) {
				if (register_consumer(object)) {
					nurs_log(NURS_ERROR, "failed to register"
						 " consumer: %s\n",
						 strerror(errno));
					goto decref;
				}
			} else if (!strcmp(*name, "coveter")) {
				if (register_coveter(object)) {
					nurs_log(NURS_ERROR, "failed to register"
						 " coveter: %s\n",
						 strerror(errno));
					goto decref;
				}
			} else {
				nurs_log(NURS_ERROR,
					 "unknown plugin type: %s\n", *name);
				goto decref;
			}
		}
	}
	ret = 0;
decref:
	json_decref(root);
	return ret;
}

void init(void)
{
	char *jsonenv = getenv(JSON_ENV_NAME);
	char *jfname;

	if (!jsonenv) {
		nurs_log(NURS_ERROR, "require NURS_PYTON env var\n");
		return;
	}

	jfname = strdup(jsonenv);
	if (!jfname) {
		nurs_log(NURS_ERROR, "failed to alloc: %s\n", strerror(errno));
		return;
	}

	jfname = strtok(jfname, ":");
	do {
		if (register_by_json(jfname)) {
			nurs_log(NURS_ERROR, "failed to regist %s\n", jfname);
			break;
		}
		jfname = strtok(NULL, ":");
	} while (jfname);

	free(jfname);
}

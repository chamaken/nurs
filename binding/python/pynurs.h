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
#ifndef PYNURS_H
#define PYNURS_H

#include <Python.h>

#include <linux/netlink.h>
#include <nurs/nurs.h>

#define JSON_ENV_NAME "NURS_PYSON"

enum py_config {
	PY_CONFIG_PATH,
	PY_CONFIG_MODULE,
	PY_CONFIG_MAX,
};

enum pynus_nlmsg_type {
	NURS_PYIPC_T_NONE,			/* */

	NURS_PYIPC_T_REQ_LOG,			/* c>p nurs_log */

	NURS_PYIPC_T_REQ_START,			/* p>c nurs_start_t */
	NURS_PYIPC_T_REQ_PRODUCER_START,	/* p>c nurs_producer_start_t */
	NURS_PYIPC_T_REQ_STOP,			/* p>c nurs_stop_t */
	NURS_PYIPC_T_REQ_PRODUCER_STOP,		/* p>c nurs_producer_stop_t */
	NURS_PYIPC_T_REQ_SIGNAL,		/* p>c nurs_signal_t */
	NURS_PYIPC_T_REQ_PRODUCER_SIGNAL,	/* p>c nurs_producer_signal_t */
	NURS_PYIPC_T_REQ_ORGANIZE,		/* p>c nurs_organize_t */
	NURS_PYIPC_T_REQ_COVETER_ORGANIZE,	/* p>c nurs_coveter_organize_t */
	NURS_PYIPC_T_REQ_PRODUCER_ORGANIZE,	/* p>c nurs_producer_organize_t */
	NURS_PYIPC_T_REQ_DISORGANIZE,		/* p>c nurs_disorganize_t */
	NURS_PYIPC_T_REQ_PRODUCER_DISORGANIZE,	/* p>c nurs_producer_disorganize_t */
	NURS_PYIPC_T_REQ_FILTER_INTERP,		/* p>c nurs_filter_interp_t */
	NURS_PYIPC_T_REQ_CONSUMER_INTERP,	/* p>c nurs_consumer_interp_t */

	NURS_PYIPC_T_REQ_FD_CALLBACK,		/* p>c nurs_fd_cb_t */

	NURS_PYIPC_T_REQ_TIMER_REGISTER,	/* c>p nurs_timer_add */
	NURS_PYIPC_T_REQ_ITIMER_REGISTER,	/* c>p nurs_itimer_add */
	NURS_PYIPC_T_REQ_TIMER_UNREGISTER,	/* c>p nurs_timer_del */
	NURS_PYIPC_T_REQ_TIMER_PENDING,		/* c>p nurs_timer_pending */
	NURS_PYIPC_T_REQ_TIMER_CALLBACK,	/* p>c nurs_timer_cb_t */

	NURS_PYIPC_T_REQ_PUBLISH,		/* c>p nurs_publish */
	NURS_PYIPC_T_REQ_GET_OUTPUT,		/* c>p nurs_get_output */
	NURS_PYIPC_T_REQ_PUT_OUTPUT,		/* c>p nurs_put_output */
	NURS_PYIPC_T_REQ_FD_REGISTER,		/* c>p nurs_fd_register */
	NURS_PYIPC_T_REQ_FD_UNREGISTER,		/* c>p nurs_fd_unregister */

	NURS_PYIPC_T_REQ_MAX,			/* */

	NURS_PYIPC_T_ACK_PUBLISH,		/* p>c nurs_publish return */
	NURS_PYIPC_T_ACK_GET_OUTPUT,		/* p>c nurs_get_output return */
	NURS_PYIPC_T_ACK_PUT_OUTPUT,		/* p>c nurs_put_output return */
	NURS_PYIPC_T_ACK_FD_REGISTER,		/* p>c nurs_fd_register return */
	NURS_PYIPC_T_ACK_FD_UNREGISTER,		/* p>c nurs_fd_unregister return */

	NURS_PYIPC_T_ACK_INIT,			/* c>p init_child */
	NURS_PYIPC_T_ACK_ORGANIZE,		/* c>p nurs_organize_t return */
	NURS_PYIPC_T_ACK_COVETER_ORGANIZE,	/* c>p nurs_coveter_organize_t return */
	NURS_PYIPC_T_ACK_PRODUCER_ORGANIZE,	/* c>p nurs_producer_organize_t return */
	NURS_PYIPC_T_ACK_DISORGANIZE,		/* c>p nurs_disorganize_t return */
	NURS_PYIPC_T_ACK_PRODUCER_DISORGANIZE,	/* nurs_producer_disorganize_t return */
	NURS_PYIPC_T_ACK_START,			/* c>p nurs_start_t return */
	NURS_PYIPC_T_ACK_PRODUCER_START,	/* c>p nurs_producer_start_t return */
	NURS_PYIPC_T_ACK_STOP,			/* c>p nurs_stop_t return */
	NURS_PYIPC_T_ACK_PRODUCER_STOP,		/* c>p nurs_producer_stop_t return */
	NURS_PYIPC_T_ACK_SIGNAL,		/* c>p nurs_signal_t return */
	NURS_PYIPC_T_ACK_PRODUCER_SIGNAL,	/* c>p nurs_producer_signal_t return */
	NURS_PYIPC_T_ACK_FILTER_INTERP,		/* c>p nurs_filter_interp_t return */
	NURS_PYIPC_T_ACK_CONSUMER_INTERP,	/* c>p nurs_consumer_interp_t return */

	NURS_PYIPC_T_ACK_FD_CALLBACK,		/* c>p nurs_fd_cb_t return */

	NURS_PYIPC_T_ACK_TIMER_REGISTER,	/* p>p nurs_timer_add return */
	NURS_PYIPC_T_ACK_ITIMER_REGISTER,	/* p>p nurs_itimer_add return */
	NURS_PYIPC_T_ACK_TIMER_UNREGISTER,	/* p>p nurs_timer_del return */
	NURS_PYIPC_T_ACK_TIMER_PENDING,		/* p>p nurs_timer_pending return */
	NURS_PYIPC_T_ACK_TIMER_CALLBACK,	/* c>p nurs_timer_cb_t return */

	NURS_PYIPC_T_MAX,
};

#define MY_ATTR_ALIGN(len)	\
	(int)(((len)+(size_t)(MNL_ALIGNTO-1)) & ~((size_t)(MNL_ALIGNTO-1)))
#define MY_NLMSG_HDRLEN		MY_ATTR_ALIGN(sizeof(struct nlmsghdr))
#define MY_NLATTR_HDRLEN	MY_ATTR_ALIGN(sizeof(struct nlattr))
#define ERRBUF_SIZE            1024



struct pynurs_config {
	PyObject_HEAD
	const struct nurs_config *raw;
};

struct pynurs_input {
	PyObject_HEAD
	const struct nurs_input *raw;
};

struct pynurs_output {
	PyObject_HEAD
	struct nurs_output *raw;
};

struct pynurs_plugin {
	PyObject_HEAD
	const struct nurs_plugin *raw;
};

struct pynurs_producer {
	PyObject_HEAD
	struct nurs_producer *raw;
};

struct py_nfd {
	struct py_priv *priv;
	struct nurs_fd *nfd;
        void *data;
};

struct pynurs_fd {
	PyObject_HEAD
	struct py_nfd *raw;
	PyObject *file, *cb, *data;
};

struct py_timer {
	struct py_priv *priv;
	struct nurs_timer *timer;
	nurs_timer_cb_t cb;
	void *data;
};

struct pynurs_timer {
	PyObject_HEAD
	struct py_timer *raw;
        PyObject *cb, *data;
};


/*
 * common
 */
char *py_strerror(char *buf, size_t len);
int py_sendf(int sockfd, uint16_t type, uint16_t flags,
	     int cdata, const char *format, va_list ap);
ssize_t py_recv(int fd, void *buf, size_t len, int *cdata);
int py_recvf(int sockfd, uint16_t type, uint16_t flags,
	     int *cdata, const char *format, va_list ap);
int unpack_nlmsg(const struct nlmsghdr *nlh, const char *format, ...);


/*
 * child (for mostly pyobj.c)
 */
void __pycli_log(int level, char *file, int line, char *format, ...);
#define pycli_log(level, format, args...) \
	__pycli_log(level, __FILE__, __LINE__, format, ## args)
void __pynurs_log(int level, char *file, int line, char *format, ...);

void pycli_init(int fd, const char *path, const char *modname);

struct py_nfd *pycli_fd_register(int fd, uint16_t when, struct pynurs_fd *data);
int pycli_fd_unregister(struct py_nfd *pfd);
struct py_timer *
pycli_timer_register(time_t sc, struct pynurs_timer *data);
struct py_timer *
pycli_itimer_register(time_t ini, time_t per, struct pynurs_timer *data);
int pycli_timer_unregister(struct py_timer *ptimer);
int pycli_timer_pending(struct py_timer *ptimer);
int pycli_publish(struct nurs_output *output);
struct nurs_output *pycli_get_output(struct nurs_producer *producer);
int pycli_put_output(struct nurs_output *output);

/*
 * pyobj
 */
int py_init(const char *modname);

enum nurs_return_t py_start(struct nurs_plugin *plugin);
enum nurs_return_t py_producer_start(struct nurs_producer *producer);
enum nurs_return_t py_stop(struct nurs_plugin *plugin);
enum nurs_return_t py_producer_stop(struct nurs_producer *producer);
enum nurs_return_t py_signal(struct nurs_plugin *plugin, uint32_t signum);
enum nurs_return_t py_producer_signal(struct nurs_producer *producer,
				      uint32_t signum);
enum nurs_return_t py_organize(struct nurs_plugin *plugin);
enum nurs_return_t py_coveter_organize(struct nurs_plugin *plugin,
				       struct nurs_input *input);
enum nurs_return_t py_producer_organize(struct nurs_producer *producer);
enum nurs_return_t py_disorganize(struct nurs_plugin *plugin);
enum nurs_return_t py_producer_disorganize(struct nurs_producer *producer);
enum nurs_return_t py_filter_interp(struct nurs_plugin *plugin,
				    struct nurs_input *input,
				    struct nurs_output *output);
enum nurs_return_t py_consumer_interp(struct nurs_plugin *plugin,
				      struct nurs_input *input);
enum nurs_return_t py_fd_callback(struct pynurs_fd *nfd, uint16_t when);
enum nurs_return_t py_timer_callback(struct pynurs_timer *timer);
#endif

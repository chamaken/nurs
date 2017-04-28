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
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <nurs/nurs.h>
#include <nurs/utils.h>

#define LISTEN_OUTPUT_MESSAGE_MAX 4096

struct listen_priv {
        int fd;
        struct nurs_fd *nfd;
};

enum listen_output_keys_index {
	LISTEN_OUTPUT_MESSAGE = 0,
	LISTEN_OUTPUT_MAX,
};

static struct nurs_output_def listen_output = {
	.len	= LISTEN_OUTPUT_MAX,
	.keys	= {
		[LISTEN_OUTPUT_MESSAGE]	= {
			.name	= "message",
			.type	= NURS_KEY_T_EMBED,
			.flags	= NURS_OKEY_F_ALWAYS,
			.len	= LISTEN_OUTPUT_MESSAGE_MAX,
		},
	},
};

enum listen_config_keys_index {
        LISTEN_CONFIG_SOURCE,
	LISTEN_CONFIG_MAX,
};

static struct nurs_config_def listen_config = {
	.len	= LISTEN_CONFIG_MAX,
	.keys	= {
		[LISTEN_CONFIG_SOURCE] = {
			.name	 = "source",
			.type	 = NURS_CONFIG_T_STRING,
			.flags   = NURS_CONFIG_F_MANDATORY,
			.string	 = "",
		},
	},
};

#define config_source(x)	nurs_config_string(nurs_producer_config(x), LISTEN_CONFIG_SOURCE)

static int accept_fd_cb(struct nurs_fd *nfd, uint16_t what)
{
        struct nurs_producer *producer = nurs_fd_get_data(nfd);
        struct nurs_output *output = nurs_get_output(producer);
	char *buf = nurs_output_pointer(output, LISTEN_OUTPUT_MESSAGE);
	ssize_t nread, nwrite, n;
        int ret = NURS_RET_OK;
        char *last;
        int fd = nurs_fd_get_fd(nfd);
        
        nread = read(fd, buf, LISTEN_OUTPUT_MESSAGE_MAX);
        if (nread < 0) {
                nurs_log(NURS_ERROR, "failed to read from accept socket: %s\n",
                         strerror(errno));
                return NURS_RET_ERROR;
        } else if (nread == 0) {
                nurs_log(NURS_INFO, "closing accept socket\n");
                if (nurs_fd_unregister(nfd)) {
                        nurs_log(NURS_ERROR, "failed to unregister fd: %s\n",
                                 strerror(errno));
                        ret = NURS_RET_ERROR;
                }
                if (close(fd)) {
                        nurs_log(NURS_ERROR, "failed to close accept fd: %s\n",
                                 strerror(errno));
                        ret = NURS_RET_ERROR;
                }
                return ret;
        }

        last = buf + nread - 1;
        if (*last != '\n') {
                nurs_log(NURS_ERROR, "recv too long line, exceeds: %d\n",
                         LISTEN_OUTPUT_MESSAGE_MAX);
                return NURS_RET_ERROR;
        }
        
        for (nwrite = nread; nwrite > 0; ) {
                n = write(fd, buf + nread - nwrite, (size_t)nwrite);
                if (n < 0) {
                        nurs_log(NURS_ERROR, "failed to write to client: %s\n",
                                 strerror(errno));
                        return NURS_RET_ERROR;
                }
                nwrite -= n;
        }

        *last = '\0';
        nurs_output_set_valid(output, LISTEN_OUTPUT_MESSAGE);
        nurs_publish(output);

        return NURS_RET_OK;
}

static int listen_fd_cb(struct nurs_fd *nfd, uint16_t what)
{
	struct nurs_producer *producer = nurs_fd_get_data(nfd);
        struct sockaddr_storage addr = {0};
        socklen_t addrlen = 0;
        int afd, fd = nurs_fd_get_fd(nfd);

	if (!(what & NURS_FD_F_READ))
		return 0;
        
        afd = accept(fd, (struct sockaddr *)&addr, &addrlen);
        if (afd == -1) {
                nurs_log(NURS_ERROR, "failed to accept: %sn", strerror(errno));
                return NURS_RET_ERROR;
        }
        
        nurs_log(NURS_ERROR, "registering accept nfd\n");
        if (!nurs_fd_register(afd, NURS_FD_F_READ, accept_fd_cb, producer)) {
                nurs_log(NURS_ERROR, "failed to regist accept nfd: %s\n",
                         strerror(errno));
                goto error_close;
        }
        
        return NURS_RET_OK;

error_close:
        close(afd);

        return NURS_RET_ERROR;
}

static int listen_organize(struct nurs_producer *producer)
{
        struct listen_priv *priv = nurs_producer_context(producer);
        const char *src = config_source(producer);

        priv->fd = open_listen_socket(src);
        if (priv->fd == -1) {
                nurs_log(NURS_FATAL, "failed to open listening socket: %s\n",
                         strerror(errno));
                return NURS_RET_ERROR;
        }

	return NURS_RET_OK;
}

static int listen_disorganize(struct nurs_producer *producer)
{
	struct listen_priv *priv = nurs_producer_context(producer);

        close(nurs_fd_get_fd(priv->nfd));

        /* not close accept socket,
         * but closing epoll fd will do it */
	return NURS_RET_OK;
}

static int listen_start(struct nurs_producer *producer)
{
	struct listen_priv *priv = nurs_producer_context(producer);

        priv->nfd = nurs_fd_register(
                priv->fd, NURS_FD_F_READ, listen_fd_cb, producer);
	if (!priv->nfd) {
		nurs_log(NURS_ERROR, "failed to register nfd: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static int listen_stop(struct nurs_producer *producer)
{
	struct listen_priv *priv = nurs_producer_context(producer);

	if (nurs_fd_unregister(priv->nfd)) {
		nurs_log(NURS_ERROR, "failed to unregister listenfd: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}

        /* XXX: not wait accept socket finished */
	return NURS_RET_OK;
}

static struct nurs_producer_def listen_producer = {
	.version	= VERSION,
	.name 		= "LISTEN",
	.context_size	= sizeof(struct listen_priv),
	.config_def	= &listen_config,
	.output_def	= &listen_output,
	.organize	= &listen_organize,
	.disorganize	= &listen_disorganize,
	.start		= &listen_start,
	.stop		= &listen_stop,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	nurs_producer_register(&listen_producer);
}

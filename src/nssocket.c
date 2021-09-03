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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>
#include <wait.h>

#include <linux/limits.h>
#include <linux/sched.h>

#include <nurs/nurs.h>
#include <nurs/list.h>
#include "internal.h"

enum {
	CMD_NONE,
	CMD_SYNC,
	CMD_SOCKET, /* int domain, int type, int protocol */
	CMD_DONE,
	CMD_MAX,
};

struct nsfd {
	struct list_head list;
	pid_t pid;
	int peerfd;
	char name[PATH_MAX]; /* more suitable size? */
};

static LIST_HEAD(nsfds);
static int peerfd;
#ifdef DEBUG_PTHREAD
static pthread_mutex_t nsfds_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
#else
static pthread_mutex_t nsfds_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static int get_unaligned_int(const void *s)
{
	int x;
	memcpy(&x, s, sizeof(x));
	return x;
}

static void put_unaligned_int(void *d, int x)
{
	memcpy(d, &x, sizeof(x));
}

/*
 * message exchange via socketpair using send/recv msg()
 *
 * - use cdata:
 *   cdata represents a file descriptor
 *   cmd[0] means -errno
 *
 * - without cdata:
 *   cmd[0] means:
 *   > 0:  command
 *   == 0: sync, echo
 *   < 0:  -errno
 *
 * it's an given fact that tx() and rx() never fail.
 */
static ssize_t tx(int fd, int *cmd, uint8_t cmdlen, int cdata)
{
	struct msghdr msg;
	struct iovec iov[cmdlen];
	size_t cmsglen = CMSG_SPACE(sizeof(int));
	char control[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	int i;

	memset(&msg, 0, sizeof(struct msghdr));
	memset(iov, 0, sizeof(struct iovec) * cmdlen);

	msg.msg_iov = iov;
	msg.msg_iovlen = cmdlen;
	for (i = 0; i < cmdlen; i++) {
		iov[i].iov_len = sizeof(int);
		iov[i].iov_base = &cmd[i];
	}
	if (cdata) {
		msg.msg_control = control;
		msg.msg_controllen = cmsglen;
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		put_unaligned_int(CMSG_DATA(cmsg), cdata);
	}

	return sendmsg(fd, &msg, 0);
}

static ssize_t rx(int fd, int *cmd, uint8_t cmdlen, int *cdata)
{
	struct msghdr msg;
	struct iovec iov[cmdlen];
	size_t cmsglen = CMSG_SPACE(sizeof(int));
	char control[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	ssize_t ret;
	int i;

	memset(&msg, 0, sizeof(struct msghdr));
	memset(iov, 0, sizeof(struct iovec));

	msg.msg_iov = iov;
	msg.msg_iovlen = cmdlen;
	for (i = 0; i < cmdlen; i++) {
		iov[i].iov_len = sizeof(int);
		iov[i].iov_base = &cmd[i];
	}
	if (cdata != NULL) {
		msg.msg_control = control;
		msg.msg_controllen = cmsglen;
	}

	ret = recvmsg(fd, &msg, 0);
	if (ret == -1) {
		nurs_log(NURS_ERROR, "failed to recvmsg: %s\n",
			 strerror(errno));
		return ret;
	}

	if (cdata == NULL)
		return ret;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || cmsg->cmsg_len != CMSG_LEN(sizeof(int))
	    || cmsg->cmsg_level != SOL_SOCKET
	    || cmsg->cmsg_type != SCM_RIGHTS) {
		errno = EBADMSG;
		return -1;
	}
	*cdata = get_unaligned_int(CMSG_DATA(cmsg));

	return ret;
}

static ssize_t tx_cmd(int fd, int cmd)
{
	return tx(fd, &cmd, 1, 0);
}

static int rx_cmd(int fd)
{
	int cmd;
	if (rx((fd), &cmd, 1, NULL) <= 0)
		return -1;
	return cmd;
}

static ssize_t tx_fd(int fd1, int fd2, int e)
{
	return tx(fd1, &e, 1, fd2);
}

static int rx_fd(int fd1)
{
	int e, fd2;

	if (rx(fd1, &e, 1, &fd2) == -1)
		return -1;

	errno = -e;
	return fd2;
}

/*
 * bind_etc() and netns_switch()
 * are copied from lib/namespace.c in iproute2
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#define NETNS_RUN_DIR "/var/run/netns"
#define NETNS_ETC_DIR "/etc/netns"

static void bind_etc(const char *name)
{
	char etc_netns_path[sizeof(NETNS_ETC_DIR) + NAME_MAX];
	char netns_name[PATH_MAX];
	char etc_name[PATH_MAX];
	struct dirent *entry;
	DIR *dir;

	if (strlen(name) >= NAME_MAX)
		return;

	snprintf(etc_netns_path, sizeof(etc_netns_path), "%s/%s",
		 NETNS_ETC_DIR, name);
	dir = opendir(etc_netns_path);
	if (!dir)
		return;

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0)
			continue;
		if (strcmp(entry->d_name, "..") == 0)
			continue;
		snprintf(netns_name, sizeof(netns_name), "%s/%s",
			 etc_netns_path, entry->d_name);
		snprintf(etc_name, sizeof(etc_name), "/etc/%s", entry->d_name);
		if (mount(netns_name, etc_name, "none", MS_BIND, NULL) < 0) {
			nurs_log(NURS_ERROR, "Bind %s -> %s failed: %s\n",
				 netns_name, etc_name, strerror(errno));
		}
	}
	closedir(dir);
}

static int netns_switch(const char *name)
{
	char net_path[PATH_MAX];
	int netns;
	unsigned long mountflags = 0;
	struct statvfs fsstat;

	snprintf(net_path, sizeof(net_path), "%s/%s", NETNS_RUN_DIR, name);
	netns = open(net_path, O_RDONLY | O_CLOEXEC);
	if (netns < 0) {
		nurs_log(NURS_ERROR,
			 "Cannot open network namespace \"%s\": %s\n",
			 name, strerror(errno));
		return -1;
	}

	if (setns(netns, CLONE_NEWNET) < 0) {
		nurs_log(NURS_ERROR,
			 "setting the network namespace \"%s\" failed: %s\n",
			 name, strerror(errno));
		close(netns);
		return -1;
	}
	close(netns);

	if (unshare(CLONE_NEWNS) < 0) {
		nurs_log(NURS_ERROR, "unshare failed: %s\n", strerror(errno));
		return -1;
	}
	/* Don't let any mounts propagate back to the parent */
	if (mount("", "/", "none", MS_SLAVE | MS_REC, NULL)) {
		nurs_log(NURS_ERROR, "\"mount --make-rslave /\" failed: %s\n",
			 strerror(errno));
		return -1;
	}

	/* Mount a version of /sys that describes the network namespace */

	if (umount2("/sys", MNT_DETACH) < 0) {
		/* If this fails, perhaps there wasn't a sysfs instance mounted.
		 * Good. */
		if (statvfs("/sys", &fsstat) == 0) {
			/* We couldn't umount the sysfs, we'll attempt to
			 * overlay it. A read-only instance can't be shadowed
			 * with a read-write one. */
			if (fsstat.f_flag & ST_RDONLY)
				mountflags = MS_RDONLY;
		}
	}
	if (mount(name, "/sys", "sysfs", mountflags, NULL) < 0) {
		nurs_log(NURS_ERROR, "mount of /sys failed: %s\n",
                         strerror(errno));
		return -1;
	}

	/* Setup bind mounts for config files in /etc */
	bind_etc(name);
	return 0;
}

#define child_exit(format, args...)		\
	do {					\
	nurs_log(NURS_ERROR, format, ## args);	\
	shutdown(peerfd, SHUT_RDWR); \
	_exit(errno);\
	} while (0)

static void child(const char *nsname)
{
	int cmd = CMD_SYNC;
	int params[3]; /* XXX: magic number, see enum CALL_ */
	int sockfd;

	if (netns_switch(nsname) == -1) {
		/* netns_switch will show error message */
		shutdown(peerfd, SHUT_RDWR);
		_exit(errno);
	}
	if (tx_cmd(peerfd, CMD_SYNC) == -1)
		child_exit("failed to send SYNC command\n");

	/* waiting cmd */
	while (1) {
		cmd = rx_cmd(peerfd);
		switch (cmd) {
		case -1:
			child_exit("failed to recv command: %s\n",
				   strerror(errno));
			break;
		case CMD_DONE:
			close(peerfd);
			_exit(0);
			break;
		case CMD_SOCKET:
			if (rx(peerfd, params, 3, NULL) == -1)
				child_exit("failed to recv command: %s\n",
					   strerror(errno));
			sockfd = socket(params[0], params[1], params[2]);
			if (tx_fd(peerfd, sockfd, -errno) == -1)
				child_exit("failed to send fd: %s\n",
					   strerror(errno));
			break;
		default:
			nurs_log(NURS_ERROR, "recv unknown command: %d\n", cmd);
			if (tx_fd(peerfd, -1, -EINVAL) == -1)
				child_exit("failed to send fd: %s\n",
					   strerror(errno));
			break;
		}
	}
}

static struct nsfd *lookup(const char *name)
{
	struct nsfd *nsfd = NULL;
	int fds[2];

	if (nurs_mutex_lock(&nsfds_mutex))
		return NULL;

	list_for_each_entry(nsfd, &nsfds, list)
		if (!strcmp(nsfd->name, name))
			goto exit;

	// if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == -1)
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == -1)
		goto exit;

	nsfd = calloc(1, sizeof(struct nsfd));
	if (!nsfd)
		goto exit;
	nsfd->pid = fork();
	switch (nsfd->pid) {
	case -1:
		goto free_nsfd;
	case 0:
		peerfd = fds[1];
		free(nsfd);
		child(name);
		break;
	default:
		if (rx_cmd(fds[0]) <= 0) {
			/* XXX: on recv side error, kill child */
			goto free_nsfd;
		}
		nsfd->peerfd = fds[0];
		strncpy(nsfd->name, name, PATH_MAX);
		nsfd->name[PATH_MAX - 1] = '\0';
		list_add(&nsfd->list, &nsfds);
		goto exit;
		break;
	}

free_nsfd:
	free(nsfd);
	nsfd = NULL;
exit:
	nurs_mutex_unlock(&nsfds_mutex);
	return nsfd;
}

int nurs_nssocket(const char *name, int domain, int type, int protocol)
{
	struct nsfd *nsfd = lookup(name);
	int cmd[] = {CMD_SOCKET, domain, type, protocol};

	if (!nsfd) {
		errno = ENOENT; /* maybe */
		return -1;
	}
	if (tx(nsfd->peerfd, cmd, 4, 0) == -1)
		return -1;

	return rx_fd(nsfd->peerfd);
}
EXPORT_SYMBOL(nurs_nssocket);

int nurs_reap_nssocket(pid_t pid)
{
	struct nsfd *nsfd;
	bool found = false;
	int status, rc, ret = 0;

	if (nurs_mutex_lock(&nsfds_mutex))
		return -1;

	list_for_each_entry(nsfd, &nsfds, list) {
		if (nsfd->pid == pid) {
			found = true;
			break;
		}
	}
	if (!found)
		goto exit;

	rc = waitpid(pid, &status, WNOHANG);
	if (rc == -1) {
		nurs_log(NURS_ERROR, "failed to waitpid: %s\n",
			 strerror(errno));
		ret = -1;
		goto exit;
	} else if (rc == 0) {
		nurs_log(NURS_ERROR, "ns child: %s have not changed state\n",
			 nsfd->name);
		ret = -1;
		goto exit;
	}
	if (status) {
		nurs_log(NURS_ERROR, "ns child: %s exited abnormally: %d\n",
			 nsfd->name, status);
	}
exit:
	nurs_mutex_unlock(&nsfds_mutex);
	return ret;
}

/* must be called synchronously.
 * mutex is not locked here but in signal handler above */
void nurs_fini_nssocket(int force)
{
	struct nsfd *nsfd, *tmp;

	list_for_each_entry_safe(nsfd, tmp, &nsfds, list) {
		if (tx_cmd(nsfd->peerfd, CMD_DONE) == -1) {
			nurs_log(NURS_ERROR, "failed to send DONE: %s\n",
				 strerror(errno));
			if (force)
				kill(nsfd->pid, SIGTERM); /* or KILL? */
		}
		close(nsfd->peerfd);
		list_del(&nsfd->list);
		free(nsfd);
	}
}

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
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/signalfd.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <assert.h>

#include <nurs/nurs.h>

#include "internal.h"

/* main.c */
static char nurs_logfname[NURS_STRING_LEN] = NURS_DEFAULT_LOGFNAME;
static FILE *nurs_logfd		= NULL;
static bool nurs_log_sync	= false;
static bool nurs_verbose	= false;

#define NURS_LOG_TIME_LEN 64
static char nurs_log_time_format[NURS_NAME_LEN + 1];
static size_t nurs_log_time_format_len;
#define NURS_DEFAULT_TIME_FORMAT "%FT%T"

static struct nurs_fd *signal_nfd; /* XXX: close on err/exit */

extern void *global_dl_handler;

const char *nurs_loglevel_string[] = {
	[NURS_DEBUG]	= "DEBUG",
	[NURS_INFO]	= "INFO",
	[NURS_NOTICE]	= "NOTICE",
	[NURS_ERROR]	= "ERROR",
	[NURS_FATAL]	= "FATAL",
};

static const int nurs_syslog_level[] = {
	[NURS_DEBUG]	= LOG_DEBUG,
	[NURS_INFO]	= LOG_INFO,
	[NURS_NOTICE]	= LOG_NOTICE,
	[NURS_ERROR]	= LOG_ERR,
	[NURS_FATAL]	= LOG_CRIT,
};

/* expanding? va_list many times make rather slow? */

static void _log_file(FILE *fd, int level, char *file, int line,
		      const char *format, va_list ap)
{
	time_t t;
	char timestr[NURS_LOG_TIME_LEN + 1] = "";
	char prefix[128]; /* non reasonable magic number */
	va_list ac;

	if (nurs_log_time_format_len) {
		t = time(NULL);
		if (!strftime(timestr, NURS_LOG_TIME_LEN,
			      nurs_log_time_format, localtime(&t)))
			timestr[0] = '\0';
		snprintf(prefix, 127, "%s %6s %s[%d] %s",
			 timestr, nurs_loglevel_string[level],
			 file, line, format);
	} else {
		snprintf(prefix, 127, "%s %6s",
			 nurs_loglevel_string[level], format);
	}

	va_copy(ac, ap);
	vfprintf(fd, prefix, ap);
	if (nurs_log_sync)
		fflush(fd);

	if (nurs_verbose && fd != stderr) {
		vfprintf(stderr, prefix, ac);
		if (nurs_log_sync)
			fflush(stderr);
	}
	va_end(ac);
}

static void log_nothing(int level, char *file, int line,
			const char *format, va_list ap)
{
}

static void log_stderr(int level, char *file, int line,
		       const char *format, va_list ap)
{
	_log_file(stderr, level, file, line, format, ap);
}

static void log_file(int level, char *file, int line,
		     const char *format, va_list ap)
{
	_log_file(nurs_logfd, level, file, line, format, ap);
}

static void log_syslog(int level, char *file, int line,
		       const char *format, va_list ap)
{
	char newf[128]; /* non reasonable magic number */

	snprintf(newf, 127, "%s[%d] %s", file, line, format);
	vsyslog(nurs_syslog_level[level], newf, ap);
}

static void (*nurs_log_funcs[])(int, char *, int, const char *, va_list) = {
	[NURS_DEBUG]	= log_nothing,
	[NURS_INFO]	= log_nothing,
	[NURS_NOTICE]	= log_stderr,
	[NURS_ERROR]	= log_stderr,
	[NURS_FATAL]	= log_stderr,
};

void __nurs_log(int level, char *file, int line, const char *format, ...)
{
	va_list ap;

	assert(level < NURS_LOGLEVEL_MAX);

	va_start(ap, format);
	nurs_log_funcs[level](level, file, line, format, ap);
	va_end(ap);
}
EXPORT_SYMBOL(__nurs_log);

int log_settle(const char *fname, int level, char *time_format,
	       bool sync, bool verbose)
{
	void (*logf)(int, char *, int, const char *, va_list);
	int i;

	if (level >= NURS_LOGLEVEL_MAX) {
		errno = EINVAL;
		return -1;
	}

	if (!fname || !strlen(fname)) {
		logf = log_stderr;
		nurs_logfd = stderr;
	} else if (fname == NURS_SYSLOG_FNAME) {
		logf = log_syslog;
		openlog("nursd", LOG_PID, LOG_DAEMON);
		nurs_logfd = NURS_SYSLOG_FD;
	} else {
		logf = log_file;
		nurs_logfd = fopen(fname, "a");
		if (!nurs_logfd)
			return -1;
	}

	for (i = NURS_DEBUG; i < level; i++)
		nurs_log_funcs[i] = log_nothing;
	for (; i < NURS_LOGLEVEL_MAX; i++)
		nurs_log_funcs[i] = logf;

	if (time_format && strlen(time_format)) {
		nurs_log_time_format_len = strlen(time_format);
		strncpy(nurs_log_time_format, time_format, NURS_NAME_LEN);
	} else {
		nurs_log_time_format_len = 0;
		strncpy(nurs_log_time_format, "", NURS_NAME_LEN);
	}

	nurs_log_sync = sync;
	nurs_verbose = verbose;

	return 0;
}

int nurs_close_log(void)
{
	int ret = 0;

	if (!nurs_logfd)
		return ret;
	if (nurs_logfd == NURS_SYSLOG_FD)
		closelog();
	else if (nurs_logfd != stderr) {
		ret = fclose(nurs_logfd);
	}
	nurs_logfd = NULL;

	return ret;
}

static void stop_handler(uint32_t signal)
{
	if (signal != SIGTERM && signal != SIGINT)
		nurs_log(NURS_FATAL, "something weird happen?\n");
	nfd_cancel();
}

static enum nurs_return_t
signal_cb(int fd, uint16_t when, void *data)
{
	struct signalfd_siginfo fdsi;
	FILE *prevfd;
	ssize_t s;
	int ret;

	s = read(fd, &fdsi, sizeof(struct signalfd_siginfo));
	if (s != sizeof(struct signalfd_siginfo)) {
		nurs_log(NURS_ERROR, "read: %s\n", _sys_errlist[errno]);
		return NURS_RET_ERROR;
	}

	/* reopen logfile */
	if (fdsi.ssi_signo == SIGHUP &&
	    nurs_log_funcs[NURS_LOGLEVEL_MAX - 1] == log_file) {
		prevfd = nurs_logfd;
		nurs_logfd = freopen(nurs_logfname, "a", nurs_logfd);
		if (!nurs_logfd) {
			/* hacky...?
			 * for (i = 0; i < NURS_LOGLEVEL_MAX; i++)
			 *	if (nurs_log_funcs[i] == log_file)
			 *		nurs_log_funcs[i] = log_stderr;
			 */
			nurs_logfd = prevfd;
			nurs_log(NURS_ERROR, "could not open logfile %s: %s\n",
				 nurs_logfname, strerror(errno));
		}
	} else if (fdsi.ssi_signo == SIGTERM ||
		   fdsi.ssi_signo == SIGINT) {
		stop_handler(fdsi.ssi_signo);
	}

	/* call signal callback synchronously */
	if (workers_suspend()) {
		nurs_log(NURS_FATAL, "failed to suspend workers\n");
		return NURS_RET_ERROR;
	}
	ret = plugins_signal(fdsi.ssi_signo, true); /* ignore error? */
	/* XXX: need to resume even if signal cb failed? */
	if (workers_resume()) {
		nurs_log(NURS_FATAL, "failed to resume workers\n");
		return NURS_RET_ERROR;
	}

	return ret ? NURS_RET_ERROR : NURS_RET_OK;
}

int signal_nfd_init(void)
{
	sigset_t mask;
	int sigfd;

	if (signal_nfd) {
		errno = EALREADY;
		return -1;
	}

	sigemptyset(&mask);
	if (sigaddset(&mask, SIGTERM) ||
	    sigaddset(&mask, SIGINT)  ||
	    sigaddset(&mask, SIGHUP)  ||
	    sigaddset(&mask, SIGALRM) ||
	    sigaddset(&mask, SIGUSR1) ||
	    sigaddset(&mask, SIGUSR2)) {
		nurs_log(NURS_FATAL, "failed to sigaddset: %s\n",
			 strerror(errno));
		return -1;
	}

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		nurs_log(NURS_FATAL, "failed to sigprocmask: %s\n",
			 strerror(errno));
		return -1;
	}

	sigfd = signalfd(-1, &mask, 0);
	if (sigfd < 0) {
		nurs_log(NURS_FATAL, "failed to signalfd: %s\n",
			 strerror(errno));
		return -1;
	}

	signal_nfd = nurs_fd_create(sigfd, NURS_FD_F_READ);
	if (!signal_nfd) {
		nurs_log(NURS_FATAL, "failed to create signal nfd: %s\n",
			 strerror(errno));
		return -1;
	}

	if (nurs_fd_register(signal_nfd, signal_cb, NULL)) {
		nurs_log(NURS_ERROR, "failed to register signalfd: %s\n",
			 strerror(errno));
		return -1;
	}

	return 0;
}

int signal_nfd_fini(void)
{
	sigset_t mask;

	if (nurs_fd_unregister(signal_nfd)) {
		nurs_log(NURS_ERROR, "failed to unregister signalfd: %s\n",
			 strerror(errno));
		return -1;
	}
	if (close(signal_nfd->fd)) {
		nurs_log(NURS_ERROR, "failed to close signalfd: %s\n",
			 strerror(errno));
		return -1;
	}
	nurs_fd_destroy(signal_nfd);
	signal_nfd = NULL;

	sigemptyset(&mask);
	if (sigaddset(&mask, SIGTERM)	!= 0 ||
	    sigaddset(&mask, SIGINT)	!= 0 ||
	    sigaddset(&mask, SIGHUP)	!= 0 ||
	    sigaddset(&mask, SIGALRM)	!= 0 ||
	    sigaddset(&mask, SIGUSR1)	!= 0 ||
	    sigaddset(&mask, SIGUSR2)	!= 0) {
		nurs_log(NURS_FATAL, "failed to sigaddset: %s\n",
			 strerror(errno));
		return -1;
	}

	if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1) {
		nurs_log(NURS_FATAL, "failed to sigprocmask: %s\n",
			 strerror(errno));
		return -1;
	}

	return 0;
}

int log_config_parser(const char *line)
{
	/* filename (or stderr), <(sync|nosync)>, <(verbose|quit)> */
	char buf[NURS_STRING_LEN], fname[NURS_STRING_LEN] = {0};
	bool syslog = false, sync = false, verbose = false;
	int i, level = NURS_NOTICE;
	FILE *fd = NULL;
	const char *s;
	uintptr_t p = (uintptr_t)line
		+ (strlen(line) > NURS_STRING_LEN
		   ? NURS_STRING_LEN : strlen(line));

	s = get_word(line, ",", true, fname, (size_t)(p - (uintptr_t)line));
	if (!*s++)
		return log_settle(NULL, level, NURS_DEFAULT_TIME_FORMAT,
				  sync, verbose);

	if (!strcasecmp(fname, "syslog"))
		syslog = true;
	else if (fname[0] != '\0' && fname[0] != '/') {
		nurs_log(NURS_ERROR, "require abs path logfile\n");
		/* because of daemon(0, 0) in main.c */
		return -1;
	}

	s = get_word(s, ",", true, buf, (size_t)(p - (uintptr_t)s));
	if (!*s++) goto log_settle;
	if (strlen(buf)) {
		for (i = NURS_DEBUG; i < NURS_LOGLEVEL_MAX; i++)
			if (!strcasecmp(buf, nurs_loglevel_string[i])) {
				level = i;
				break;
			}
		if (i == NURS_LOGLEVEL_MAX) {
			nurs_log(NURS_ERROR, "invalid log level: %s\n", buf);
			if (fd) fclose(fd);
			return -1;
		}
	}

	s = get_word(s, ",", true, buf, (size_t)(p - (uintptr_t)s));
	if (!*s++) goto log_settle;
	if (strlen(buf) && !strcasecmp(buf, "sync"))
		sync = true;

	s = get_word(s, ",", true, buf, (size_t)(p - (uintptr_t)s));
	if (strlen(buf) && !strcasecmp(buf, "verbose"))
		verbose = true;

log_settle:
	return log_settle(syslog ? NURS_SYSLOG_FNAME : fname,
			  level, NURS_DEFAULT_TIME_FORMAT,
			  sync, verbose);
}

/* useless minimum environment */
int useless_init(size_t nthread)
{
	int ret = 0;

	ret |= nfd_init();
	ret |= signal_nfd_init();
	ret |= workers_start(nthread);

	return ret;
}

/* just antonym init */
int useless_fini(void)
{
	int ret = 0;

	ret |= workers_stop();

	ret |= plugins_stop(true);
	/* can be removed if caller resumes workers
	 * and call this nurs_plugins_stop()? */

	ret |= signal_nfd_fini();
	ret |= nfd_fini();

	return ret;
}

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
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"

#define COPYRIGHT							\
	"(C) 2000-2006 Harald Welte <laforge@netfilter.org>\n"		\
	"(C) 2008-2012 Pablo Neira Ayuso <pablo@netfilter.org>\n"	\
	"(C) 2008-2012 Eric Leblond <eric@regit.org>\n"			\
	"(C) 2016 Ken-ichirou MATSUZAWA <chamas@h4.dion.ne.jp>\n"

extern bool nurs_show_pluginfo;			/* plugin.c */
extern const char *nurs_loglevel_string[];	/* nurs.c */

enum {
	NURS_CONFIG_LOGFILE,
	NURS_CONFIG_PLUGIN,
	NURS_CONFIG_STACK,
	NURS_CONFIG_WORKERS,
	NURS_CONFIG_IOSETS,
	NURS_CONFIG_MAX,
};

static struct nurs_config_def global_config = {
	.len		= NURS_CONFIG_MAX,
	.keys	= {
		[NURS_CONFIG_LOGFILE]	= {
			.name	= "log",
			.type	= NURS_CONFIG_T_CALLBACK,
			/* file, level, sync, verbose*/
			.parser	= log_config_parser,	/* ::nurs.c */
		},
		[NURS_CONFIG_PLUGIN]	= {
			.name	= "plugin",
			.type	= NURS_CONFIG_T_CALLBACK,
			.flags	= NURS_CONFIG_F_MULTI,
			.parser	= plugin_config_parser,	/* ::plugin.c */
		},
		[NURS_CONFIG_STACK]	= {
			.name	= "stack",
			.type	= NURS_CONFIG_T_CALLBACK,
			.flags	= NURS_CONFIG_F_MULTI,
			.parser	= stack_config_parser,	/* ::stack.c */
		},
		[NURS_CONFIG_WORKERS]	= {
			.name	= "workers",
			.type	= NURS_CONFIG_T_INTEGER,
			.flags	= NURS_CONFIG_T_NONE,
			.integer = 8,
		},
		[NURS_CONFIG_IOSETS]	= {
			.name	= "iosets",
			.type	= NURS_CONFIG_T_INTEGER,
			.flags	= NURS_CONFIG_T_NONE,
			.integer = 8,
		},
	},
};

static int nurs(char *cfname)
{
	struct nurs_config *config;
	int nworkers, niosets;
	int ret = EXIT_SUCCESS;

	nurs_log(NURS_INFO, "initialize plugins\n");
	if (plugin_init()) {
		nurs_log(NURS_FATAL, "failed to init plugin class\n");
		exit(EXIT_FAILURE);
	}

	nurs_log(NURS_INFO, "init nurs fds\n");
	if (nfd_init()) {
		nurs_log(NURS_FATAL, "failed to initialize nfd\n");
		exit(EXIT_FAILURE);
	}
	nurs_log(NURS_INFO, "init signal fd\n");
	if (signal_nfd_init()) {
		nurs_log(NURS_FATAL, "failed to initialize signal fd\n");
		ret = EXIT_FAILURE;
		goto fini_nfd;
	}

	nurs_log(NURS_INFO, "read global config\n");
	if (config_fopen(cfname)) {
		nurs_log(NURS_FATAL, "failed to open config file: %s\n",
			 cfname);
		goto fini_signal;
	}
	config = config_parse_section("global", &global_config);
	if (!config) {
		nurs_log(NURS_FATAL, "failed to parse config file: %s\n",
			 cfname);
		ret = EXIT_FAILURE;
		goto unregister_all_plugin;
	}
	if (config_fclose()) {
		nurs_log(NURS_FATAL, "failed to close config file: %s\n",
			 cfname);
		free(config);
		ret = EXIT_FAILURE;
		goto unregister_all_plugin;
	}
	errno = 0;
	nworkers = nurs_config_integer(config, NURS_CONFIG_WORKERS);
	if (errno) {
		nurs_log(NURS_FATAL, "failed to get nworkers config: %s",
			 strerror(errno));
		free(config);
		ret = EXIT_FAILURE;
		goto unregister_all_plugin;
	}
	niosets = nurs_config_integer(config, NURS_CONFIG_IOSETS);
	if (errno) {
		nurs_log(NURS_FATAL, "failed to get niosets config: %s",
			 strerror(errno));
		free(config);
		ret = EXIT_FAILURE;
		goto unregister_all_plugin;
	}
	free(config);

	nurs_log(NURS_INFO, "setting workers: %d, iosets (per stack): %d\n",
		 nworkers, niosets);
	if (stack_settle((size_t)niosets)) {
		nurs_log(NURS_FATAL, "failed to settle stacks\n");
		ret = EXIT_FAILURE;
		goto unregister_all_plugin;
	}

	if (workers_start((size_t)nworkers)) {
		nurs_log(NURS_FATAL, "failed to start workers\n");
		ret = EXIT_FAILURE;
		goto unsettle_stack;
	}

	plugins_order_group();

	nurs_log(NURS_INFO, "organize plugins\n");
	if (plugins_organize(cfname)) {
		nurs_log(NURS_FATAL, "failed to organize plugins\n");
		ret = EXIT_FAILURE;
		goto stop_workers;
	}
	nurs_log(NURS_INFO, "start plugins\n");
	if (plugins_start()) {
		nurs_log(NURS_FATAL, "failed to start plugins\n");
		ret = EXIT_FAILURE;
		goto disorganize_plugin;
	}

	nurs_log(NURS_INFO, "enter main loop\n");
	if (nfd_loop()) {
		nurs_log(NURS_FATAL, "fd loop exit unsuccessfully: %s\n",
			 strerror(errno));
		ret = EXIT_FAILURE;
	}

	nurs_log(NURS_INFO, "stop plugins\n");
	if (plugins_stop(true)) {
		nurs_log(NURS_ERROR, "failed to stop plugins\n");
		ret = EXIT_FAILURE;
	}
disorganize_plugin:
	nurs_log(NURS_INFO, "disorganize plugins\n");
	if (plugins_disorganize(true)) {
		nurs_log(NURS_ERROR, "failed to disorganize plugins\n");
		ret = EXIT_FAILURE;
	}
stop_workers:
	nurs_log(NURS_INFO, "stop workers\n");
	if (workers_stop()) {
		nurs_log(NURS_ERROR, "failed to stop workers\n");
		ret = EXIT_FAILURE;
	}
unsettle_stack:
	nurs_log(NURS_INFO, "unsettle stacks\n");
	if (stack_unsettle()) {
		nurs_log(NURS_ERROR, "failed to unsettle stacks\n");
		ret = EXIT_FAILURE;
	}
unregister_all_plugin:
	nurs_log(NURS_INFO, "unregister all plugins\n");
	if (plugin_unregister_all()) {
		nurs_log(NURS_ERROR, "failed to unregister plugins\n");
		ret = EXIT_FAILURE;
	}
fini_signal:
	nurs_log(NURS_INFO, "fini signal nfd\n");
	if (signal_nfd_fini()) {
		nurs_log(NURS_ERROR, "failed to finalize signal fd\n");
		ret = EXIT_FAILURE;
	}
fini_nfd:
	nurs_log(NURS_INFO, "fini nurs fds\n");
	if (nfd_fini()) {
		nurs_log(NURS_ERROR, "failed to finalize nfd\n");
		ret = EXIT_FAILURE;
	}

	return ret;
}

static void usage(char *progname)
{
	printf("nurs version %s\n", VERSION);
	printf(COPYRIGHT);
	printf("This is free software with ABSOLUTELY NO WARRANTY.\n\n");
	printf("%s [options] <config file>\n", progname);
	printf("where options are:\n");
	printf("\t-h --help\tthis help page\n");
	printf("\t-V --version\tprint version information\n");
	printf("\t-d --daemon\tdaemonize (fork into background) [false]\n");
	printf("\t-v --verbose\toutput info on standard error too [false]\n");
	printf("\t-f --logfile\tset log file [stderr]\n");
	printf("\t-l --loglevel\tset log level [INFO]\n");
	printf("\t-s --sync\tflush each log output [false]\n");
	printf("\t-p --pidfile\trecord ulogd PID in file [no default]\n");
	printf("\t-i --info\tdisplay infos about plugin\n");
}

static struct option opts[] = {
	{ "daemon",	0, NULL, 'd' },
	{ "help",	0, NULL, 'h' },
	{ "info",	1, NULL, 'i' },
	{ "logfile",	1, NULL, 'f' },
	{ "loglevel",	1, NULL, 'l' },
	{ "pidfile",	1, NULL, 'p' },
	{ "sync",	0, NULL, 's' },
	{ "verbose",	0, NULL, 'v' },
	{ "version",	0, NULL, 'V' },
	{NULL, 0, NULL, 0},
};

#ifndef NURS_TEST_LIB
int main(int argc, char *argv[])
{
	int loglevel = NURS_INFO;
	bool verbose = false;
	bool logsync = false;
	bool daemonize = false;
	char *cwd, cwdbuf[PATH_MAX + 1];
	char cfname[PATH_MAX + 1] = {0};
	char logfname[PATH_MAX + 1] = {0};
	char pidfname[PATH_MAX + 1] = {0};
	FILE *pidfd = NULL;
	int i, argch, ret = EXIT_FAILURE;

	cwd = getcwd(cwdbuf, PATH_MAX);
	if (!cwd) {
		fprintf(stderr, "failed to get cwd: %s\n", strerror(errno));
		goto failure;
	}

	while ((argch = getopt_long(argc, argv,
				    "dhi:f:l:p:svV", opts, NULL)) != -1) {
		switch (argch) {
		default:
		case '?':
			if (isprint(optopt))
				fprintf(stderr, "unknown option `-%c'.\n",
					optopt);
			else
				fprintf(stderr, "unknown option character "
					"`\\x%x'.\n", optopt);
			usage(argv[0]);
			exit(EXIT_FAILURE);
			break;
		case 'd':
			daemonize = true;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		case 'i':
			if (plugin_init()) {
				fprintf(stderr, "failed to init plugins\n");
				exit(EXIT_FAILURE);
			}
			nurs_show_pluginfo = true;
			if (plugin_config_parser(optarg))
				exit(EXIT_FAILURE);
			exit(EXIT_SUCCESS);
			break;
		case 'f':
			if (*optarg == '/') {
				snprintf(logfname, PATH_MAX, "%s", optarg);
				break;
			}
			snprintf(logfname, PATH_MAX, "%s/%s", cwd, optarg);
			break;
		case 'p':
			if (*optarg == '/') {
				snprintf(pidfname, PATH_MAX, "%s", optarg);
				break;
			}
			snprintf(pidfname, PATH_MAX, "%s/%s", cwd, optarg);
			break;
		case 'l':
			for (i = NURS_DEBUG; i < NURS_LOGLEVEL_MAX; i++)
				if (!strcasecmp(optarg,
						nurs_loglevel_string[i])) {
					loglevel = i;
					break;
				}
			if (i == NURS_LOGLEVEL_MAX) {
				fprintf(stderr, "invalid log level: %s\n",
					optarg);
				goto failure;
			}
			break;
		case 's':
			logsync = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 'V':
			printf("nursd version %s\n", VERSION);
			printf(COPYRIGHT);
			exit(EXIT_SUCCESS);
			break;
		}
	}
	if (optind >= argc) {
		fprintf(stderr, "no config file specified\n");
		goto failure;
	}
	if (!realpath(argv[optind], cfname)) {
		fprintf(stderr, "invalid config file: %s\n", strerror(errno));
		goto failure;
	}
	optind++;
	if (optind < argc) {
		fprintf(stderr, "can not handle multiple config\n");
		goto failure;
	}

	if (verbose) {
		if (daemonize) {
			fprintf(stderr, "can not specify both"
				" verbose and daemonize\n");
			goto failure;
		}
		if (!strlen(logfname))
			fprintf(stderr, "verbose without logfile?\n");
	}

	if (daemonize && !strlen(logfname)) {
		fprintf(stderr, "daemon needs a logfile\n");
		goto failure;
	}

	if (log_settle(logfname, loglevel, "%F %T", logsync, verbose)) {
		fprintf(stderr, "failed to set log: %s\n", strerror(errno));
		goto failure;
	}

	if (strlen(pidfname)) {
		pidfd = fopen(pidfname, "wx");
		if (!pidfd) {
			nurs_log(NURS_ERROR, "failed to create pidfile: %s\n",
				strerror(errno));
			goto failure;
		}
	}

	if (daemonize && daemon(0, 0)) {
		nurs_log(NURS_ERROR, "failed to daemonize: %s",
			 strerror(errno));
		goto close_pidfd;
	}

	if (pidfd) {
		if (fprintf(pidfd, "%d\n", getpid()) < 0) {
			nurs_log(NURS_ERROR, "failed to write pid: %s\n",
				strerror(errno));
			goto close_pidfd;
		}
		if (fclose(pidfd)) {
			nurs_log(NURS_ERROR, "failed to close pidfile: %s\n",
				 strerror(errno));
			goto failure;
		}
		pidfd = NULL;
	}

	ret = nurs(cfname);

	if (strlen(pidfname)) {
		if (unlink(pidfname)) {
			nurs_log(NURS_ERROR, "failed to unlink pidfile: %s\n",
				 strerror(errno));
			goto failure;
		}
	}

	if (nurs_close_log()) {
		nurs_log(NURS_ERROR, "failed to close log: %s\n",
			 strerror(errno));
		goto failure;
	}

	ret = EXIT_SUCCESS;

close_pidfd:
	if (pidfd)
		fclose(pidfd);
failure:
	return ret;
}
#endif

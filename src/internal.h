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
#ifndef _NURS_INTERNAL_H
#define _NURS_INTERNAL_H

#include <dlfcn.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <nurs/nurs.h>

/* no check hidden_visibility_attribute */
#define __visible		__attribute__((visibility("default")))
#define EXPORT_SYMBOL(x)	typeof(x) (x) __visible

/*
 * config
 */
struct nurs_config_entry {
	struct nurs_config_entry_def	*def;
	int				hit;	/* need duplication? */
	union {
		int			integer;
		bool			boolean;
		char			string[NURS_STRING_LEN + 1];
	};
};

struct nurs_config {
	uint8_t				len;
	bool				release_defs; /* json? */
	struct nurs_config_entry	keys[];
};

int config_fopen(const char *fname);
int config_fclose(void);
struct nurs_config *config_parse_section(const char *section,
					 struct nurs_config_def *defs);
const char *get_word(const char *line, const char *delim,
		     bool trim, char *buf, size_t buflen);

/*
 * keys
 */
#define NURS_KEY_F_VALID	((uint16_t)(1<<0))

struct nurs_output_key {
	struct nurs_output_key_def *def;	/* reference, or copy? see other .def too */
	uint16_t		flags;		/* only valid or not currently */
	union {
		bool		b;
		int8_t		i8;
		int16_t		i16;
		int32_t		i32;
		int64_t		i64;
		uint8_t		u8;
		uint16_t	u16;
		uint32_t	u32;
		uint64_t	u64;
		struct in6_addr	in6;
		in_addr_t	in4;
		void		*ptr; /* pointer, embed */
		char		*string;
		char		umax[16]; /* in6_addr size */
	};
};

/* check nurs_ioset_(input|output)::ioset.c after
 * updating below - nurs_(input|output) */
struct nurs_output {
	uint16_t		len;
	struct nurs_output_key	*keys;
};

struct nurs_input {
	uint16_t		len;
	struct nurs_output_key	**keys;
};

struct nurs_producer;

/*
 * ioset
 */
struct nurs_ioset {
	struct list_head	list;	/* head: producer.iosets */
	size_t			size;	/* for munmap */
	struct nurs_producer	*producer;

	int			refcnt;
	pthread_mutex_t		refcnt_mutex;
	pthread_cond_t		refcnt_condv;

	/* [
	 *   okeys: producer plugin output
	 *   ikeys: filter1 plugin input
	 *   okeys: filter1 plugin output
	 *   ...
	 *   ikeys: filter# plugin input
	 *   okeys: filter# plugin output
	 *   ikeys: consumer plugin input
	 * ] */
	uint8_t			len;
	struct nurs_output	base[];
};

struct nurs_input *ioset_input(struct nurs_ioset *ioset, uint8_t idx);
struct nurs_output *ioset_output(struct nurs_ioset *ioset, uint8_t idx);
int ioset_create(struct nurs_producer *producer, size_t num);
int ioset_destroy(struct nurs_producer *producer);
struct nurs_ioset *ioset_get(struct nurs_producer *producer);
int ioset_put(struct nurs_producer *producer, struct nurs_ioset *ioset);

/*
 * plugin
 */
enum nurs_plugin_type {
	NURS_PLUGIN_T_NONE,
	NURS_PLUGIN_T_PRODUCER,
	NURS_PLUGIN_T_FILTER,
	NURS_PLUGIN_T_CONSUMER,
	NURS_PLUGIN_T_COVETER,
	NURS_PLUGIN_T_MAX,
};

enum nurs_plugin_ioflag {
	NURS_PLUGIN_IOF_INPUT		= (1<<0),
	NURS_PLUGIN_IOF_OUTPUT		= (1<<1),
	NURS_PLUGIN_IOF_WILDINPUT	= (1<<2),
};

struct nurs_plugin {
	enum nurs_plugin_type		type;
	struct list_head 		list;
	int				refcnt;
	char				id[NURS_NAME_LEN + 1];
	struct nurs_config		*config;
	struct nurs_plugin_def		*def;
};

struct nurs_plugin_ops {
	enum nurs_plugin_type type;
	uint16_t ioflags;
	struct nurs_plugin *(*create)(struct nurs_plugin_def *def, const char *id);
	int (*destroy)(struct nurs_plugin *plugin);
	int (*resolve_cb)(struct nurs_plugin_def *def);
	int (*check)(const struct nurs_plugin_def *def);
	int (*show)(const struct nurs_plugin_def *def);
};

struct nurs_producer {
	enum nurs_plugin_type		type;
	struct list_head 		list;
	int				refcnt;
	char				id[NURS_NAME_LEN + 1];
	struct nurs_config		*config;
	struct nurs_producer_def	*def;	/* reference, not copy */

	struct list_head	plist;		/* producers list */
	struct list_head	iosets;		/* struct nurs_ioset */
	size_t			iosets_size;	/* for munmap */
	pthread_mutex_t		iosets_mutex;
	pthread_cond_t		iosets_condv;

	/* list of stack which root is this producer plugin */
	int			nstacks;
	struct list_head 	stacks;		/* struct nurs_stack */
};

struct nurs_filter {
	enum nurs_plugin_type		type;
	struct list_head 		list;
	int				refcnt;
	char				id[NURS_NAME_LEN + 1];
	struct nurs_config		*config;
	struct nurs_filter_def		*def;	/* reference, not copy */

	pthread_mutex_t			mutex;	/* mtsafe */
};

struct nurs_consumer {
	enum nurs_plugin_type		type;
	struct list_head 		list;
	int				refcnt;
	char				id[NURS_NAME_LEN + 1];
	struct nurs_config		*config;
	struct nurs_consumer_def	*def;	/* reference, not copy */

	pthread_mutex_t			mutex;	/* mtsafe */
};

struct nurs_wildlist_element {
	struct list_head		list;
	struct nurs_input_key_def	keydef;
};

struct nurs_coveter { /* aka wildcard consumer */
	enum nurs_plugin_type		type;
	struct list_head 		list;
	int				refcnt;
	char				id[NURS_NAME_LEN + 1];
	struct nurs_config		*config;
	struct nurs_coveter_def		*def;	/* reference, not copy */

	pthread_mutex_t			mutex;	/* mtsafe */

	struct list_head		wildlist;
	struct nurs_input_def		*input_def;
	struct nurs_input		*input_template;
};

#define plugin_context(x) ((void *)((uintptr_t)(x) + (uintptr_t)sizeof(typeof(*x))))

struct nurs_dl_handle {
	int	refcnt;
	void	*h;
};

const void *plugin_resolve_symbol(const char *name, const char *symbol);
struct nurs_plugin *plugin_get(enum nurs_plugin_type type,
			       const char *name, const char *id);
int plugin_put(struct nurs_plugin *plugin);
struct nurs_producer *
	plugin_producer_get(const char *name, const char *id);
struct nurs_filter *
	plugin_filter_get(const char *name, const char *id);
struct nurs_consumer *
	plugin_consumer_get(const char *name, const char *id);
struct nurs_coveter *
	plugin_coveter_get(const char *name, const char *id);
int plugin_producer_put(struct nurs_producer *producer);
int plugin_filter_put(struct nurs_filter *filter);
int plugin_consumer_put(struct nurs_consumer *consumer);
int plugin_coveter_put(struct nurs_coveter *coveter);

int plugin_config_parser(const char *line);

int plugin_unload(void);

struct nurs_plugin *
plugin_cb(const struct nurs_plugin *from, const char *name,
	  enum nurs_return_t (*cb)(struct nurs_plugin *, void *),
	  void *data, bool force);
struct nurs_producer *
producer_cb(const char *name,
	    enum nurs_return_t (*cb)(struct nurs_producer *, void *),
	    void *data, bool force);
int plugins_organize(const char *fname);
int plugins_disorganize(bool force);
int plugins_start(void);
int plugins_stop(bool force);
int plugins_signal(uint32_t signum, bool force);
void plugins_order_group(void);

/* for plugin_*.c */
int plugin_show_output(const struct nurs_output_def *def);
int plugin_show_input(const struct nurs_input_def *def);
int plugin_check_input(const char *plname, const struct nurs_input_def *input);
int plugin_check_output(const char *plname, const struct nurs_output_def *output);
int plugin_resolve_output_destructor(void *handle, struct nurs_output_def *output);
int plugin_resolve_cbsym(struct nurs_plugin_def *def, const char *name, void **p);

int plugin_resolve_cbsym(struct nurs_plugin_def *def, const char *name, void **p);
int plugin_resolve_output_destructor(void *handle, struct nurs_output_def *output);

int register_plugin_ops(struct nurs_plugin_ops *op);
int producer_init(void);
int filter_init(void);
int consumer_init(void);
int coveter_init(void);
int plugin_init(void);
int plugin_unregister_all(void);

/*
 * stack
 */
struct nurs_stack {
	struct list_head 	list;		/* head: nurs_producer */
	struct list_head 	elements;	/* nurs_stack_element */
	char			*name;	/* no thought, this stack name? - XXX: thread.c use it for log */
	// struct nurs_producer *spl;
};

struct nurs_stack_element {
	struct list_head	list;	/* head: nurs_stack.elements */
	struct nurs_plugin	*plugin;
	uint8_t			idx;
	uint8_t			odx;
};

#define stack_element_producer(e)	((struct nurs_producer *)((e)->plugin))
#define stack_element_filter(e)		((struct nurs_filter *)((e)->plugin))
#define stack_element_consumer(e)	((struct nurs_consumer *)((e)->plugin))
#define stack_element_coveter(e)	((struct nurs_coveter *)((e)->plugin))

#define for_each_stack_element(_producer, _stack, _element)	\
	list_for_each_entry(_stack, &_producer->stacks, list)	\
	list_for_each_entry(_element, &_stack->elements, list)

#define for_each_stack_element_safe(_producer, _stack, _element, _tmp)	\
	list_for_each_entry(_stack, &_producer->stacks, list)		\
	list_for_each_entry_safe(_element, _tmp, &_stack->elements, list)

int stack_config_parser(const char *line); /* nurs_config_parser_t */
int stack_settle(size_t nioset);
int stack_unsettle(void);

/*
 * worker thread
 */
enum nurs_workers_state {
	NURS_WORKERS_RUNNABLE,
	NURS_WORKERS_SUSPEND,
	NURS_WORKERS_STOP,
};

struct nurs_worker {
	struct list_head	list;
	struct list_head	runnable_list;
	pthread_t		tid;
	pthread_mutex_t		mutex;	/* stacks, runnable and ioset */
	pthread_cond_t		condv;	/* runnable and ioset update */
	bool			runnable;
	int			retval;		/* errno in thread */

	/* from producer plugin to this thread */
	struct nurs_ioset	*ioset;
	struct nurs_producer	*producer;
	struct nurs_stack	*stack;
};

int workers_start(size_t nthreads);
int workers_suspend(void);
int workers_resume(void);
int workers_stop(void);

/* for tests */
struct nurs_worker *worker_get(void);
int worker_put(struct nurs_worker *worker);
void nurs_output_set_validate(bool b);

/*
 * fd
 */
struct nurs_fd {
	int		fd;
	uint16_t	when;
	nurs_fd_cb_t	cb;
	void		*data;
};

int nfd_init(void);
int nfd_fini(void);
int nfd_loop(void);
int nfd_cancel(void);

struct nurs_timer {
	struct nurs_fd		*nfd;
	nurs_timer_cb_t		cb;
	void			*data;
};

/*
 * misc
 */
#define NURS_SYSLOG_FNAME "syslog"
#define NURS_SYSLOG_FD    (FILE *)(-1)

int log_settle(const char *fname, int level, char *time_format,
	       bool sync, bool verbose);
int nurs_close_log(void);
int log_config_parser(const char *line);
int signal_nfd_init(void);
int signal_nfd_fini(void);

int useless_init(size_t nthread);
int useless_fini(void);

#define NURS_ALIGNTO		4
#define NURS_ALIGN(len)		(((len) + NURS_ALIGNTO - 1) & ~(NURS_ALIGNTO - 1))

#define NURS_IOSET_ALIGN(len)	(((len) + sizeof(struct nurs_ioset) - 1) & ~(sizeof(struct nurs_ioset) - 1))


/*
 * nssocket
 */
int nurs_reap_nssocket(pid_t pid);
void nurs_fini_nssocket(int force);
/*
 * boot option
 */
struct nurs_options {
	char *logfname;
	int loglevel;
	FILE *logfd;
	bool logsync;

	bool verbose;
	bool daemonize;
	char *pidfname;
};

/*		verbose	daemon	pidfname
 * verbose	-	F	F
 * daemon	F	-	T
 * pidfname	F	T	-
 *
 * default: (if not specified)
 *   logfname:  use stderr as logfd
 *   loglevel:  INFO
 *   logsync:   false
 *   verbose:   false
 *   daemonize: false
 *   pidfname:  no pid file
 */

#endif /* _NURS_INTERNAL_H */

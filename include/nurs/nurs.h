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
#ifndef _NURS_H
#define _NURS_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>
#include <syslog.h>
#include <netinet/in.h>

#include <jansson.h>

#include <nurs/list.h>

#define VERSION "0.1" /* not include config.h */

#define NURS_NAME_LEN	127
#define NURS_STRING_LEN	511

/*
 * config
 */
enum nurs_config_type {
	NURS_CONFIG_T_NONE,
	NURS_CONFIG_T_INTEGER,
	NURS_CONFIG_T_BOOLEAN,
	NURS_CONFIG_T_STRING,
	NURS_CONFIG_T_CALLBACK,
};

enum nurs_config_flag {
	NURS_CONFIG_F_NONE	= 0,
	NURS_CONFIG_F_MANDATORY	= (1<<0),
	NURS_CONFIG_F_MULTI	= (1<<1),
	/* NURS_CONFIG_F_PROTECTED	= (1<<2), */
};

/* return negative errno on error */
typedef int (*nurs_config_parser_t)(const char *s);

struct nurs_config_entry_def {
	uint16_t		type;		/* type; see above */
	uint16_t		flags;		/* tune setup of option */
	char			name[NURS_NAME_LEN + 1];
	union {
		bool		boolean;
		int		integer;
		char		string[NURS_STRING_LEN + 1];
		struct {
			union {
				nurs_config_parser_t	parser;
				char parser_cb_s[NURS_NAME_LEN + 1];
			};
			bool	resolve_parser;
		};
	};
};

struct nurs_config_def {
	uint8_t		len;
	struct nurs_config_entry_def keys[];
};

struct nurs_config;

int nurs_config_integer(const struct nurs_config *config, uint8_t idx);
bool nurs_config_boolean(const struct nurs_config *config, uint8_t idx);
const char *nurs_config_string(const struct nurs_config *config, uint8_t idx);
uint8_t nurs_config_len(const struct nurs_config *config);
uint16_t nurs_config_type(const struct nurs_config *config, uint8_t idx);
uint8_t nurs_config_index(const struct nurs_config *config, const char *name);

/*
 * key
 */
enum nurs_key_type {
	NURS_KEY_T_NONE,
	NURS_KEY_T_BOOL,	/* .b */
	NURS_KEY_T_INT8,	/* .i8 */
	NURS_KEY_T_INT16,	/* .i16 */
	NURS_KEY_T_INT32,	/* .i32 */
	NURS_KEY_T_INT64,	/* .i64 */
	NURS_KEY_T_UINT8,	/* .ui8 */
	NURS_KEY_T_UINT16,	/* .ui16 */
	NURS_KEY_T_UINT32,	/* .ui32 */
	NURS_KEY_T_UINT64,	/* .ui64 */
	NURS_KEY_T_INADDR,	/* .in4 XXX: = NURS_KEY_T_UINT32? */
	NURS_KEY_T_IN6ADDR,	/* .in6 */
	NURS_KEY_T_POINTER,	/* .ptr */

	/* require .type field */
	NURS_KEY_T_STRING,	/* .ptr, null terminated, len */
	NURS_KEY_T_EMBED,	/* .ptr, must have len */
	NURS_KEY_T_MAX,
};

enum nurs_ikey_flag {
	NURS_IKEY_F_REQUIRED	= (1<<1),	/* & OKEY_F_ALWAYS */
	NURS_IKEY_F_OPTIONAL	= (1<<2),
	NURS_IKEY_F_ANY		= (1<<3),
};

enum nurs_okey_flag {
	/* no flags means the value is scalar and will always be set */
	NURS_OKEY_F_ALWAYS	= (0x0100<<0),	/* always contains valid result */
	NURS_OKEY_F_FREE	= (0x0100<<1),	/* ptr needs to be free()d */
	NURS_OKEY_F_DESTRUCT	= (0x0100<<2),	/* call destructor, .type must be POINTER */
	NURS_OKEY_F_OPTIONAL	= (0x0100<<3),	/* this key is optional */

	/* NURS_OKEY_F_INACTIVE	= (0x0100<<4),	   marked as inactive (i.e. totally
						 * to be ignored by everyone) */
};

typedef void (*key_destructor_t)(void *);

struct nurs_key_def {
	uint16_t type;
	uint16_t flags;
	char name[NURS_NAME_LEN + 1];
};

struct nurs_output_key_def {
	uint16_t	type;
	uint16_t	flags;
	char		name[NURS_NAME_LEN + 1];

	uint32_t	len;

	/* IETF IPFIX attribute ID */
	struct {
		uint32_t	vendor;
		uint16_t	field_id;
	} ipfix;

	/* Store field name for Common Information Model */
	char cim_name[NURS_NAME_LEN + 1];

	/* destructor for this key */
	bool resolve_destructor;
	union {
		key_destructor_t	destructor;
		char			destructor_cb_s[NURS_NAME_LEN + 1];
	};
};

struct nurs_output_def {
	uint16_t			len;
	struct nurs_output_key_def	keys[];
};

struct nurs_input_key_def {
	uint16_t	type;
	uint16_t	flags;
	char		name[NURS_NAME_LEN + 1];
};

struct nurs_input_def {
	uint16_t			len;
	struct nurs_input_key_def	keys[];
};

struct nurs_input;
/* sorry for bad naming...
 * input_len returns how many keys in input, and
 * input_size returns length of key specified by name */
uint16_t nurs_input_len(const struct nurs_input *input);
uint32_t nurs_input_size(const struct nurs_input *input, uint16_t idx);

const char *nurs_input_name(const struct nurs_input *input, uint16_t idx);
uint16_t nurs_input_type(const struct nurs_input *input, uint16_t idx);
uint16_t nurs_input_index(const struct nurs_input *input, const char *name);

bool nurs_input_bool(const struct nurs_input *input, uint16_t idx);
uint8_t nurs_input_u8(const struct nurs_input *input, uint16_t idx);
uint16_t nurs_input_u16(const struct nurs_input *input, uint16_t idx);
uint32_t nurs_input_u32(const struct nurs_input *input, uint16_t idx);
uint64_t nurs_input_u64(const struct nurs_input *input, uint16_t idx);
in_addr_t nurs_input_in_addr(const struct nurs_input *input, uint16_t idx);
const struct in6_addr *
	nurs_input_in6_addr(const struct nurs_input *input, uint16_t idx);
const void *nurs_input_pointer(const struct nurs_input *input, uint16_t idx);
const char *nurs_input_string(const struct nurs_input *input, uint16_t idx);
bool nurs_input_is_valid(const struct nurs_input *input, uint16_t idx);
bool nurs_input_is_active(const struct nurs_input *input, uint16_t idx);
uint32_t nurs_input_ipfix_vendor(const struct nurs_input *input, uint16_t idx);
uint16_t nurs_input_ipfix_field(const struct nurs_input *input, uint16_t idx);
const char *nurs_input_cim_name(const struct nurs_input *input, uint16_t idx);

struct nurs_output;
uint16_t nurs_output_len(const struct nurs_output *output);
uint32_t nurs_output_size(const struct nurs_output *output, uint16_t idx);
uint16_t nurs_output_type(const struct nurs_output *output, uint16_t idx);
uint16_t nurs_output_index(const struct nurs_output *output, const char *name);

int nurs_output_set_bool(struct nurs_output *output,
			 uint16_t idx, bool value);
int nurs_output_set_u8(struct nurs_output *output,
		       uint16_t idx, uint8_t value);
int nurs_output_set_u16(struct nurs_output *output,
			uint16_t idx, uint16_t value);
int nurs_output_set_u32(struct nurs_output *output,
			uint16_t idx, uint32_t value);
int nurs_output_set_u64(struct nurs_output *output,
			uint16_t idx, uint64_t value);
int nurs_output_set_in_addr(struct nurs_output *output,
			    uint16_t idx, in_addr_t value);
int nurs_output_set_in6_addr(struct nurs_output *output,
			     uint16_t idx, const struct in6_addr *value);
int nurs_output_set_pointer(struct nurs_output *output,
			    uint16_t idx, const void *value);
int nurs_output_set_string(struct nurs_output *output,
			   uint16_t idx, const char *value);
void *nurs_output_pointer(const struct nurs_output *output, uint16_t idx);
int nurs_output_set_valid(struct nurs_output *output, uint16_t idx);


/*
 * plugin
 */
enum nurs_return_t {
	NURS_RET_ERROR	= -1,
	NURS_RET_STOP	= -2,
	NURS_RET_OK	= 0,
};

struct nurs_plugin;
struct nurs_producer;

typedef enum nurs_return_t
	(*nurs_start_t)(const struct nurs_plugin *plugin);
typedef enum nurs_return_t
	(*nurs_producer_start_t)(struct nurs_producer *producer);

typedef enum nurs_return_t
	(*nurs_stop_t)(const struct nurs_plugin *plugin);
typedef enum nurs_return_t
	(*nurs_producer_stop_t)(struct nurs_producer *producer);
/*
 * typedef enum nurs_return_t
 *	(*nurs_signal_t)(const struct nurs_plugin *plugin,
 *			 uint32_t signum, void *cdata);
 * typedef enum nurs_return_t
 *	(*nurs_producer_signal_t)(struct nurs_producer *producer,
 *				  uint32_t signum, void *cdata);
 */

typedef enum nurs_return_t
	(*nurs_signal_t)(const struct nurs_plugin *plugin, uint32_t signum);
typedef enum nurs_return_t
	(*nurs_producer_signal_t)(struct nurs_producer *producer, uint32_t signum);


typedef enum nurs_return_t
	(*nurs_organize_t)(const struct nurs_plugin *plugin);
typedef enum nurs_return_t
	(*nurs_coveter_organize_t)(const struct nurs_plugin *plugin,
				   const struct nurs_input *template);
typedef enum nurs_return_t
	(*nurs_producer_organize_t)(struct nurs_producer *producer);

typedef enum nurs_return_t
	(*nurs_disorganize_t)(const struct nurs_plugin *plugin);
typedef enum nurs_return_t
	(*nurs_producer_disorganize_t)(struct nurs_producer *producer);

typedef enum nurs_return_t
	(*nurs_filter_interp_t)(const struct nurs_plugin *plugin,
				const struct nurs_input *input,
				struct nurs_output *output);
typedef enum nurs_return_t
	(*nurs_consumner_interp_t)(const struct nurs_plugin *plugin,
				   const struct nurs_input *input);
enum nurs_plugin_type;
struct nurs_dl_handle;

struct nurs_plugin_def {
	/* internal use */
	struct list_head	list;
	struct nurs_dl_handle	*dlh;
	int			type;

	bool			resolve_callback;
	bool			dynamic;	/* allocate by calloc? */
	int16_t			refcnt;

	char			version[NURS_NAME_LEN + 1];	/* required */
	char			name[NURS_NAME_LEN + 1];	/* required */
	uint16_t		context_size;			/* optional */
	struct nurs_config_def	*config_def;			/* optional */
};

struct nurs_producer_def {
	struct list_head 	list;
	struct nurs_dl_handle	*dlh;
	int			type;

	bool			resolve_callback;
	bool			dynamic;
	int16_t			refcnt;

	char			version[NURS_NAME_LEN + 1];
	char			name[NURS_NAME_LEN + 1];
	uint16_t		context_size;
	struct nurs_config_def	*config_def;

	struct nurs_output_def	*output_def;		/* required */

	union {						/* required */
		nurs_producer_organize_t	organize;
		/* _cb_s are for dynamic cb assignment from string */
		char			organize_cb_s[NURS_NAME_LEN + 1];
	};
	union {						/* required */
		nurs_producer_disorganize_t	disorganize;
		/* _cb_s are for dynamic cb assignment from string */
		char			disorganize_cb_s[NURS_NAME_LEN + 1];
	};
	union {
		nurs_producer_start_t	start;		/* optional */
		char			start_cb_s[NURS_NAME_LEN + 1];
	};
	union {
		nurs_producer_stop_t	stop;		/* optional */
		char			stop_cb_s[NURS_NAME_LEN + 1];
	};
	union {
		nurs_producer_signal_t	signal;		/* optional */
		char			signal_cb_s[NURS_NAME_LEN + 1];
	};
};

struct nurs_filter_def {
	struct list_head 	list;
	struct nurs_dl_handle	*dlh;
	int 			type;

	bool			resolve_callback;
	bool			dynamic;
	int16_t			refcnt;

	char			version[NURS_NAME_LEN + 1];
	char			name[NURS_NAME_LEN + 1];
	uint16_t		context_size;
	struct nurs_config_def	*config_def;

	bool			mtsafe;			/* default false */
	struct nurs_input_def	*input_def;		/* required */
	struct nurs_output_def	*output_def;		/* required */

	union {						/* optional */
		nurs_organize_t		organize;
		char			organize_cb_s[NURS_NAME_LEN + 1];
	};
	union {						/* optional */
		nurs_disorganize_t	disorganize;
		char			disorganize_cb_s[NURS_NAME_LEN + 1];
	};
	union {						/* optional */
		nurs_start_t		start;
		char			start_cb_s[NURS_NAME_LEN + 1];
	};
	union {						/* optional */
		nurs_stop_t		stop;
		char			stop_cb_s[NURS_NAME_LEN + 1];
	};
	union {						/* required */
		nurs_filter_interp_t	interp;
		char			interp_cb_s[NURS_NAME_LEN + 1];
	};
	union {						/* optional */
		nurs_signal_t		signal;
		char			signal_cb_s[NURS_NAME_LEN + 1];
	};
};

struct nurs_consumer_def {
	struct list_head 	list;
	struct nurs_dl_handle	*dlh;
	int			type;

	bool			resolve_callback;
	bool			dynamic;
	int16_t			refcnt;

	char			version[NURS_NAME_LEN + 1];
	char			name[NURS_NAME_LEN + 1];
	uint16_t		context_size;
	struct nurs_config_def	*config_def;

	bool			mtsafe;			/* default false */
	struct nurs_input_def	*input_def;		/* required */

	union {						/* optional */
		nurs_organize_t		organize;
		char			organize_cb_s[NURS_NAME_LEN + 1];
	};
	union {						/* optional */
		nurs_disorganize_t	disorganize;
		char			disorganize_cb_s[NURS_NAME_LEN + 1];
	};
	union {						/* optional */
		nurs_start_t		start;
		char			start_cb_s[NURS_NAME_LEN + 1];
	};
	union {						/* optional */
		nurs_stop_t		stop;
		char			stop_cb_s[NURS_NAME_LEN + 1];
	};
	union {						/* required */
		nurs_consumner_interp_t	interp;
		char			interp_cb_s[NURS_NAME_LEN + 1];
	};
	union {						/* optional */
		nurs_signal_t		signal;
		char			signal_cb_s[NURS_NAME_LEN + 1];
	};
};

struct nurs_coveter_def {
	struct list_head 	list;
	struct nurs_dl_handle	*dlh;
	int 			type;

	bool			resolve_callback;
	bool			dynamic;
	int16_t			refcnt;

	char			version[NURS_NAME_LEN + 1];
	char			name[NURS_NAME_LEN + 1];
	uint16_t		context_size;
	struct nurs_config_def	*config_def;

	bool			mtsafe;			/* default false */

	union {						/* optional */
		nurs_coveter_organize_t	organize;
		char			organize_cb_s[NURS_NAME_LEN + 1];
	};
	union {						/* optional */
		nurs_disorganize_t	disorganize;
		char			disorganize_cb_s[NURS_NAME_LEN + 1];
	};
	union {						/* optional */
		nurs_start_t		start;
		char			start_cb_s[NURS_NAME_LEN + 1];
	};
	union {						/* optional */
		nurs_stop_t		stop;
		char			stop_cb_s[NURS_NAME_LEN + 1];
	};
	union {						/* required */
		nurs_consumner_interp_t	interp;
		char			interp_cb_s[NURS_NAME_LEN + 1];
	};
	union {						/* optional */
		nurs_signal_t		signal;
		char			signal_cb_s[NURS_NAME_LEN + 1];
	};
};

int nurs_producer_register(struct nurs_producer_def *def);
int nurs_filter_register(struct nurs_filter_def *def);
int nurs_consumer_register(struct nurs_consumer_def *def);
int nurs_coveter_register(struct nurs_coveter_def *def);
int nurs_producer_unregister(struct nurs_producer_def *def);
int nurs_producer_unregister_name(const char *name);
int nurs_filter_unregister(struct nurs_filter_def *def);
int nurs_filter_unregister_name(const char *name);
int nurs_consumer_unregister(struct nurs_consumer_def *def);
int nurs_consumer_unregister_name(const char *name);
int nurs_coveter_unregister(struct nurs_coveter_def *def);
int nurs_coveter_unregister_name(const char *name);

struct nurs_producer_def *
nurs_producer_register_json(json_t *json, uint16_t context_size, bool enlist);
struct nurs_filter_def *
nurs_filter_register_json(json_t *json, uint16_t context_size, bool enlist);
struct nurs_consumer_def *
nurs_consumer_register_json(json_t *json, uint16_t context_size, bool enlist);
struct nurs_coveter_def *
nurs_coveter_register_json(json_t *json, uint16_t context_size, bool enlist);

int nurs_producer_unregister_json(json_t *json);
int nurs_filter_unregister_json(json_t *json);
int nurs_consumer_unregister_json(json_t *json);
int nurs_coveter_unregister_json(json_t *json);

struct nurs_producer_def *
	nurs_producer_register_jsons(const char *input, uint16_t context_size);
struct nurs_filter_def *
	nurs_filter_register_jsons(const char *input, uint16_t context_size);
struct nurs_consumer_def *
	nurs_consumer_register_jsons(const char *input, uint16_t context_size);
struct nurs_coveter_def *
	nurs_coveter_register_jsons(const char *input, uint16_t context_size);
struct nurs_producer_def *
	nurs_producer_register_jsonf(const char *fname, uint16_t context_size);
struct nurs_filter_def *
	nurs_filter_register_jsonf(const char *fname, uint16_t context_size);
struct nurs_consumer_def *
	nurs_consumer_register_jsonf(const char *fname, uint16_t context_size);
struct nurs_coveter_def *
	nurs_coveter_register_jsonf(const char *fname, uint16_t context_size);
int nurs_plugins_register_jsonf(const char *fname);
int nurs_plugins_unregister_jsonf(const char *fname);

void *nurs_producer_context(const struct nurs_producer *producer);
void *nurs_plugin_context(const struct nurs_plugin *plugin);
const struct nurs_config *nurs_producer_config(const struct nurs_producer *producer);
const struct nurs_config *nurs_plugin_config(const struct nurs_plugin *plugin);

/**
 *  no doxygen comment below
 */

/*
 * worker
 */
enum nurs_return_t
nurs_publish(struct nurs_output *output);

/*
 * ioset
 */
struct nurs_output *nurs_get_output(struct nurs_producer *producer);
int nurs_put_output(struct nurs_output *output);

/*
 * fd
 */
enum nurs_fd_event {
	NURS_FD_F_READ		= 0x0001,
	NURS_FD_F_WRITE		= 0x0002,
	NURS_FD_F_EXCEPT	= 0x0004,
};

struct nurs_fd;
typedef enum nurs_return_t
	(*nurs_fd_cb_t)(int fd, uint16_t when, void *data);

struct nurs_fd *nurs_fd_create(int fd, uint16_t when);
void nurs_fd_destroy(struct nurs_fd *nfd);
int nurs_fd_register(struct nurs_fd *nfd, nurs_fd_cb_t cb, void *data);
int nurs_fd_unregister(struct nurs_fd *nfd);

/*
 * timer
 */
struct nurs_timer;
typedef enum nurs_return_t
	(*nurs_timer_cb_t)(struct nurs_timer *timer, void *data);

struct nurs_timer *nurs_timer_create(const nurs_timer_cb_t cb, void *data);
int nurs_timer_destroy(struct nurs_timer *timer);
int nurs_timer_add(struct nurs_timer *timer, time_t sc);
int nurs_itimer_add(struct nurs_timer *timer, time_t ini, time_t per);
int nurs_timer_del(struct nurs_timer *timer);
int nurs_timer_pending(struct nurs_timer *timer);

/*
 * misc
 */
#define DEBUG_PTHREAD
#ifdef DEBUG_PTHREAD
#define NURS_MUTEX_INITIALIZER PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP
#define NURS_MUTEX_ATTR PTHREAD_MUTEX_ERRORCHECK_NP
#else
#define NURS_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#define NURS_MUTEX_ATTR PTHREAD_MUTEX_FAST_NP
#endif

#define nurs_mutex_lock(m) ({						\
      int _ret = pthread_mutex_lock((m));				\
      if (_ret) {							\
	      nurs_log(NURS_FATAL, "pthread_mutex_lock: %s\n", _sys_errlist[_ret]); \
	      errno = _ret;						\
      }									\
      _ret; })
#define nurs_mutex_unlock(m) ({						\
	int _ret = pthread_mutex_unlock((m));				\
	if (_ret) {							\
		nurs_log(NURS_FATAL, "pthread_mutex_unlock: %s\n", _sys_errlist[_ret]); \
		errno = _ret;						\
	}								\
	_ret; })
#define nurs_cond_signal(c) ({						\
	int _ret = pthread_cond_signal((c));				\
	if (_ret) {							\
		nurs_log(NURS_FATAL, "pthread_cond_signal: %s\n", _sys_errlist[_ret]); \
		errno = _ret;						\
	}								\
	_ret; })
#define nurs_cond_broadcast(c) ({					\
	int _ret = pthread_cond_broadcast((c));				\
	if (_ret) {							\
		nurs_log(NURS_FATAL, "pthread_cond_broadcast: %s\n", _sys_errlist[_ret]); \
		errno = _ret;						\
	}								\
	_ret; })
#define nurs_cond_wait(c, v) ({						\
	int _ret = pthread_cond_wait((c), (v));				\
	if (_ret) {							\
		nurs_log(NURS_FATAL, "pthread_cond_wait: %s\n", _sys_errlist[_ret]); \
		errno = _ret;						\
	}								\
	_ret; })

enum nurs_log_level {
	NURS_DEBUG,
	NURS_INFO,
	NURS_NOTICE,
	NURS_ERROR,
	NURS_FATAL,
	NURS_LOGLEVEL_MAX,
};

void __nurs_log(int level, char *file, int line, const char *message, ...);

#define nurs_log(level, format, args...)			\
	__nurs_log(level, __FILE__, __LINE__, format, ## args)
#define nurs_llog(level, line, format, args...)			\
	__nurs_log(level, __FILE__, line, format, ## args)
#define nurs_flog(level, file, line, format, args...)	\
	__nurs_log(level, file, line, format, ## args)

/* create socket for namespace */
int nurs_nssocket(const char *name, int domain, int type, int protocol);

#endif /* _NURS_H */

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
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"

/**
 * \defgroup nurs config
 * @{
 * struct nurs_config is defined by struct nurs_config_def in plugin definition
 * and acquired by nurs_producer_config() or nurs_plugin_config(). index param
 * specifies the index in struct nurs_config_def.
 */

static FILE *nurs_config_file;

const char *get_word(const char *line, const char *delim,
		     bool trim, char *buf, size_t buflen)
{
	const char *p = line;
	char *b = buf, *limit = buf + buflen - 1;
	int inquote = 0;

	if (trim) for (; isblank(*p); p++);
	for (; *p; p++) {
		if (b > limit) {
			nurs_log(NURS_ERROR, "too long word\n");
			return NULL;
		}

		if (inquote) {
			if (*p == '"') {
				p++;
				inquote = 0;
				break;
			} else if (*p == '\\') {
				if (*++p != '"') {
					nurs_log(NURS_ERROR,
						 "invalid escape\n");
					return NULL;
				}
			}
		} else if (strchr(delim, *p)) {
			break;
		} else if (*p == '"') {
			inquote = 1;
			continue;
		}
		*b++ = *p;
	}

	if (inquote) {
		nurs_log(NURS_ERROR, "unbalanced quote\n");
		return NULL;
	}

	*b-- = '\0';
	if (trim)
		for (; b > buf && isblank(*b); b--)
			*b = '\0';
	return p;
}

/* 0 on success
 * negative: critical error
 * positive: non critical error */
int config_fopen(const char *fname)
{
	if (nurs_config_file) {
		nurs_log(NURS_ERROR, "config file has already been registered\n");
		return EALREADY; /* not negative since it's not fatal */
	}
	if (access(fname, R_OK) != 0) {
		nurs_log(NURS_ERROR, "unable to read file: %s, %s\n",
			 fname, strerror(errno));
		return -errno;
	}
	nurs_config_file = fopen(fname, "r");
	if (!nurs_config_file) {
		nurs_log(NURS_FATAL, "could not open file: %s, %s\n",
			 fname, strerror(errno));
		return -errno;
	}
	return 0;
}

int config_fclose(void)
{
	int ret;

	if (!nurs_config_file) {
		nurs_log(NURS_ERROR, "no config file has opend\n");
		return -EBADF;
	}

	ret = fclose(nurs_config_file);
	if (ret) {
		nurs_log(NURS_ERROR, "could not close config: %s\n",
			 strerror(errno));
		return ret;
	}
	nurs_config_file = NULL;

	return ret;
}

/* success: 0
 * empty line: '\n'
 * new section: 1
 * error: -1
 */
static int parse_config_line(const char *id, int lineno, const char *line,
			     struct nurs_config *config)
{
	struct nurs_config_entry *entry;
	struct nurs_config_entry_def *def;
	const char *p = line;
	char key[NURS_NAME_LEN + 1], value[NURS_STRING_LEN + 1];
	nurs_config_parser_t psr;
	long longval;
	uint8_t i;
	int error;

	for (; isblank(*p); p++);
	if (*p == '\0' || *p == '\n' || *p == '#') return '\n';
	if (*p == '[')	return 1; /* new section */

	/* left key */
	p = get_word(p, "= \t", true, key, NURS_NAME_LEN);
	if (p == NULL)	return -1;

	for (i = 0; i < config->len; i++)
		if (!strncmp(config->keys[i].def->name, key, NURS_NAME_LEN))
			break;
	if (i == config->len) {
		nurs_log(NURS_NOTICE, "no config name[%d] for %s: %s\n",
			 lineno, id, key);
		return '\n'; /* regard as empty line */
	}
	entry = &config->keys[i];
	def = entry->def;

	if (!(def->flags & NURS_CONFIG_F_MULTI) && entry->hit) {
		nurs_log(NURS_ERROR, "only single entry allowed key: %s\n",
			 def->name);
		return -1;
	}

	/* = */
	for (; isblank(*p); p++);
	if (*p++ != '=') {
		nurs_log(NURS_ERROR, "no value (=) found[%d]: %s\n",
			 lineno, key);
		return -1;
	}
	for (; isblank(*p); p++);

	/* right value */
	p = get_word(p, " \t", true, value, NURS_STRING_LEN);
	if (p == NULL)	{
		nurs_log(NURS_ERROR, "no right value? [%d]\n", lineno);
		return -1;
	}
	for (; isblank(*p); p++);
	if (*p != '\0' && *p != '#')
		nurs_log(NURS_NOTICE, "extra value? [%d]: %s\n", lineno, p);

	/* assign to config */
	switch (def->type) {
	case NURS_CONFIG_T_INTEGER:
		errno = 0;
		longval = strtol(value, NULL, 0);
		if (longval >= INT_MAX || longval <= INT_MIN) {
			nurs_log(NURS_ERROR, "over int range[%d]: %s\n",
				 lineno, value);
			return -ERANGE;
		}
		if (errno != 0 && longval) {
			nurs_log(NURS_ERROR, "invalid integer[%d]: %s, %s\n",
				 lineno, value, strerror(errno));
			return -errno;
		}
		if (entry->hit)
			nurs_log(NURS_NOTICE, "override integer key:"
				 " %s, value: %d\n",
				 def->name, entry->integer);
 		entry->integer = (int)longval;
		entry->hit++;
		return 0;
	case NURS_CONFIG_T_BOOLEAN:
		if (entry->hit)
			nurs_log(NURS_NOTICE, "override boolean key:"
				 " %s, value: %s\n",
				 def->name, entry->boolean);
		if (!strcasecmp("off", value) ||
			 !strcasecmp("no", value) ||
			 !strcasecmp("false", value) ||
			 !strcmp("0", value))
			entry->boolean = false;
		else
			entry->boolean = true;
		return 0;
	case NURS_CONFIG_T_STRING:
		if (entry->hit)
			nurs_log(NURS_NOTICE, "override string key:"
				 " %s, value: %s\n",
				 def->name, entry->string);
		strncpy(entry->string, value, NURS_STRING_LEN);
		entry->hit++;
		return 0;
	case NURS_CONFIG_T_CALLBACK:
		psr = def->parser;
		if (def->resolve_parser) {
			psr = plugin_resolve_symbol(id, def->parser_cb_s);
			if (psr == NULL) {
				nurs_log(NURS_ERROR, "could not resolve symbol"
					 ": %s:%s\n", id, def->parser_cb_s);
				return -1;
			}
		}
		error = psr(value);
		if (error) {
			nurs_log(NURS_ERROR, "failed to parse lhs: %s\n", def->name);
			return error;
		}
		entry->hit++;
		return 0;
	default:
		nurs_log(NURS_ERROR, "invalid config type[%s]: %d\n",
			 def->name, def->type);
		return -1;
	}

	return -1;
}

struct nurs_config *
config_parse_section(const char *section, struct nurs_config_def *def)
{
	struct nurs_config *config;
	struct nurs_config_entry *entries;
	char line[1024], word[NURS_NAME_LEN + 1], *newline;
	const char *p;
	uint8_t i;
	int lineno = 0, ret = 0;
	bool error = false;

	if (!def) {
		config = calloc(1, sizeof(struct nurs_config));
		if (!config) {
			nurs_log(NURS_ERROR, "failed to calloc: %s\n",
				 strerror(errno));
			return NULL;
		}
		config->len = 0;
		return config;
	}
	if (nurs_config_file == NULL) {
		nurs_log(NURS_ERROR, "config file has not opened yet\n");
		return NULL;
	}
	if (fseek(nurs_config_file, SEEK_SET, 0) == -1) {
		nurs_log(NURS_ERROR, "could not seek: %s\n", strerror(errno));
		return NULL;
	}

	/* seek section */
	while (1) {
		/* getline? getdelim? requires malloc area? */
		lineno++;
		p = fgets(line, sizeof(line), nurs_config_file);
		if (!p) {
			if (feof(nurs_config_file)) {
				nurs_log(NURS_ERROR, "could not found section"
					 ": %s\n", section);
				return NULL;
			}
			nurs_log(NURS_ERROR, "fgets: %s\n", strerror(errno));
			return NULL;
		}
		for (; isblank(*p); p++);
		if (*p != '[') continue;

		newline = strchr(line, '\n');
		if (newline) *newline = '\0';
		p = get_word(p + 1, "]", false, word, NURS_NAME_LEN);
		if (p == NULL) {
			nurs_log(NURS_ERROR, "unbalanced section ``[''\n");
			return NULL;
		}

		if (!strncmp(word, section, NURS_NAME_LEN))
			break;
	}

	/* create configs from def */
	config = calloc(1, sizeof(struct nurs_config)
			   + sizeof(struct nurs_config_entry) * def->len);
	if (config == NULL) {
		nurs_log(NURS_ERROR, "calloc: %s\n", strerror(errno));
		return NULL;
	}
	config->len = def->len;
	entries = config->keys;
	for (i = 0; i < config->len; i++) {
		entries[i].def = &def->keys[i];
		switch (def->keys[i].type) {
		case NURS_CONFIG_T_INTEGER:
			entries[i].integer = def->keys[i].integer;
			break;
		case NURS_CONFIG_T_BOOLEAN:
			entries[i].boolean = def->keys[i].boolean;
			break;
		case NURS_CONFIG_T_STRING:
			strncpy(entries[i].string, def->keys[i].string,
				NURS_NAME_LEN);
			break;
		case NURS_CONFIG_T_CALLBACK:
			break;
		default:
			nurs_log(NURS_ERROR, "invalid config type: %d\n",
				 def->keys[i].type);
			goto error_free;
		}
	}

	/* process each line in the section */
	do {
		lineno++;
		p = fgets(line, sizeof(line), nurs_config_file);
		if (!p) {
			if (feof(nurs_config_file))
				break;
			nurs_log(NURS_ERROR, "fgets: %s\n", strerror(errno));
			goto error_free;
		}
		newline = strchr(line, '\n');
		if (newline) *newline = '\0';
		ret = parse_config_line(section, lineno, line, config);
		if (ret < 0) {
			nurs_log(NURS_ERROR, "config error at %s:%d %s\n",
				 section, lineno, line);
			error = true;
		}
	} while (ret != 1); /* until new section */
	if (error) goto error_free;

	/* mandatory check */
	for (i = 0; i < config->len; i++) {
		if (entries[i].def->flags & NURS_CONFIG_F_MANDATORY &&
		    !entries[i].hit) {
			nurs_log(NURS_ERROR, "no mandatory entry: %s\n",
				 entries[i].def->name);
			goto error_free;
		}
	}

	return config;
error_free:
	free(config);
	return NULL;
}

/**
 * nurs_config_integer - obtain integer value
 * \param config config obtained via nurs_(producer|plugin)_config
 * \param idx    index in nurs_config_def
 *
 * This function returns integer described in nurs config file
 * On error, it returns 0 and errno is appropriately set.
 */
int nurs_config_integer(const struct nurs_config *config, uint8_t idx)
{
	if (idx >= config->len) {
		errno = ENOENT;
		return 0;
	}
	if (config->keys[idx].def->type != NURS_CONFIG_T_INTEGER) {
		errno = EINVAL;
		return 0;
	}
	return config->keys[idx].integer;
}
EXPORT_SYMBOL(nurs_config_integer);

/**
 * nurs_config_boolean - obtain boolean value
 * \param config config obtained via nurs_(producer|plugin)_config
 * \param idx    index in nurs_config_def
 *
 * This function returns bool value described in nurs config file
 * On error, it returns false and errno is appropriately set.
 */
bool nurs_config_boolean(const struct nurs_config *config, uint8_t idx)
{
	if (idx >= config->len) {
		errno = ENOENT;
		return false;
	}
	if (config->keys[idx].def->type != NURS_CONFIG_T_BOOLEAN) {
		errno = EINVAL;
		return false;
	}
	return config->keys[idx].boolean;
}
EXPORT_SYMBOL(nurs_config_boolean);

/**
 * nurs_config_string - obtain string from config
 * \param config config obtained via nurs_(producer|plugin)_config
 * \param idx    index in nurs_config_def
 *
 * This function returns string (const char *) described in nurs config file
 * On error, it returns NULL and errno is appropriately set.
 */
const char *nurs_config_string(const struct nurs_config *config, uint8_t idx)
{
	if (idx >= config->len) {
		errno = ENOENT;
		return NULL;
	}
	if (config->keys[idx].def->type != NURS_CONFIG_T_STRING) {
		errno = EINVAL;
		return NULL;
	}
	return config->keys[idx].string;
}
EXPORT_SYMBOL(nurs_config_string);

/**
 * nurs_config_len - obtain array size of config
 * \param config config obtained via nurs_(producer|plugin)_config
 *
 * This function returns config array size.
 */
uint8_t nurs_config_len(const struct nurs_config *config)
{
	return config->len;
}
EXPORT_SYMBOL(nurs_config_len);

/**
 * nurs_config_type - obtain config value type
 * \param config config obtained via nurs_(producer|plugin)_config
 * \param idx    index in nurs_config_def
 *
 * This function returns config value type integer, where types are either:
 *	NURS_CONFIG_T_INTEGER
 *	NURS_CONFIG_T_BOOLEAN
 *	NURS_CONFIG_T_STRING
 *	NURS_CONFIG_T_CALLBACK
 * On error, it returns 0 and errno is appropriately set.
 */
uint16_t nurs_config_type(const struct nurs_config *config, uint8_t idx)
{
	if (idx >= config->len) {
		errno = ENOENT;
		return 0;
	}
	return config->keys[idx].def->type;
}
EXPORT_SYMBOL(nurs_config_type);

/**
 * nurs_config_index - obtain index by name
 * \param config config obtained via nurs_(producer|plugin)_config
 * \param name   name of config key
 *
 * This function returns config index specified by name.
 * On error, it returns 0 and errno is appropriately set.
 */
uint8_t nurs_config_index(const struct nurs_config *config, const char *name)
{
	uint8_t i;

	for (i = 0; i < config->len; i++)
		if (!strcmp(config->keys[i].def->name, name))
			return i;

	errno = ENOENT;
	return 0;
}
EXPORT_SYMBOL(nurs_config_index);

/**
 * @}
 */

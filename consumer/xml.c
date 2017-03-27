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
#include <inttypes.h>
#include <string.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#include "../config.h"
#ifdef HAVE_LNFLOG
#include <libnetfilter_log/libnetfilter_log.h>
#endif /* BUILD_NFLOG */
#ifdef HAVE_LNFCT
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif /* BUILD_NFCT */
#ifdef HAVE_LNFACCT
#include <libnetfilter_acct/libnetfilter_acct.h>
#endif /* BUILD_NFACCT */
#ifdef HAVE_LNFT
#include <linux/netfilter/nf_tables.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/gen.h>
#include <libnftnl/common.h>
#endif /* BUILD_NFT */

#include <nurs/nurs.h>

enum {
	XML_CONFIG_FILENAME,
	XML_CONFIG_SYNC,
	XML_CONFIG_TIMESTAMP,
	XML_CONFIG_MAX,
};

static struct nurs_config_def xml_config = {
	.len     = XML_CONFIG_MAX,
	.keys = {
		[XML_CONFIG_FILENAME] = {
			.name  = "filename",
			.type  = NURS_CONFIG_T_STRING,
			.flags = NURS_CONFIG_F_MANDATORY,
		},
		[XML_CONFIG_SYNC] = {
			.name  = "sync",
			.type  = NURS_CONFIG_T_BOOLEAN,
			.flags = NURS_CONFIG_F_NONE,
			.boolean = false,
		},
		[XML_CONFIG_TIMESTAMP] = {
			.name  = "timestamp",
			.type  = NURS_CONFIG_T_BOOLEAN,
			.flags = NURS_CONFIG_F_NONE,
			.boolean = false,
		},
	},
};

#define config_filename(x)	nurs_config_string(nurs_plugin_config(x), XML_CONFIG_FILENAME)
#define config_sync(x)		nurs_config_boolean(nurs_plugin_config(x), XML_CONFIG_SYNC)
#define config_timestamp(x)	nurs_config_boolean(nurs_plugin_config(x), XML_CONFIG_TIMESTAMP)

enum xml_input_keys {
	XML_INPUT_NFCT,
	XML_INPUT_NFLOG,
	XML_INPUT_NFACCT,
	XML_INPUT_NFT_EVENT,
	XML_INPUT_NFT_TABLE,
	XML_INPUT_NFT_RULE,
	XML_INPUT_NFT_CHAIN,
	XML_INPUT_NFT_SET,
	XML_INPUT_NFT_SET_ELEM,
	XML_INPUT_NFT_GEN,
	XML_INPUT_MAX,
};

static struct nurs_input_def xml_input = {
	.len  = XML_INPUT_MAX,
	.keys = {
		[XML_INPUT_NFCT] = {
			.type  = NURS_KEY_T_POINTER,
			.flags = NURS_IKEY_F_ANY,
			.name  = "nfct",
		},
		[XML_INPUT_NFLOG] = {
			.type  = NURS_KEY_T_POINTER,
			.flags = NURS_IKEY_F_ANY,
			.name  = "nflog",
		},
		[XML_INPUT_NFACCT] = {
			.type  = NURS_KEY_T_POINTER,
			.flags = NURS_IKEY_F_ANY,
			.name  = "nfacct",
		},
		[XML_INPUT_NFT_EVENT] = {
			.type  = NURS_KEY_T_UINT32,
			.flags = NURS_IKEY_F_ANY,
			.name  = "nft.event",
		},
		[XML_INPUT_NFT_TABLE] = {
			.type  = NURS_KEY_T_POINTER,
			.flags = NURS_IKEY_F_ANY,
			.name  = "nft.table.object",
		},
		[XML_INPUT_NFT_RULE] = {
			.type  = NURS_KEY_T_POINTER,
			.flags = NURS_IKEY_F_ANY,
			.name  = "nft.rule.object",
		},
		[XML_INPUT_NFT_CHAIN] = {
			.type  = NURS_KEY_T_POINTER,
			.flags = NURS_IKEY_F_ANY,
			.name  = "nft.chain.object",
		},
		[XML_INPUT_NFT_SET] = {
			.type  = NURS_KEY_T_POINTER,
			.flags = NURS_IKEY_F_ANY,
			.name  = "nft.set.object",
		},
		[XML_INPUT_NFT_SET_ELEM] = {
			.type  = NURS_KEY_T_POINTER,
			.flags = NURS_IKEY_F_ANY,
			.name  = "nft.set_elem.object",
		},
		[XML_INPUT_NFT_GEN] = {
			.type  = NURS_KEY_T_POINTER,
			.flags = NURS_IKEY_F_ANY,
			.name  = "nft.gen.object",
		},
	},
};

struct xml_priv {
        FILE *of;
	int (*output_ts)(char *buf, ssize_t size);
};

static int xml_output_ts_none(char *buf, ssize_t size)
{
	return 0;
}

static int xml_output_ts(char *buf, ssize_t size)
{
	struct timeval tv;
	struct tm tm;
	char tmp[64];

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	strftime(tmp, sizeof(tmp), "%FT%T", &tm);

	return snprintf(buf, (size_t)size, "<ts>%s.%06lu</ts>", tmp, tv.tv_usec);
}

static int
xml_output_nfct(struct xml_priv *priv, const struct nurs_input *inp,
		char *buf, ssize_t size)
{
#ifdef HAVE_LNFCT
	const struct nf_conntrack *ct = nurs_input_pointer(inp, XML_INPUT_NFCT);
	int tmp;

	tmp = snprintf(buf, (size_t)size, "<conntrack>");
	if (tmp < 0 || tmp >= size)
		return -1;
	size -= tmp; buf += tmp;

	tmp = priv->output_ts(buf, size);
	if (tmp < 0 || tmp >= size)
		return -1;
	size -= tmp; buf += tmp;

	tmp = nfct_snprintf(buf, (unsigned int)size, ct, 0, NFCT_O_XML,
			    NFCT_OF_SHOW_LAYER3 | NFCT_OF_ID | NFCT_OF_TIME);
	if (tmp < 0 || tmp >= size)
		return -1;
	size -= tmp; buf += tmp;

	tmp = snprintf(buf, (size_t)size, "</conntrack>");
	if (tmp < 0 || tmp >= size)
		return -1;

	return 0;
#else
	return 1;
#endif
}

static int
xml_output_nflog(struct xml_priv *priv, const struct nurs_input *inp,
		  char *buf, ssize_t size)
{
#ifdef HAVE_LNFLOG
	const struct nflog_data *ldata = nurs_input_pointer(inp, XML_INPUT_NFLOG);
	struct nflog_data *obj = (struct nflog_data *)(uintptr_t)ldata;
	int tmp;

	tmp = snprintf(buf, (size_t)size, "<nflog>");
	if (tmp < 0 || tmp >= size)
		return -1;
	size -= tmp; buf += tmp;

	tmp = priv->output_ts(buf, size);
	if (tmp < 0 || tmp >= size)
		return -1;
	size -= tmp; buf += tmp;

	tmp = nflog_snprintf_xml(buf, (size_t)size, obj, NFLOG_XML_ALL);
	if (tmp < 0 || tmp >= size)
		return -1;
	size -= tmp; buf += tmp;

	tmp = snprintf(buf, (size_t)size, "</nflog>");
	if (tmp < 0 || tmp >= size)
		return -1;

	return 0;
#else
	return 1;
#endif
}

static int
xml_output_nfacct(struct xml_priv *priv, const struct nurs_input *inp,
		  char *buf, ssize_t size)
{
#ifdef HAVE_LNFACCT
	const struct nfacct *nfacct = nurs_input_pointer(inp, XML_INPUT_NFACCT);
	struct nfacct *obj = (struct nfacct *)(uintptr_t)nfacct;
	int tmp;

	tmp = snprintf(buf, (size_t)size, "<sum>");
	if (tmp < 0 || tmp >= size)
		return -1;
	size -= tmp; buf += tmp;

	tmp = priv->output_ts(buf, size);
	if (tmp < 0 || tmp >= size)
		return -1;
	size -= tmp; buf += tmp;

	tmp = nfacct_snprintf(buf, (size_t)size, obj,
			      NFACCT_SNPRINTF_T_XML, NFACCT_SNPRINTF_F_TIME);
	if (tmp < 0 || tmp >= size)
		return -1;
	size -= tmp; buf += tmp;

	tmp = snprintf(buf, (size_t)size, "</sum>");
	if (tmp < 0 || tmp >= size)
		return -1;

	return 0;
#else
	return 1;
#endif
}

#ifdef HAVE_LNFT
static uint32_t event2flag(uint32_t event)
{
	switch (event) {
	case NFT_MSG_NEWTABLE:
	case NFT_MSG_NEWCHAIN:
	case NFT_MSG_NEWRULE:
	case NFT_MSG_NEWSET:
	case NFT_MSG_NEWSETELEM:
	case NFT_MSG_NEWGEN:
		return NFTNL_OF_EVENT_NEW;
	case NFT_MSG_DELTABLE:
	case NFT_MSG_DELCHAIN:
	case NFT_MSG_DELRULE:
	case NFT_MSG_DELSET:
	case NFT_MSG_DELSETELEM:
		return NFTNL_OF_EVENT_DEL;
	}

	return 0;
}
#endif

static int
xml_output_nft(struct xml_priv *priv, const struct nurs_input *inp,
	       char *buf, ssize_t size)
{
#ifdef HAVE_LNFT
	uint32_t event = nurs_input_u32(inp, XML_INPUT_NFT_EVENT);
	int tmp;

	tmp = snprintf(buf, (size_t)size, "<nft>");
	if (tmp < 0 || tmp >= size)
		return -1;
	size -= tmp; buf += tmp;

	tmp = priv->output_ts(buf, size);
	if (tmp < 0 || tmp >= size)
		return -1;
	size -= tmp; buf += tmp;

	if (nurs_input_is_valid(inp, XML_INPUT_NFT_TABLE)) {
		const struct nftnl_table *t
			= nurs_input_pointer(inp, XML_INPUT_NFT_TABLE);
		struct nftnl_table *o = (struct nftnl_table *)(uintptr_t)t;
		tmp = nftnl_table_snprintf(buf, (size_t)size, o,
					   NFTNL_OUTPUT_XML, event2flag(event));
		if (tmp == -1)
			nurs_log(NURS_ERROR, "nftnl_table : %s\n",
				 strerror(errno));
	} else if (nurs_input_is_valid(inp, XML_INPUT_NFT_RULE)) {
		const struct nftnl_rule *t
			= nurs_input_pointer(inp, XML_INPUT_NFT_RULE);
		struct nftnl_rule *o = (struct nftnl_rule *)(uintptr_t)t;
		tmp = nftnl_rule_snprintf(buf, (size_t)size, o,
					  NFTNL_OUTPUT_XML, event2flag(event));
		if (tmp == -1)
			nurs_log(NURS_ERROR, "nftnl_rule : %s\n",
				 strerror(errno));
	} else if (nurs_input_is_valid(inp, XML_INPUT_NFT_CHAIN)) {
		const struct nftnl_chain *t
			= nurs_input_pointer(inp, XML_INPUT_NFT_CHAIN);
		struct nftnl_chain *o = (struct nftnl_chain *)(uintptr_t)t;
		tmp = nftnl_chain_snprintf(buf, (size_t)size, o,
					   NFTNL_OUTPUT_XML, event2flag(event));
		if (tmp == -1)
			nurs_log(NURS_ERROR, "nftnl_chain : %s\n",
				 strerror(errno));
	} else if (nurs_input_is_valid(inp, XML_INPUT_NFT_SET)) {
		const struct nftnl_set *t
			= nurs_input_pointer(inp, XML_INPUT_NFT_SET);
		struct nftnl_set *o = (struct nftnl_set *)(uintptr_t)t;
		tmp = nftnl_set_snprintf(buf, (size_t)size, o,
					 NFTNL_OUTPUT_XML, event2flag(event));
		if (tmp == -1)
			nurs_log(NURS_ERROR, "nftnl_set : %s\n",
				 strerror(errno));
	} else if (nurs_input_is_valid(inp, XML_INPUT_NFT_SET_ELEM)) {
		const struct nftnl_set *t
			= nurs_input_pointer(inp, XML_INPUT_NFT_SET_ELEM);
		struct nftnl_set *o = (struct nftnl_set *)(uintptr_t)t;
		tmp = nftnl_set_snprintf(buf, (size_t)size, o,
					 NFTNL_OUTPUT_XML, event2flag(event));
		if (tmp == -1)
			nurs_log(NURS_ERROR, "nftnl_set_elem : %s\n",
				 strerror(errno));
	} else if (nurs_input_is_valid(inp, XML_INPUT_NFT_GEN)) {
		return 1;
	} else {
		nurs_log(NURS_ERROR, "unknown nft event: %d\n", event);
		return -1;
	}
	if (tmp < 0 || tmp >= size)
		return NURS_RET_ERROR;

	size -= tmp; buf += tmp;

	tmp = snprintf(buf, (size_t)size, "</nft>");
	if (tmp < 0 || tmp >= size)
		return -1;

	return 0;
#endif
	return 1;
}

/* may not escape */
static int xml_interp(const struct nurs_plugin *plugin,
		      const struct nurs_input *input)
{
	struct xml_priv *priv = nurs_plugin_context(plugin);
	static char buf[4096];
	int ret = 1;

	if (nurs_input_is_valid(input, XML_INPUT_NFCT)) {
		nurs_log(NURS_DEBUG, "output nfct\n");
		ret = xml_output_nfct(priv, input, buf, sizeof(buf));
	} else if (nurs_input_is_valid(input, XML_INPUT_NFLOG)) {
		nurs_log(NURS_DEBUG, "output nflog\n");
		ret = xml_output_nflog(priv, input, buf, sizeof(buf));
	} else if (nurs_input_is_valid(input, XML_INPUT_NFACCT)) {
		nurs_log(NURS_DEBUG, "output nfacct\n");
		ret = xml_output_nfacct(priv, input, buf, sizeof(buf));
	} else if (nurs_input_is_valid(input, XML_INPUT_NFT_EVENT)) {
		nurs_log(NURS_DEBUG, "output nft\n");
		ret = xml_output_nft(priv, input, buf, sizeof(buf));
	} else {
		nurs_log(NURS_DEBUG, "no XMLable input?\n");
	}

	/*
	 * xml_output_<nfnl subsys> returns
	 * 0 : success
	 * -1: error
	 * other: ignore
	 */
	switch (ret) {
	case 0:
		break;
	case -1:
		return NURS_RET_ERROR;
	default:
		return NURS_RET_OK;
	}

	flockfile(priv->of);
	fprintf(priv->of, "%s\n", buf);
	if (config_sync(plugin))
		fflush(priv->of);
	funlockfile(priv->of);

	return NURS_RET_OK;
}

static enum nurs_return_t
xml_open_file(const struct nurs_plugin *plugin)
{
	struct xml_priv *priv = nurs_plugin_context(plugin);

	if (!strncmp(config_filename(plugin), "-", 1)) {
		priv->of = stdout;
	} else {
		priv->of = fopen(config_filename(plugin), "a");
		if (!priv->of) {
			nurs_log(NURS_FATAL, "can't open XML file - %s: %s\n",
				 config_filename(plugin), strerror(errno));
			return NURS_RET_ERROR;
		}
	}

	return NURS_RET_OK;
}

static void xml_print_header(const struct nurs_plugin *plugin)
{
	struct xml_priv *priv = nurs_plugin_context(plugin);

	fprintf(priv->of, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
	fprintf(priv->of, "<netfilter>\n");
	if (config_sync(plugin))
		fflush(priv->of);
}

static enum nurs_return_t
xml_organize(const struct nurs_plugin *plugin)
{
	struct xml_priv *priv = nurs_plugin_context(plugin);

	if (xml_open_file(plugin) != NURS_RET_OK)
		return NURS_RET_ERROR;

	if (config_timestamp(plugin))
		priv->output_ts = xml_output_ts;
	else
		priv->output_ts = xml_output_ts_none;

	return NURS_RET_OK;
}

static enum nurs_return_t
xml_disorganize(const struct nurs_plugin *plugin)
{
	struct xml_priv *priv = nurs_plugin_context(plugin);
	enum nurs_return_t ret = NURS_RET_OK;

	if (priv->of != stdout && fclose(priv->of))
		ret = NURS_RET_ERROR;

	return ret;
}

static enum nurs_return_t xml_start(const struct nurs_plugin *plugin)
{
	xml_print_header(plugin);

	return NURS_RET_OK;
}

static enum nurs_return_t
xml_stop(const struct nurs_plugin *plugin)
{
	struct xml_priv *priv = nurs_plugin_context(plugin);

	fprintf(priv->of, "</netfilter>\n");

	return NURS_RET_OK;
}

static enum nurs_return_t
xml_signal(const struct nurs_plugin *plugin, uint32_t signum)
{
	switch (signum) {
	case SIGHUP:
		nurs_log(NURS_NOTICE, "XML: reopening logfile\n");
		xml_stop(plugin);
		if (xml_open_file(plugin) != NURS_RET_OK) {
			nurs_log(NURS_FATAL, "can't open XML file - %s: %s\n",
				 config_filename(plugin), strerror(errno));
			return NURS_RET_ERROR;
		}
		xml_print_header(plugin);
		break;
	default:
		break;
	}
	return NURS_RET_OK;
}

static struct nurs_consumer_def xml_consumer = {
	.name		= "XML",
	.version	= VERSION,
	.context_size	= sizeof(struct xml_priv),
	.mtsafe		= true,
	.config_def	= &xml_config,
	.input_def	= &xml_input,
	.organize	= &xml_organize,
	.disorganize	= &xml_disorganize,
	.start		= &xml_start,
	.stop		= &xml_stop,
	.interp		= &xml_interp,
	.signal		= &xml_signal,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	nurs_consumer_register(&xml_consumer);
}

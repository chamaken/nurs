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
#include <sys/socket.h>
#include <linux/if.h>	/* IFNAMSIZ */
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <stdlib.h>
#include <string.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/gen.h>
#include <libnftnl/common.h>
#include <libnftnl/expr.h>

#include <nurs/nurs.h>

/* libnftnl commit 37268a018e99181a1d203f0a8a6fc5c6670d09b2 */
enum nftnl_output_keys_index {
	NFTNL_OUTPUT_NFTNL_EVENT = 0,

	/* src/table.c, include/libnftnl/table.h						*/
	NFTNL_OUTPUT_TABLE_OBJECT,	/* struct nftnl_table 					*/

	/* src/rule.c, include/libnftnl/rule.h							*/
	NFTNL_OUTPUT_RULE_OBJECT,	/* struct nftnl_rule					*/

	/* src/chain.c, include/libnftnl/chain.h						*/
	NFTNL_OUTPUT_CHAIN_OBJECT,	/* struct nftnl_chain					*/

	/* include/set.h, include/libnftnl/set.h						*/
	NFTNL_OUTPUT_SET_OBJECT,	/* struct nftnl_set					*/

	/* include/set_elem.h, include/libnftnl/set.h						*/
	NFTNL_OUTPUT_SET_ELEM_OBJECT,	/* struct nftnl_set_elem				*/

	/* src/gen.c, include/libnftnl/gen.h							*/
	NFTNL_OUTPUT_GEN_OBJECT,	/* struct nftnl_gen					*/

	/*** primitive */
	/* struct nftnl_table::src/table.c, include/libnftnl/table.h				*/
	NFTNL_OUTPUT_TABLE_NAME,	/* const char	*name		NFTNL_TABLE_ATTR_NAME	*/
	NFTNL_OUTPUT_TABLE_FAMILY,	/* uint32_t	family		NFTNL_TABLE_ATTR_FAMILY	*/
	NFTNL_OUTPUT_TABLE_TABLE_FLAGS,	/* uint32_t	table_flags	NFTNL_TABLE_ATTR_FLAGS	*/
	NFTNL_OUTPUT_TABLE_USE = 10,	/* uint32_t	use		NFTNL_TABLE_ATTR_USE	*/

	/* struct nftnl_rule::src/rule.c, include/libnftnl/rule.h					*/
	NFTNL_OUTPUT_RULE_FAMILY,	/* uint32_t	family		NFTNL_RULE_ATTR_FAMILY	*/
	NFTNL_OUTPUT_RULE_TABLE,	/* const char	*table		NFTNL_RULE_ATTR_TABLE	*/
	NFTNL_OUTPUT_RULE_CHAIN,	/* const char	*chain		NFTNL_RULE_ATTR_CHAIN	*/
	NFTNL_OUTPUT_RULE_HANDLE,	/* uint64_t	handle		NFTNL_RULE_ATTR_HANDLE	*/
	NFTNL_OUTPUT_RULE_POSITION,	/* uint64_t	position	NFTNL_RULE_ATTR_POSITION	*/
	NFTNL_OUTPUT_RULE_USER_DATA,	/* void		*data		NFTNL_RULE_ATTR_USERDATA	*/
					/* uint32_t	len					*/
	NFTNL_OUTPUT_RULE_COMPAT_FLAGS,	/* uint32_t	flags		NFTNL_RULE_ATTR_COMPAT_FLAGS	*/
	NFTNL_OUTPUT_RULE_COMPAT_PROTO,	/* uint32_t	proto		NFTNL_RULE_ATTR_COMPAT_PROTO	*/

	/* struct nftnl_chain::src/chain.c, include/libnftnl/chain.h				*/
	NFTNL_OUTPUT_CHAIN_NAME,	/* char		name[NFTNL_CHAIN_MAXNAMELEN] NFTNL_CHAIN_ATTR_NAME	*/
	NFTNL_OUTPUT_CHAIN_TYPE = 20,	/* const char	*type		NFTNL_CHAIN_ATTR_TYPE	*/
	NFTNL_OUTPUT_CHAIN_TABLE,	/* const char	*table		NFTNL_CHAIN_ATTR_TABLE	*/
	NFTNL_OUTPUT_CHAIN_DEV,		/* const char	*dev		NFTNL_CHAIN_ATTR_DEV	*/
	NFTNL_OUTPUT_CHAIN_FAMILY,	/* uint32_t	family		NFTNL_CHAIN_ATTR_FAMILY	*/
	NFTNL_OUTPUT_CHAIN_POLICY,	/* uint32_t	policy		NFTNL_CHAIN_ATTR_POLICY	*/
	NFTNL_OUTPUT_CHAIN_HOOKNUM,	/* uint32_t	hooknum		NFTNL_CHAIN_ATTR_HOOKNUM	*/
	NFTNL_OUTPUT_CHAIN_PRIO,	/* int32_t	prio		NFTNL_CHAIN_ATTR_PRIO	*/
	NFTNL_OUTPUT_CHAIN_USE,		/* uint32_t	use		NFTNL_CHAIN_ATTR_USE	*/
	NFTNL_OUTPUT_CHAIN_PACKETS,	/* uint64_t	packets		NFTNL_CHAIN_ATTR_PACKETS	*/
	NFTNL_OUTPUT_CHAIN_BYTES,	/* uint64_t	bytes		NFTNL_CHAIN_ATTR_BYTES	*/
	NFTNL_OUTPUT_CHAIN_HANDLE = 30,	/* uint64_t	handle		NFTNL_CHAIN_ATTR_HANDLE	*/

	/* struct nftnl_set::include/set.h, include/libnftnl/set.h				*/
	NFTNL_OUTPUT_SET_FAMILY,	/* uint32_t	family		NFTNL_SET_ATTR_FAMILY	*/
	NFTNL_OUTPUT_SET_SET_FLAGS,	/* uint32_t	set_flags	NFTNL_SET_ATTR_FLAGS	*/
	NFTNL_OUTPUT_SET_TABLE,		/* const char	*table		NFTNL_SET_ATTR_TABLE	*/
	NFTNL_OUTPUT_SET_NAME,		/* const char	*name		NFTNL_SET_ATTR_NAME	*/
	NFTNL_OUTPUT_SET_KEY_TYPE,	/* uint32_t	key_type	NFTNL_SET_ATTR_KEY_TYPE	*/
	NFTNL_OUTPUT_SET_KEY_LEN,	/* uint32_t	key_len		NFTNL_SET_ATTR_KEY_LEN	*/
	NFTNL_OUTPUT_SET_DATA_TYPE,	/* uint32_t	data_type	NFTNL_SET_ATTR_DATA_TYPE	*/
	NFTNL_OUTPUT_SET_DATA_LEN,	/* uint32_t	data_len	NFTNL_SET_ATTR_DATA_LEN	*/
	NFTNL_OUTPUT_SET_ID,		/* uint32_t	id		NFTNL_SET_ATTR_ID		*/
	NFTNL_OUTPUT_SET_POLICY = 40,	/* enum nftnl_set_policies policy	NFTNL_SET_ATTR_POLICY	*/
	NFTNL_OUTPUT_SET_DESC_SIZE,	/* uint32_t	size		NFTNL_SET_ATTR_DESC_SIZE	*/
	NFTNL_OUTPUT_SET_GC_INTERVAL,	/* uint32_t	gc_interval	NFTNL_SET_ATTR_GC_INTERVAL*/
	NFTNL_OUTPUT_SET_TIEOUT,	/* uint64_t	timeout		NFTNL_SET_ATTR_TIMEOUT	*/

	/* struct nftnl_set_elem::include/set_elem.h, include/libnftnl/set.h			*/
	NFTNL_OUTPUT_SET_ELEM_FLAGS,	/* uint32_t	set_elem_flags	NFTNL_SET_ELEM_ATTR_FLAGS	*/
	NFTNL_OUTPUT_SET_ELEM_KEY,	/* union nftnl_data_reg	key	NFTNL_SET_ELEM_ATTR_KEY	*/
	NFTNL_OUTPUT_SET_ELEM_DATA,	/* union nftnl_data_reg	data	NFTNL_SET_ELEM_ATTR_DATA	*/
	NFTNL_OUTPUT_SET_ELEM_EXPR,	/* struct nftnl_rule_expr	*expr	NFTNL_SET_ELEM_ATTR_EXPR	*/
	NFTNL_OUTPUT_SET_ELEM_TIMEOUT,	/* uint64_t	timeout		NFTNL_SET_ELEM_ATTR_TIMEOUT	*/
	NFTNL_OUTPUT_SET_ELEM_EXPIRATION, /* uint64_t	expiration	NFTNL_SET_ELEM_ATTR_EXPIRATION	*/
	NFTNL_OUTPUT_SET_USER_DATA = 50,/* void		*data		NFTNL_SET_ELEM_ATTR_USERDATA	*/
					/* uint32_t	len						*/
	NFTNL_OUTPUT_SET_ELEM_VERDICT,	/* int nftnl_data_reg.verdict	NFTNL_SET_ELEM_ATTR_VERDICT	*/
	NFTNL_OUTPUT_SET_ELEM_CHAIN,	/* char *nftnl_data_reg.chain 	NFTNL_SET_ELEM_ATTR_CHAIN	*/

	/* struct nftnl_gen::src/gen.c, include/libnftnl/gen.h					*/
	NFTNL_OUTPUT_GEN_ID,		/* uint32_t 	id		NFTNL_GEN_ID		*/
	NFTNL_OUTPUT_MAX,
};

static struct nurs_output_def nftnl_output = {
	.len	= NFTNL_OUTPUT_MAX,
	.keys	= {
		[NFTNL_OUTPUT_NFTNL_EVENT]	= {
			.name	= "nft.event",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_ACTIVE,
		},
		[NFTNL_OUTPUT_TABLE_OBJECT]	= {
			.name	= "nft.table.object",
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_OPTIONAL | NURS_OKEY_F_DESTRUCT,
			.destructor = (void (*)(void *))nftnl_table_free,
		},
		[NFTNL_OUTPUT_RULE_OBJECT]	= {
			.name	= "nft.rule.object",
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_OPTIONAL | NURS_OKEY_F_DESTRUCT,
			.destructor = (void (*)(void *))nftnl_rule_free,
		},
		[NFTNL_OUTPUT_CHAIN_OBJECT]	= {
			.name	= "nft.chain.object",
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_OPTIONAL | NURS_OKEY_F_DESTRUCT,
			.destructor = (void (*)(void *))nftnl_chain_free,
		},
		[NFTNL_OUTPUT_SET_OBJECT]	= {
			.name	= "nft.set.object",
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_OPTIONAL | NURS_OKEY_F_DESTRUCT,
			.destructor = (void (*)(void *))nftnl_set_free,
		},
		[NFTNL_OUTPUT_SET_ELEM_OBJECT]	= {
			.name	= "nft.set_elem.object",
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_OPTIONAL | NURS_OKEY_F_DESTRUCT,
			/* .destructor = (void (*)(void *))nftnl_set_elem_free, */
			.destructor = (void (*)(void *))nftnl_set_free,
		},
		[NFTNL_OUTPUT_GEN_OBJECT]	= {
			.name	= "nft.gen.object",
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_OPTIONAL | NURS_OKEY_F_DESTRUCT,
			.destructor = (void (*)(void *))nftnl_gen_free,
		},

		/*** primitive */
		[NFTNL_OUTPUT_TABLE_NAME]	= {
			.name	= "nft.table.name",
			.type	= NURS_KEY_T_STRING,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.len	= NFT_TABLE_MAXNAMELEN,
		},
		[NFTNL_OUTPUT_TABLE_FAMILY]	= {
			.name	= "nft.table.family",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_TABLE_TABLE_FLAGS]	= {
			.name	= "nft.table.flags",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_TABLE_USE]	= {
			.name	= "nft.table.use",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_RULE_FAMILY]	= {
			.name	= "nft.rule.family",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_RULE_TABLE]	= {
			.name	= "nft.rule.table",
			.type	= NURS_KEY_T_STRING,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.len	= NFT_TABLE_MAXNAMELEN,
		},
		[NFTNL_OUTPUT_RULE_CHAIN]	= {
			.name	= "nft.rule.chain",
			.type	= NURS_KEY_T_STRING,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.len	= NFT_CHAIN_MAXNAMELEN,
		},
		[NFTNL_OUTPUT_RULE_HANDLE]	= {
			.name	= "nft.rule.handle",
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_RULE_POSITION]	= {
			.name	= "nft.rule.position",
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_RULE_USER_DATA]	= {
			.name	= "nft.rule.userdata",
			.type	= NURS_KEY_T_EMBED,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.len	= NFT_USERDATA_MAXLEN,
		},
		[NFTNL_OUTPUT_RULE_COMPAT_FLAGS]	= {
			.name	= "nft.rule.compat_flags",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_RULE_COMPAT_PROTO]	= {
			.name	= "nft.rule.compat_proto",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_CHAIN_NAME]	= {
			.name	= "nft.chain.name",
			.type	= NURS_KEY_T_STRING,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.len	= NFT_CHAIN_MAXNAMELEN,
		},
		[NFTNL_OUTPUT_CHAIN_TYPE]	= {
			.name	= "nft.chain.type",
			.type	= NURS_KEY_T_STRING,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.len	= 16, /* filter / nat / route */
		},
		[NFTNL_OUTPUT_CHAIN_TABLE]	= {
			.name	= "nft.chain.table",
			.type	= NURS_KEY_T_STRING,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.len	= NFT_TABLE_MAXNAMELEN,
		},
		[NFTNL_OUTPUT_CHAIN_DEV]	= {
			.name	= "nft.chain.dev",
			.type	= NURS_KEY_T_STRING,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.len	= IFNAMSIZ,
		},
		[NFTNL_OUTPUT_CHAIN_FAMILY]	= {
			.name	= "nft.chain.family",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_CHAIN_POLICY]	= {
			.name	= "nft.chain.policy",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_CHAIN_HOOKNUM]	= {
			.name	= "nft.chain.hooknum",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_CHAIN_PRIO]	= {
			.name	= "nft.chain.prio",
			.type	= NURS_KEY_T_INT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_CHAIN_USE]	= {
			.name	= "nft.chain.use",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_CHAIN_PACKETS]	= {
			.name	= "nft.chain.packets",
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_CHAIN_BYTES]	= {
			.name	= "nft.chain.bytes",
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_CHAIN_HANDLE]	= {
			.name	= "nft.chain.handle",
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_SET_FAMILY]	= {
			.name	= "nft.set.family",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_SET_SET_FLAGS]	= {
			.name	= "nft.set.flags",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_SET_TABLE]	= {
			.name	= "nft.set.table",
			.type	= NURS_KEY_T_STRING,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.len	= NFT_TABLE_MAXNAMELEN,
		},
		[NFTNL_OUTPUT_SET_NAME]	= {
			.name	= "nft.set.name",
			.type	= NURS_KEY_T_STRING,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.len	= IFNAMSIZ,
		},
		[NFTNL_OUTPUT_SET_KEY_TYPE]	= {
			.name	= "nft.set.key_type",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_SET_KEY_LEN]	= {
			.name	= "nft.set.key_len",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_SET_DATA_TYPE]	= {
			.name	= "nft.set.data_type",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_SET_DATA_LEN]	= {
			.name	= "nft.set.data_len",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_SET_ID]	= {
			.name	= "nft.set.id",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_SET_POLICY]	= {
			.name	= "nft.set.policy",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_SET_DESC_SIZE]	= {
			.name	= "nft.set.desc_size",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_SET_GC_INTERVAL]	= {
			.name	= "nft.set.gc_interval",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_SET_TIEOUT]	= {
			.name	= "nft.set.timeout",
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_SET_ELEM_FLAGS]	= {
			.name	= "nft.set_elem.flags",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_SET_ELEM_KEY]	= {
			.name	= "nft.set_elem.key",
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_OPTIONAL,
			/* XXX: len */
		},
		[NFTNL_OUTPUT_SET_ELEM_DATA]	= {
			.name	= "nft.set_elem.data",
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_OPTIONAL,
			/* XXX: len */
		},
		[NFTNL_OUTPUT_SET_ELEM_VERDICT]	= {
			.name	= "nft.set_elem.verdict",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_SET_ELEM_CHAIN]	= {
			.name	= "nft.set_elem.chain",
			.type	= NURS_KEY_T_STRING,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.len	= NFT_CHAIN_MAXNAMELEN,
		},
		[NFTNL_OUTPUT_SET_ELEM_EXPR]	= {
			.name	= "nft.set_elem.expr",
			.type	= NURS_KEY_T_POINTER,
			.flags	= NURS_OKEY_F_OPTIONAL | NURS_OKEY_F_DESTRUCT,
			.destructor = (void (*)(void *))nftnl_set_free,
		},
		[NFTNL_OUTPUT_SET_ELEM_TIMEOUT]	= {
			.name	= "nft.set_elem.timeout",
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_SET_ELEM_EXPIRATION]	= {
			.name	= "nft.set_elem.expiration",
			.type	= NURS_KEY_T_UINT64,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
		[NFTNL_OUTPUT_SET_USER_DATA]	= {
			.name	= "nft.set_elem.userdata",
			.type	= NURS_KEY_T_EMBED,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.len	= NFT_USERDATA_MAXLEN,
		},
		[NFTNL_OUTPUT_GEN_ID]	= {
			.name	= "nft.gen.id",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
		},
	},
};

enum nftable_config_keys_index {
	NFTNL_CONFIG_BUFSIZE,
	NFTNL_CONFIG_MAX,
};

static struct nurs_config_def nftnl_config = {
	.len	= NFTNL_CONFIG_MAX,
	.keys	= {
		[NFTNL_CONFIG_BUFSIZE]	= {
			.name	 = "socket_buffer_size",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 0,
		},
	},
};

#define bufsize_ce(x)	nurs_config_integer(nurs_producer_config(x), NFTNL_CONFIG_BUFSIZE)

struct nftnl_priv {
	struct mnl_socket *nls;
	struct nurs_fd *fd;
};

static int set_table_keys(struct nurs_output *output, struct nftnl_table *src)
{
	return MNL_CB_OK;
}

static int set_chain_keys(struct nurs_output *output, struct nftnl_chain *src)
{
	return MNL_CB_OK;
}

static int set_rule_keys(struct nurs_output *output, struct nftnl_rule *src)
{
	return MNL_CB_OK;
}

static int set_set_keys(struct nurs_output *output, struct nftnl_set *src)
{
	return MNL_CB_OK;
}

static int set_gen_keys(struct nurs_output *output, struct nftnl_gen *src)
{
	return MNL_CB_OK;
}

static int set_set_elems_keys(struct nurs_output *output, struct nftnl_set *src)
{
	return MNL_CB_OK;
}

#define NFTNL_CB(name, objname, keyidx)					\
static int name##_cb(struct nurs_producer *producer,			\
		     const struct nlmsghdr *nlh, uint32_t event) {	\
	struct nurs_output *_output = nurs_get_output(producer);	\
	struct nftnl_##objname *_t = nftnl_##objname##_alloc();		\
	if (_t == NULL)							\
		return MNL_CB_ERROR;					\
	if (nftnl_##name##_nlmsg_parse(nlh, _t) < 0)			\
		goto free;						\
	nurs_output_set_u32(_output, NFTNL_OUTPUT_NFTNL_EVENT, event);	\
	nurs_output_set_pointer(_output, keyidx, _t);			\
	set_##name##_keys(_output, _t);					\
	if (nurs_propagate(producer, _output) == 0)			\
		return MNL_CB_OK;					\
free:									\
	nurs_output_set_pointer(_output, keyidx, NULL);			\
	nftnl_##objname##_free(_t);					\
	return MNL_CB_ERROR;						\
}

NFTNL_CB(table,		table,	NFTNL_OUTPUT_TABLE_OBJECT)
NFTNL_CB(chain,		chain,	NFTNL_OUTPUT_CHAIN_OBJECT)
NFTNL_CB(rule,		rule,	NFTNL_OUTPUT_RULE_OBJECT)
NFTNL_CB(set,		set,	NFTNL_OUTPUT_SET_OBJECT)
NFTNL_CB(set_elems,	set,	NFTNL_OUTPUT_SET_ELEM_OBJECT)
NFTNL_CB(gen,		gen,	NFTNL_OUTPUT_GEN_OBJECT)

static int events_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nurs_producer *producer = data;
	uint32_t event = NFNL_MSG_TYPE(nlh->nlmsg_type);
	int ret;

	switch(event) {
	case NFT_MSG_NEWTABLE:
	case NFT_MSG_DELTABLE:
		ret = table_cb(producer, nlh, event);
		break;
	case NFT_MSG_NEWCHAIN:
	case NFT_MSG_DELCHAIN:
		ret = chain_cb(producer, nlh, event);
		break;
	case NFT_MSG_NEWRULE:
	case NFT_MSG_DELRULE:
		ret = rule_cb(producer, nlh, event);
		break;
	case NFT_MSG_NEWSET:
	case NFT_MSG_DELSET:
		ret = set_cb(producer, nlh, event);
		break;
	case NFT_MSG_NEWSETELEM:
	case NFT_MSG_DELSETELEM:
		ret = set_elems_cb(producer, nlh, event);
		break;
	case NFT_MSG_NEWGEN:
		ret = gen_cb(producer, nlh, event);
		break;
	default:
		nurs_log(NURS_ERROR, "unknown nft event: %d\n", event);
		mnl_nlmsg_fprintf(stderr, nlh, nlh->nlmsg_len, 0);
		ret = MNL_CB_ERROR;
	}

	return ret;
}

static int nftnl_fd_cb(int fd, uint16_t what, void *param)
{
	struct nurs_producer *producer = param;
	struct nftnl_priv *priv = nurs_producer_context(producer);
	char buf[MNL_SOCKET_BUFFER_SIZE];
	ssize_t nrecv;
	int ret;

	if (!(what & NURS_FD_F_READ))
		return 0;

	nrecv = mnl_socket_recvfrom(priv->nls, buf, sizeof(buf));
	if (nrecv < 0) {
		nurs_log(NURS_ERROR, "mnl_socket_recvfrom: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}

	ret = mnl_cb_run(buf, (size_t)nrecv, 0, 0, events_cb, producer);
	if (ret == MNL_CB_ERROR) {
		nurs_log(NURS_ERROR, "mnl_cb_run: %s\n", strerror(errno));
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static int setnlbufsize(struct mnl_socket *nl, int size)
{
	int fd = mnl_socket_get_fd(nl);
	socklen_t socklen = sizeof(int);

	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, socklen) == -1) {
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, socklen);
	}
	if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, &socklen) == -1)
		return -1;
	return size;
}

static int nftnl_organize(const struct nurs_producer *producer)
{
	struct nftnl_priv *priv = nurs_producer_context(producer);
	int nlbufsize = bufsize_ce(producer);

	priv->nls = mnl_socket_open(NETLINK_NETFILTER);
	if (priv->nls == NULL) {
		nurs_log(NURS_FATAL, "mnl_socket_open: %s\n",
			 strerror(errno));
		goto err_exit;
	}
	if (nlbufsize > 0) {
		if (setnlbufsize(priv->nls, nlbufsize) < 0) {
			nurs_log(NURS_FATAL, "setnlbufsize: %s\n",
				 strerror(errno));
			goto err_close;
		}
	}
	if (mnl_socket_bind(priv->nls, (1 << (NFNLGRP_NFTABLES-1)), MNL_SOCKET_AUTOPID) < 0) {
		nurs_log(NURS_FATAL, "mnl_socket_bind: %s\n",
			 strerror(errno));
		goto err_close;
	}

	priv->fd = nurs_fd_create(mnl_socket_get_fd(priv->nls),
				  NURS_FD_F_READ);
	if (!priv->fd)
		goto err_close;

	return NURS_RET_OK;
err_close:
	mnl_socket_close(priv->nls);
err_exit:
	return NURS_RET_ERROR;
}

static int nftnl_disorganize(const struct nurs_producer *producer)
{
	struct nftnl_priv *priv = nurs_producer_context(producer);

	nurs_fd_destroy(priv->fd);
	if (mnl_socket_close(priv->nls)) {
		nurs_log(NURS_ERROR, "mnl_socket_close: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static int nftnl_start(const struct nurs_producer *producer)
{
	struct nftnl_priv *priv = nurs_producer_context(producer);
	void *cbdata = (void *)(uintptr_t)producer; /* remove const qualifier */

	if (nurs_fd_register(priv->fd, nftnl_fd_cb, cbdata)) {
		nurs_log(NURS_ERROR, "nurs_fd_register failed: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static int nftnl_stop(const struct nurs_producer *producer)
{
	struct nftnl_priv *priv = nurs_producer_context(producer);

	if (nurs_fd_unregister(priv->fd)) {
		nurs_log(NURS_ERROR, "nurs_fd_unregister: %s\n",
			 strerror(errno));
		return NURS_RET_ERROR;
	}

	return NURS_RET_OK;
}

static struct nurs_producer_def nftnl_producer = {
	.version	= VERSION,
	.name 		= "NFT",
	.context_size	= sizeof(struct nftnl_priv),
	.config_def	= &nftnl_config,
	.output_def	= &nftnl_output,
	.organize	= &nftnl_organize,
	.disorganize	= &nftnl_disorganize,
	.start		= &nftnl_start,
	.stop		= &nftnl_stop,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	nurs_producer_register(&nftnl_producer);
}

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
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <nurs/nurs.h>
#include <nurs/ipfix_protocol.h>

struct markif_priv {
	uint32_t	in_mask, out_mask;
	uint32_t	in_shift, out_shift;
};

/*
 *       LAN              WAN
 *              +---+
 * ---- eth1 -- | B | -- eth2 ----
 *              | O |
 *              | X | -- eth3 ----
 *              +---+
 *
 * interface eth1
 *   ip flow ingress
 *   ip flow egress
 *
 * *nat
 * # indev
 * -A PREROUTING  -i eth1 -j CONNMARK --set-mark 0x000001/0x0100ff
 * -A PREROUTING  -i eth2 -j CONNMARK --set-mark 0x010002/0x0100ff
 * -A PREROUTING  -i eth3 -j CONNMARK --set-mark 0x010003/0x0100ff
 * # outdev
 * -A POSTROUTING -o eth1 -j CONNMARK --set-mark 0x000100/0x00ff00
 * -A POSTROUTING -o eth2 -j CONNMARK --set-mark 0x000200/0x00ff00
 * -A POSTROUTING -o eth3 -j CONNMARK --set-mark 0x000300/0x00ff00
 *
 * config:
 * mask_ingress="0xff"
 * mask_egress="0xff00 >> 8"
 * mask_flow=0x10000
 *
 * Then:           ingressInterface         egressInterface        flowDirection
 *   eth1->eth2            1                       2                    0 ingress
 *   eth1->eth3            1                       3                    0 ingress
 *   eth2->eth1            2                       1                    1 egress
 *   eth3->eth1            3                       1                    1 egress
 *   eth2->eth3            2                       3                    1 egress?
 *
 * http://patchwork.ozlabs.org/patch/278213/
 */

enum {
	MARKIF_CONFIG_MASK_IN,
	MARKIF_CONFIG_MASK_OUT,
	MARKIF_CONFIG_MASK_FLOW,
	MARKIF_CONFIG_MAX,
};

static struct nurs_config_def markif_config = {
	.len	 = MARKIF_CONFIG_MAX,
	.keys = {
		[MARKIF_CONFIG_MASK_IN] = {
			.name	= "mask_ingress",
			.type	= NURS_CONFIG_T_STRING,
			.flags	= NURS_CONFIG_F_MANDATORY,
		},
		[MARKIF_CONFIG_MASK_OUT] = {
			.name	= "mask_egress",
			.type	= NURS_CONFIG_T_STRING,
			.flags	= NURS_CONFIG_F_MANDATORY,
		},
		[MARKIF_CONFIG_MASK_FLOW] = {
			/* & == 0: ingress flow, 0
			 *   != 0: egress flow,  1 */
			.name	= "mask_flow",
			.type	= NURS_CONFIG_T_INTEGER,
			.integer = 0,
		},
	},
};

#define config_maskin(x)	nurs_config_string(nurs_plugin_config(x), MARKIF_CONFIG_MASK_IN)
#define config_maskout(x)	nurs_config_string(nurs_plugin_config(x), MARKIF_CONFIG_MASK_OUT)
#define config_maskflow(x)	((uint32_t)nurs_config_integer(nurs_plugin_config(x), MARKIF_CONFIG_MASK_FLOW))

enum {
	MARKIF_INPUT_CT_MARK,
	MARKIF_INPUT_MAX,
};

static struct nurs_input_def markif_input = {
	.len	= MARKIF_INPUT_MAX,
	.keys	= {
		[MARKIF_INPUT_CT_MARK] = {
			.name	= "ct.mark",
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_IKEY_F_OPTIONAL, /* or OPTIONAL? */
		},
	},
};

enum {
	MARKIF_OUTPUT_OOB_IFINDEX_IN,
	MARKIF_OUTPUT_OOB_IFINDEX_OUT,
	MARKIF_OUTPUT_FLOW_DIRECTION,
	MARKIF_OUTPUT_MAX,
};

static struct nurs_output_def markif_output = {
	.len	= MARKIF_OUTPUT_MAX,
	.keys	= {
		[MARKIF_OUTPUT_OOB_IFINDEX_IN] = {
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "oob.ifindex_in",
			.ipfix	= {
				.vendor		= IPFIX_VENDOR_IETF,
				.field_id	= IPFIX_ingressInterface,
			},
		},
		[MARKIF_OUTPUT_OOB_IFINDEX_OUT] = {
			.type	= NURS_KEY_T_UINT32,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "oob.ifindex_out",
			.ipfix	= {
				.vendor		= IPFIX_VENDOR_IETF,
				.field_id	= IPFIX_egressInterface,
			},
		},
		[MARKIF_OUTPUT_FLOW_DIRECTION] = {
			.type 	= NURS_KEY_T_UINT8,
			.flags	= NURS_OKEY_F_OPTIONAL,
			.name	= "flow.direction",
			.ipfix	= {
				.vendor		= IPFIX_VENDOR_IETF,
				.field_id	= IPFIX_flowDirection,
			},
		},
	},
};

static int extract_param(const char *s, uint32_t *mask, uint32_t *shift)
{
	char *t = NULL;
	uintmax_t v;

	if ((t = strstr(s, ">>")) != NULL) {
		*t = '\0';
		t += 2;
		v = strtoumax(t, NULL, 0);
	} else {
		v = 0;
	}
	*shift = (uint32_t)v;
	v = strtoumax(s, NULL, 0);
	*mask = (uint32_t)v;
	return 0;
}

static enum nurs_return_t
markif_organize(const struct nurs_plugin *plugin)
{
	struct markif_priv *priv = nurs_plugin_context(plugin);

	if (!strlen(config_maskin(plugin))) {
		nurs_log(NURS_FATAL, "no mask_ingress specified\n");
		return NURS_RET_ERROR;
	}
	if (extract_param(config_maskin(plugin),
			  &priv->in_mask, &priv->in_shift)) {
		nurs_log(NURS_FATAL, "invalid mask_ingress\n");
		return NURS_RET_ERROR;
	}
	nurs_log(NURS_INFO, "ingress mask: %#x >> %#x\n",
		 priv->in_mask, priv->in_shift);

	if (!strlen(config_maskout(plugin))) {
		nurs_log(NURS_FATAL, "no mask_egress spcefied\n");
		return NURS_RET_ERROR;
	}
	if (extract_param(config_maskout(plugin),
			  &priv->out_mask, &priv->out_shift)) {
		nurs_log(NURS_FATAL, "invalid mask_egress\n");
		return NURS_RET_ERROR;
	}
	nurs_log(NURS_INFO, "egress mask: %#x >> %#x\n",
		 priv->out_mask, priv->out_shift);

	nurs_log(NURS_INFO, "direction mask: %#x\n", config_maskflow(plugin));

	return NURS_RET_OK;
}

static enum nurs_return_t
 markif_interp(const struct nurs_plugin *plugin,
	       const struct nurs_input *input,
	       struct nurs_output *output)
{
	struct markif_priv *priv = nurs_plugin_context(plugin);
	uint32_t ctmark;

	if (!nurs_input_is_valid(input, MARKIF_INPUT_CT_MARK)) {
		nurs_log(NURS_ERROR, "no ct.mark in input\n");
		return NURS_RET_ERROR;
	}
	ctmark = nurs_input_u32(input, MARKIF_INPUT_CT_MARK);

	nurs_output_set_u32(output, MARKIF_OUTPUT_OOB_IFINDEX_IN,
			    (ctmark & priv->in_mask) >> priv->in_shift);
	nurs_output_set_u32(output, MARKIF_OUTPUT_OOB_IFINDEX_OUT,
			    (ctmark & priv->out_mask) >> priv->out_shift);
	nurs_output_set_u8(output, MARKIF_OUTPUT_FLOW_DIRECTION,
			   (ctmark & config_maskflow(plugin)) != 0);

	return NURS_RET_OK;
}

static struct nurs_filter_def markif_filter = {
	.name		= "MARKIF",
	.version	= VERSION,
	.context_size	= sizeof(struct markif_priv),
	.config_def	= &markif_config,
	.input_def	= &markif_input,
	.output_def	= &markif_output,
	.mtsafe		= true,
	.organize	= &markif_organize,
	.interp		= &markif_interp,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	nurs_filter_register(&markif_filter);
}

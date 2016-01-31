/*
 * (C) 2005 by Harald Welte <laforge@gnumonks.org>
 * (C) 2016 by Ken-ichirou MATSUZAWA <chamas@h4.dion.ne.jp>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * TODO:
 * - SCTP with PR_SCTP, must be in RFC but...
 */
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <nurs/nurs.h>
#include <nurs/list.h>
#include <nurs/ipfix_protocol.h>
#include <nurs/utils.h>

enum {
	IPFIX_CONFIG_DEST,
	IPFIX_CONFIG_DOMAIN_ID,
	IPFIX_CONFIG_NTH_TEMPLATE,
	IPFIX_CONFIG_CORKSETS_MAX,
	IPFIX_CONFIG_MAX,
};

static struct nurs_config_def ipfix_config = {
	.len	= IPFIX_CONFIG_MAX,
	.keys	= {
		[IPFIX_CONFIG_DEST] = {
			.name 	 = "dest",
			.type	 = NURS_CONFIG_T_STRING,
			.flags = NURS_CONFIG_F_MANDATORY,
		},
		[IPFIX_CONFIG_DOMAIN_ID] = {
			.name	 = "domain_id",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 0,
		},
		[IPFIX_CONFIG_NTH_TEMPLATE] = {
			.name	 = "nth_template",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 16,
		},
		[IPFIX_CONFIG_CORKSETS_MAX] = {
			.name	 = "corksets_max",
			.type	 = NURS_CONFIG_T_INTEGER,
			.integer = 16,
		},
	},
};

#define config_dest(x)		nurs_config_string(nurs_plugin_config(x), IPFIX_CONFIG_DEST)
#define config_domain(x)	(uint32_t)nurs_config_integer(nurs_plugin_config(x), IPFIX_CONFIG_DOMAIN_ID)
#define config_nth_template(x)	nurs_config_integer(nurs_plugin_config(x), IPFIX_CONFIG_NTH_TEMPLATE)
#define config_corksets_max(x)	nurs_config_integer(nurs_plugin_config(x), IPFIX_CONFIG_CORKSETS_MAX)

struct ipfix_template {
	struct list_head list;
	struct nfct_bitmask *bitmask;
	int until_template;		/* decide if it's time to retransmit our template */
	size_t tmplset_len, dataset_len;
	struct ipfix_sethdr *template;

	pthread_mutex_t sethdrs_mutex;
	pthread_cond_t sethdrs_condv;
	struct ipfix_sethdr *sethdrs;
	int sethdrs_max;
	int sethdrs_pos;
};

struct ipfix_priv {
	int fd;		/* socket that we use for sending IPFIX data */

	uint16_t next_template_id;

	struct list_head tmpls; /* ipfix_template */
	pthread_mutex_t tmpls_mutex;

	int nth_template;
	struct ipfix_msghdr msghdr;

	pthread_mutex_t vecs_mutex;
	pthread_cond_t vecs_condv;
	struct iovec *iovecs;	/* index 0 is reserved for ipfix_msghdr */
	int iovcnt;
	int iovmax;
	size_t msglen;
	uint32_t hdr_seq;
	uint32_t seq;
};

/* +2 for sending with template on next */
#define iovecs_full(x) ((x)->iovcnt + 2 >= (int)(x)->iovmax)
#define ipfix_data(x) (void *)((uintptr_t)(x) + sizeof(struct ipfix_sethdr))

#define NURS_IPFIX_TEMPL_BASE 1024


// #define DEBUG_TMMAP
#ifdef DEBUG_TMMAP
#include <sys/mman.h>
FILE *mmfd;
void *mmaddr;
static int ipfix_fprintf_header(FILE *fd, const struct ipfix_priv *priv);
#endif

static struct ipfix_template *
alloc_template(struct ipfix_priv *priv,
		     const struct nurs_input *input,
		     struct nfct_bitmask *bm)
{
	struct ipfix_template *tmpl;
	uint16_t i, input_len = nurs_input_len(input);
	size_t tmpl_len = 0, data_len = 0;

	for (i = 0; i < input_len; i++) {
		if (!nfct_bitmask_test_bit(bm, i))
			continue;

		if (nurs_input_ipfix_vendor(input, i) == IPFIX_VENDOR_IETF)
			tmpl_len += sizeof(struct ipfix_ietf_field);
		else
			tmpl_len += sizeof(struct ipfix_vendor_field);

		data_len += nurs_input_size(input, i);
	}

	tmpl = calloc(1, sizeof(struct ipfix_template));
	if (!tmpl)
		return NULL;

	tmpl->bitmask = nfct_bitmask_clone(bm);
	if (!tmpl->bitmask)
		goto free_tmpl;

	tmpl->dataset_len = sizeof(struct ipfix_sethdr) + data_len;
	tmpl->tmplset_len = sizeof(struct ipfix_sethdr)
		+ sizeof(struct ipfix_tmpl_hdr) + tmpl_len;
	/* XXX: no alignment? confirm 3.3.1. Set Format */

	tmpl->template = calloc(1, tmpl->tmplset_len);
	if (!tmpl->template)
		goto free_bitmask;

	tmpl->sethdrs_max = priv->iovmax - 1;
	tmpl->sethdrs = calloc((size_t)tmpl->sethdrs_max, tmpl->dataset_len);
	if (!tmpl->sethdrs)
		goto free_template;

	return tmpl;

free_template:
	free(tmpl->template);
free_bitmask:
	nfct_bitmask_destroy(tmpl->bitmask);
free_tmpl:
	free(tmpl);

	return NULL;
}

/* Build the IPFIX template from the input keys */
static struct ipfix_template *
create_template(struct ipfix_priv *priv,
		const struct nurs_input *input,
		struct nfct_bitmask *bm)
{
	struct ipfix_template *tmpl;
	struct ipfix_tmpl_hdr *tmpl_hdr;
	uintptr_t tmpl_rec;
	struct ipfix_sethdr *sethdr;
	uint16_t field_id, field_count = 0;
	uint32_t vendor;
	uint16_t i, input_size, input_len = nurs_input_len(input);
        pthread_mutexattr_t attr;

	tmpl = alloc_template(priv, input, bm);
	if (!tmpl)
		return NULL;

        pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, NURS_MUTEX_ATTR);
	if (pthread_mutex_init(&tmpl->sethdrs_mutex, &attr)) {
		nurs_log(NURS_FATAL, "pthread_mutex_init: %s\n",
			 _sys_errlist[errno]);
		return NULL;
	}
	if (pthread_cond_init(&tmpl->sethdrs_condv, NULL)) {
		nurs_log(NURS_FATAL, "pthread_cond_init: %s\n",
			 _sys_errlist[errno]);
		return NULL;
	}

	/* build template records */
	tmpl_rec = (uintptr_t)tmpl->template
		+ sizeof(struct ipfix_sethdr)
		+ sizeof(struct ipfix_tmpl_hdr);
	for (i = 0; i < input_len; i++) {
		if (!nfct_bitmask_test_bit(tmpl->bitmask, i))
			continue;

		field_count++;
		field_id = nurs_input_ipfix_field(input, i);
		input_size = nurs_input_size(input, i);
		vendor = nurs_input_ipfix_vendor(input, i);
		if (vendor == IPFIX_VENDOR_IETF) {
			struct ipfix_ietf_field *field
				= (struct ipfix_ietf_field *)tmpl_rec;

			field->type = htons(field_id);
			field->length = htons(input_size);
			tmpl_rec += sizeof(*field);
		} else {
			struct ipfix_vendor_field *field
				= (struct ipfix_vendor_field *)tmpl_rec;

			field->type = htons(field_id | 0x8000);
			field->length = htons(input_size);
			field->enterprise_num = htonl(vendor);
			tmpl_rec += sizeof(*field);
		}
	}

	/* initialize template set header */
	tmpl->template->set_id = htons(2);
	tmpl->template->length = htons(tmpl->tmplset_len);

	/* initialize template record header */
	tmpl_hdr = (struct ipfix_tmpl_hdr *)((uintptr_t)tmpl->template
					     + sizeof(struct ipfix_sethdr));
	tmpl_hdr->template_id = htons(priv->next_template_id++);
	tmpl_hdr->field_count = htons(field_count);

	/* initialize data buffer */
	for (i = 0; i < priv->iovmax - 1; i++) {
		sethdr = (struct ipfix_sethdr *)((uintptr_t)tmpl->sethdrs
						 + i * tmpl->dataset_len);
		sethdr->set_id = tmpl_hdr->template_id;
		sethdr->length = htons(tmpl->dataset_len);
	}

	return tmpl;
}

static struct ipfix_template *
find_template(struct ipfix_priv *priv, struct nfct_bitmask *bm)
{
	struct ipfix_template *tmpl;

	/* FIXME: this can be done more efficient! */
	list_for_each_entry(tmpl, &priv->tmpls, list)
		if (nfct_bitmask_equal(bm, tmpl->bitmask))
			return tmpl;

	return NULL;
}

static struct ipfix_template *
lookup_template(struct ipfix_priv *priv, const struct nurs_input *input,
		struct nfct_bitmask *bm)
{
	struct ipfix_template *tmpl;

	if (nurs_mutex_lock(&priv->tmpls_mutex))
		return NULL;

	tmpl = find_template(priv, bm);
	if (!tmpl) {
		tmpl = create_template(priv, input, bm);
		if (!tmpl) {
			nurs_log(NURS_ERROR, "failed to create template\n");
			goto exit;
		}
		list_add(&tmpl->list, &priv->tmpls);
	}
exit:
	if (nurs_mutex_unlock(&priv->tmpls_mutex))
		return NULL;

	return tmpl;
}

static struct ipfix_sethdr *get_sethdr(struct ipfix_template *tmpl)
{
	struct ipfix_sethdr *sethdr;
	void *data;

	if (nurs_mutex_lock(&tmpl->sethdrs_mutex))
		return NULL;
	while (tmpl->sethdrs_pos >= tmpl->sethdrs_max) {
		if (nurs_cond_wait(&tmpl->sethdrs_condv,
				   &tmpl->sethdrs_mutex)) {
			nurs_mutex_unlock(&tmpl->sethdrs_mutex);
			return NULL;
		}
	}

	sethdr = (struct ipfix_sethdr *)
		((uintptr_t)tmpl->sethdrs
		 + (uintptr_t)(tmpl->sethdrs_pos * (int)tmpl->dataset_len));
	data = ipfix_data(sethdr);
	memset(data, 0, tmpl->dataset_len - sizeof(struct ipfix_sethdr));
	tmpl->sethdrs_pos++;

	if (nurs_mutex_unlock(&tmpl->sethdrs_mutex))
		return NULL;

	return sethdr;
}

static struct ipfix_sethdr *
build_sethdr(struct ipfix_priv *priv, const struct nurs_input *input,
	     struct ipfix_template *tmpl)
{
	struct ipfix_sethdr *sethdr = get_sethdr(tmpl);
	void *buf = ipfix_data(sethdr);
	size_t buflen = tmpl->dataset_len;
	uint16_t i, input_len = nurs_input_len(input);
	int ret;

	if (!sethdr) return NULL;

	for (i = 0; i < input_len; i++) {
		if (!nfct_bitmask_test_bit(tmpl->bitmask, i))
			continue;
		ret = nurs_key_putn(input, i, buf, buflen);
		if (ret < 0)
			return NULL;

		buf = (void *)((uintptr_t)buf + (uintptr_t)ret);
		buflen -= (size_t)ret;
	}

	return sethdr;
}

static int push_input(struct ipfix_priv *priv, const struct nurs_input *input,
		      struct ipfix_template *tmpl)
{
	struct ipfix_sethdr *sethdr = build_sethdr(priv, input, tmpl);
	int ret = 0;

	if ((ret = nurs_mutex_lock(&priv->vecs_mutex)))
		return ret;
	while (iovecs_full(priv)) {
		ret = nurs_cond_wait(&priv->vecs_condv, &priv->vecs_mutex);
		if (ret) goto unlock;
	}

	if (!tmpl->until_template) {
		tmpl->until_template = priv->nth_template;

		priv->iovecs[priv->iovcnt].iov_base = tmpl->template;
		priv->iovecs[priv->iovcnt].iov_len = tmpl->tmplset_len;
		priv->msglen += tmpl->tmplset_len;
		priv->iovcnt++;
	}
	tmpl->until_template--;

	priv->iovecs[priv->iovcnt].iov_base = sethdr;
	priv->iovecs[priv->iovcnt].iov_len = tmpl->dataset_len;
	priv->msglen += tmpl->dataset_len;
	priv->iovcnt++;
	priv->seq++;

unlock:
	ret = nurs_mutex_unlock(&priv->vecs_mutex);
	return ret;
}

static ssize_t send_ipfix(struct ipfix_priv *priv, bool force)
{
	ssize_t nsent, ret = 0;
	struct ipfix_template *tmpl;

	if ((ret = nurs_mutex_lock(&priv->vecs_mutex)))
		goto exit;
	if (!iovecs_full(priv) && !force)
		goto unlock;

	priv->msglen += sizeof(struct ipfix_msghdr);
	priv->msghdr.export_time = htonl((uint32_t)(time(NULL)));
	priv->msghdr.length = htons(priv->msglen);
	priv->msghdr.seq = htonl(priv->hdr_seq);
	priv->hdr_seq = priv->seq;

#ifdef DEBUG_TMMAP
	ipfix_fprintf_header(stdout, priv);
	fflush(stdout);
#endif
	nsent = writev(priv->fd, priv->iovecs, priv->iovcnt);
	if (nsent == -1) {
		nurs_log(NURS_ERROR, "failed to send: %s\n",
			 _sys_errlist[errno]);
	} else if (nsent != (ssize_t)priv->msglen) {
		nurs_log(NURS_ERROR, "could not send all -attempt: %d,"
			 " but: %d\n", priv->msglen, nsent);
	}
	ret = nsent - (ssize_t)priv->msglen;
	priv->msglen = 0;
	priv->iovcnt = 1;

	if ((ret = nurs_mutex_lock(&priv->tmpls_mutex)))
		goto unlock;
	list_for_each_entry(tmpl, &priv->tmpls, list) {
		nurs_mutex_lock(&tmpl->sethdrs_mutex);
		tmpl->sethdrs_pos = 0;
		nurs_cond_broadcast(&tmpl->sethdrs_condv);
		nurs_mutex_unlock(&tmpl->sethdrs_mutex);
	}
	if ((ret = nurs_mutex_unlock(&priv->tmpls_mutex)))
		goto unlock;
	if ((ret = nurs_cond_broadcast(&priv->vecs_condv)))
		goto unlock;
unlock:
	ret = nurs_mutex_unlock(&priv->vecs_mutex);
exit:
	return ret;
}

static enum nurs_return_t
ipfix_interp(const struct nurs_plugin *plugin, const struct nurs_input *input)
{
	struct ipfix_priv *priv = nurs_plugin_context(plugin);
	struct ipfix_template *tmpl;
	struct nfct_bitmask *validmask;
	uint16_t i, input_len = nurs_input_len(input);
	enum nurs_return_t ret = NURS_RET_ERROR;

	/* FIXME: it would be more cache efficient if the IS_VALID
	 * flags would be a separate bitmask outside of the array.
	 * nurs core could very easily flush it after every packet,
	 * too. */
	validmask = nfct_bitmask_new(input_len);
	if (!validmask) {
		nurs_log(NURS_ERROR, "failed to create nfct_bitmask\n");
		return NURS_RET_ERROR;
	}

	for (i = 0; i < input_len; i++) {
		if (!nurs_input_is_valid(input, i))
			continue;
		if (!nurs_input_ipfix_field(input, i))
			continue;
		nfct_bitmask_set_bit(validmask, i);
	}

	/* lookup template ID for this bitmask */
	tmpl = lookup_template(priv, input, validmask);
	if (!tmpl) {
		nurs_log(NURS_ERROR, "failed to lookup template\n");
		goto destroy_bitmask;
	}

	if (push_input(priv, input, tmpl)) {
		nurs_log(NURS_ERROR, "failed to build message\n");
		/* reset_counters(priv); XXX: ? */
		goto destroy_bitmask;
	}

	if (!send_ipfix(priv, false))
		ret = NURS_RET_OK;
destroy_bitmask:
	nfct_bitmask_destroy(validmask);
	return ret;
}

static enum nurs_return_t
ipfix_organize(const struct nurs_plugin *plugin, const struct nurs_input *input)
{
	struct ipfix_priv *priv = nurs_plugin_context(plugin);
        pthread_mutexattr_t attr;
	int ret;

	ret = config_corksets_max(plugin);
	if (ret < 2) {
		nurs_log(NURS_ERROR, "corksets_max should be more than 2"
			 " from implementation perspective\n");
		return NURS_RET_ERROR;
	}
	priv->iovmax = ret + 1;	/* +1 for msghdr */

	ret = config_nth_template(plugin);
	if (ret < 1) {
		nurs_log(NURS_ERROR, "invalid nth_template: %d\n", ret);
		return NURS_RET_ERROR;
	}
	priv->nth_template = ret;

	priv->iovecs = calloc((size_t)priv->iovmax, sizeof(struct iovec));
	if (!priv->iovecs) {
		nurs_log(NURS_ERROR, "failed to alloc iovecs: %s\n",
			 _sys_errlist[errno]);
		return NURS_RET_ERROR;
	}

	priv->fd = open_connect_descriptor(config_dest(plugin));
	if (priv->fd < 0) {
		nurs_log(NURS_ERROR, "failed to open descriptor: %s\n",
			 _sys_errlist[errno]);
		goto free_iovecs;
	}

	priv->msghdr.version = htons(10);
	priv->msghdr.domain_id = htonl(config_domain(plugin));
	priv->iovecs[0].iov_base = &priv->msghdr;
	priv->iovecs[0].iov_len = sizeof(priv->msghdr);
	priv->iovcnt = 1;
	priv->next_template_id = NURS_IPFIX_TEMPL_BASE;
	init_list_head(&priv->tmpls);
        pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, NURS_MUTEX_ATTR);

	if ((ret = pthread_mutex_init(&priv->tmpls_mutex, &attr))) {
		nurs_log(NURS_FATAL, "pthread_mutex_init: %s\n",
			 _sys_errlist[errno]);
		goto close_connection;
	}
	if ((ret = pthread_mutex_init(&priv->vecs_mutex, &attr))) {
		nurs_log(NURS_FATAL, "pthread_mutex_init: %s\n",
			 _sys_errlist[errno]);
		goto destroy_tmpls_mutex;
	}
	if ((ret = pthread_cond_init(&priv->vecs_condv, NULL))) {
		nurs_log(NURS_FATAL, "pthread_cond_init: %s\n",
			 _sys_errlist[errno]);
		goto destroy_vecs_mutex;
	}

#ifdef DEBUG_TMMAP
	mmfd = tmpfile();
	if (!mmfd) {
		nurs_log(NURS_ERROR, "failed to open debug file\n");
		goto destroy_vecs_mutex;
	}
	mmaddr = mmap(NULL, 65507, PROT_READ | PROT_WRITE, MAP_PRIVATE, fileno(mmfd), 0);
	if (mmaddr == MAP_FAILED) {
		nurs_log(NURS_ERROR, "failed to mmap debug file\n");
		fclose(mmfd);
		goto destroy_vecs_mutex;
	}
#endif
	return NURS_RET_OK;

destroy_vecs_mutex:
	pthread_mutex_destroy(&priv->vecs_mutex);
destroy_tmpls_mutex:
	pthread_mutex_destroy(&priv->tmpls_mutex);
close_connection:
	close(priv->fd);
free_iovecs:
	free(priv->iovecs);
	return NURS_RET_ERROR;
}

static enum nurs_return_t
ipfix_disorganize(const struct nurs_plugin *plugin)
{
	struct ipfix_priv *priv = nurs_plugin_context(plugin);
	int ret = 0;

#ifdef DEBUG_TMMAP
	ret |= munmap(mmaddr, 65507);
	ret |= fclose(mmfd);
#endif
	ret |= close(priv->fd);
	ret |= pthread_cond_destroy(&priv->vecs_condv);
	ret |= pthread_mutex_destroy(&priv->vecs_mutex);
	ret |= pthread_mutex_destroy(&priv->tmpls_mutex);

	/* XXX: release templates buf? */
	free(priv->iovecs);
	if (ret)
		return NURS_RET_ERROR;
	return NURS_RET_OK;
}

static enum nurs_return_t ipfix_stop(const struct nurs_plugin *plugin)
{
	struct ipfix_priv *priv = nurs_plugin_context(plugin);
	struct ipfix_template *tmpl, *tmp;

	if (priv->iovcnt)
		send_ipfix(priv, true);

	list_for_each_entry_safe(tmpl, tmp, &priv->tmpls, list) {
		nfct_bitmask_destroy(tmpl->bitmask);
		free(tmpl->template);
		free(tmpl->sethdrs);
		pthread_mutex_destroy(&tmpl->sethdrs_mutex);
		pthread_cond_destroy(&tmpl->sethdrs_condv);
		list_del(&tmpl->list);
		free(tmpl);
	}

	return NURS_RET_OK;
}

static struct nurs_coveter_def ipfix_coveter = {
	.name = "IPFIX",
	.version	= VERSION,
	.context_size	= sizeof(struct ipfix_priv),
	.mtsafe		= true,
	.config_def	= &ipfix_config,
	.organize	= ipfix_organize,
	.disorganize	= ipfix_disorganize,
	.stop		= ipfix_stop,
	.interp		= ipfix_interp,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	nurs_coveter_register(&ipfix_coveter);
}

#ifdef DEBUG_TMMAP
static int ipfix_fprintf_ietf_field(FILE *fd,
		const struct ipfix_ietf_field *field, size_t len);
static int ipfix_fprintf_vendor_field(FILE *fd,
		const struct ipfix_vendor_field *field, size_t len);

static int ipfix_fprintf_ietf_field(FILE *fd,
		const struct ipfix_ietf_field *field, size_t len)
{
	int ret;
	void *ptr;

	if (len < sizeof(*field)) {
		fprintf(fd, "ERROR ietf field: too short buflen for IETF field: %lu\n", len);
		return -1;
	}

	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "|0 Information Emement id: %5d |            Field Length: %5d |\n",
		ntohs(field->type), ntohs(field->length));

	len -= sizeof(*field);
	if (len == 0)
		return sizeof(*field);

	ptr = (void *)((uintptr_t)field + sizeof(*field));
	if (*(uint8_t *)ptr & 0x80)
		ret = ipfix_fprintf_vendor_field(fd, ptr, len);
	else
		ret = ipfix_fprintf_ietf_field(fd, ptr, len);

	if (ret == -1)
		return -1;
	return ret + (int)sizeof(*field);
}

static int ipfix_fprintf_vendor_field(FILE *fd,
				      const struct ipfix_vendor_field *field,
				      size_t len)
{
	int ret;
	void *ptr;

	if (len < sizeof(*field)) {
		fprintf(fd, "ERROR vendor field: too short buflen for vendor field: %lu\n", len);
		return -1;
	}

	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "|1 Information Emement id: %5d |            Field Length: %5d |\n",
		ntohs(field->type) & 0x7fff, ntohs(field->length));
	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "|               Enterprise Number: %10d                     |\n",
		ntohl(field->enterprise_num));

	len -= sizeof(*field);
	if (len == 0)
		return sizeof(*field);

	ptr = (void *)((uintptr_t)field + sizeof(*field));
	if (*(uint8_t *)ptr & 0x80) /* vendor */
		ret = ipfix_fprintf_vendor_field(fd, ptr, len);
	else /* ietf */
		ret = ipfix_fprintf_ietf_field(fd, ptr, len);

	if (ret == -1)
		return -1;
	return ret + (int)sizeof(*field);
}

static int ipfix_fprintf_data_records(FILE *fd, const void *data, size_t len)
{
	uintptr_t i;
	int over;

	fprintf(fd, "+-----------------------------------------------------------------+\n");
	/* don't say messy...*/
	for (i = 0; i < len; i += 4) {
		over = (int)len - (int)i - 4;
		switch (over) {
		case -3:
			fprintf(fd, "|          0x%02x                                                   |\n",
				*(uint8_t *)((uintptr_t)data + i));
			break;
		case -2:
			fprintf(fd, "|          0x%02x          0x%02x                                     |\n",
				*(uint8_t *)((uintptr_t)data + i),
				*(uint8_t *)((uintptr_t)data + i + 1));
			break;
		case -1:
			fprintf(fd, "|          0x%02x          0x%02x          0x%02x                       |\n",
				*(uint8_t *)((uintptr_t)data + i),
				*(uint8_t *)((uintptr_t)data + i + 1),
				*(uint8_t *)((uintptr_t)data + i + 2));
			break;
		default:
			fprintf(fd, "|          0x%02x          0x%02x          0x%02x          0x%02x         |\n",
				*(uint8_t *)((uintptr_t)data + i),
				*(uint8_t *)((uintptr_t)data + i + 1),
				*(uint8_t *)((uintptr_t)data + i + 2),
				*(uint8_t *)((uintptr_t)data + i + 3));
			break;
		}
	}
	return (int)len;
}

static int ipfix_fprintf_template_records(FILE *fd, const struct ipfix_tmpl_hdr *hdr,
					  size_t len)
{
	int ret;
	void *field;

	if (len < (int)sizeof(*hdr)) {
		fprintf(fd, "ERROR template records: too short buflen for template record: %lu\n", len);
		return -1;
	}

	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "|             Template ID: %5d |             Field Count: %5d |\n",
		ntohs(hdr->template_id), ntohs(hdr->field_count));

	len -= sizeof(*hdr);
	if (len == 0)
		return sizeof(*hdr);

	field = (void *)((uintptr_t)hdr + sizeof(*hdr));
	if (*(uint8_t *)field & 0x80)
		ret = ipfix_fprintf_vendor_field(fd, field, len);
	else
		ret = ipfix_fprintf_ietf_field(fd, field, len);

	if (ret == -1)
		return -1;

	return ret + (int)sizeof(*hdr);
}

static int ipfix_fprintf_set_header(FILE *fd, const struct ipfix_sethdr *hdr, size_t len)
{
	int ret;
	size_t setlen, total_len;
	void *ptr;

	if (len < (int)sizeof(*hdr)) {
		fprintf(fd, "ERROR set header: too short buflen for set header: %lu\n", len);
		return -1;
	}
	setlen = (size_t)ntohs(hdr->length);
	if (len < setlen) {
		fprintf(fd, "ERROR set header: buflen: %lu is smaller than set length field: %lu\n", len, setlen);
		/* return -1; */
	}
	if (setlen < (int)sizeof(*hdr)) {
		fprintf(fd, "ERROR set header: too short set length field: %lu\n", setlen);
		return -1;
	}

	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "|                  Set ID: %5d |                  Length: %5lu |\n",
		ntohs(hdr->set_id), setlen);

	setlen -= sizeof(*hdr);
	ptr = (void *)((uintptr_t)hdr + sizeof(*hdr));
	total_len = sizeof(*hdr);

	switch (ntohs(hdr->set_id)) {
	case 2:
		ret = ipfix_fprintf_template_records(fd, ptr, setlen);
		break;
	case 3:
		/* XXX: ret = ipfix_fprintf_options_template_records(fd, ptr, setlen); */
		fprintf(fd, "ERROR: options template is not implemented yet, sorry");
		ret = (int)setlen;
		break;
	default:
		ret = ipfix_fprintf_data_records(fd, ptr, setlen);
		break;
	}

	if (ret == -1 || ret != (int)setlen)
		return -1;

	fprintf(fd, "+-----------------------------------------------------------------+\n");
	return (int)total_len + ret;
}

static int _ipfix_fprintf_header(FILE *fd, const struct ipfix_msghdr *hdr)
{
	int ret, len;
	char outstr[20];
	void *ptr;
	time_t t = (time_t)(ntohl(hdr->export_time));
	struct tm *tmp = localtime(&t);

	/* XXX: tmp == NULL and strftime == 0 */
	strftime(outstr, sizeof(outstr), "%F %T", tmp);

	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "|          Version Number: %5d |                  Length: %5d |\n",
		ntohs(hdr->version), ntohs(hdr->length));
	fprintf(fd, "+--------------------------------+--------------------------------+\n");
	fprintf(fd, "|                     Exoprt Time: %10d                     |\t%s\n",
		ntohl(hdr->export_time), outstr);
	fprintf(fd, "+-----------------------------------------------------------------+\n");
	fprintf(fd, "|                 Sequence Number: %10d                     |\n",
		ntohl(hdr->seq));
	fprintf(fd, "+-----------------------------------------------------------------+\n");
	fprintf(fd, "|           Observation Domain ID: %10d                     |\n",
		ntohl(hdr->domain_id));
	fprintf(fd, "+-----------------------------------------------------------------+\n");

	len = (int)ntohs(hdr->length) - (int)sizeof(*hdr);
	ptr = (void *)((uintptr_t)hdr + sizeof(*hdr));

	while (len > 0) {
		ret = ipfix_fprintf_set_header(fd, ptr, (size_t)len);
		if (ret == -1)
			return -1;
		len -= ret;
		ptr = (void *)((uintptr_t)ptr + (uintptr_t)ret);
	}

	return (int)ntohs(hdr->length) - len;
}

static int ipfix_fprintf_header(FILE *fd, const struct ipfix_priv *priv)
{
	fseek(mmfd, 0, SEEK_SET);
	writev(fileno(mmfd), priv->iovecs, priv->iovcnt);
	return _ipfix_fprintf_header(fd, (struct ipfix_msghdr *)mmaddr);
}
#endif

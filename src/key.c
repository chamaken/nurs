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
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>

#include "internal.h"

/* always success (unless input is valid) */
uint16_t nurs_input_len(const struct nurs_input *input)
{
	return input->len;
}
EXPORT_SYMBOL(nurs_input_len);

/* return 0 on error */
static uint16_t key_size(const struct nurs_output_key *key)
{
	switch (key->def->type) {
	case NURS_KEY_T_BOOL:
		return sizeof(bool);
	case NURS_KEY_T_INT8:
		return sizeof(int8_t);
	case NURS_KEY_T_INT16:
		return sizeof(int16_t);
	case NURS_KEY_T_INT32:
		return sizeof(int32_t);
	case NURS_KEY_T_INT64:
		return sizeof(int64_t);
	case NURS_KEY_T_UINT8:
		return sizeof(uint8_t);
	case NURS_KEY_T_UINT16:
		return sizeof(uint16_t);
	case NURS_KEY_T_UINT32:
		return sizeof(uint32_t);
	case NURS_KEY_T_UINT64:
		return sizeof(uint64_t);
	case NURS_KEY_T_INADDR:
		return sizeof(struct in_addr);
	case NURS_KEY_T_IN6ADDR:
		return sizeof(struct in6_addr);
	case NURS_KEY_T_POINTER:
		return sizeof(void *);
	case NURS_KEY_T_STRING:
	case NURS_KEY_T_EMBED:
		return key->def->len;
	default:
		return 0;
	}
	return 0;
}

/* set errno and returns 0 on error */
uint16_t nurs_input_size(const struct nurs_input *input, uint16_t idx)
{
	if (idx >= input->len) {
		errno = ERANGE;
		return 0;
	}
	if (!input->keys[idx]) {
		errno = ENOENT;
		return 0;
	}
	return key_size(input->keys[idx]);
}
EXPORT_SYMBOL(nurs_input_size);

/* set errno and returns NULL on error */
const char *nurs_input_name(const struct nurs_input *input, uint16_t idx)
{
	if (idx >= input->len) {
		errno = ERANGE;
		return NULL;
	}
	if (!input->keys[idx]) {
		errno = ENOENT;
		return NULL;
	}
	return input->keys[idx]->def->name;
}
EXPORT_SYMBOL(nurs_input_name);

/* set errno and returns 0 on error */
uint16_t nurs_input_type(const struct nurs_input *input, uint16_t idx)
{
	if (idx >= input->len) {
		errno = ERANGE;
		return 0;
	}
	if (!input->keys[idx]) {
		errno = ENOENT;
		return 0;
	}
	return input->keys[idx]->def->type;
}
EXPORT_SYMBOL(nurs_input_type);

/* set errno and returns on error */
uint16_t nurs_input_index(const struct nurs_input *input, const char *name)
{
	uint16_t i;

	for (i = 0; i < input->len; i++) {
		if (!input->keys[i]) continue;
		if (!strcmp(input->keys[i]->def->name, name))
			return i;
	}

	errno = ENOENT;
	return 0;
}
EXPORT_SYMBOL(nurs_input_index);

#define check_input(_ret) do { \
	if (idx >= input->len) {					\
		errno = ERANGE;						\
		return _ret;						\
	}								\
	if (!input->keys[idx] ||					\
	    !(input->keys[idx]->flags & (uint16_t)NURS_KEY_F_VALID)) {	\
		errno = ENOENT;						\
		return _ret;						\
	}								\
	} while (0)

#define check_input_type(_t, _ret) do {					\
	check_input(_ret);						\
	if (input->keys[idx]->def->type != _t) {			\
		errno = EINVAL;						\
		return _ret;						\
	}								\
	} while (0)

/* set errno and returns false on error */
bool nurs_input_bool(const struct nurs_input *input, uint16_t idx)
{
	check_input_type(NURS_KEY_T_BOOL, false);
	return input->keys[idx]->b;
}
EXPORT_SYMBOL(nurs_input_bool);

/* set errno and returns 0 on error */
uint8_t nurs_input_u8(const struct nurs_input *input, uint16_t idx)
{
	check_input_type(NURS_KEY_T_UINT8, 0);
	return input->keys[idx]->u8;
}
EXPORT_SYMBOL(nurs_input_u8);

/* set errno and returns 0 on error */
uint16_t nurs_input_u16(const struct nurs_input *input, uint16_t idx)
{
	check_input_type(NURS_KEY_T_UINT16, 0);
	return input->keys[idx]->u16;
}
EXPORT_SYMBOL(nurs_input_u16);

/* set errno and returns 0 on error */
uint32_t nurs_input_u32(const struct nurs_input *input, uint16_t idx)
{
	check_input_type(NURS_KEY_T_UINT32, 0);
	return input->keys[idx]->u32;
}
EXPORT_SYMBOL(nurs_input_u32);

/* set errno and returns 0 on error */
uint64_t nurs_input_u64(const struct nurs_input *input, uint16_t idx)
{
	check_input_type(NURS_KEY_T_UINT64, 0);
	return input->keys[idx]->u64;
}
EXPORT_SYMBOL(nurs_input_u64);

/* set errno and returns 0 on error */
in_addr_t nurs_input_in_addr(const struct nurs_input *input, uint16_t idx)
{
	check_input_type(NURS_KEY_T_INADDR, 0);
	return input->keys[idx]->in4;
}
EXPORT_SYMBOL(nurs_input_in_addr);

/* set errno and returns NULL on error */
const struct in6_addr *
nurs_input_in6_addr(const struct nurs_input *input, uint16_t idx)
{
	check_input_type(NURS_KEY_T_IN6ADDR, NULL);
	/* XXX: copy? */
	return &input->keys[idx]->in6;
}
EXPORT_SYMBOL(nurs_input_in6_addr);

/* set errno and returns NULL on error */
const void *nurs_input_pointer(const struct nurs_input *input, uint16_t idx)
{
	if (idx >= input->len) {
		errno = ERANGE;
		return NULL;
	}
	if (!input->keys[idx] ||
	    !(input->keys[idx]->flags & (uint16_t)NURS_KEY_F_VALID)) {
		errno = ENOENT;
		return NULL;
	}
	if (input->keys[idx]->def->type != NURS_KEY_T_POINTER &&
	    input->keys[idx]->def->type != NURS_KEY_T_EMBED) {
		errno = EINVAL;
		return NULL;
	}

	return input->keys[idx]->ptr;
}
EXPORT_SYMBOL(nurs_input_pointer);

const char *nurs_input_string(const struct nurs_input *input, uint16_t idx)
{
	check_input_type(NURS_KEY_T_STRING, NULL);
	/* XXX: copy? */
	return input->keys[idx]->string;
}
EXPORT_SYMBOL(nurs_input_string);


/* set errno and returns false on error */
bool nurs_input_is_valid(const struct nurs_input *input, uint16_t idx)
{
	if (idx >= input->len) {
		errno = ERANGE;
		return false;
	}
	return input->keys[idx] &&
		(input->keys[idx]->flags & (uint16_t)NURS_KEY_F_VALID)
		== NURS_KEY_F_VALID;
}
EXPORT_SYMBOL(nurs_input_is_valid);

/* set errno and returns false on error */
bool nurs_input_is_active(const struct nurs_input *input, uint16_t idx)
{
	if (idx >= input->len) {
		errno = ERANGE;
		return false;
	}
	return input->keys[idx] != NULL;
}
EXPORT_SYMBOL(nurs_input_is_active);

/* set errno and returns UINT32_MAX on error */
uint32_t nurs_input_ipfix_vendor(const struct nurs_input *input, uint16_t idx)
{
	check_input(0); /* 0 is reserved for IETF but... */
	return input->keys[idx]->def->ipfix.vendor;
}
EXPORT_SYMBOL(nurs_input_ipfix_vendor);

/* set errno and returns 0 on error */
uint16_t nurs_input_ipfix_field(const struct nurs_input *input, uint16_t idx)
{
	check_input(0);
	return input->keys[idx]->def->ipfix.field_id;
}
EXPORT_SYMBOL(nurs_input_ipfix_field);

/* set errno and returns NULL on error */
const char *nurs_input_cim_name(const struct nurs_input *input, uint16_t idx)
{
	check_input(NULL);
	return input->keys[idx]->def->cim_name;
}
EXPORT_SYMBOL(nurs_input_cim_name);

#undef check_input_type
#undef check_input

uint16_t nurs_output_len(const struct nurs_output *output)
{
	return output->len;
}
EXPORT_SYMBOL(nurs_output_len);

/* set errno and return 0 on error */
uint16_t nurs_output_type(const struct nurs_output *output, uint16_t idx)
{
	if (idx >= output->len) {
		errno = ERANGE;
		return 0;
	}
	return output->keys[idx].def->type;
}
EXPORT_SYMBOL(nurs_output_type);

/* set errno and return 0 on error */
uint16_t nurs_output_index(const struct nurs_output *output, const char *name)
{
	uint16_t i;

	for (i = 0; i < output->len; i++) {
		if (!strcmp(output->keys[i].def->name, name))
			return i;
	}

	errno = ENOENT;
	return 0;
}
EXPORT_SYMBOL(nurs_output_index);

/* set errno and return 0 on error */
uint16_t nurs_output_size(const struct nurs_output *output, uint16_t idx)
{
	if (idx >= output->len) {
		errno = ERANGE;
		return 0;
	}
	return key_size(&output->keys[idx]);
}
EXPORT_SYMBOL(nurs_output_size);

#define set_valid(_i) do {					\
	output->keys[_i].flags |= (uint16_t)NURS_KEY_F_VALID; \
	} while (0)

#define check_output_type(_t, _ret) do {				\
	if (idx >= output->len) {					\
		errno = ERANGE;						\
		return _ret;						\
	}								\
	if (output->keys[idx].def->type != _t)	{			\
		errno = EINVAL;						\
		return _ret;						\
	}								\
	} while (0)

/* set errno and returns -1 on error */
int nurs_output_set_bool(struct nurs_output *output, uint16_t idx, bool value)
{
	check_output_type(NURS_KEY_T_BOOL, -1);
	output->keys[idx].b = value;
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_bool);

/* set errno and returns -1 on error */
int nurs_output_set_u8(struct nurs_output *output, uint16_t idx, uint8_t value)
{
	check_output_type(NURS_KEY_T_UINT8, -1);
	output->keys[idx].u8 = value;
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_u8);

/* set errno and returns -1 on error */
int nurs_output_set_u16(struct nurs_output *output, uint16_t idx, uint16_t value)
{
	check_output_type(NURS_KEY_T_UINT16, -1);
	output->keys[idx].u16 = value;
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_u16);

/* set errno and returns -1 on error */
int nurs_output_set_u32(struct nurs_output *output, uint16_t idx, uint32_t value)
{
	check_output_type(NURS_KEY_T_UINT32, -1);
	output->keys[idx].u32 = value;
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_u32);

/* set errno and returns -1 on error */
int nurs_output_set_u64(struct nurs_output *output, uint16_t idx, uint64_t value)
{
	check_output_type(NURS_KEY_T_UINT64, -1);
	output->keys[idx].u64 = value;
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_u64);

/* set errno and returns -1 on error */
int nurs_output_set_in_addr(struct nurs_output *output,
			    uint16_t idx, in_addr_t value)
{
	check_output_type(NURS_KEY_T_INADDR, -1);
	output->keys[idx].in4 = value;
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_in_addr);

/* set errno and returns -1 on error */
int nurs_output_set_in6_addr(struct nurs_output *output,
			     uint16_t idx, const struct in6_addr *value)
{
	check_output_type(NURS_KEY_T_IN6ADDR, -1);
	memcpy(&output->keys[idx].in6, value, sizeof(struct in6_addr));
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_in6_addr);

/* set errno and returns -1 on error */
int nurs_output_set_pointer(struct nurs_output *output,
			    uint16_t idx, const void *value)
{
	check_output_type(NURS_KEY_T_POINTER, -1);
	output->keys[idx].ptr = (void *)(uintptr_t)value;
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_pointer);

int nurs_output_set_string(struct nurs_output *output,
			   uint16_t idx, const char *value)
{
	check_output_type(NURS_KEY_T_STRING, -1);
	strncpy(output->keys[idx].string, value, output->keys[idx].def->len);
	output->keys[idx].string[output->keys[idx].def->len - 1] = '\0';
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_string);

/* set errno and returns NULL on error */
void *nurs_output_pointer(const struct nurs_output *output, uint16_t idx)
{
	if (idx >= output->len) {
		errno = ERANGE;
		return NULL;
	}
	if(output->keys[idx].def->type != NURS_KEY_T_STRING &&
	   output->keys[idx].def->type != NURS_KEY_T_EMBED) {
		errno = EINVAL;
		return NULL;
	}
	return output->keys[idx].ptr;
}
EXPORT_SYMBOL(nurs_output_pointer);

/* set errno and returns -1 on error */
int nurs_output_set_valid(struct nurs_output *output, uint16_t idx)
{
	if (idx >= output->len) {
		errno = ERANGE;
		return -1;
	}
	if (output->keys[idx].def->type != NURS_KEY_T_STRING &&
	    output->keys[idx].def->type != NURS_KEY_T_EMBED) {
		errno = EINVAL;
		return -1;
	}
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_valid);

#undef set_valid

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

/**
 * \defgroup nurs input / output
 * @{
 * struct nurs_input is defined by struct nurs_input_def and
 * and struct nurs_output is by struct nurs_output_def in plugin definition.
 * nurs_input is passed as param in interp callback and nurs_output is same for
 * filter and consumer, coveter. And also can be acquired by
 * nurs_get_output() by producer.
 */

/**
 * nurs_input_len - obtain input array size
 * \param input input passed by callback param
 *
 * This function returns the size of input.
 */
uint16_t nurs_input_len(const struct nurs_input *input)
{
	return input->len;
}
EXPORT_SYMBOL(nurs_input_len);

/* return 0 on error */
static uint32_t key_size(const struct nurs_output_key *key)
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

/**
 * nurs_input_size - obtain input key size
 * \param input input passed by callback param
 * \param idx index in nurs_input_def
 *
 * This function returns the input key size specified by idx.
 * On error, it returns 0 and errno is appropriately set.
 */
uint32_t nurs_input_size(const struct nurs_input *input, uint16_t idx)
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

/**
 * nurs_input_name - obtain input key name
 * \param input input passed by callback param
 * \param idx index in nurs_input_def
 *
 * This function returns name of the input key specified by idx.
 * On error, it returns NULL and errno is appropriately set.
 */
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

/**
 * nurs_input_type - obtain input key type
 * \param input input passed by callback param
 * \param idx index in nurs_input_def
 *
 * This function returns type of the input key specified by idx, either
 *	NURS_KEY_T_BOOL
 *	NURS_KEY_T_INT8
 *	NURS_KEY_T_INT16
 *	NURS_KEY_T_INT32
 *	NURS_KEY_T_INT64
 *	NURS_KEY_T_UINT8
 *	NURS_KEY_T_UINT16
 *	NURS_KEY_T_UINT32
 *	NURS_KEY_T_UINT64
 *	NURS_KEY_T_INADDR
 *	NURS_KEY_T_IN6ADDR
 *	NURS_KEY_T_POINTER
 *	NURS_KEY_T_STRING
 *	NURS_KEY_T_EMBED
 * On error, it returns 0 and errno is appropriately set.
 */
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

/**
 * nurs_input_index - obtain input key index
 * \param input input passed by callback param
 * \param name input key name
 *
 * This function returns index of the input key specified by name.
 * On error, it returns 0 and errno is appropriately set.
 */
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

/**
 * nurs_input_bool - obtain bool value from input
 * \param input input passed by callback param
 * \param idx input key index
 *
 * This function returns boolean value of the input specified by index.
 * On error, it returns false and errno is appropriately set.
 */
bool nurs_input_bool(const struct nurs_input *input, uint16_t idx)
{
	check_input_type(NURS_KEY_T_BOOL, false);
	return input->keys[idx]->b;
}
EXPORT_SYMBOL(nurs_input_bool);

/**
 * nurs_input_u8 - obtain uint8_t value from input
 * \param input input passed by callback param
 * \param idx input key index
 *
 * This function returns uint8_t value of the input specified by index.
 * On error, it returns 0 and errno is appropriately set.
 */
uint8_t nurs_input_u8(const struct nurs_input *input, uint16_t idx)
{
	check_input_type(NURS_KEY_T_UINT8, 0);
	return input->keys[idx]->u8;
}
EXPORT_SYMBOL(nurs_input_u8);

/**
 * nurs_input_u16 - obtain uint16_t value from input
 * \param input input passed by callback param
 * \param idx input key index
 *
 * This function returns uint16_t value of the input specified by index.
 * On error, it returns 0 and errno is appropriately set.
 */
uint16_t nurs_input_u16(const struct nurs_input *input, uint16_t idx)
{
	check_input_type(NURS_KEY_T_UINT16, 0);
	return input->keys[idx]->u16;
}
EXPORT_SYMBOL(nurs_input_u16);

/**
 * nurs_input_u32 - obtain uint32_t value from input
 * \param input input passed by callback param
 * \param idx input key index
 *
 * This function returns uint32_t value of the input specified by index.
 * On error, it returns 0 and errno is appropriately set.
 */
uint32_t nurs_input_u32(const struct nurs_input *input, uint16_t idx)
{
	check_input_type(NURS_KEY_T_UINT32, 0);
	return input->keys[idx]->u32;
}
EXPORT_SYMBOL(nurs_input_u32);

/**
 * nurs_input_u64 - obtain uint64_t value from input
 * \param input input passed by callback param
 * \param idx input key index
 *
 * This function returns uint64_t value of the input specified by index.
 * On error, it returns 0 and errno is appropriately set.
 */
uint64_t nurs_input_u64(const struct nurs_input *input, uint16_t idx)
{
	check_input_type(NURS_KEY_T_UINT64, 0);
	return input->keys[idx]->u64;
}
EXPORT_SYMBOL(nurs_input_u64);

/**
 * nurs_input_in_addr - obtain in_addr_t value from input
 * \param input input passed by callback param
 * \param idx input key index
 *
 * This function returns in_addr_t (uint32_t) value of the input specified by
 * index. On error, it returns 0 and errno is appropriately set.
 */
in_addr_t nurs_input_in_addr(const struct nurs_input *input, uint16_t idx)
{
	check_input_type(NURS_KEY_T_INADDR, 0);
	return input->keys[idx]->in4;
}
EXPORT_SYMBOL(nurs_input_in_addr);

/**
 * nurs_input_in6_addr - obtain pointer to struct in6_addr from input
 * \param input input passed by callback param
 * \param idx input key index
 *
 * This function returns struct in6_addr pointer of the input specified by
 * index. On error, it returns NULL and errno is appropriately set.
 */
const struct in6_addr *
nurs_input_in6_addr(const struct nurs_input *input, uint16_t idx)
{
	check_input_type(NURS_KEY_T_IN6ADDR, NULL);
	/* XXX: copy? */
	return &input->keys[idx]->in6;
}
EXPORT_SYMBOL(nurs_input_in6_addr);

/**
 * nurs_input_pointer - obtain pointer from input
 * \param input input passed by callback param
 * \param idx input key index
 *
 * This function returns pointer (void *) of the input specified by
 * index. On error, it returns NULL and errno is appropriately set.
 */
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

/**
 * nurs_input_string - obtain string from input
 * \param input input passed by callback param
 * \param idx input key index
 *
 * This function returns string (char *) of the input specified by
 * index. On error, it returns NULL and errno is appropriately set.
 */
const char *nurs_input_string(const struct nurs_input *input, uint16_t idx)
{
	check_input_type(NURS_KEY_T_STRING, NULL);
	/* XXX: copy? */
	return input->keys[idx]->string;
}
EXPORT_SYMBOL(nurs_input_string);

/**
 * nurs_input_is_valid - check input validity
 * \param input input passed by callback param
 * \param idx input key index
 *
 * This function returns true if the input specified by index is set or returns
 * false. On error, it returns false and errno is appropriately set.
 */
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

/**
 * nurs_input_is_active - check input key has source output or not.
 * \param input input passed by callback param
 * \param idx input key index
 *
 * This function returns true if the input specified by index is has source in
 * the stack or returns false. On error, it returns false and errno is
 * appropriately set.
 */
bool nurs_input_is_active(const struct nurs_input *input, uint16_t idx)
{
	if (idx >= input->len) {
		errno = ERANGE;
		return false;
	}
	return input->keys[idx] != NULL;
}
EXPORT_SYMBOL(nurs_input_is_active);

/**
 * nurs_input_ipfix_vendor - obtain IPFIX vendor code from input
 * \param input input passed by callback param
 * \param idx input key index
 *
 * This function returns IPFIX vendor code of the input specified by index.  On
 * error, it returns 0 (caution, IETF code is 0) and errno is appropriately set.
 */
uint32_t nurs_input_ipfix_vendor(const struct nurs_input *input, uint16_t idx)
{
	check_input(0); /* 0 is reserved for IETF but... */
	return input->keys[idx]->def->ipfix.vendor;
}
EXPORT_SYMBOL(nurs_input_ipfix_vendor);

/**
 * nurs_input_ipfix_field - obtain IPFIX field id from input
 * \param input input passed by callback param
 * \param idx input key index
 *
 * This function returns IPFIX field id of the input specified by index.  On
 * error, it returns 0 and errno is appropriately set.
 */
uint16_t nurs_input_ipfix_field(const struct nurs_input *input, uint16_t idx)
{
	check_input(0);
	return input->keys[idx]->def->ipfix.field_id;
}
EXPORT_SYMBOL(nurs_input_ipfix_field);

/**
 * nurs_input_cim_name - obtain cim name from input
 * \param input input passed by callback param
 * \param idx input key index
 *
 * This function returns cim name (char *) of the input specified by index.
 * On error, it returns NULL and errno is appropriately set.
 */
const char *nurs_input_cim_name(const struct nurs_input *input, uint16_t idx)
{
	check_input(NULL);
	return input->keys[idx]->def->cim_name;
}
EXPORT_SYMBOL(nurs_input_cim_name);

#undef check_input_type
#undef check_input

/**
 * nurs_output_len - obtain output array size
 * \param output output passed by callback param or get by nurs_get_output()
 *
 * This function returns array size of output.
 */
uint16_t nurs_output_len(const struct nurs_output *output)
{
	return output->len;
}
EXPORT_SYMBOL(nurs_output_len);

/**
 * nurs_output_type - obtain output key type
 * \param output output passed by callback param or get by nurs_get_output()
 * \param idx index in nurs_output_def
 *
 * This function returns type of the output key specified by idx, same as
 * nurs_input_type. On error, it returns 0 and errno is appropriately set.
 */
uint16_t nurs_output_type(const struct nurs_output *output, uint16_t idx)
{
	if (idx >= output->len) {
		errno = ERANGE;
		return 0;
	}
	return output->keys[idx].def->type;
}
EXPORT_SYMBOL(nurs_output_type);

/**
 * nurs_output_index - obtain output key index
 * \param output output passed by callback param or get by nurs_get_output()
 * \param name output key name
 *
 * This function returns index of the output key specified by name.
 * On error, it returns 0 and errno is appropriately set.
 */
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

/**
 * nurs_output_size - obtain output key size
 * \param output output passed by callback param or get by nurs_get_output()
 * \param idx index in nurs_output_def
 *
 * This function returns the output key size specified by idx.
 * On error, it returns 0 and errno is appropriately set.
 */
uint32_t nurs_output_size(const struct nurs_output *output, uint16_t idx)
{
	if (idx >= output->len) {
		errno = ERANGE;
		return 0;
	}
	return key_size(&output->keys[idx]);
}
EXPORT_SYMBOL(nurs_output_size);

#define set_valid(_i) do {						\
		output->keys[_i].flags |= (uint16_t)NURS_KEY_F_VALID;	\
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

/**
 * nurs_output_set_bool - set boolean value to output
 * \param output output passed by callback param or get by nurs_get_output()
 * \param idx output key index
 * \param value value to set
 *
 * This function set boolean value to the output specified by index.
 * On error, it returns -1 and errno is appropriately set, or returns 0 on
 * success.
 */
int nurs_output_set_bool(struct nurs_output *output, uint16_t idx, bool value)
{
	check_output_type(NURS_KEY_T_BOOL, -1);
	output->keys[idx].b = value;
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_bool);

/**
 * nurs_output_set_u8 - set uint8_t value to output
 * \param output output passed by callback param or get by nurs_get_output()
 * \param idx output key index
 * \param value value to set
 *
 * This function set uint8_t value to the output specified by index.
 * On error, it returns -1 and errno is appropriately set, or returns 0 on
 * success.
 */
int nurs_output_set_u8(struct nurs_output *output, uint16_t idx, uint8_t value)
{
	check_output_type(NURS_KEY_T_UINT8, -1);
	output->keys[idx].u8 = value;
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_u8);

/**
 * nurs_output_set_u16 - set uint16_t value to output
 * \param output output passed by callback param or get by nurs_get_output()
 * \param idx output key index
 * \param value value to set
 *
 * This function set uint16_t value to the output specified by index.
 * On error, it returns -1 and errno is appropriately set, or returns 0 on
 * success.
 */
int nurs_output_set_u16(struct nurs_output *output, uint16_t idx, uint16_t value)
{
	check_output_type(NURS_KEY_T_UINT16, -1);
	output->keys[idx].u16 = value;
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_u16);

/**
 * nurs_output_set_u32 - set uint32_t value to output
 * \param output output passed by callback param or get by nurs_get_output()
 * \param idx output key index
 * \param value value to set
 *
 * This function set uint32_t value to the output specified by index.
 * On error, it returns -1 and errno is appropriately set, or returns 0 on
 * success.
 */
int nurs_output_set_u32(struct nurs_output *output, uint16_t idx, uint32_t value)
{
	check_output_type(NURS_KEY_T_UINT32, -1);
	output->keys[idx].u32 = value;
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_u32);

/**
 * nurs_output_set_u64 - set uint64_t value to output
 * \param output output passed by callback param or get by nurs_get_output()
 * \param idx output key index
 * \param value value to set
 *
 * This function set uint64_t value to the output specified by index.
 * On error, it returns -1 and errno is appropriately set, or returns 0 on
 * success.
 */
int nurs_output_set_u64(struct nurs_output *output, uint16_t idx, uint64_t value)
{
	check_output_type(NURS_KEY_T_UINT64, -1);
	output->keys[idx].u64 = value;
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_u64);

/**
 * nurs_output_set_in_addr - set in_addr_t value to output
 * \param output output passed by callback param or get by nurs_get_output()
 * \param idx output key index
 * \param value value to set
 *
 * This function set in_addr_t value to the output specified by index.
 * On error, it returns -1 and errno is appropriately set, or returns 0 on
 * success.
 */
int nurs_output_set_in_addr(struct nurs_output *output,
			    uint16_t idx, in_addr_t value)
{
	check_output_type(NURS_KEY_T_INADDR, -1);
	output->keys[idx].in4 = value;
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_in_addr);

/**
 * nurs_output_set_in6_addr - copy struct in6_addr value to output
 * \param output output passed by callback param or get by nurs_get_output()
 * \param idx output key index
 * \param value value to copy
 *
 * This function copy struct in6_addr value to the output specified by index.
 * On error, it returns -1 and errno is appropriately set, or returns 0 on
 * success.
 */
int nurs_output_set_in6_addr(struct nurs_output *output,
			     uint16_t idx, const struct in6_addr *value)
{
	check_output_type(NURS_KEY_T_IN6ADDR, -1);
	memcpy(&output->keys[idx].in6, value, sizeof(struct in6_addr));
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_in6_addr);

/**
 * nurs_output_set_pointer - set pointer value to output
 * \param output output passed by callback param or get by nurs_get_output()
 * \param idx output key index
 * \param value value to set
 *
 * This function set pointer (void *) to the output specified by index.
 * On error, it returns -1 and errno is appropriately set, or returns 0 on
 * success.
 */
int nurs_output_set_pointer(struct nurs_output *output,
			    uint16_t idx, const void *value)
{
	check_output_type(NURS_KEY_T_POINTER, -1);
	output->keys[idx].ptr = (void *)(uintptr_t)value;
	set_valid(idx);
	return 0;
}
EXPORT_SYMBOL(nurs_output_set_pointer);

/**
 * nurs_output_set_string - copy string to output
 * \param output output passed by callback param or get by nurs_get_output()
 * \param idx output key index
 * \param value value to copy
 *
 * This function copy string (char *) to the output specified by index.
 * On error, it returns -1 and errno is appropriately set, or returns 0 on
 * success.
 */
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

/**
 * nurs_output_pointer - obtain pointer from output
 * \param output output passed by callback param or get by nurs_get_output()
 * \param idx output key index
 *
 * This function returns pointer (void *) of the output specified by
 * index. On error, it returns NULL and errno is appropriately set.
 */
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

/**
 * nurs_output_set_valid - set valid to output
 * \param output output passed by callback param or get by nurs_get_output()
 * \param idx output key index
 *
 * This function set valid flag to output specified by index. This may be used
 * combined with nurs_output_pointer(). On error, it returns NULL and errno is
 * appropriately set.
 */
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

/**
 * @}
 */

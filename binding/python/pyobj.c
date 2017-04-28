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
#include <Python.h>
#include <frameobject.h>	/* PyFrameObject */

#include <errno.h>

#include <nurs/nurs.h>
#include "pynurs.h"

PyObject *module;
/* plugin callbacks */
PyObject *organize_cb,
	*disorganize_cb,
	*start_cb,
	*stop_cb,
	*signal_cb,
	*interp_cb;
/* args holder */
PyObject *plugin_obj,
	*producer_obj,
	*config_obj,
	*input_obj,
	*output_obj;

PyMODINIT_FUNC PyInit_nurs(void);

#define py_check_errno do {				\
	if (errno) {					\
		PyErr_SetFromErrno(PyExc_OSError);	\
		return NULL;				\
	}						\
	} while(0)

/* use nurs_log instead of pycli_log in here */
int py_init(const char *modname)
{
	PyObject *nurs;
	PyObject *name;
	char ebuf[ERRBUF_SIZE];

	name = PyUnicode_FromString(modname);
	if (!name)
		return -1;

	module = PyImport_Import(name);
	Py_DECREF(name);
	if (!module) {
		nurs_log(NURS_ERROR, "could not load module %s: %s\n",
			 modname, py_strerror(ebuf, ERRBUF_SIZE));
		return -1;
	}

	/* get callbacks */
#define _resolve_cb(_cbname) do {					\
	_cbname ## _cb = PyObject_GetAttrString(module, #_cbname); 	\
	if (_cbname ## _cb && !PyCallable_Check(_cbname ## _cb)) {	\
		nurs_log(NURS_ERROR, "can not call %s." #_cbname ": %s\n", \
			 modname, py_strerror(ebuf, ERRBUF_SIZE));	\
		return -1;						\
	}								\
	} while (0)

	_resolve_cb(organize);
	_resolve_cb(disorganize);
	_resolve_cb(start);
	_resolve_cb(stop);
	_resolve_cb(signal);
	_resolve_cb(interp);
#undef _resolve_cb
	PyErr_Clear();
	nurs = PyInit_nurs();
	if (PyErr_Occurred()) {
		nurs_log(NURS_ERROR, "failed to create nurs module :%s\n",
			 py_strerror(ebuf, ERRBUF_SIZE));
		return -1;
	}

#define _set_holder(_var, _name) do {					\
	PyObject *_cls;							\
	_cls = PyObject_GetAttrString(nurs, _name);			\
	if (!_cls) {							\
		nurs_log(NURS_ERROR, "failed to get nurs." _name	\
			 ": %s\n", py_strerror(ebuf, ERRBUF_SIZE));	\
		return -1;						\
	}								\
	_var = PyObject_CallObject(_cls, NULL);				\
	Py_DECREF(_cls);						\
	if (!_var) {							\
		if (PyErr_Occurred()) \
			nurs_log(NURS_ERROR, "failed to init: nurs."	\
				 ": %s\n", py_strerror(ebuf, ERRBUF_SIZE)); \
		else							\
			nurs_log(NURS_ERROR, "failed to init: nurs." _name "\n"); \
		return -1;						\
	}								\
	} while (0)

	_set_holder(config_obj,	  "Config");
	_set_holder(input_obj,	  "Input");
	_set_holder(output_obj,	  "Output");
	_set_holder(plugin_obj,   "Plugin");
	_set_holder(producer_obj, "Producer");

	if (PyObject_SetAttrString(module, "nurs", nurs))
		return -1;
	Py_XDECREF(nurs);

	return 0;
}

#define py_input(_i) \
	({ ((struct pynurs_input *)input_obj)->raw = _i; input_obj; })
#define py_output(_o) \
	({ ((struct pynurs_output *)output_obj)->raw = _o; output_obj; })
#define py_plugin(_p) \
	({ ((struct pynurs_plugin *)plugin_obj)->raw = _p; plugin_obj; })
#define py_producer(_p) \
	({ ((struct pynurs_producer *)producer_obj)->raw = _p; producer_obj; })

/* decrefing */
static enum nurs_return_t py_nurs_return(PyObject *obj)
{
	enum nurs_return_t ret = NURS_RET_ERROR;
	char ebuf[ERRBUF_SIZE];
	long rc;

	if (!obj) {
		if (PyErr_Occurred()) {
			pycli_log(NURS_ERROR, "error: %s\n",
				  py_strerror(ebuf, ERRBUF_SIZE));
		} else {
			pycli_log(NURS_ERROR, "got only NULL\n");
		}
		return ret;
	}
	if (!PyLong_Check(obj)) {
		pycli_log(NURS_ERROR, "require returning an integer\n");
		goto decref;
	}
	rc = PyLong_AsLong(obj);
	switch(rc) {
	case NURS_RET_OK:
	case NURS_RET_STOP:
	case NURS_RET_ERROR:
		ret = rc;
		break;
	default:
		break;
	}

decref:
	Py_DECREF(obj);
	return ret;
}

enum nurs_return_t py_organize(struct nurs_plugin *plugin)
{
	if (!organize_cb)
		return NURS_RET_OK;

	return py_nurs_return(
		PyObject_CallFunctionObjArgs(
			organize_cb,
			py_plugin(plugin),
			NULL));
}

enum nurs_return_t py_coveter_organize(struct nurs_plugin *plugin,
				       struct nurs_input *input)
{
	if (!organize_cb)
		return NURS_RET_OK;

	return py_nurs_return(
		PyObject_CallFunctionObjArgs(
			organize_cb,
			py_plugin(plugin),
			py_input(input),
			NULL));
}

enum nurs_return_t py_producer_organize(struct nurs_producer *producer)
{
	if (!organize_cb)
		return NURS_RET_OK;

	return py_nurs_return(
		PyObject_CallFunctionObjArgs(
			organize_cb,
			py_producer(producer),
			NULL));
}

enum nurs_return_t py_disorganize(struct nurs_plugin *plugin)
{
	if (!disorganize_cb)
		return NURS_RET_OK;

	return py_nurs_return(
		PyObject_CallFunctionObjArgs(
			disorganize_cb,
			py_plugin(plugin),
			NULL));
}

enum nurs_return_t py_producer_disorganize(struct nurs_producer *producer)
{
	if (!disorganize_cb)
		return NURS_RET_OK;

	return py_nurs_return(
		PyObject_CallFunctionObjArgs(
			disorganize_cb,
			py_producer(producer),
			NULL));
}

enum nurs_return_t py_start(struct nurs_plugin *plugin)
{
	if (!start_cb)
		return NURS_RET_OK;

	return py_nurs_return(
		PyObject_CallFunctionObjArgs(
			start_cb,
			py_plugin(plugin),
			NULL));
}

enum nurs_return_t py_producer_start(struct nurs_producer *producer)
{
	if (!start_cb)
		return NURS_RET_OK;

	return py_nurs_return(
		PyObject_CallFunctionObjArgs(
			start_cb,
			py_producer(producer),
			NULL));
}

enum nurs_return_t py_stop(struct nurs_plugin *plugin)
{
	if (!stop_cb)
		return NURS_RET_OK;

	return py_nurs_return(
		PyObject_CallFunctionObjArgs(
			stop_cb,
			py_plugin(plugin),
			NULL));
}

enum nurs_return_t py_producer_stop(struct nurs_producer *producer)
{
	if (!stop_cb)
		return NURS_RET_OK;

	return py_nurs_return(
		PyObject_CallFunctionObjArgs(
			stop_cb,
			py_producer(producer),
			NULL));
}

enum nurs_return_t py_signal(struct nurs_plugin *plugin, uint32_t signum)
{
	PyObject *num;

	if (!signal_cb)
		return NURS_RET_OK;

	num = Py_BuildValue("I", signum);
	return py_nurs_return(
		PyObject_CallFunctionObjArgs(
			signal_cb,
			py_plugin(plugin),
			num, NULL));
}

enum nurs_return_t py_producer_signal(struct nurs_producer *producer,
				      uint32_t signum)
{
	PyObject *num;

	if (!signal_cb)
		return NURS_RET_OK;

	num = Py_BuildValue("I", signum);
	return py_nurs_return(
		PyObject_CallFunctionObjArgs(
			signal_cb,
			py_producer(producer),
			num, NULL));

}

enum nurs_return_t py_filter_interp(struct nurs_plugin *plugin,
				    struct nurs_input *input,
				    struct nurs_output *output)
{
	if (!interp_cb)
		return NURS_RET_OK;

	return py_nurs_return(
		PyObject_CallFunctionObjArgs(
			interp_cb,
			py_plugin(plugin),
			py_input(input),
			py_output(output),
			NULL));
}

enum nurs_return_t py_consumer_interp(struct nurs_plugin *plugin,
				      struct nurs_input *input)
{
	if (!interp_cb)
		return NURS_RET_OK;

	return py_nurs_return(
		PyObject_CallFunctionObjArgs(
			interp_cb,
			py_plugin(plugin),
			py_input(input),
			NULL));
}

/****
 *
 */
static PyObject *
pynurs_log(int level, PyObject *arg)
{
	PyThreadState *state;
	PyFrameObject *frame;
	char *file, *msg;
	PyObject *file_ascii = NULL, *msg_ascii;
	int line;

	if (!PyUnicode_Check(arg)) {
		PyErr_SetString(PyExc_TypeError, "not an string");
		return NULL;
	}
	msg_ascii = PyUnicode_AsASCIIString(arg);
	if (!msg_ascii) {
		PyErr_SetString(PyExc_TypeError, "not an ascii");
		return NULL;
	}
	msg = PyBytes_AsString(msg_ascii);

	state = PyThreadState_GET();
	if (!state || !state->frame) {
		__pynurs_log(level, "(unknown)", 0, "%s\n", msg);
		goto dec_msg_ascii;
		Py_RETURN_NONE;
	}

	frame = state->frame;
	line = frame->f_lineno;
	file_ascii = PyUnicode_AsASCIIString(frame->f_code->co_filename);
	if (!file_ascii) {
		__pynurs_log(level, "(unknown)", line, "%s\n", msg);
		goto dec_msg_ascii;
		Py_RETURN_NONE;
	}

	file = PyBytes_AsString(file_ascii);
	if (!file) {
		__pynurs_log(level, "(unknown)", line, "%s\n", msg);
		goto dec_msg_ascii;
		Py_RETURN_NONE;
	}

	__pynurs_log(level, basename(file), line, "%s\n", msg);

	Py_DECREF(file_ascii);
dec_msg_ascii:
	Py_DECREF(msg_ascii);

	Py_RETURN_NONE;
}

static PyObject *
pynurs_log_debug(PyObject *self, PyObject *arg)
{
	return pynurs_log(NURS_DEBUG, arg);
}

static PyObject *
pynurs_log_info(PyObject *self, PyObject *arg)
{
	return pynurs_log(NURS_INFO, arg);
}

static PyObject *
pynurs_log_notice(PyObject *self, PyObject *arg)
{
	return pynurs_log(NURS_NOTICE, arg);
}

static PyObject *
pynurs_log_error(PyObject *self, PyObject *arg)
{
	return pynurs_log(NURS_ERROR, arg);
}

static PyObject *
pynurs_log_fatal(PyObject *self, PyObject *arg)
{
	return pynurs_log(NURS_FATAL, arg);
}

static PyMethodDef pynurs_log_methods[] = {
	{ "debug",  pynurs_log_debug,  METH_O | METH_STATIC, "debug log", },
	{ "info",   pynurs_log_info,   METH_O | METH_STATIC, "info log", },
	{ "notice", pynurs_log_notice, METH_O | METH_STATIC, "notice log", },
	{ "error",  pynurs_log_error,  METH_O | METH_STATIC, "error log", },
	{ "fatal",  pynurs_log_fatal,  METH_O | METH_STATIC, "fatal log", },
	{ NULL, },
};

static PyTypeObject pynurs_log_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "nurs.Log",
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "nurs_log()",
	.tp_methods	= pynurs_log_methods,
};

/****
 * struct nurs_config
 */
static void pynurs_config_dealloc(struct pynurs_input *self)
{
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static Py_ssize_t
pynurs_config_len(struct pynurs_config *self)
{
	return (int)nurs_config_len(self->raw);
}

static PyObject *
pynurs_config_get_value(struct pynurs_config *self, PyObject *arg)
{
	const struct nurs_config *config = self->raw;
	PyObject *ascii;
	uint16_t ctype;
	uint8_t index;
	char *name;
	int rcint;
	bool rcbool;
	const char *rcstr;

	if (PyLong_Check(arg))
		index = (uint8_t)PyLong_AsLong(arg);
	else if (PyUnicode_Check(arg)) {
		ascii = PyUnicode_AsASCIIString(arg);
		if (!ascii) {
			PyErr_SetString(PyExc_TypeError, "not an ascii");
			return NULL;
		}
		name = PyBytes_AsString(ascii);
		errno = 0;
		index = nurs_config_index(config, name);
		Py_DECREF(ascii);
		if (!index && errno) {
			PyErr_Format(PyExc_KeyError, "not exist: %s", name);
			return NULL;
		}
	} else {
		PyErr_SetString(PyExc_TypeError, "invalid key type");
		return NULL;
	}

	errno = 0;
	ctype = nurs_config_type(config, index);
	if (!ctype) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}
	switch (ctype) {
	case NURS_CONFIG_T_INTEGER:
		rcint = nurs_config_integer(config, index);
		if (!rcint && errno) {
			PyErr_SetFromErrno(PyExc_OSError);
			return NULL;
		}
		return Py_BuildValue("I", rcint);
	case NURS_CONFIG_T_BOOLEAN:
		rcbool = nurs_config_boolean(config,index);
		if (!rcbool && errno) {
			PyErr_SetFromErrno(PyExc_OSError);
			return NULL;
		}
		if (rcbool)
			Py_RETURN_TRUE;
		Py_RETURN_FALSE;
	case NURS_CONFIG_T_STRING:
		rcstr = nurs_config_string(config, index);
		if (!rcstr) {
			PyErr_SetFromErrno(PyExc_OSError);
			return NULL;
		}
		return Py_BuildValue("s", rcstr);
	default:
		pycli_log(NURS_ERROR, "unsupported type: %d\n", ctype);
		PyErr_Format(PyExc_TypeError, "unsupported type: %d", ctype);
	}

	return NULL;
}

static PyMappingMethods pynurs_config_as_mapping = {
	(lenfunc)pynurs_config_len,
	(binaryfunc)pynurs_config_get_value,
	NULL,
};

static PyTypeObject pynurs_config_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "nurs.Config",
	.tp_basicsize	= sizeof(struct pynurs_config),
	.tp_new		= PyType_GenericNew,
	.tp_dealloc	= (destructor)pynurs_config_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct nurs_config",
	.tp_as_mapping	= &pynurs_config_as_mapping,
};

/****
 * struct nurs_input
 */
static void pynurs_input_dealloc(struct pynurs_input *self)
{
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static Py_ssize_t
pynurs_input_len(struct pynurs_input *self)
{
	return (int)nurs_input_len(self->raw);
}

/* returns UINT16_MAX on error */
static uint16_t input_index(const struct nurs_input *input, PyObject *arg)
{
	uint16_t index;
	char *name;
	PyObject *ascii;

	if (PyLong_Check(arg))
		index = (uint16_t)PyLong_AsLong(arg);
	else if (PyUnicode_Check(arg)) {
		ascii = PyUnicode_AsASCIIString(arg);
		if (!ascii) {
			PyErr_SetString(PyExc_TypeError, "not an ascii");
			return UINT16_MAX;
		}
		name = PyBytes_AsString(ascii);
		errno = 0;
		index = nurs_input_index(input, name);
		Py_DECREF(ascii);
		if (errno) { /* XXX: should be set errno? */
			PyErr_Format(PyExc_KeyError, "not exist: %s", name);
			return UINT16_MAX;
		}
	} else {
		PyErr_SetString(PyExc_TypeError, "invalid arg type");
		return UINT16_MAX;
	}

	return index;
}

static PyObject *
pynurs_input_get_name(struct pynurs_input *self, PyObject *arg)
{
	const struct nurs_input *input = self->raw;
	uint16_t index;
	const char *name;

	index = input_index(input, arg);
	if (index == UINT16_MAX)
		return NULL;

	name = nurs_input_name(input, index);
	if (!name) {
		PyErr_SetString(PyExc_TypeError, "invalid key");
		return NULL;
	}

	return Py_BuildValue("s", name);
}

static PyObject *
pynurs_input_get_type(struct pynurs_input *self, PyObject *arg)
{
	const struct nurs_input *input = self->raw;
	uint16_t index;
	uint16_t ktype;

	index = input_index(input, arg);
	if (index == UINT16_MAX)
		return NULL;

	ktype = nurs_input_type(input, index);
	if (!ktype) {
		PyErr_SetString(PyExc_TypeError, "invalid key");
		return NULL;
	}

	return Py_BuildValue("H", ktype);
}

static PyObject *
pynurs_input_get_size(struct pynurs_input *self, PyObject *arg)
{
	const struct nurs_input *input = self->raw;
	uint32_t ksize;
	uint16_t index;

	index = input_index(input, arg);
	if (index == UINT16_MAX)
		return NULL;

	ksize = nurs_input_size(input, index);
	if (!ksize) {
		PyErr_SetString(PyExc_TypeError, "invalid key");
		return NULL;
	}

	return Py_BuildValue("H", ksize);
}

static PyObject *
pynurs_input_get_value(struct pynurs_input *self, PyObject *arg)
{
	const struct nurs_input *input = self->raw;
	uint16_t index;
	uint16_t ktype;
	bool b;
	uint8_t u8;
	uint16_t u16;
	uint32_t u32;
	uint64_t u64;
	in_addr_t inaddr;
	const struct in6_addr *in6addr;
	const void *ptr;

	index = input_index(input, arg);
	if (index == UINT16_MAX)
		return NULL;

	ktype = nurs_input_type(input, index);
	if (!ktype) {
		PyErr_SetString(PyExc_TypeError, "invalid key");
		return NULL;
	}

	errno = 0;
	switch (ktype) {
	case NURS_KEY_T_BOOL:
		b = nurs_input_bool(input, index);
		py_check_errno;
		if (b)
			Py_RETURN_TRUE;
		Py_RETURN_FALSE;
	case NURS_KEY_T_UINT8:
		u8 = nurs_input_u8(input, index);
		py_check_errno;
		return Py_BuildValue("B", u8);
	case NURS_KEY_T_UINT16:
		u16 = nurs_input_u16(input, index);
		py_check_errno;
		return Py_BuildValue("H", u16);
	case NURS_KEY_T_UINT32:
		u32 = nurs_input_u32(input, index);
		py_check_errno;
		return Py_BuildValue("I", u32);
	case NURS_KEY_T_UINT64:
		u64 = nurs_input_u64(input, index);
		py_check_errno;
		return Py_BuildValue("K", u64);
	case NURS_KEY_T_INADDR:
		inaddr = nurs_input_in_addr(input, index);
		py_check_errno;
		return Py_BuildValue("H", inaddr);
	case NURS_KEY_T_IN6ADDR:
		in6addr = nurs_input_in6_addr(input, index);
		py_check_errno;
		return Py_BuildValue("y#", in6addr, sizeof(struct in6_addr));
	case NURS_KEY_T_EMBED:
		ptr = nurs_input_pointer(input, index);
		py_check_errno;
		/* return Py_BuildValue("K", ptr); */
		return PyByteArray_FromStringAndSize(ptr, nurs_input_size(input, index));
	case NURS_KEY_T_STRING:
		ptr = nurs_input_string(input, index);
		py_check_errno;
		return Py_BuildValue("s", ptr, nurs_input_size(input, index));
	case NURS_KEY_T_POINTER:
	default:
		PyErr_Format(PyExc_TypeError, "unsupported type: %d", ktype);
	}

	return NULL;
}

static PyObject *
pynurs_input_get_cim_name(struct pynurs_input *self, PyObject *arg)
{
	const struct nurs_input *input = self->raw;
	uint16_t index;
	const char *name;

	index = input_index(input, arg);
	if (index == UINT16_MAX)
		return NULL;

	name = nurs_input_cim_name(input, index);
	if (!name) {
		PyErr_SetString(PyExc_TypeError, "invalid key");
		return NULL;
	}

	return Py_BuildValue("s", name);
}

static PyObject *
pynurs_input_get_ipfix_vendor(struct pynurs_input *self, PyObject *arg)
{
	const struct nurs_input *input = self->raw;
	uint16_t index;
	uint32_t vendor;

	index = input_index(input, arg);
	if (index == UINT16_MAX)
		return NULL;

	errno = 0;
	vendor = nurs_input_ipfix_vendor(input, index);
	if (!vendor && errno) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	return Py_BuildValue("I", vendor);
}

static PyObject *
pynurs_input_get_ipfix_field(struct pynurs_input *self, PyObject *arg)
{
	const struct nurs_input *input = self->raw;
	uint16_t index;
	uint16_t field;

	index = input_index(input, arg);
	if (index == UINT16_MAX)
		return NULL;

	field = nurs_input_ipfix_field(input, index);
	if (!field) {
		PyErr_SetString(PyExc_TypeError, "invalid key");
		return NULL;
	}

	return Py_BuildValue("H", field);
}

static PyObject *
pynurs_input_is_valid(struct pynurs_input *self, PyObject *arg)
{
	const struct nurs_input *input = self->raw;
	uint16_t index;
	bool valid;

	index = input_index(input, arg);
	if (index == UINT16_MAX)
		return NULL;

	errno = 0;
	valid = nurs_input_is_valid(input, index);
	if (errno) {
		PyErr_SetString(PyExc_TypeError, "invalid key");
		return NULL;
	}

	if (valid) Py_RETURN_TRUE;
	Py_RETURN_FALSE;
}

static PyObject *
pynurs_input_is_active(struct pynurs_input *self, PyObject *arg)
{
	const struct nurs_input *input = self->raw;
	uint16_t index;
	bool active;

	index = input_index(input, arg);
	if (index == UINT16_MAX)
		return NULL;

	errno = 0;
	active = nurs_input_is_active(input, index);
	if (errno) {
		PyErr_SetString(PyExc_TypeError, "invalid key");
		return NULL;
	}

	if (active) return Py_True;
	return Py_False;
}

static PyMethodDef pynurs_input_methods[] = {
	{ "__len__", (PyCFunction)pynurs_input_len, METH_NOARGS,
	  "length", },
	{ "name", (PyCFunction)pynurs_input_get_name, METH_O,
	  "get name", },
	{ "type", (PyCFunction)pynurs_input_get_type, METH_O,
	  "get type", },
	{ "size", (PyCFunction)pynurs_input_get_size, METH_O,
	  "get size", },
	{ "value", (PyCFunction)pynurs_input_get_value, METH_O,
	  "get value",},
	{ "cim_name", (PyCFunction)pynurs_input_get_cim_name, METH_O,
	  "get cim name",},
	{ "ipfix_vendor", (PyCFunction)pynurs_input_get_ipfix_vendor, METH_O,
	  "get ipfix vendor",},
 	{ "ipfix_field", (PyCFunction)pynurs_input_get_ipfix_field, METH_O,
	  "get ipfix field", },
	{ "is_valid", (PyCFunction)pynurs_input_is_valid, METH_O,
	  "check validity", },
	{ "is_active", (PyCFunction)pynurs_input_is_active, METH_O,
	  "check active or not", },
	{ NULL, },
};

static PyTypeObject pynurs_input_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "nurs.Input",
	.tp_basicsize	= sizeof(struct pynurs_input),
	.tp_new		= PyType_GenericNew,
	.tp_dealloc	= (destructor)pynurs_input_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct nurs_input",
	.tp_methods	= pynurs_input_methods,
};

/****
 * struct nurs_output
 */
static void pynurs_output_dealloc(struct pynurs_output *self)
{
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static Py_ssize_t
pynurs_output_len(struct pynurs_output *self)
{
	return (int)nurs_output_len(self->raw);
}

/* returns UINT16_MAX on error */
static uint16_t output_index(const struct nurs_output *output, PyObject *arg)
{
	uint16_t index;
	char *name;
	PyObject *ascii;

	if (PyLong_Check(arg))
		index = (uint16_t)PyLong_AsLong(arg);
	else if (PyUnicode_Check(arg)) {
		ascii = PyUnicode_AsASCIIString(arg);
		if (!ascii) {
			PyErr_SetString(PyExc_TypeError, "not an ascii");
			return UINT16_MAX;
		}
		name = PyBytes_AsString(ascii);
		errno = 0;
		index = nurs_output_index(output, name);
		Py_DECREF(ascii);
		if (errno) {
			PyErr_Format(PyExc_KeyError, "not exist: %s", name);
			return UINT16_MAX;
		}
	} else {
		PyErr_SetString(PyExc_TypeError, "invalid arg type");
		return UINT16_MAX;
	}

	return index;
}

static PyObject *
pynurs_output_get_type(struct pynurs_output *self, PyObject *arg)
{
	const struct nurs_output *output = self->raw;
	uint16_t index;
	uint16_t ktype;

	index = output_index(output, arg);
	if (index == UINT16_MAX)
		return NULL;

	ktype = nurs_output_type(output, index);
	if (!ktype) {
		PyErr_SetString(PyExc_TypeError, "invalid key");
		return NULL;
	}

	return Py_BuildValue("H", ktype);
}

static PyObject *
pynurs_output_get_size(struct pynurs_output *self, PyObject *arg)
{
	const struct nurs_output *output = self->raw;
	uint32_t ksize;
	uint16_t index;

	index = output_index(output, arg);
	if (index == UINT16_MAX)
		return NULL;

	ksize = nurs_output_size(output, index);
	if (!ksize) {
		PyErr_SetString(PyExc_TypeError, "invalid key");
		return NULL;
	}

	return Py_BuildValue("H", ksize);
}

static int
pynurs_output_set_value(struct pynurs_output *self,
			PyObject *key, PyObject *value)
{
	struct nurs_output *output = self->raw;
	Py_buffer view, *viewp;
	PyObject *ascii;
	uint16_t index, ktype;
	char *src;
	int ret = -1;

	if (!value) {
		PyErr_SetString(PyExc_TypeError, "null value");
		return -1;
	}

	index = output_index(output, key);
	if (index == UINT16_MAX)
		return -1;

	ktype = nurs_output_type(output, index);
	if (!ktype) {
		PyErr_SetString(PyExc_TypeError, "invalid key");
		return -1;
	}

	/* Py_INCREF(value); */
	switch (ktype) {
	case NURS_KEY_T_BOOL:
		if (!PyBool_Check(value)) {
			PyErr_SetString(PyExc_TypeError, "not a boolean");
			break;
		}
		if (value == Py_True)
			ret = nurs_output_set_bool(output, index, true);
		ret = nurs_output_set_bool(output, index, false);
		break;
	case NURS_KEY_T_UINT8:
		if (!PyLong_Check(value)) {
			PyErr_SetString(PyExc_TypeError, "not a integer");
			break;
		}
		ret = nurs_output_set_u8(output, index,
					 (uint8_t)PyLong_AsLong(value));
		break;
	case NURS_KEY_T_UINT16:
		if (!PyLong_Check(value)) {
			PyErr_SetString(PyExc_TypeError, "not a integer");
			break;
		}
		ret = nurs_output_set_u16(output, index,
					  (uint16_t)PyLong_AsLong(value));
		break;
	case NURS_KEY_T_UINT32:
		if (!PyLong_Check(value)) {
			PyErr_SetString(PyExc_TypeError, "not a integer");
			break;
		}
		ret = nurs_output_set_u32(output, index,
					  (uint32_t)PyLong_AsLong(value));
		break;
	case NURS_KEY_T_UINT64:
		if (!PyLong_Check(value)) {
			PyErr_SetString(PyExc_TypeError, "not a integer");
			break;
		}
		/* XXX: based on long long is u64 */
		ret = nurs_output_set_u64(output, index,
					  (uint64_t)PyLong_AsLongLong(value));
		break;
	case NURS_KEY_T_INADDR:
		if (!PyLong_Check(value)) {
			PyErr_SetString(PyExc_TypeError, "not a integer");
			break;
		}
		ret = nurs_output_set_in_addr(output, index,
					      (in_addr_t)PyLong_AsLong(value));
		break;
	case NURS_KEY_T_IN6ADDR:
		if (!PyObject_CheckBuffer(value)) {
			/* XXX: */
			PyErr_SetString(PyExc_TypeError, "not a buffer");
			break;
		}
		if (!PyObject_GetBuffer(value, &view, PyBUF_SIMPLE))
			break;
		ret = nurs_output_set_in6_addr(output, index, view.buf);
		break;
	case NURS_KEY_T_STRING:
		if (!PyUnicode_Check(value)) {
			PyErr_SetString(PyExc_TypeError, "not a unicode");
			break;
		}
		ascii = PyUnicode_AsASCIIString(value);
		if (!ascii) {
			PyErr_SetString(PyExc_TypeError, "not an ascii");
			break;
		}
		src = PyBytes_AsString(ascii);
		if (!src) {
			PyErr_SetString(PyExc_TypeError, "null bytes");
			break;
		}
		ret = nurs_output_set_string(output, index, src);
		Py_DECREF(ascii);
		return ret;
        case NURS_KEY_T_EMBED:
		if (!PyMemoryView_Check(value)) {
			PyErr_SetString(PyExc_TypeError, "not a memory view");
			break;
		}
                viewp = PyMemoryView_GET_BUFFER(value);
                if (viewp->buf != nurs_output_pointer(output, index)) {
			PyErr_SetString(PyExc_TypeError, "invalid memory view");
                        break;
                }
                ret = nurs_output_set_valid(output, index);
                /*  Py_DECREF(value); */
                return ret;
	default:
		PyErr_Format(PyExc_TypeError, "unsupported type: %d", ktype);
	}
	/* see Objects/bytearrayobject.c for NURS_KEY_T_EMBED
	 * PyBytearrayObject *ba
	 * PyBytearray_Size(ba) ? and  ba->ob_bytes
	 */

	/* Py_DECREF(value); */
	return ret;
}

static PyObject *
pynurs_output_get_pointer(struct pynurs_output *self, PyObject *key)
{
	struct nurs_output *output = self->raw;
        uint16_t index;
        char *mem;
        Py_ssize_t size;

        index = output_index(output, key);
        if (index == UINT16_MAX) {
		PyErr_SetString(PyExc_Exception, "invalid index key");
                return NULL;
        }

        if (nurs_output_type(output, index) != NURS_KEY_T_EMBED) {
		PyErr_SetString(PyExc_Exception, "type is not a EMBED");
                return NULL;
        }

        size = nurs_output_size(output, index);
        mem = nurs_output_pointer(output, index);

        return PyMemoryView_FromMemory(mem, size, PyBUF_WRITE);
}

static PyObject *
pynurs_publish(struct pynurs_output *output)
{
	if (pycli_publish(output->raw) != NURS_RET_OK) {
		/* XXX: need errno */
		PyErr_SetString(PyExc_Exception, "failed to publish");
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *
pynurs_put_output(struct pynurs_output *output)
{
	if (pycli_put_output(output->raw)) {
		/* XXX: need errno */
		PyErr_SetString(PyExc_Exception, "failed to put output");
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyMethodDef pynurs_output_methods[] = {
	{ "__len__", (PyCFunction)pynurs_output_len, METH_NOARGS,
	  "length", },
	{ "type", (PyCFunction)pynurs_output_get_type, METH_O,
	  "get type", },
	{ "size", (PyCFunction)pynurs_output_get_size, METH_O,
	  "get size", },
	{ "publish", (PyCFunction)pynurs_publish, METH_NOARGS,
	  "publish nurs.Output", },
	{ "put", (PyCFunction)pynurs_put_output, METH_NOARGS,
	  "put nurs.Output", },
	{ NULL, },
};

static PyMappingMethods pynurs_output_as_mapping = {
	(lenfunc)pynurs_output_len,
        (binaryfunc)pynurs_output_get_pointer,
	(objobjargproc)pynurs_output_set_value,
};

static PyTypeObject pynurs_output_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "nurs.Output",
	.tp_basicsize	= sizeof(struct pynurs_output),
	.tp_new		= PyType_GenericNew,
	.tp_dealloc	= (destructor)pynurs_output_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct nurs_output",
	.tp_methods	= pynurs_output_methods,
	.tp_as_mapping	= &pynurs_output_as_mapping,
};

/****
 * struct nurs_plugin
 */
static void pynurs_plugin_dealloc(struct pynurs_plugin *self)
{
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
pynurs_plugin_get_config(struct pynurs_plugin *self, void *closure)
{
	const struct nurs_config *config = nurs_plugin_config(self->raw);

	if (!config)
		Py_RETURN_NONE;

	((struct pynurs_config *)config_obj)->raw = config;
	return config_obj;
}

static PyGetSetDef pynurs_plugin_getseters[] = {
	{
		"config",
		(getter)pynurs_plugin_get_config,
		NULL,
		"nurs.Config",
		NULL,
	},
	{ NULL },
};

static PyTypeObject pynurs_plugin_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "nurs.Plugin",
	.tp_basicsize	= sizeof(struct pynurs_plugin),
	.tp_new		= PyType_GenericNew,
	.tp_dealloc	= (destructor)pynurs_plugin_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct nurs_plugin",
	.tp_getset	= pynurs_plugin_getseters,
};

/****
 * struct nurs_producer
 */
static void pynurs_producer_dealloc(struct pynurs_producer *self)
{
	Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
pynurs_producer_get_config(struct pynurs_producer *self, void *closure)
{
	const struct nurs_config *config = nurs_producer_config(self->raw);

	if (!config)
		Py_RETURN_NONE;

	((struct pynurs_config *)config_obj)->raw = config;
	return config_obj;
}

static PyObject *
pynurs_producer_get_output(struct pynurs_producer *self)
{
	struct nurs_output *output = pycli_get_output(self->raw);

	if (!output) {
		/* XXX: need errno */
		PyErr_SetString(PyExc_Exception, "failed to get output");
		return NULL;
	}
	((struct pynurs_output *)output_obj)->raw = output;

	return output_obj;
}

static PyGetSetDef pynurs_producer_getseters[] = {
	{
		"config",
		(getter)pynurs_producer_get_config,
		NULL,
		"nurs.Config",
		NULL,
	},
	{ NULL },
};

static PyMethodDef pynurs_producer_methods[] = {
	{ "get_output", (PyCFunction)pynurs_producer_get_output, METH_NOARGS,
	  "get nurs.Output", },
	{ NULL, },
};

static PyTypeObject pynurs_producer_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "nurs.Producer",
	.tp_basicsize	= sizeof(struct pynurs_producer),
	.tp_new		= PyType_GenericNew,
	.tp_dealloc	= (destructor)pynurs_producer_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct nurs_producer",
	.tp_methods	= pynurs_producer_methods,
	.tp_getset	= pynurs_producer_getseters,
};

/****
 * struct nurs_fd
 */
enum nurs_return_t py_fd_callback(struct pynurs_fd *nfd, uint16_t when)
{
	return py_nurs_return(
		PyObject_CallFunction(nfd->cb, "OH", nfd, when));
}

static void pynurs_fd_dealloc(struct pynurs_fd *self)
{
	if (self->raw && pycli_fd_unregister(self->raw))
		PyErr_SetString(PyExc_Exception, "failed to unregister cb");

	Py_XDECREF(self->file);
	Py_XDECREF(self->cb);
	Py_XDECREF(self->data);

	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int pynurs_fd_init(struct pynurs_fd *self, PyObject *args)
{
	PyObject *file, *cb, *data, *fileno, *value;
	uint16_t when;

	if (!PyArg_ParseTuple(args, "OHOO", &file, &when, &cb, &data))
		return -1;

	fileno = PyObject_GetAttrString(file, "fileno");
	if (!fileno || !PyCallable_Check(fileno)) {
		PyErr_SetString(PyExc_TypeError, "first arg has no fileno()");
		return -1;
	}
	value = PyObject_CallFunctionObjArgs(fileno, NULL);
	Py_DECREF(fileno);
	if (PyErr_Occurred())
		return -1;
	if (!PyLong_Check(value)) {
		PyErr_SetString(PyExc_AttributeError,
				"fileno() must return an integer");
		return -1;
	}
	if (!PyCallable_Check(cb)) {
		PyErr_SetString(PyExc_TypeError, "cb is not callable");
                Py_DECREF(value);
		return -1;
	}

	self->raw = pycli_fd_register((int)PyLong_AsLong(value), when, self);
	Py_DECREF(value);
	if (!self->raw) {
		PyErr_SetString(PyExc_Exception,
				"failed to create fd");
		return -1;
	}
	self->file = file;
	self->cb = cb;
	self->data = data;
	Py_INCREF(self->file);
	Py_INCREF(self->cb);
	Py_INCREF(self->data);

	return 0;
}

/* below accessors are valid only at callback */
static PyObject *pynurs_fd_get_fd(struct pynurs_fd *self)
{
        Py_INCREF(self->file);
        return self->file;
}

static PyObject *pynurs_fd_get_data(struct pynurs_fd *self)
{
	Py_INCREF(self->data);
        return self->data;
}

static PyGetSetDef pynurs_fd_getseters[] = {
        {
                "fd",
                (getter)pynurs_fd_get_fd,
                NULL,
                "nurs.Fd",
                NULL,
        },
        {
                "data",
                (getter)pynurs_fd_get_data,
                NULL,
                "nurs.Fd",
                NULL,
        },
        { NULL },
};

static PyTypeObject pynurs_fd_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "nurs.Fd",
	.tp_basicsize	= sizeof(struct pynurs_fd),
	.tp_new		= PyType_GenericNew,
	.tp_dealloc	= (destructor)pynurs_fd_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct nurs_fd",
	.tp_methods	= NULL,
	.tp_init	= (initproc)pynurs_fd_init,
        .tp_getset	= pynurs_fd_getseters,
};

/****
 * struct nurs_timer
 */

enum nurs_return_t py_timer_callback(struct pynurs_timer *timer)
{
	return py_nurs_return(
		PyObject_CallFunction(timer->cb, "O", timer));
}

static void pynurs_timer_dealloc(struct pynurs_timer *self)
{
	if (self->raw && pycli_timer_unregister(self->raw))
		PyErr_SetString(PyExc_Exception, "failed to unregister cb");

	Py_XDECREF(self->cb);
	Py_XDECREF(self->data);

	Py_TYPE(self)->tp_free((PyObject *)self);
}

static int pynurs_timer_init(struct pynurs_timer *self, PyObject *args)
{
	PyObject *cb, *data;
        time_t ini, per = 0;

	if (!PyArg_ParseTuple(args, "IOO|I", &ini, &cb, &data, &per))
		return -1;

	if (!PyCallable_Check(cb)) {
		PyErr_SetString(PyExc_TypeError, "cb is not callable");
		return -1;
	}

        if (per)
                self->raw = pycli_itimer_register(ini, per, self);
        else
                self->raw = pycli_timer_register(ini, self);
	if (!self->raw) {
		PyErr_SetString(PyExc_Exception,
				"failed to create fd");
		return -1;
	}

	self->cb = cb;
	self->data = data;
        Py_INCREF(self);
	Py_INCREF(self->cb);
	Py_INCREF(self->data);

	return 0;
}

static PyObject *
pynurs_timer_pending(struct pynurs_timer *self)
{
        if (self)
                Py_RETURN_TRUE;
        Py_RETURN_FALSE;
}

static PyMethodDef pynurs_timer_methods[] = {
	{ "pending", (PyCFunction)pynurs_timer_pending, METH_NOARGS,
	  "is pending", },
	{ NULL, },
};

static PyObject *pynurs_timer_get_data(struct pynurs_timer *self)
{
        Py_INCREF(self->data);
        return self->data;
}

static PyGetSetDef pynurs_timer_getseters[] = {
        {
                "data",
                (getter)pynurs_timer_get_data,
                NULL,
                "nurs.Fd",
                NULL,
        },
        { NULL },
};

static PyTypeObject pynurs_timer_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name	= "nurs.Timer",
	.tp_basicsize	= sizeof(struct pynurs_timer),
	.tp_new		= PyType_GenericNew,
	.tp_dealloc	= (destructor)pynurs_timer_dealloc,
	.tp_flags	= Py_TPFLAGS_DEFAULT,
	.tp_doc		= "struct nurs_timer",
	.tp_methods	= pynurs_timer_methods,
	.tp_init	= (initproc)pynurs_timer_init,
        .tp_getset	= pynurs_timer_getseters,
};


/****
 * init module
 */
static PyModuleDef nurs_module = {
	PyModuleDef_HEAD_INIT,
	"nurs",
	"python module for nurs",
	-1,
	NULL, NULL, NULL, NULL, NULL,
};

PyMODINIT_FUNC PyInit_nurs(void)
{
	PyObject *m;

	if (PyType_Ready(&pynurs_log_type) < 0)
		return NULL;
	if (PyType_Ready(&pynurs_config_type) < 0)
		return NULL;
	if (PyType_Ready(&pynurs_input_type) < 0)
		return NULL;
	if (PyType_Ready(&pynurs_output_type) < 0)
		return NULL;
	if (PyType_Ready(&pynurs_plugin_type) < 0)
		return NULL;
	if (PyType_Ready(&pynurs_producer_type) < 0)
		return NULL;
	if (PyType_Ready(&pynurs_fd_type) < 0)
		return NULL;
	if (PyType_Ready(&pynurs_timer_type) < 0)
		return NULL;

	/* nurs_module.m_methods = pynurs_methods; */
	m = PyModule_Create(&nurs_module);
	if (m == NULL)
		return NULL;

	Py_INCREF(&pynurs_log_type);
	PyModule_AddObject(m, "Log", (PyObject *)&pynurs_log_type);

	Py_INCREF(&pynurs_config_type);
	PyModule_AddObject(m, "Config", (PyObject *)&pynurs_config_type);

	Py_INCREF(&pynurs_input_type);
	PyModule_AddObject(m, "Input", (PyObject *)&pynurs_input_type);

	Py_INCREF(&pynurs_output_type);
	PyModule_AddObject(m, "Output", (PyObject *)&pynurs_output_type);

	Py_INCREF(&pynurs_plugin_type);
	PyModule_AddObject(m, "Plugin", (PyObject *)&pynurs_plugin_type);

	Py_INCREF(&pynurs_producer_type);
	PyModule_AddObject(m, "Producer", (PyObject *)&pynurs_producer_type);

	Py_INCREF(&pynurs_fd_type);
	PyModule_AddObject(m, "Fd", (PyObject *)&pynurs_fd_type);

	Py_INCREF(&pynurs_timer_type);
	PyModule_AddObject(m, "Timer", (PyObject *)&pynurs_timer_type);

	PyModule_AddIntMacro(m, NURS_KEY_T_BOOL);
	PyModule_AddIntMacro(m, NURS_KEY_T_INT8);
	PyModule_AddIntMacro(m, NURS_KEY_T_INT16);
	PyModule_AddIntMacro(m, NURS_KEY_T_INT32);
	PyModule_AddIntMacro(m, NURS_KEY_T_INT64);
	PyModule_AddIntMacro(m, NURS_KEY_T_UINT8);
	PyModule_AddIntMacro(m, NURS_KEY_T_UINT16);
	PyModule_AddIntMacro(m, NURS_KEY_T_UINT32);
	PyModule_AddIntMacro(m, NURS_KEY_T_UINT64);
	PyModule_AddIntMacro(m, NURS_KEY_T_INADDR);
	PyModule_AddIntMacro(m, NURS_KEY_T_IN6ADDR);
	PyModule_AddIntMacro(m, NURS_KEY_T_STRING);

	PyModule_AddIntMacro(m, NURS_RET_ERROR);
	PyModule_AddIntMacro(m, NURS_RET_STOP);
	PyModule_AddIntMacro(m, NURS_RET_OK);

	PyModule_AddIntMacro(m, NURS_FD_F_READ);
	PyModule_AddIntMacro(m, NURS_FD_F_WRITE);
	PyModule_AddIntMacro(m, NURS_FD_F_EXCEPT);

	return m;
}

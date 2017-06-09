// (C) 2016 by Ken-ichirou MATSUZAWA <chamas@h4.dion.ne.jp>
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published
// by the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// based on ulogd which was almost entirely written by Harald Welte,
// with contributions from fellow hackers such as Pablo Neira Ayuso,
// Eric Leblond and Pierre Chifflier.
package nurs

// #cgo CFLAGS: -I../../include
// #cgo LDFLAGS: -Wl,--unresolved-symbols=ignore-all
// #include <arpa/inet.h>
// #include <signal.h>
// #include <string.h>
// #include "nurs/nurs.h"
// #include "helper.h"
import "C"

import (
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"unsafe"
)

type Config C.struct_nurs_config

type ConfigType C.enum_nurs_config_type

const (
	CONFIG_T_INTEGER  = ConfigType(C.NURS_CONFIG_T_INTEGER)
	CONFIG_T_BOOLEAN  = ConfigType(C.NURS_CONFIG_T_BOOLEAN)
	CONFIG_T_STRING   = ConfigType(C.NURS_CONFIG_T_STRING)
	CONFIG_T_CALLBACK = ConfigType(C.NURS_CONFIG_T_CALLBACK)
)

// int nurs_config_integer(const struct nurs_config *config, uint8_t idx);
func nursConfigInteger(config *Config, idx uint8) (int, error) {
	ret, err := C.nurs_config_integer((*C.struct_nurs_config)(config), C.uint8_t(idx))
	return int(ret), err
}

// bool nurs_config_boolean(const struct nurs_config *config, uint8_t idx);
func nursConfigBoolean(config *Config, idx uint8) (bool, error) {
	ret, err := C.nurs_config_boolean((*C.struct_nurs_config)(config), C.uint8_t(idx))
	return bool(ret), err
}

// const char *nurs_config_string(const struct nurs_config *config, uint8_t idx);
func nursConfigString(config *Config, idx uint8) (string, error) {
	ret, err := C.nurs_config_string((*C.struct_nurs_config)(config), C.uint8_t(idx))
	return C.GoString(ret), err
}

// uint8_t nurs_config_len(const struct nurs_config *config);
func nursConfigLen(config *Config) uint8 {
	ret, _ := C.nurs_config_len((*C.struct_nurs_config)(config))
	return uint8(ret)
}

// uint16_t nurs_config_type(const struct nurs_config *config, uint8_t idx);
func nursConfigType(config *Config, idx uint8) (ConfigType, error) {
	ret, err := C.nurs_config_type((*C.struct_nurs_config)(config), C.uint8_t(idx))
	return ConfigType(ret), err
}

// uint8_t nurs_config_index(const struct nurs_config *config, const char *name);
func nursConfigIndex(config *Config, name string) (uint8, error) {
	cs := C.CString(name)
	defer C.free(unsafe.Pointer(cs))
	ret, err := C.nurs_config_index((*C.struct_nurs_config)(config), cs)
	return uint8(ret), err
}

type KeyType C.enum_nurs_key_type

const (
	KEY_T_BOOL    = KeyType(C.NURS_KEY_T_BOOL)
	KEY_T_INT8    = KeyType(C.NURS_KEY_T_INT8)
	KEY_T_INT16   = KeyType(C.NURS_KEY_T_INT16)
	KEY_T_INT32   = KeyType(C.NURS_KEY_T_INT32)
	KEY_T_INT64   = KeyType(C.NURS_KEY_T_INT64)
	KEY_T_UINT8   = KeyType(C.NURS_KEY_T_UINT8)
	KEY_T_UINT16  = KeyType(C.NURS_KEY_T_UINT16)
	KEY_T_UINT32  = KeyType(C.NURS_KEY_T_UINT32)
	KEY_T_UINT64  = KeyType(C.NURS_KEY_T_UINT64)
	KEY_T_INADDR  = KeyType(C.NURS_KEY_T_INADDR)
	KEY_T_IN6ADDR = KeyType(C.NURS_KEY_T_IN6ADDR)
	KEY_T_POINTER = KeyType(C.NURS_KEY_T_POINTER)
	KEY_T_STRING  = KeyType(C.NURS_KEY_T_STRING)
	KEY_T_EMBED   = KeyType(C.NURS_KEY_T_EMBED)
)

type Input C.struct_nurs_input

// uint16_t nurs_input_len(const struct nurs_input *input);
func nursInputLen(input *Input) uint16 {
	ret, _ := C.nurs_input_len((*C.struct_nurs_input)(input))
	return uint16(ret)
}

// uint32_t nurs_input_size(const struct nurs_input *input, uint16_t idx);
func nursInputSize(input *Input, idx uint16) (uint32, error) {
	ret, err := C.nurs_input_size((*C.struct_nurs_input)(input), C.uint16_t(idx))
	return uint32(ret), err
}

// const char *nurs_input_name(const struct nurs_input *input, uint16_t idx);
func nursInputName(input *Input, idx uint16) (string, error) {
	ret, err := C.nurs_input_name((*C.struct_nurs_input)(input), C.uint16_t(idx))
	return C.GoString(ret), err
}

// uint16_t nurs_input_type(const struct nurs_input *input, uint16_t idx);
func nursInputType(input *Input, idx uint16) (KeyType, error) {
	ret, err := C.nurs_input_type((*C.struct_nurs_input)(input), C.uint16_t(idx))
	return KeyType(ret), err
}

// uint16_t nurs_input_index(const struct nurs_input *input, const char *name);
func nursInputIndex(input *Input, name string) (uint16, error) {
	cs := C.CString(name)
	defer C.free(unsafe.Pointer(cs))
	ret, err := C.nurs_input_index((*C.struct_nurs_input)(input), cs)
	return uint16(ret), err
}

// bool nurs_input_bool(const struct nurs_input *input, uint16_t idx);
func nursInputBool(input *Input, idx uint16) (bool, error) {
	ret, err := C.nurs_input_bool((*C.struct_nurs_input)(input), C.uint16_t(idx))
	return bool(ret), err
}

// uint8_t nurs_input_u8(const struct nurs_input *input, uint16_t idx);
func nursInputU8(input *Input, idx uint16) (uint8, error) {
	ret, err := C.nurs_input_u8((*C.struct_nurs_input)(input), C.uint16_t(idx))
	return uint8(ret), err
}

// uint16_t nurs_input_u16(const struct nurs_input *input, uint16_t idx);
func nursInputU16(input *Input, idx uint16) (uint16, error) {
	ret, err := C.nurs_input_u16((*C.struct_nurs_input)(input), C.uint16_t(idx))
	return uint16(ret), err
}

// uint32_t nurs_input_u32(const struct nurs_input *input, uint16_t idx);
func nursInputU32(input *Input, idx uint16) (uint32, error) {
	ret, err := C.nurs_input_u32((*C.struct_nurs_input)(input), C.uint16_t(idx))
	return uint32(ret), err
}

// uint64_t nurs_input_u64(const struct nurs_input *input, uint16_t idx);
func nursInputU64(input *Input, idx uint16) (uint64, error) {
	ret, err := C.nurs_input_u64((*C.struct_nurs_input)(input), C.uint16_t(idx))
	return uint64(ret), err
}

// in_addr_t nurs_input_in_addr(const struct nurs_input *input, uint16_t idx);
func nursInputInAddr(input *Input, idx uint16) (net.IP, error) {
	ret, err := C.nurs_input_in_addr((*C.struct_nurs_input)(input), C.uint16_t(idx))
	if err != nil {
		return nil, err
	}
	return net.ParseIP(InetNtop(C.AF_INET, unsafe.Pointer(&ret))), err
}

// nurs_input_in6_addr(const struct nurs_input *input, uint16_t idx);
func nursInputIn6Addr(input *Input, idx uint16) (net.IP, error) {
	ret, err := C.nurs_input_in6_addr((*C.struct_nurs_input)(input), C.uint16_t(idx))
	if err != nil {
		return nil, err
	}
	return net.ParseIP(InetNtop(C.AF_INET6, unsafe.Pointer(ret))), err
}

// const void *nurs_input_pointer(const struct nurs_input *input, uint16_t idx);
func nursInputPointer(input *Input, idx uint16) (unsafe.Pointer, error) {
	ret, err := C.nurs_input_pointer((*C.struct_nurs_input)(input), C.uint16_t(idx))
	return ret, err
}

func nursInputBytes(input *Input, idx uint16) ([]byte, error) {
	var b []byte

	h := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	size, err := nursInputSize(input, idx)
	if err != nil {
		return nil, err
	}
	h.Cap = int(size)
	h.Len = int(size)
	ptr, err := nursInputPointer(input, idx)
	if err != nil {
		return nil, err
	}
	h.Data = uintptr(ptr)
	return b, nil
}

// const char *nurs_input_string(const struct nurs_input *input, uint16_t idx);
func nursInputString(input *Input, idx uint16) (string, error) {
	ret, err := C.nurs_input_string((*C.struct_nurs_input)(input), C.uint16_t(idx))
	if err != nil {
		return "", err
	}
	// return C.GoStringN((*C.char)(ret), C.int(C.nurs_input_size((*C.struct_nurs_input)(input), C.uint16_t(idx)))), nil
	return C.GoString((*C.char)(ret)), nil
}

// bool nurs_input_is_valid(const struct nurs_input *input, uint16_t idx);
func nursInputIsValid(input *Input, idx uint16) (bool, error) {
	ret, err := C.nurs_input_is_valid((*C.struct_nurs_input)(input), C.uint16_t(idx))
	return bool(ret), err
}

// bool nurs_input_is_active(const struct nurs_input *input, uint16_t idx);
func nursInputIsActive(input *Input, idx uint16) (bool, error) {
	ret, err := C.nurs_input_is_active((*C.struct_nurs_input)(input), C.uint16_t(idx))
	return bool(ret), err
}

// XXX: no type and const, returns raw uint32
// uint32_t nurs_input_ipfix_vendor(const struct nurs_input *input, uint16_t idx);
func nursInputIpfixVendor(input *Input, idx uint16) (uint32, error) {
	ret, err := C.nurs_input_ipfix_vendor((*C.struct_nurs_input)(input), C.uint16_t(idx))
	return uint32(ret), err
}

// XXX: no type and const, returns raw uint16
// uint16_t nurs_input_ipfix_field(const struct nurs_input *input, uint16_t idx);
func nursInputIpfixField(input *Input, idx uint16) (uint16, error) {
	ret, err := C.nurs_input_ipfix_field((*C.struct_nurs_input)(input), C.uint16_t(idx))
	return uint16(ret), err
}

// const char *nurs_input_cim_name(const struct nurs_input *input, uint16_t idx);
func nursInputCimName(input *Input, idx uint16) (string, error) {
	ret, err := C.nurs_input_cim_name((*C.struct_nurs_input)(input), C.uint16_t(idx))
	return C.GoString(ret), err
}

type Output C.struct_nurs_output

// uint16_t nurs_output_len(const struct nurs_output *output);
func nursOutputLen(output *Output) uint16 {
	ret, _ := C.nurs_output_len((*C.struct_nurs_output)(output))
	return uint16(ret)
}

// uint32_t nurs_output_size(const struct nurs_output *output, uint16_t idx);
func nursOutputSize(output *Output, idx uint16) (uint32, error) {
	ret, err := C.nurs_output_size((*C.struct_nurs_output)(output), C.uint16_t(idx))
	return uint32(ret), err
}

// uint16_t nurs_output_type(const struct nurs_output *output, uint16_t idx);
func nursOutputType(output *Output, idx uint16) (KeyType, error) {
	ret, err := C.nurs_output_size((*C.struct_nurs_output)(output), C.uint16_t(idx))
	return KeyType(ret), err
}

// uint16_t nurs_output_index(const struct nurs_output *output, const char *name);
func nursOutputIndex(output *Output, name string) (uint16, error) {
	cs := C.CString(name)
	defer C.free(unsafe.Pointer(cs))
	ret, err := C.nurs_output_index((*C.struct_nurs_output)(output), cs)
	return uint16(ret), err
}

// int nurs_output_set_bool(struct nurs_output *output, uint16_t idx, bool value);
func nursOutputSetBool(output *Output, idx uint16, value bool) error {
	_, err := C.nurs_output_set_bool((*C.struct_nurs_output)(output), C.uint16_t(idx), C.bool(value))
	return err
}

// int nurs_output_set_u8(struct nurs_output *output, uint16_t idx, uint8_t value);
func nursOutputSetU8(output *Output, idx uint16, value uint8) error {
	_, err := C.nurs_output_set_u8((*C.struct_nurs_output)(output), C.uint16_t(idx), C.uint8_t(value))
	return err
}

// int nurs_output_set_u16(struct nurs_output *output, uint16_t idx, uint16_t value);
func nursOutputSetU16(output *Output, idx uint16, value uint16) error {
	_, err := C.nurs_output_set_u16((*C.struct_nurs_output)(output), C.uint16_t(idx), C.uint16_t(value))
	return err
}

// int nurs_output_set_u32(struct nurs_output *output, uint16_t idx, uint32 value);
func nursOutputSetU32(output *Output, idx uint16, value uint32) error {
	_, err := C.nurs_output_set_u32((*C.struct_nurs_output)(output), C.uint16_t(idx), C.uint32_t(value))
	return err
}

// int nurs_output_set_u64(struct nurs_output *output, uint16_t idx, uint64 value);
func nursOutputSetU64(output *Output, idx uint16, value uint64) error {
	_, err := C.nurs_output_set_u64((*C.struct_nurs_output)(output), C.uint16_t(idx), C.uint64_t(value))
	return err
}

// int nurs_output_set_in_addr(struct nurs_output *output, uint16_t idx, in_addr_t value);
func nursOutputSetInAddr(output *Output, idx uint16, value net.IP) error {
	s, err := InetPton(C.AF_INET, value.String())
	if err != nil {
		return err
	}
	_, err = C.nurs_output_set_in_addr((*C.struct_nurs_output)(output), C.uint16_t(idx),
		*(*C.in_addr_t)(unsafe.Pointer(&s[0])))
	return err
}

// int nurs_output_set_in6_addr(struct nurs_output *output, uint16_t idx, const struct in6_addr *value);
func nursOutputSetIn6Addr(output *Output, idx uint16, value net.IP) error {
	s, err := InetPton(C.AF_INET6, value.String())
	if err != nil {
		return err
	}
	_, err = C.nurs_output_set_in6_addr((*C.struct_nurs_output)(output), C.uint16_t(idx),
		(*C.struct_in6_addr)(unsafe.Pointer(&s[0])))
	return err
}

// int nurs_output_set_pointer(struct nurs_output *output, uint16_t idx, const void *value);
func nursOutputSetPointer(output *Output, idx uint16, value unsafe.Pointer) error {
	_, err := C.nurs_output_set_pointer((*C.struct_nurs_output)(output), C.uint16_t(idx), value)
	return err
}

// int nurs_output_set_string(struct nurs_output *output, uint16_t idx, const char *value);
func nursOutputSetString(output *Output, idx uint16, value string) error {
	cs := C.CString(value)
	defer C.free(unsafe.Pointer(cs))
	_, err := C.nurs_output_set_string((*C.struct_nurs_output)(output), C.uint16_t(idx), cs)
	return err
}

// void *nurs_output_pointer(const struct nurs_output *output, uint16_t idx);
func nursOutputPointer(output *Output, idx uint16) (unsafe.Pointer, error) {
	ret, err := C.nurs_output_pointer((*C.struct_nurs_output)(output), C.uint16_t(idx))
	return ret, err
}

func nursOutputBytes(output *Output, idx uint16) ([]byte, error) {
	var b []byte

	h := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	size, err := nursOutputSize(output, idx)
	if err != nil {
		return nil, err
	}
	h.Cap = int(size)
	h.Len = int(size)
	ptr, err := nursOutputPointer(output, idx)
	if err != nil {
		return nil, err
	}
	h.Data = uintptr(ptr)
	return b, nil
}

// int nurs_output_set_valid(struct nurs_output *output, uint16_t idx);
func nursOutputSetValid(output *Output, idx uint16) error {
	_, err := C.nurs_output_set_valid((*C.struct_nurs_output)(output), C.uint16_t(idx))
	return err
}

type ReturnType C.enum_nurs_return_t

const (
	RET_ERROR = ReturnType(C.NURS_RET_ERROR)
	RET_STOP  = ReturnType(C.NURS_RET_STOP)
	RET_OK    = ReturnType(C.NURS_RET_OK)
)

type Plugin C.struct_nurs_plugin
type Producer C.struct_nurs_producer

// typedef enum nurs_return_t (*nurs_start_t)(const struct nurs_plugin *plugin);
type StartCb func(*Plugin) ReturnType

// typedef enum nurs_return_t (*nurs_producer_start_t)(struct nurs_producer *producer);
type ProducerStartCb func(*Producer) ReturnType

// typedef enum nurs_return_t (*nurs_stop_t)(const struct nurs_plugin *plugin);
type StopCb func(*Plugin) ReturnType

// typedef enum nurs_return_t (*nurs_producer_stop_t)(struct nurs_producer *producer);
type ProducerStopCb func(*Producer) ReturnType

// typedef enum nurs_return_t (*nurs_signal_t)(const struct nurs_plugin *plugin, uint32_t signum);
type SignalCb func(*Plugin, uint32) ReturnType

// typedef enum nurs_return_t (*nurs_producer_signal_t)(struct nurs_producer *producer, uint32_t signum);
type ProducerSignalCb func(*Producer, uint32) ReturnType

// typedef enum nurs_return_t (*nurs_organize_t)(const struct nurs_plugin *plugin);
type OrganizeCb func(*Plugin) ReturnType

// typedef enum nurs_return_t (*nurs_coveter_organize_t)(const struct nurs_plugin *plugin,
//				const struct nurs_input *template);
type CoveterOrganizeCb func(*Plugin, *Input) ReturnType

// typedef enum nurs_return_t (*nurs_producer_organize_t)(struct nurs_producer *producer);
type ProducerOrganizeCb func(*Producer) ReturnType

// typedef enum nurs_return_t (*nurs_disorganize_t)(const struct nurs_plugin *plugin);
type DisorganizeCb func(*Plugin) ReturnType

// typedef enum nurs_return_t (*nurs_producer_disorganize_t)(struct nurs_producer *producer);
type ProducerDisorganizeCb func(*Producer) ReturnType

// typedef enum nurs_return_t (*nurs_filter_interp_t)(const struct nurs_plugin *plugin,
//				const struct nurs_input *input,
//				struct nurs_output *output);
type FilterInterpCb func(*Plugin, *Input, *Output) ReturnType

// typedef enum nurs_return_t(*nurs_consumner_interp_t)(const struct nurs_plugin *plugin,
//				const struct nurs_input *input);
type ConsumerInterpCb func(*Plugin, *Input, *Output) ReturnType

// enum nurs_return_t nurs_publish(struct nurs_output *output);
func nursPublish(output *Output) (ReturnType, error) {
	ret, err := C.nurs_publish((*C.struct_nurs_output)(output))
	return ReturnType(ret), err
}

// disable using plugin instance private area. see:
//     https://golang.org/cmd/cgo/#hdr-Passing_pointers
// void *nurs_producer_context(const struct nurs_producer *producer);
// void *nurs_plugin_context(const struct nurs_plugin *plugin);

// const struct nurs_config *nurs_producer_config(const struct nurs_producer *producer);
func nursProducerConfig(producer *Producer) *Config {
	ret, _ := C.nurs_producer_config((*C.struct_nurs_producer)(producer))
	return (*Config)(ret)
}

// const struct nurs_config *nurs_plugin_config(const struct nurs_plugin *plugin);
func nursPluginConfig(plugin *Plugin) *Config {
	ret, _ := C.nurs_plugin_config((*C.struct_nurs_plugin)(plugin))
	return (*Config)(ret)
}

// struct nurs_producer_def *nurs_producer_register_jsons(const char *input, uint16_t context_size);
func ProducerRegisterJsons(input string, ctxsz uint16) error {
	cs := C.CString(input)
	defer C.free(unsafe.Pointer(cs))
	_, err := C.nurs_producer_register_jsons(cs, C.uint16_t(ctxsz))
	return err
}

// struct nurs_filter_def *nurs_filter_register_jsons(const char *input, uint16_t context_size);
func FilterRegisterJsons(input string, ctxsz uint16) error {
	cs := C.CString(input)
	defer C.free(unsafe.Pointer(cs))
	_, err := C.nurs_filter_register_jsons(cs, C.uint16_t(ctxsz))
	return err
}

// struct nurs_consumer_def *nurs_consumer_register_jsons(const char *input, uint16_t context_size);
func ConsumerRegisterJsons(input string, ctxsz uint16) error {
	cs := C.CString(input)
	defer C.free(unsafe.Pointer(cs))
	_, err := C.nurs_consumer_register_jsons(cs, C.uint16_t(ctxsz))
	return err
}

// struct nurs_coveter_def *nurs_coveter_register_jsons(const char *input, uint16_t context_size);
func CoveterRegisterJsons(input string, ctxsz uint16) error {
	cs := C.CString(input)
	defer C.free(unsafe.Pointer(cs))
	_, err := C.nurs_coveter_register_jsons(cs, C.uint16_t(ctxsz))
	return err
}

// struct nurs_producer_def *nurs_producer_register_jsonf(const char *fname, uint16_t context_size);
func ProducerRegisterJsonf(fname string, ctxsz uint16) error {
	cs := C.CString(fname)
	defer C.free(unsafe.Pointer(cs))
	_, err := C.nurs_producer_register_jsonf(cs, C.uint16_t(ctxsz))
	return err
}

// struct nurs_filter_def *nurs_filter_register_jsonf(const char *fname, uint16_t context_size);
func FilterRegisterJsonf(fname string, ctxsz uint16) error {
	cs := C.CString(fname)
	defer C.free(unsafe.Pointer(cs))
	_, err := C.nurs_filter_register_jsonf(cs, C.uint16_t(ctxsz))
	return err
}

// struct nurs_consumer_def *nurs_consumer_register_jsonf(const char *fname, uint16_t context_size);
func ConsumerRegisterJsonf(fname string, ctxsz uint16) error {
	cs := C.CString(fname)
	defer C.free(unsafe.Pointer(cs))
	_, err := C.nurs_consumer_register_jsonf(cs, C.uint16_t(ctxsz))
	return err
}

// struct nurs_coveter_def *nurs_coveter_register_jsonf(const char *fname, uint16_t context_size);
func CoveterRegisterJsonf(fname string, ctxsz uint16) error {
	cs := C.CString(fname)
	defer C.free(unsafe.Pointer(cs))
	_, err := C.nurs_coveter_register_jsonf(cs, C.uint16_t(ctxsz))
	return err
}

// struct nurs_output *nurs_get_output(struct nurs_producer *producer);
func nursGetOutput(producer *Producer) (*Output, error) {
	ret, err := C.nurs_get_output((*C.struct_nurs_producer)(producer))
	return (*Output)(ret), err
}

// int nurs_put_output(struct nurs_output *output);
func nursPutOutput(output *Output) error {
	_, err := C.nurs_put_output((*C.struct_nurs_output)(output))
	return err
}

type FdEvent C.enum_nurs_fd_event

const (
	FD_F_READ   = FdEvent(C.NURS_FD_F_READ)
	FD_F_WRITE  = FdEvent(C.NURS_FD_F_WRITE)
	FD_F_EXCEPT = FdEvent(C.NURS_FD_F_EXCEPT)
)

type Fd C.struct_nurs_fd

// typedef enum nurs_return_t
//	(*nurs_fd_cb_t)(struct nurs_fd *nfd, uint16_t when);
type FdCb func(*Fd, FdEvent) ReturnType

type fdCbData struct {
	cb   FdCb
	data interface{}
}

// for just holding, means prevene GCed
// https://gist.github.com/dwbuiten/c9865c4afb38f482702e
// https://blog.golang.org/go-maps-in-action
var fds = struct {
	sync.RWMutex
	m map[*Fd]*fdCbData
}{m: make(map[*Fd]*fdCbData)}

func nursFdGetFd(fd *Fd) int {
	return int(C.nurs_fd_get_fd((*C.struct_nurs_fd)(fd)))
}

func nursFdGetData(fd *Fd) interface{} {
	fcb := C.nurs_fd_get_data((*C.struct_nurs_fd)(fd))
	return ((*fdCbData)(fcb)).data
}

//export goFdCb
func goFdCb(nfd *C.struct_nurs_fd, when C.uint16_t) C.enum_nurs_return_t {
	fcb, err := C.nurs_fd_get_data((*C.struct_nurs_fd)(nfd))
	if err != nil {
		Log(ERROR, "failed to get data from nfd\n")
		return C.NURS_RET_ERROR
	}
	return C.enum_nurs_return_t(((*fdCbData)(fcb)).cb((*Fd)(nfd), FdEvent(when)))
}

// int nurs_fd_register(struct nurs_fd *nfd, nurs_fd_cb_t cb, void *data);
func nursFdRegister(fd int, when FdEvent, cb FdCb, data interface{}) (*Fd, error) {
	cbdata := &fdCbData{cb, data}
	cfd, err := C.nurs_fd_register_helper(C.int(fd), C.uint16_t(when), unsafe.Pointer(cbdata))
	if err != nil {
		return nil, err
	}
	nfd := (*Fd)(cfd)
	fds.Lock()
	fds.m[nfd] = cbdata
	fds.Unlock()
	return nfd, nil
}

// int nurs_fd_unregister(struct nurs_fd *nfd);
func nursFdUnregister(fd *Fd) error {
	_, err := C.nurs_fd_unregister((*C.struct_nurs_fd)(fd))
	if err == nil {
		fds.Lock()
		delete(fds.m, fd)
		fds.Unlock()
	}
	return err
}

type Timer C.struct_nurs_timer

// typedef enum nurs_return_t
//	(*nurs_timer_cb_t)(struct nurs_timer *timer, void *data);
type TimerCb func(*Timer) ReturnType

type timerCbData struct {
	cb   TimerCb
	data interface{}
}

var timers = struct {
	sync.RWMutex
	m map[*Timer]*timerCbData
}{m: make(map[*Timer]*timerCbData)}

//export goTimerCb
func goTimerCb(timer *C.struct_nurs_timer) C.enum_nurs_return_t {
	tcb, err := C.nurs_timer_get_data((*C.struct_nurs_timer)(timer))
	if err != nil {
		Log(ERROR, "failed to get data from timer\n")
		return C.NURS_RET_ERROR
	}
	return C.enum_nurs_return_t(((*timerCbData)(tcb)).cb((*Timer)(timer)))
}

func nursTimerRegister(sc uint, cb TimerCb, data interface{}) (*Timer, error) {
	cbdata := &timerCbData{cb, data}
	ctimer, err := C.nurs_timer_register_helper(C.time_t(sc), unsafe.Pointer(cbdata))
	timer := (*Timer)(ctimer)
	if err != nil {
		return nil, err
	}
	timers.Lock()
	timers.m[timer] = cbdata
	timers.Unlock()
	return timer, nil
}

func nursITimerRegister(ini uint, per uint, cb TimerCb, data interface{}) (*Timer, error) {
	cbdata := &timerCbData{cb, data}
	ctimer, err := C.nurs_itimer_register_helper(C.time_t(ini), C.time_t(per), unsafe.Pointer(cbdata))
	timer := (*Timer)(ctimer)
	if err != nil {
		return nil, err
	}
	timers.Lock()
	timers.m[timer] = cbdata
	timers.Unlock()
	return timer, nil
}

// void *nurs_timer_get_data(const struct nurs_timer *nfd);
func nursTimerGetData(timer *Timer) interface{} {
	tcb := C.nurs_timer_get_data((*C.struct_nurs_timer)(timer))
	return ((*timerCbData)(tcb)).data
}

func nursTimerUnregister(timer *Timer) error {
	_, err := C.nurs_timer_unregister((*C.struct_nurs_timer)(timer))
	if err == nil {
		timers.Lock()
		delete(timers.m, timer)
		timers.Unlock()
	}
	return err
}

// int nurs_timer_pending(struct nurs_timer *timer);
func nursTimerPending(timer *Timer) (bool, error) {
	ret, err := C.nurs_timer_pending((*C.struct_nurs_timer)(timer))
	return bool(ret), err
}

type LogLevel C.enum_nurs_log_level

const (
	DEBUG  = LogLevel(C.NURS_DEBUG)
	INFO   = LogLevel(C.NURS_INFO)
	NOTICE = LogLevel(C.NURS_NOTICE)
	ERROR  = LogLevel(C.NURS_ERROR)
	FATAL  = LogLevel(C.NURS_FATAL)
)

func Log(level LogLevel, format string, v ...interface{}) {
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		file = "???"
		line = 0
	}

	csFile := C.CString(filepath.Base(file))
	csMsg := C.CString(fmt.Sprintf(format, v...))
	defer C.free(unsafe.Pointer(csFile))
	defer C.free(unsafe.Pointer(csMsg))
	C.nurs_glog(C.int(level), csFile, C.int(line), csMsg)
}

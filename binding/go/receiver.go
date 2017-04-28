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

import (
	"net"
	"unsafe"
)

func (config *Config) Integer(idx uint8) (int, error) {
	return nursConfigInteger(config, idx)
}

func (config *Config) Boolean(idx uint8) (bool, error) {
	return nursConfigBoolean(config, idx)
}

func (config *Config) String(idx uint8) (string, error) {
	return nursConfigString(config, idx)
}

func (config *Config) Len() uint8 {
	return nursConfigLen(config)
}

func (config *Config) Type(idx uint8) (ConfigType, error) {
	return nursConfigType(config, idx)
}

func (config *Config) Index(name string) (uint8, error) {
	return nursConfigIndex(config, name)
}

func (input *Input) Len() uint16 {
	return nursInputLen(input)
}

func (input *Input) Size(idx uint16) (uint32, error) {
	return nursInputSize(input, idx)
}

func (input *Input) Name(idx uint16) (string, error) {
	return nursInputName(input, idx)
}

func (input *Input) Type(idx uint16) (KeyType, error) {
	return nursInputType(input, idx)
}

func (input *Input) Index(name string) (uint16, error) {
	return nursInputIndex(input, name)
}

func (input *Input) Bool(idx uint16) (bool, error) {
	return nursInputBool(input, idx)
}

func (input *Input) U8(idx uint16) (uint8, error) {
	return nursInputU8(input, idx)
}

func (input *Input) U16(idx uint16) (uint16, error) {
	return nursInputU16(input, idx)
}

func (input *Input) U32(idx uint16) (uint32, error) {
	return nursInputU32(input, idx)
}

func (input *Input) U64(idx uint16) (uint64, error) {
	return nursInputU64(input, idx)
}

func (input *Input) InAddr(idx uint16) (net.IP, error) {
	return nursInputInAddr(input, idx)
}

func (input *Input) In6Addr(idx uint16) (net.IP, error) {
	return nursInputIn6Addr(input, idx)
}

func (input *Input) Pointer(idx uint16) (unsafe.Pointer, error) {
	return nursInputPointer(input, idx)
}

func (input *Input) String(idx uint16) (string, error) {
	return nursInputString(input, idx)
}

func (input *Input) IsValid(idx uint16) (bool, error) {
	return nursInputIsValid(input, idx)
}

func (input *Input) IsActive(idx uint16) (bool, error) {
	return nursInputIsActive(input, idx)
}

func (input *Input) IpfixVendor(idx uint16) (uint32, error) {
	return nursInputIpfixVendor(input, idx)
}

func (input *Input) IpfixField(idx uint16) (uint16, error) {
	return nursInputIpfixField(input, idx)
}

func (input *Input) CimName(idx uint16) (string, error) {
	return nursInputCimName(input, idx)
}

func (output *Output) Size(idx uint16) (uint32, error) {
	return nursOutputSize(output, idx)
}

func (output *Output) Type(idx uint16) (KeyType, error) {
	return nursOutputType(output, idx)
}

func (output *Output) Index(name string) (uint16, error) {
	return nursOutputIndex(output, name)
}

func (output *Output) SetBool(idx uint16, value bool) error {
	return nursOutputSetBool(output, idx, value)
}

func (output *Output) SetU8(idx uint16, value uint8) error {
	return nursOutputSetU8(output, idx, value)
}

func (output *Output) SetU16(idx uint16, value uint16) error {
	return nursOutputSetU16(output, idx, value)
}

func (output *Output) SetU32(idx uint16, value uint32) error {
	return nursOutputSetU32(output, idx, value)
}

func (output *Output) SetU64(idx uint16, value uint64) error {
	return nursOutputSetU64(output, idx, value)
}

func (output *Output) SetInAddr(idx uint16, value net.IP) error {
	return nursOutputSetInAddr(output, idx, value)
}

func (output *Output) SetIn6Addr(idx uint16, value net.IP) error {
	return nursOutputSetIn6Addr(output, idx, value)
}

func (output *Output) SetPointer(idx uint16, value unsafe.Pointer) error {
	return nursOutputSetPointer(output, idx, value)
}

func (output *Output) SetString(idx uint16, value string) error {
	return nursOutputSetString(output, idx, value)
}

func (output *Output) Pointer(idx uint16) (unsafe.Pointer, error) {
	return nursOutputPointer(output, idx)
}

func (output *Output) SetValid(idx uint16) error {
	return nursOutputSetValid(output, idx)
}

func (output *Output) Publish() (ReturnType, error) {
	return nursPublish(output)
}

func (output *Output) Put() error {
	return nursPutOutput(output)
}

func (producer *Producer) Config() *Config {
	return nursProducerConfig(producer)
}

func (plugin *Plugin) Config() *Config {
	return nursPluginConfig(plugin)
}

func (producer *Producer) GetOutput() (*Output, error) {
	return nursGetOutput(producer)
}

func (fd *Fd) Fd() int {
	return nursFdGetFd(fd)
}

func (fd *Fd) Data() interface{} {
	return nursFdGetData(fd)
}

func RegisterFd(fd int, when FdEvent, cb FdCb, data interface{}) (*Fd, error) {
	return nursFdRegister(fd, when, cb, data)
}

func (fd *Fd) Unregister() error {
	return nursFdUnregister(fd)
}

func RegisterTimer(sc uint, cb TimerCb, data interface{}) (*Timer, error) {
	return nursTimerRegister(sc, cb, data)
}

func RegisterITimer(ini uint, per uint, cb TimerCb, data interface{}) (*Timer, error) {
	return nursITimerRegister(ini, per, cb, data)
}

func (fd *Timer) Data() interface{} {
	return nursTimerGetData(fd)
}

func (timer *Timer) Unregister() error {
	return nursTimerUnregister(timer)
}

func (timer *Timer) IsPending() (bool, error) {
	return nursTimerPending(timer)
}

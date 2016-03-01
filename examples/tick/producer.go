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
package main

// #cgo CFLAGS: -I../../include
// #include <nurs/nurs.h>
import "C"
import nurs "../../binding/go"

type tickPriv struct {
	counter uint64
	timer   *nurs.Timer
	myname	string
}

var privs = make(map[*nurs.Producer] *tickPriv)

func timerCb(timer *nurs.Timer, data interface{}) nurs.ReturnType {
	producer := data.(*nurs.Producer)
	priv := privs[producer]
	output, _ := producer.GetOutput()

	output.SetU64(0, priv.counter)
	priv.counter += 1
	output.SetString(1, priv.myname)

	ret, _ := output.Publish()
	return ret
}

//export tickOrganize
func tickOrganize(cproducer *C.struct_nurs_producer) C.enum_nurs_return_t {
	var err error
	producer := (*nurs.Producer)(cproducer)
	priv := &tickPriv{}

	if priv.timer, err = nurs.NewTimer(timerCb, producer); err != nil {
		nurs.Log(nurs.ERROR, "failed to create timer\n")
		return C.enum_nurs_return_t(nurs.RET_ERROR)
	}

	config := producer.Config()
	priv.myname, _ = config.String(0)

	privs[producer] = priv
	return C.enum_nurs_return_t(nurs.RET_OK)
}

//export tickDisorganize
func tickDisorganize(cproducer *C.struct_nurs_producer) C.enum_nurs_return_t {
	producer := (*nurs.Producer)(cproducer)
	priv := privs[producer]

	if err := priv.timer.Destroy(); err != nil {
		nurs.Log(nurs.ERROR, "failed to destroy timer\n")
		return C.enum_nurs_return_t(nurs.RET_ERROR)
	}

	delete(privs, producer)
	return C.enum_nurs_return_t(nurs.RET_OK)
}

//export tickStart
func tickStart(cproducer *C.struct_nurs_producer) C.enum_nurs_return_t {
	producer := (*nurs.Producer)(cproducer)
	priv := privs[producer]

	if err := priv.timer.AddInterval(1, 1); err != nil {
		nurs.Log(nurs.ERROR, "failed to add itimer\n")
		return C.enum_nurs_return_t(nurs.RET_ERROR)
	}

	return C.enum_nurs_return_t(nurs.RET_OK)
}

//export tickStop
func tickStop(cproducer *C.struct_nurs_producer) C.enum_nurs_return_t {
	producer := (*nurs.Producer)(cproducer)
	priv := privs[producer]

	if err := priv.timer.Del(); err != nil {
		nurs.Log(nurs.ERROR, "failed to del timer\n")
		return C.enum_nurs_return_t(nurs.RET_ERROR)
	}

	return C.enum_nurs_return_t(nurs.RET_OK)
}

const jsonrc = `{
    "version": "0.1",
    "name": "GO_TICK_PRODUCER",
    "config": [
	{ "name": "myname",
	  "type": "NURS_CONFIG_T_STRING",
	  "flags": ["NURS_CONFIG_F_MANDATORY"]}
    ],
    "output" : [
	{ "name": "counter",
	  "type": "NURS_KEY_T_UINT64",
	  "flags": ["NURS_OKEY_F_ALWAYS"] },
	{ "name": "producer.name",
	  "type": "NURS_KEY_T_STRING",
	  "flags": ["NURS_OKEY_F_ALWAYS"],
	  "len":  32 }
    ],
    "organize":		"tickOrganize",
    "disorganize":	"tickDisorganize",
    "start":		"tickStart",
    "stop":		"tickStop"
}`

func init() {
	nurs.ProducerRegisterJsons(jsonrc, 0)
}

func main() {}

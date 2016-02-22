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

// #cgo CFLAGS: -I../../../include
// #include <nurs/nurs.h>
import "C"

import (
	"os"
	"log"

	nfct "github.com/chamaken/cgolmnfct"
	nurs "../../../binding/go"
)

type nfctPriv struct {
	file	*os.File
	log	*log.Logger
}

var privs = make(map[*nurs.Plugin] *nfctPriv)

//export organize
func organize(cplugin *C.struct_nurs_plugin) C.enum_nurs_return_t {
	plugin := (*nurs.Plugin)(cplugin)
	config := plugin.Config()
	priv := &nfctPriv{}
	var err error

	fname, _ := config.String(0)
	priv.file, err = os.OpenFile(fname, os.O_CREATE|os.O_WRONLY, 0)
	if err != nil {
		nurs.Log(nurs.ERROR, "failed to open file %s: %s\n", fname, err)
		return C.enum_nurs_return_t(nurs.RET_ERROR)
	}

	priv.log = log.New(priv.file, "", log.LstdFlags)

	privs[plugin] = priv;
	return C.enum_nurs_return_t(nurs.RET_OK)
}

//export disorganize
func disorganize(cplugin *C.struct_nurs_plugin) C.enum_nurs_return_t {
	plugin := (*nurs.Plugin)(cplugin)
	priv := privs[plugin]

	priv.log = log.New(os.Stderr, "", log.LstdFlags)
	if err := priv.file.Close(); err != nil {
		nurs.Log(nurs.ERROR, "failed to close logfile: %s\n", err)
		return C.enum_nurs_return_t(nurs.RET_ERROR)
	}

	delete(privs, plugin)
	return C.enum_nurs_return_t(nurs.RET_OK)
}

//export interp
func interp(cplugin *C.struct_nurs_plugin, cinput *C.struct_nurs_input) C.enum_nurs_return_t {
	plugin := (*nurs.Plugin)(cplugin)
	priv := privs[plugin]
	input := (*nurs.Input)(cinput)
	buf := make([]byte, 4096)

	i, err := input.U32(0)
	if err != nil {
		nurs.Log(nurs.ERROR, "failed to get message type: %s\n", err)
		return C.enum_nurs_return_t(nurs.RET_ERROR)
	}
	msg_type := nfct.ConntrackMsgType(i)

	ptr, err := input.Pointer(1)
	if err != nil {
		nurs.Log(nurs.ERROR, "failed to get input pointer1: %s\n", err)
		return C.enum_nurs_return_t(nurs.RET_ERROR)
	}
	ct := (*nfct.Conntrack)(ptr)

	n, _ := ct.Snprintf(buf, msg_type, nfct.NFCT_O_DEFAULT, 0)
	priv.log.Printf("%s\n", string(buf[:n]))

	return C.enum_nurs_return_t(nurs.RET_OK)
}

var jsonrc = `{
    "version"	: "0.1",
    "name"	: "GO_NFCT_LOG",
    "config"	: [
        { "name"	: "logfile",
          "type"	: "NURS_CONFIG_T_STRING",
	  "flags"	: ["NURS_CONFIG_F_MANDATORY"]
        }
    ],
    "input"	: [
        { "name"        : "ct.event",
          "type"        : "NURS_KEY_T_UINT32",
          "flags"       : ["NURS_IKEY_F_REQUIRED"]
        },
        { "name"	: "nfct",
	  "type"	: "NURS_KEY_T_POINTER",
	  "flags"	: ["NURS_IKEY_F_REQUIRED"]
	}
    ],
    "organize"		: "organize",
    "disorganize"	: "disorganize",
    "interp"		: "interp"
}`

func init() {
	nurs.ConsumerRegisterJsons(jsonrc, 0)
}

func main() {}

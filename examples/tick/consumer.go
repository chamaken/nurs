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

//export tickOrganize
func tickOrganize(cplugin *C.struct_nurs_plugin) C.enum_nurs_return_t {
	plugin := (*nurs.Plugin)(cplugin)
	config := plugin.Config()
	s, _ := config.String(0)
	nurs.Log(nurs.NOTICE, "organize - config-string: %s\n", s)

	return C.enum_nurs_return_t(nurs.RET_OK)
}

//export tickInterp
func tickInterp(cplugin *C.struct_nurs_plugin, cinput *C.struct_nurs_input) C.enum_nurs_return_t {
	input := (*nurs.Input)(cinput)
	v, _ := input.U64(0)
	nurs.Log(nurs.NOTICE, "counter x 1: %d\n", v)
	return C.enum_nurs_return_t(nurs.RET_OK)
}

func init() {
	nurs.ConsumerRegisterJsonf("consumer_go.json", 0)
}

func main() {}

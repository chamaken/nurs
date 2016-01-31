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
	"encoding/json"
	"os"
	"strings"
	"syscall"
)

type keyName struct {
	Name	string
}

type PluginDefKeys struct {
	Config	[]keyName
	Input	[]keyName
	Output	[]keyName
}

func ParseJsonKeys(rc string) (*PluginDefKeys, error) {
	dec := json.NewDecoder(strings.NewReader(rc))
	var keys PluginDefKeys
	if err := dec.Decode(&keys); err != nil {
		return nil, err
	}

	return &keys, nil
}

func ParseJsonKeysFile(fname string) (*PluginDefKeys, error) {
	file, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	dec := json.NewDecoder(file)
	var keys PluginDefKeys
	if err := dec.Decode(&keys); err != nil {
		return nil, err
	}

	return &keys, nil
}

func keyIndex(keyNames []keyName, name string) int {
	for i, key := range(keyNames) {
		if key.Name == name {
			return i
		}
	}
	return -1
}

func (defkeys *PluginDefKeys) ConfigIndex(name string) (uint8, error) {
	i := keyIndex(defkeys.Config, name)
	if i < 0 {
		return 0, syscall.EINVAL
	}
	return uint8(i), nil
}

func (defkeys *PluginDefKeys) InputIndex(name string) (uint16, error) {
	i := keyIndex(defkeys.Input, name)
	if i < 0 {
		return 0, syscall.EINVAL
	}
	return uint16(i), nil
}

func (defkeys *PluginDefKeys) OutputIndex(name string) (uint16, error) {
	i := keyIndex(defkeys.Output, name)
	if i < 0 {
		return 0, syscall.EINVAL
	}
	return uint16(i), nil
}

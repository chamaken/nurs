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
// #include <stdlib.h>
// #include <linux/netlink.h>
// #include <linux/netfilter/nfnetlink.h>
// #include <linux/netfilter/nfnetlink_conntrack.h>
// #include <nurs/nurs.h>
import "C"

import (
	"net"
	"syscall"
	"unsafe"

	nfct "github.com/chamaken/cgolmnfct"
	mnl "github.com/chamaken/cgolmnl"

	nurs "../../../binding/go"
)

type nfctPriv struct {
	nl	*mnl.Socket
	fd	*nurs.Fd
}

var (
	idx_ct_event,
	idx_oob_family,
	idx_ip_protocol,
	idx_orig_pktlen,
	idx_orig_pktcount,
	idx_reply_pktlen,
	idx_reply_pktcount,
	idx_orig_ip_saddr,
	idx_orig_ip_daddr,
	idx_orig_ip6_saddr,
	idx_orig_ip6_daddr,
	idx_nfct uint16
)

func dataCb(nlh *mnl.Nlmsghdr, data interface{}) (int, syscall.Errno) {
	producer := data.(*nurs.Producer)
	event := uint32(nfct.NFCT_T_UNKNOWN)

	switch nlh.Type & 0xFF {
	case C.IPCTNL_MSG_CT_NEW:
		if nlh.Flags & (C.NLM_F_CREATE|C.NLM_F_EXCL) != 0 {
			event = uint32(nfct.NFCT_T_NEW) // "NEW"
		} else {
			event = uint32(nfct.NFCT_T_UPDATE) // "UPDATE"
		}
	case C.IPCTNL_MSG_CT_DELETE:
		event = uint32(nfct.NFCT_T_DESTROY) // "DESTROY"
	}

	output, err := producer.GetOutput()
	if err != nil {
		nurs.Log(nurs.ERROR, "failed to get output\n")
		return mnl.MNL_CB_ERROR, err.(syscall.Errno)
	}

	ct, err := nfct.NewConntrack()
	if err != nil {
		nurs.Log(nurs.ERROR, "failed to create new conntrack\n")
		return mnl.MNL_CB_ERROR, err.(syscall.Errno)
	}
	if _, err := ct.NlmsgParse(nlh); err != nil {
		nurs.Log(nurs.ERROR, "failed to parse nfct nlmsg\n");
		ct.Destroy()
		producer.PutOutput(output)
		return mnl.MNL_CB_ERROR, err.(syscall.Errno)
	}

	l3proto, _ := ct.AttrU8(nfct.ATTR_L3PROTO)
	output.SetU32(idx_ct_event, event)
	output.SetU8(idx_oob_family, l3proto)
	if ret, _ := ct.AttrIsSet(nfct.ATTR_ORIG_L4PROTO); ret {
		l4proto, _ := ct.AttrU8(nfct.ATTR_ORIG_L4PROTO)
		output.SetU8(idx_ip_protocol, l4proto)
	} else {
		output.SetU8(idx_ip_protocol, 0)
	}

	if ret, _ := ct.AttrIsSet(nfct.ATTR_ORIG_COUNTER_BYTES); ret {
		pktlen, _ := ct.AttrU64(nfct.ATTR_ORIG_COUNTER_BYTES)
		output.SetU64(idx_orig_pktlen, pktlen)
	} else {
		output.SetU64(idx_orig_pktlen, 0)
	}
	if ret, _ := ct.AttrIsSet(nfct.ATTR_ORIG_COUNTER_PACKETS); ret {
		pktcount, _ := ct.AttrU64(nfct.ATTR_ORIG_COUNTER_PACKETS)
		output.SetU64(idx_orig_pktcount, pktcount)
	} else {
		output.SetU64(idx_orig_pktcount, 0)
	}

	if ret, _ := ct.AttrIsSet(nfct.ATTR_REPL_COUNTER_BYTES); ret {
		pktlen, _ := ct.AttrU64(nfct.ATTR_REPL_COUNTER_BYTES)
		output.SetU64(idx_reply_pktlen, pktlen)
	} else {
		output.SetU64(idx_reply_pktlen, 0)
	}
	if ret, _ := ct.AttrIsSet(nfct.ATTR_REPL_COUNTER_PACKETS); ret {
		pktcount, _ := ct.AttrU64(nfct.ATTR_REPL_COUNTER_PACKETS)
		output.SetU64(idx_reply_pktcount, pktcount)
	} else {
		output.SetU64(idx_reply_pktcount, 0)
	}

	if l3proto == C.AF_INET {
		addr, _ := ct.AttrU32(nfct.ATTR_ORIG_IPV4_SRC)
		output.SetInAddr(idx_orig_ip_saddr, net.ParseIP(nurs.InetNtop(int(l3proto), unsafe.Pointer(&addr))))
		addr, _ = ct.AttrU32(nfct.ATTR_ORIG_IPV4_DST)
		output.SetInAddr(idx_orig_ip_daddr, net.ParseIP(nurs.InetNtop(int(l3proto), unsafe.Pointer(&addr))))
	} else if l3proto == C.AF_INET6 {
		addr, _ := ct.Attr(nfct.ATTR_ORIG_IPV6_SRC)
		output.SetIn6Addr(idx_orig_ip6_saddr, net.ParseIP(nurs.InetNtop(int(l3proto), unsafe.Pointer(addr))))
		addr, _ = ct.Attr(nfct.ATTR_ORIG_IPV6_DST)
		output.SetIn6Addr(idx_orig_ip6_daddr, net.ParseIP(nurs.InetNtop(int(l3proto), unsafe.Pointer(addr))))
	}

	output.SetPointer(idx_nfct, unsafe.Pointer(ct))

	if _, err = producer.Propagate(output); err != nil {
		nurs.Log(nurs.ERROR, "failed to propagate: %s\n", err)
		return mnl.MNL_CB_ERROR, err.(syscall.Errno)
	}

	return mnl.MNL_CB_OK, 0
}

func fdCb(fd int, when nurs.FdEvent, data interface{}) nurs.ReturnType {
	producer := data.(*nurs.Producer)
	priv := (*nfctPriv)(producer.Context())
	buf := make([]byte, mnl.MNL_SOCKET_BUFFER_SIZE)

	nrecv, err := priv.nl.Recvfrom(buf)
	if err != nil {
		nurs.Log(nurs.ERROR, "failed to recv: %s\n", err)
		return nurs.RET_ERROR
	}
	if _, err := mnl.CbRun(buf[:nrecv], 0, 0, dataCb, producer); err != nil {
		nurs.Log(nurs.ERROR, "failed to parse nlmsg: %s\n", err)
		return nurs.RET_ERROR
	}
	return nurs.RET_OK
}

//export organize
func organize(cproducer *C.struct_nurs_producer) C.enum_nurs_return_t {
	var err error
	producer := (*nurs.Producer)(cproducer)
	priv := (*nfctPriv)(producer.Context())

	priv.nl, err = mnl.NewSocket(C.NETLINK_NETFILTER)
	if err != nil {
		nurs.Log(nurs.ERROR, "mnl_socket_open: %s\n", err)
		return C.enum_nurs_return_t(nurs.RET_ERROR)
	}

	if err = priv.nl.Bind(C.NF_NETLINK_CONNTRACK_NEW|
		C.NF_NETLINK_CONNTRACK_UPDATE|
		C.NF_NETLINK_CONNTRACK_DESTROY,
		mnl.MNL_SOCKET_AUTOPID); err != nil {
			nurs.Log(nurs.ERROR, "mnl_socket_bind: %s\n", err)
			return C.enum_nurs_return_t(nurs.RET_ERROR)
		}

	if priv.fd, err = nurs.NewFd(priv.nl.Fd(), nurs.FD_F_READ); err != nil {
		nurs.Log(nurs.ERROR, "failed to create nurs_fd: %s\n", err)
		return C.enum_nurs_return_t(nurs.RET_ERROR)
	}

	return C.enum_nurs_return_t(nurs.RET_OK)
}

//export disorganize
func disorganize(cproducer *C.struct_nurs_producer) C.enum_nurs_return_t {
	var err error
	producer := (*nurs.Producer)(cproducer)
	priv := (*nfctPriv)(producer.Context())
	failed := false

	priv.fd.Destroy()
	if err = priv.nl.Close(); err != nil {
		failed = true
		nurs.Log(nurs.ERROR, "failed to close mnl_socket: %s\n", err)
	}

	if failed {
		return C.enum_nurs_return_t(nurs.RET_ERROR)
	}
	return C.enum_nurs_return_t(nurs.RET_OK)
}

//export start
func start(cproducer *C.struct_nurs_producer) C.enum_nurs_return_t {
	producer := (*nurs.Producer)(cproducer)
	priv := (*nfctPriv)(producer.Context())

	if err := priv.fd.Register(fdCb, producer); err != nil {
		nurs.Log(nurs.ERROR, "failed to register fd: %s\n", err)
		return C.enum_nurs_return_t(nurs.RET_ERROR)
	}

	return C.enum_nurs_return_t(nurs.RET_OK)
}

//export stop
func stop(cproducer *C.struct_nurs_producer) C.enum_nurs_return_t {
	producer := (*nurs.Producer)(cproducer)
	priv := (*nfctPriv)(producer.Context())

	if err := priv.fd.Unregister(); err != nil {
		nurs.Log(nurs.ERROR, "failed to unregister fd: %s\n", err)
		return C.enum_nurs_return_t(nurs.RET_ERROR)
	}

	return C.enum_nurs_return_t(nurs.RET_OK)
}

var jsonrc = `{
    "version": "0.1",
    "name": "GO_NFCT",
    "output" : [
	{ "name"        : "ct.event",
	  "type"        : "NURS_KEY_T_UINT32",
	  "flags"       : ["NURS_OKEY_F_ALWAYS"] },
	{ "name"	: "oob.family",
	  "type"	: "NURS_KEY_T_UINT8",
	  "flags"	: ["NURS_OKEY_F_ALWAYS"] },
	{ "name"	: "orig.ip.protocol",
	  "type"	: "NURS_KEY_T_UINT8",
	  "flags"	: ["NURS_OKEY_F_ALWAYS"],
	  "ipfix_vendor": "IPFIX_VENDOR_IETF",
	  "ipfix_field" : "IPFIX_protocolIdentifier" },
	{ "name"	: "orig.raw.pktlen.delta",
	  "type"	: "NURS_KEY_T_UINT64",
	  "flags"	: ["NURS_OKEY_F_ALWAYS"],
	  "ipfix_vendor": "IPFIX_VENDOR_IETF",
	  "ipfix_field" : "IPFIX_octetTotalCount" },
	{ "name"	: "orig.raw.pktcount.delta",
	  "type"	: "NURS_KEY_T_UINT64",
	  "flags"	: ["NURS_OKEY_F_ALWAYS"],
	  "ipfix_vendor": "IPFIX_VENDOR_IETF",
	  "ipfix_field" : "IPFIX_packetTotalCount" },
	{ "name"	: "reply.raw.pktlen.delta",
	  "type"	: "NURS_KEY_T_UINT64",
	  "flags"	: ["NURS_OKEY_F_ALWAYS"],
	  "ipfix_vendor": "IPFIX_VENDOR_REVERSE",
	  "ipfix_field" : "IPFIX_octetTotalCount" },
	{ "name"	: "reply.raw.pktcount.delta",
	  "type"	: "NURS_KEY_T_UINT64",
	  "flags"	: ["NURS_OKEY_F_ALWAYS"],
	  "ipfix_vendor": "IPFIX_VENDOR_REVERSE",
	  "ipfix_field" : "IPFIX_packetTotalCount" },
	{ "name"	: "orig.ip.saddr",
	  "type" 	: "NURS_KEY_T_INADDR",
	  "flags" 	: ["NURS_OKEY_F_OPTIONAL"],
	  "ipfix_vendor": "IPFIX_VENDOR_IETF",
	  "ipfix_field" : "IPFIX_sourceIPv4Address" },
	{ "name"	: "orig.ip.daddr",
	  "type"	: "NURS_KEY_T_INADDR",
	  "flags"	: ["NURS_OKEY_F_OPTIONAL"],
	  "ipfix_vendor": "IPFIX_VENDOR_IETF",
	  "ipfix_field" : "IPFIX_destinationIPv4Address" },
	{ "name"	: "orig.ip6.saddr",
	  "type" 	: "NURS_KEY_T_IN6ADDR",
	  "flags" 	: ["NURS_OKEY_F_OPTIONAL"],
	  "ipfix_vendor": "IPFIX_VENDOR_IETF",
	  "ipfix_field" : "IPFIX_sourceIPv6Address" },
	{ "name"	: "orig.ip6.daddr",
	  "type"	: "NURS_KEY_T_IN6ADDR",
	  "flags"	: ["NURS_OKEY_F_OPTIONAL"],
	  "ipfix_vendor": "IPFIX_VENDOR_IETF",
	  "ipfix_field" : "IPFIX_destinationIPv6Address" },
	{ "name"	: "nfct",
	  "type"	: "NURS_KEY_T_POINTER",
	  "flags"	: ["NURS_OKEY_F_ALWAYS", "NURS_OKEY_F_DESTRUCT"],
	  "destructor"  : "nfct_destroy" }
    ],
    "organize":		"organize",
    "disorganize":	"disorganize",
    "start":		"start",
    "stop":		"stop"
}`


func init() {
	var priv nfctPriv
	defkeys, err := nurs.ParseJsonKeys(jsonrc)
	if err != nil {
		nurs.Log(nurs.ERROR, "failed to parse json rc: %s\n", err);
		return
	}

	idx_ct_event, err	= defkeys.OutputIndex("ct.event")
	idx_oob_family, err	= defkeys.OutputIndex("oob.family")
	idx_ip_protocol, err	= defkeys.OutputIndex("orig.ip.protocol")
	idx_orig_pktlen, err	= defkeys.OutputIndex("orig.raw.pktlen.delta")
	idx_orig_pktcount, err	= defkeys.OutputIndex("orig.raw.pktcount.delta")
	idx_reply_pktlen, err	= defkeys.OutputIndex("reply.raw.pktlen.delta")
	idx_reply_pktcount, err	= defkeys.OutputIndex("reply.raw.pktcount.delta")
	idx_orig_ip_saddr, err	= defkeys.OutputIndex("orig.ip.saddr")
	idx_orig_ip_daddr, err	= defkeys.OutputIndex("orig.ip.daddr")
	idx_orig_ip6_saddr, err	= defkeys.OutputIndex("orig.ip6.saddr")
	idx_orig_ip6_daddr, err	= defkeys.OutputIndex("orig.ip6.daddr")
	idx_nfct, err		= defkeys.OutputIndex("nfct")

	nurs.ProducerRegisterJsons(jsonrc, uint16(unsafe.Sizeof(priv)))
}

func main() {}

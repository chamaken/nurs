package main

// #cgo CFLAGS: -I../../include
// #include <nurs/nurs.h>
import "C"
import nurs "../../binding/go"

import (
	"io"
	"net"
	"sync"
)

type listenPriv struct {
	listener net.Listener
	nfd      *nurs.Fd
}

var privs = make(map[*nurs.Producer]listenPriv)

type acconn struct {
	sync.RWMutex
	m map[*nurs.Fd]net.Conn
}

var acconns = make(map[*nurs.Producer]acconn)

// var acconns = make(map[*nurs.Producer] struct {
// 	sync.RWMutex
// 	m map[*nurs.Fd] net.Conn
// } { m: make(map[*nurs.Fd] net.Conn) })

func acceptCb(nfd *nurs.Fd, what nurs.FdEvent) nurs.ReturnType {
	producer := nfd.Data().(*nurs.Producer)
	output, err := producer.GetOutput()
	if err != nil {
		nurs.Log(nurs.ERROR, "failed to get output: %v\n", err)
		return nurs.RET_ERROR
	}
	buf, err := output.Bytes(0)
	if err != nil {
		nurs.Log(nurs.ERROR, "failed to get bytes: %v\n", err)
		return nurs.RET_ERROR
	}

	conns := acconns[producer]
	conns.RLock()
	conn := conns.m[nfd]
	conns.RUnlock()

	nread, err := conn.Read(buf)
	if err == io.EOF {
		ret := nurs.RET_OK
		if err = nfd.Unregister(); err != nil {
			nurs.Log(nurs.ERROR, "failed to unregister accept fd: %v\n", err)
			ret = nurs.RET_ERROR
		}
		conn.Close()
		conns = acconns[producer]
		conns.Lock()
		delete(conns.m, nfd)
		conns.Unlock()
		output.Put()
		return ret
	} else if err != nil {
		nurs.Log(nurs.ERROR, "failed to read from accept socket: %v\n", err)
		output.Put()
		return nurs.RET_ERROR
	}

	last := nread - 1
	if buf[last] != 10 {
		nurs.Log(nurs.ERROR, "recv too long line, exceeds: %v\n",
			len(buf))
		output.Put()
		return nurs.RET_ERROR
	}

	if _, err = conn.Write(buf[:nread]); err != nil {
		nurs.Log(nurs.ERROR, "failed to write to client: %v\n", err)
		output.Put()
		return nurs.RET_ERROR
	}

	buf[last] = 0
	if err = output.SetValid(0); err != nil {
		nurs.Log(nurs.ERROR, "failed to be valid output: %v\n", err)
		return nurs.RET_ERROR
	}

	if ret, err := output.Publish(); ret != nurs.RET_OK {
		nurs.Log(nurs.ERROR, "failed to publish: %v\n", err)
		return nurs.RET_ERROR
	}

	return nurs.RET_OK
}

func listenCb(nfd *nurs.Fd, what nurs.FdEvent) nurs.ReturnType {
	if what&nurs.FD_F_READ == 0 {
		return nurs.RET_OK
	}

	producer := nfd.Data().(*nurs.Producer)
	conn, err := privs[producer].listener.Accept()
	if err != nil {
		nurs.Log(nurs.ERROR, "failed to accept: %v\n", err)
		return nurs.RET_ERROR
	}

	nfd, err = nurs.RegisterFd(
		nurs.SocketSysFd(conn), nurs.FD_F_READ, acceptCb, producer)
	if err != nil {
		nurs.Log(nurs.ERROR, "failed to register accept fd: %v\n", err)
		return nurs.RET_ERROR
	}
	conns := acconns[producer]
	conns.Lock()
	conns.m[nfd] = conn
	conns.Unlock()

	return nurs.RET_OK
}

//export listenStart
func listenStart(cproducer *C.struct_nurs_producer) C.enum_nurs_return_t {
	producer := (*nurs.Producer)(cproducer)
	config := producer.Config()
	proto, _ := config.String(0)
	laddr, _ := config.String(1)

	listener, err := net.Listen(proto, laddr)
	if err != nil {
		nurs.Log(nurs.FATAL, "failed to open listen: %v\n", err)
		return C.enum_nurs_return_t(nurs.RET_ERROR)
	}

	nfd, err := nurs.RegisterFd(
		nurs.SocketSysFd(listener), nurs.FD_F_READ, listenCb, producer)
	if err != nil {
		nurs.Log(nurs.FATAL, "failed to register listener: %v", err)
		return C.enum_nurs_return_t(nurs.RET_ERROR)
	}

	privs[producer] = listenPriv{
		listener: listener,
		nfd:      nfd,
	}
	acconns[producer] = acconn{m: make(map[*nurs.Fd]net.Conn)}
	return C.enum_nurs_return_t(nurs.RET_OK)
}

//export listenStop
func listenStop(cproducer *C.struct_nurs_producer) C.enum_nurs_return_t {
	producer := (*nurs.Producer)(cproducer)
	priv := privs[producer]

	if err := priv.nfd.Unregister(); err != nil {
		nurs.Log(nurs.ERROR, "failed to unregister listenfd: %v\n", err)
		return C.enum_nurs_return_t(nurs.RET_ERROR)
	}

	delete(acconns, producer)
	delete(privs, producer)

	return C.enum_nurs_return_t(nurs.RET_OK)
}

const jsonrc = `{
    "version": "0.1",
    "name": "GO_LISTEN",
    "config": [
	{ "name": "proto",
	  "type": "NURS_CONFIG_T_STRING",
	  "flags": ["NURS_CONFIG_F_MANDATORY"]},
	{ "name": "laddr",
	  "type": "NURS_CONFIG_T_STRING",
	  "flags": ["NURS_CONFIG_F_MANDATORY"]}
    ],
    "output" : [
	{ "name": "message",
	  "type": "NURS_KEY_T_EMBED",
	  "flags": ["NURS_OKEY_F_ALWAYS"],
	  "len":  4096 }
    ],
    "start":		"listenStart",
    "stop":		"listenStop"
}`

func init() {
	nurs.ProducerRegisterJsons(jsonrc, 0)
}

func main() {}

/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

package unit

/*
#include "nxt_cgo_lib.h"
*/
import "C"

import (
	"io"
	"net"
	"os"
	"sync"
	"unsafe"
)

type port_key struct {
	pid int
	id  int
}

type port struct {
	key port_key
	rcv *net.UnixConn
	snd *net.UnixConn
}

type port_registry struct {
	sync.RWMutex
	m map[port_key]*port
}

var port_registry_ port_registry

func find_port(key port_key) *port {
	port_registry_.RLock()
	res := port_registry_.m[key]
	port_registry_.RUnlock()

	return res
}

func add_port(p *port) {

	port_registry_.Lock()
	if port_registry_.m == nil {
		port_registry_.m = make(map[port_key]*port)
	}

	old := port_registry_.m[p.key]

	if old == nil {
		port_registry_.m[p.key] = p
	}

	port_registry_.Unlock()
}

func (p *port) Close() {
	if p.rcv != nil {
		p.rcv.Close()
	}

	if p.snd != nil {
		p.snd.Close()
	}
}

func getUnixConn(fd int) *net.UnixConn {
	if fd < 0 {
		return nil
	}

	f := os.NewFile(uintptr(fd), "sock")
	defer f.Close()

	c, err := net.FileConn(f)
	if err != nil {
		nxt_go_alert("FileConn error %s", err)
		return nil
	}

	uc, ok := c.(*net.UnixConn)
	if !ok {
		nxt_go_alert("Not a Unix-domain socket %d", fd)
		return nil
	}

	return uc
}

//export nxt_go_add_port
func nxt_go_add_port(ctx *C.nxt_unit_ctx_t, p *C.nxt_unit_port_t) C.int {

	new_port := &port{
		key: port_key{
			pid: int(p.id.pid),
			id:  int(p.id.id),
		},
		rcv: getUnixConn(int(p.in_fd)),
		snd: getUnixConn(int(p.out_fd)),
	}

	add_port(new_port)

	p.in_fd = -1
	p.out_fd = -1

	return C.NXT_UNIT_OK
}

//export nxt_go_ready
func nxt_go_ready(ctx *C.nxt_unit_ctx_t) C.int {
	go func(ctx *C.nxt_unit_ctx_t) {
		C.nxt_unit_run_shared(ctx)
	}(ctx)

	return C.NXT_UNIT_OK
}

//export nxt_go_remove_port
func nxt_go_remove_port(unit *C.nxt_unit_t, ctx *C.nxt_unit_ctx_t,
	p *C.nxt_unit_port_t) {

	key := port_key{
		pid: int(p.id.pid),
		id:  int(p.id.id),
	}

	port_registry_.Lock()
	if port_registry_.m != nil {
		delete(port_registry_.m, key)
	}

	port_registry_.Unlock()
}

//export nxt_go_port_send
func nxt_go_port_send(pid C.int, id C.int, buf unsafe.Pointer, buf_size C.int,
	oob unsafe.Pointer, oob_size C.int) C.ssize_t {

	key := port_key{
		pid: int(pid),
		id:  int(id),
	}

	p := find_port(key)

	if p == nil {
		nxt_go_alert("port %d:%d not found", pid, id)
		return 0
	}

	n, oobn, err := p.snd.WriteMsgUnix(GoBytes(buf, buf_size),
		GoBytes(oob, oob_size), nil)

	if err != nil {
		nxt_go_warn("write result %d (%d), %s", n, oobn, err)

		n = -1
	}

	return C.ssize_t(n)
}

//export nxt_go_port_recv
func nxt_go_port_recv(pid C.int, id C.int, buf unsafe.Pointer, buf_size C.int,
	oob unsafe.Pointer, oob_size *C.size_t) C.ssize_t {

	key := port_key{
		pid: int(pid),
		id:  int(id),
	}

	p := find_port(key)

	if p == nil {
		nxt_go_alert("port %d:%d not found", pid, id)
		return 0
	}

	n, oobn, _, _, err := p.rcv.ReadMsgUnix(GoBytes(buf, buf_size),
		GoBytes(oob, C.int(*oob_size)))

	if err != nil {
		if nerr, ok := err.(*net.OpError); ok {
			if nerr.Err == io.EOF {
				return 0
			}
		}

		nxt_go_warn("read result %d (%d), %s", n, oobn, err)

		n = -1

	} else {
		*oob_size = C.size_t(oobn)
	}

	return C.ssize_t(n)
}

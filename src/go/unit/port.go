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
	"sync"
	"syscall"
)

type port_key struct {
	pid int
	id  int
}

type port struct {
	key port_key
	rcv C.int
	snd C.int
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

	port_registry_.m[p.key] = p
	port_registry_.Unlock()
}

func (p *port) Close() {
	if p.rcv != -1 {
		syscall.Close(int(p.rcv))
	}

	if p.snd != -1 {
		syscall.Close(int(p.snd))
	}
}

//export nxt_go_add_port
func nxt_go_add_port(pid C.int, id C.int, rcv C.int, snd C.int) {
	p := &port{
		key: port_key{
			pid: int(pid),
			id:  int(id),
		},
		rcv: rcv,
		snd: snd,
	}

	add_port(p)
}

//export nxt_go_remove_port
func nxt_go_remove_port(pid C.int, id C.int) {
	key := port_key{
		pid: int(pid),
		id:  int(id),
	}

	port_registry_.Lock()
	if port_registry_.m != nil {
		p := port_registry_.m[key]
		if p != nil {
			p.Close()
			delete(port_registry_.m, key)
		}
	}

	port_registry_.Unlock()
}

//export nxt_go_lookup_port_pair
func nxt_go_lookup_port_pair(pid C.int, id C.int,
	in_fd *C.int, out_fd *C.int) {

	var in, out C.int = -1, -1

	port := find_port(port_key{
		pid: int(pid),
		id:  int(id),
	})

	if port != nil {
		in = port.rcv
		out = port.snd
	}

	if in_fd != nil {
		*in_fd = in
	}

	if out_fd != nil {
		*out_fd = out
	}
}

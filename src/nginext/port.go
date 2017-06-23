/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

package nginext

/*
#include "nxt_go_lib.h"
*/
import "C"

import (
	"fmt"
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

	port_registry_.m[p.key] = p

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
		fmt.Printf("FileConn error %s\n", err)
		return nil
	}

	uc, ok := c.(*net.UnixConn)
	if !ok {
		fmt.Printf("Not a Unix-domain socket %d\n", fd)
		return nil
	}

	fmt.Printf("Unix-domain socket %d\n", fd)
	return uc
}

//export nxt_go_new_port
func nxt_go_new_port(pid C.int, id C.int, t C.int, rcv C.int, snd C.int) {
	new_port(int(pid), int(id), int(t), int(rcv), int(snd))
}

//export nxt_go_port_send
func nxt_go_port_send(pid C.int, id C.int, buf unsafe.Pointer, buf_size C.int, oob unsafe.Pointer, oob_size C.int) C.int {
	key := port_key{
		pid: int(pid),
		id:  int(id),
	}

	p := find_port(key)

	if p != nil {
		n, oobn, err := p.snd.WriteMsgUnix(C.GoBytes(buf, buf_size), C.GoBytes(oob, oob_size), nil)

		if err != nil {
			fmt.Printf("write result %d (%d), %s\n", n, oobn, err)
		}

		return C.int(n)
	}

	return 0
}

func new_port(pid int, id int, t int, rcv int, snd int) *port {
	p := &port{
		key: port_key{
			pid: pid,
			id:  id,
		},
		rcv: getUnixConn(rcv),
		snd: getUnixConn(snd),
	}

	add_port(p)

	fmt.Printf("new_port: %d, %d, %d, %d\n", pid, id, rcv, snd)

	return p
}

func (p *port) read() {
	var buf [16384]byte
	var oob [1024]byte

	n, oobn, _, _, err := p.rcv.ReadMsgUnix(buf[:], oob[:])

	fmt.Printf("read result %d (%d), %s\n", n, oobn, err)

	m := new_cmsg(buf[:n], oob[:oobn])

	c_req := C.nxt_go_process_port_msg(m.buf.b, m.buf.s, m.oob.b, m.oob.s)

	if c_req == 0 {
		m.Close()
	} else {
		r := find_request(c_req)
		if len(r.msgs) == 0 {
			r.push(m)
		} else if r.ch != nil {
			r.ch <- m
		} else {
			m.Close()
		}
	}

}

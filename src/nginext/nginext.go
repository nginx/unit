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
	"os"
	"strconv"
	"strings"
	"unsafe"
)

type cbuf struct {
	b unsafe.Pointer
	s C.size_t
	f bool
}

func new_cbuf(buf []byte) *cbuf {
	if len(buf) == 0 {
		return nil
	}

	return &cbuf{
		getCBytes(buf), C.size_t(len(buf)), true,
	}
}

func (buf *cbuf) Close() {
	if buf == nil {
		return
	}

	if buf.f && buf.s > 0 {
		C.free(buf.b)
		buf.f = false
		buf.b = nil
		buf.s = 0
	}
}

func (buf *cbuf) GoBytes() []byte {
	if buf == nil {
		var b [0]byte
		return b[:0]
	}

	return C.GoBytes(buf.b, C.int(buf.s))
}

type cmsg struct {
	buf cbuf
	oob cbuf
}

func new_cmsg(buf []byte, oob []byte) *cmsg {
	return &cmsg{
		buf: cbuf{getCBytes(buf), C.size_t(len(buf)), true},
		oob: cbuf{getCBytes(oob), C.size_t(len(oob)), true},
	}
}

func (msg *cmsg) Close() {
	msg.buf.Close()
	msg.oob.Close()
}

var nxt_go_quit bool = false

//export nxt_go_set_quit
func nxt_go_set_quit() {
	nxt_go_quit = true
}

func ListenAndServe() {
	var read_port *port

	go_ports_env := os.Getenv("NXT_GO_PORTS")

	ports := strings.Split(go_ports_env, ";")
	pid := os.Getpid()

	for _, port_str := range ports {
		if len(port_str) <= 0 {
			continue
		}

		attrs := strings.Split(port_str, ",")

		var attrsN [5]int
		var err error
		for i, attr := range attrs {
			attrsN[i], err = strconv.Atoi(attr)
			if err != nil {
				fmt.Printf("err %s\n", err)
				break
			}
		}

		if err != nil {
			continue
		}

		p := new_port(attrsN[0], attrsN[1], attrsN[2], attrsN[3], attrsN[4])

		if attrsN[0] == pid {
			read_port = p
		}
	}

	if read_port != nil {
		C.nxt_go_ready()

		for !nxt_go_quit {
			read_port.read()
		}
	}

}

/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

package unit

/*
#include "nxt_go_lib.h"
*/
import "C"

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"unsafe"
)

type cbuf struct {
	b C.uintptr_t
	s C.size_t
}

func buf_ref(buf []byte) C.uintptr_t {
	if len(buf) == 0 {
		return 0
	}

	return C.uintptr_t(uintptr(unsafe.Pointer(&buf[0])))
}

func (buf *cbuf) init(b []byte) {
  buf.b = buf_ref(b)
  buf.s = C.size_t(len(b))
}

func (buf *cbuf) GoBytes() []byte {
	if buf == nil {
		var b [0]byte
		return b[:0]
	}

	return C.GoBytes(unsafe.Pointer(uintptr(buf.b)), C.int(buf.s))
}

var nxt_go_quit bool = false

//export nxt_go_set_quit
func nxt_go_set_quit() {
	nxt_go_quit = true
}

func nxt_go_warn(format string, args ...interface{}) {
  fmt.Fprintf(os.Stderr, "[go warn] " + format + "\n", args...)
}

func nxt_go_debug(format string, args ...interface{}) {
  // fmt.Fprintf(os.Stderr, "[go debug] " + format + "\n", args...)
}

func ListenAndServe(addr string, handler http.Handler) error {
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
			err := read_port.read(handler)
			if err != nil {
				return err
			}
		}
	} else {
		return http.ListenAndServe(addr, handler)
	}

	return nil
}

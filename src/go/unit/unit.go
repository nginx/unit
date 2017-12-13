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
	"errors"
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
	if go_ports_env == "" {
		return http.ListenAndServe(addr, handler)
	}

	nxt_go_debug("NXT_GO_PORTS=%s", go_ports_env)

	ports := strings.Split(go_ports_env, ";")
	pid := os.Getpid()

	if len(ports) != 4 {
		return errors.New("Invalid NXT_GO_PORTS format")
	}

	nxt_go_debug("version=%s", ports[0])

	builtin_version := C.GoString(C.nxt_go_version())

	if ports[0] != builtin_version {
		return fmt.Errorf("Versions mismatch: Unit %s, while application is built with %s",
			ports[0], builtin_version)
	}

	stream, stream_err := strconv.Atoi(ports[1])
	if stream_err != nil {
		return stream_err
	}

	read_port = nil

	for _, port_str := range ports[2:] {
		attrs := strings.Split(port_str, ",")

		if len(attrs) != 5 {
			return fmt.Errorf("Invalid port format: unexpected port attributes number %d, while 5 expected",
				len(attrs))
		}

		var attrsN [5]int
		var err error
		for i, attr := range attrs {
			attrsN[i], err = strconv.Atoi(attr)
			if err != nil {
				return fmt.Errorf("Invalid port format: number attribute expected at %d position instead of '%s'",
					i, attr);
			}
		}

		p := new_port(attrsN[0], attrsN[1], attrsN[2], attrsN[3], attrsN[4])

		if attrsN[0] == pid {
			read_port = p
		}
	}

	if read_port == nil {
		return errors.New("Application read port not found");
	}

	C.nxt_go_ready(C.uint32_t(stream))

	for !nxt_go_quit {
		err := read_port.read(handler)
		if err != nil {
			return err
		}
	}

	return nil
}

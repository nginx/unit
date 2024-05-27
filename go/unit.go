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
	"fmt"
	"net/http"
	"sync"
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

type string_header struct {
	Data unsafe.Pointer
	Len int
}

func str_ref(s string) *C.char {
	header := (*string_header)(unsafe.Pointer(&s))

	return (*C.char)(header.Data)
}

func (buf *cbuf) init_bytes(b []byte) {
	buf.b = buf_ref(b)
	buf.s = C.size_t(len(b))
}

type slice_header struct {
	Data unsafe.Pointer
	Len int
	Cap int
}

func (buf *cbuf) GoBytes() []byte {
	if buf == nil {
		var b [0]byte
		return b[:0]
	}

	header := &slice_header{
		Data: unsafe.Pointer(uintptr(buf.b)),
		Len: int(buf.s),
		Cap: int(buf.s),
	}

	return *(*[]byte)(unsafe.Pointer(header))
}

func GoBytes(buf unsafe.Pointer, size C.int) []byte {
	bytesHeader := &slice_header{
		Data: buf,
		Len: int(size),
		Cap: int(size),
	}

	return *(*[]byte)(unsafe.Pointer(bytesHeader))
}

func GoStringN(sptr *C.nxt_unit_sptr_t, l C.int) string {
	p := unsafe.Pointer(sptr)
	b := uintptr(p) + uintptr(*(*C.uint32_t)(p))

	return C.GoStringN((*C.char)(unsafe.Pointer(b)), l)
}

func nxt_go_warn(format string, args ...interface{}) {
	str := fmt.Sprintf("[go] " + format, args...)

	C.nxt_cgo_warn(str_ref(str), C.uint32_t(len(str)))
}

func nxt_go_alert(format string, args ...interface{}) {
	str := fmt.Sprintf("[go] " + format, args...)

	C.nxt_cgo_alert(str_ref(str), C.uint32_t(len(str)))
}

type handler_registry struct {
	sync.RWMutex
	next uintptr
	m map[uintptr]*http.Handler
}

var handler_registry_ handler_registry

func set_handler(handler *http.Handler) uintptr {

	handler_registry_.Lock()
	if handler_registry_.m == nil {
		handler_registry_.m = make(map[uintptr]*http.Handler)
		handler_registry_.next = 1
	}

	h := handler_registry_.next
	handler_registry_.next += 1
	handler_registry_.m[h] = handler

	handler_registry_.Unlock()

	return h
}

func get_handler(h uintptr) http.Handler {
	handler_registry_.RLock()
	defer handler_registry_.RUnlock()

	return *handler_registry_.m[h]
}

func reset_handler(h uintptr) {

	handler_registry_.Lock()
	if handler_registry_.m != nil {
		delete(handler_registry_.m, h)
	}

	handler_registry_.Unlock()
}

func ListenAndServe(addr string, handler http.Handler) error {
	if handler == nil {
		handler = http.DefaultServeMux
	}

	h := set_handler(&handler)

	rc := C.nxt_cgo_run(C.uintptr_t(h))

	reset_handler(h)

	if rc != 0 {
		return http.ListenAndServe(addr, handler)
	}

	return nil
}

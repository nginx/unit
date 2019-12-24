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
	"net/http"
)

type response struct {
	header     http.Header
	headerSent bool
	req        *http.Request
	c_req      C.uintptr_t
	ch         chan int
}

func new_response(c_req C.uintptr_t, req *http.Request) *response {
	resp := &response{
		header: http.Header{},
		req:    req,
		c_req:  c_req,
	}

	return resp
}

func (r *response) Header() http.Header {
	return r.header
}

func (r *response) Write(p []byte) (n int, err error) {
	if !r.headerSent {
		r.WriteHeader(http.StatusOK)
	}

	l := len(p)
	written := int(0)
	br := buf_ref(p)

	for written < l {
		res := C.nxt_cgo_response_write(r.c_req, br, C.uint32_t(l - written))

		written += int(res)
		br += C.uintptr_t(res)

		if (written < l) {
			if r.ch == nil {
				r.ch = make(chan int, 2)
			}

			wait_shm_ack(r.ch)
		}
	}

	return written, nil
}

func (r *response) WriteHeader(code int) {
	if r.headerSent {
		// Note: explicitly using Stderr, as Stdout is our HTTP output.
		nxt_go_warn("multiple response.WriteHeader calls")
		return
	}
	r.headerSent = true

	// Set a default Content-Type
	if _, hasType := r.header["Content-Type"]; !hasType {
		r.header.Add("Content-Type", "text/html; charset=utf-8")
	}

	fields := 0
	fields_size := 0

	for k, vv := range r.header {
		for _, v := range vv {
			fields++
			fields_size += len(k) + len(v)
		}
	}

	C.nxt_cgo_response_create(r.c_req, C.int(code), C.int(fields),
		C.uint32_t(fields_size))

	for k, vv := range r.header {
		for _, v := range vv {
			C.nxt_cgo_response_add_field(r.c_req, str_ref(k), C.uint8_t(len(k)),
				str_ref(v), C.uint32_t(len(v)))
		}
	}

	C.nxt_cgo_response_send(r.c_req)
}

func (r *response) Flush() {
	if !r.headerSent {
		r.WriteHeader(http.StatusOK)
	}
}

var observer_registry_ observable

func wait_shm_ack(c chan int) {
	observer_registry_.attach(c)

	_ = <-c
}

//export nxt_go_shm_ack_handler
func nxt_go_shm_ack_handler() {
	observer_registry_.notify(1)
}

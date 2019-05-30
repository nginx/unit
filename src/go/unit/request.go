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
	"net/http"
	"net/url"
	"crypto/tls"
	"unsafe"
)

type request struct {
	req   http.Request
	resp  *response
	c_req C.uintptr_t
}

func (r *request) Read(p []byte) (n int, err error) {
	res := C.nxt_cgo_request_read(r.c_req, buf_ref(p), C.uint32_t(len(p)))

	if res == 0 && len(p) > 0 {
		return 0, io.EOF
	}

	return int(res), nil
}

func (r *request) Close() error {
	C.nxt_cgo_request_close(r.c_req)
	return nil
}

func (r *request) response() *response {
	if r.resp == nil {
		r.resp = new_response(r.c_req, &r.req)
	}

	return r.resp
}

func (r *request) done() {
	resp := r.response()
	if !resp.headerSent {
		resp.WriteHeader(http.StatusOK)
	}
	C.nxt_cgo_request_done(r.c_req, 0)
}

func get_request(go_req uintptr) *request {
	return (*request)(unsafe.Pointer(go_req))
}

//export nxt_go_request_create
func nxt_go_request_create(c_req C.uintptr_t,
	c_method *C.nxt_cgo_str_t, c_uri *C.nxt_cgo_str_t) uintptr {

	uri := C.GoStringN(c_uri.start, c_uri.length)

	var URL *url.URL
	var err error
	if URL, err = url.ParseRequestURI(uri); err != nil {
		return 0
	}

	r := &request{
		req: http.Request{
			Method:     C.GoStringN(c_method.start, c_method.length),
			URL:        URL,
			Header:     http.Header{},
			Body:       nil,
			RequestURI: uri,
		},
		c_req: c_req,
	}
	r.req.Body = r

	return uintptr(unsafe.Pointer(r))
}

//export nxt_go_request_set_proto
func nxt_go_request_set_proto(go_req uintptr, proto *C.nxt_cgo_str_t,
	maj C.int, min C.int) {

	r := get_request(go_req)
	r.req.Proto = C.GoStringN(proto.start, proto.length)
	r.req.ProtoMajor = int(maj)
	r.req.ProtoMinor = int(min)
}

//export nxt_go_request_add_header
func nxt_go_request_add_header(go_req uintptr, name *C.nxt_cgo_str_t,
	value *C.nxt_cgo_str_t) {

	r := get_request(go_req)
	r.req.Header.Add(C.GoStringN(name.start, name.length),
		C.GoStringN(value.start, value.length))
}

//export nxt_go_request_set_content_length
func nxt_go_request_set_content_length(go_req uintptr, l C.int64_t) {
	get_request(go_req).req.ContentLength = int64(l)
}

//export nxt_go_request_set_host
func nxt_go_request_set_host(go_req uintptr, host *C.nxt_cgo_str_t) {
	get_request(go_req).req.Host = C.GoStringN(host.start, host.length)
}

//export nxt_go_request_set_url
func nxt_go_request_set_url(go_req uintptr, scheme *C.char) {
	get_request(go_req).req.URL.Scheme = C.GoString(scheme)
}

//export nxt_go_request_set_remote_addr
func nxt_go_request_set_remote_addr(go_req uintptr, addr *C.nxt_cgo_str_t) {

	get_request(go_req).req.RemoteAddr = C.GoStringN(addr.start, addr.length)
}

//export nxt_go_request_set_tls
func nxt_go_request_set_tls(go_req uintptr) {

	get_request(go_req).req.TLS = &tls.ConnectionState{ }
}

//export nxt_go_request_handler
func nxt_go_request_handler(go_req uintptr, h uintptr) {
	r := get_request(go_req)
	handler := *(*http.Handler)(unsafe.Pointer(h))

	go func(r *request) {
		handler.ServeHTTP(r.response(), &r.req)
		r.done()
	}(r)
}

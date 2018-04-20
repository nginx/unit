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
	"io"
	"net/http"
	"net/url"
	"unsafe"
)

type request struct {
	req   http.Request
	resp  *response
	c_req C.nxt_go_request_t
	id    C.uint32_t
}

func (r *request) Read(p []byte) (n int, err error) {
	c := C.size_t(len(p))
	b := C.uintptr_t(uintptr(unsafe.Pointer(&p[0])))

	res := C.nxt_go_request_read(r.c_req, b, c)

	if res == 0 && len(p) > 0 {
		return 0, io.EOF
	}

	return int(res), nil
}

func (r *request) Close() error {
	C.nxt_go_request_close(r.c_req)
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
	C.nxt_go_request_done(r.c_req)
}

func get_request(go_req C.nxt_go_request_t) *request {
	return (*request)(unsafe.Pointer(uintptr(go_req)))
}

//export nxt_go_new_request
func nxt_go_new_request(c_req C.nxt_go_request_t, id C.uint32_t,
	c_method *C.nxt_go_str_t, c_uri *C.nxt_go_str_t) uintptr {

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
		id:    id,
	}
	r.req.Body = r

	return uintptr(unsafe.Pointer(r))
}

//export nxt_go_request_set_proto
func nxt_go_request_set_proto(go_req C.nxt_go_request_t, proto *C.nxt_go_str_t,
	maj C.int, min C.int) {

	r := get_request(go_req)
	r.req.Proto = C.GoStringN(proto.start, proto.length)
	r.req.ProtoMajor = int(maj)
	r.req.ProtoMinor = int(min)
}

//export nxt_go_request_add_header
func nxt_go_request_add_header(go_req C.nxt_go_request_t, name *C.nxt_go_str_t,
	value *C.nxt_go_str_t) {

	r := get_request(go_req)
	r.req.Header.Add(C.GoStringN(name.start, name.length),
		C.GoStringN(value.start, value.length))
}

//export nxt_go_request_set_content_length
func nxt_go_request_set_content_length(go_req C.nxt_go_request_t, l C.int64_t) {
	get_request(go_req).req.ContentLength = int64(l)
}

//export nxt_go_request_set_host
func nxt_go_request_set_host(go_req C.nxt_go_request_t, host *C.nxt_go_str_t) {
	get_request(go_req).req.Host = C.GoStringN(host.start, host.length)
}

//export nxt_go_request_set_url
func nxt_go_request_set_url(go_req C.nxt_go_request_t, scheme *C.char) {
	get_request(go_req).req.URL.Scheme = C.GoString(scheme)
}

//export nxt_go_request_set_remote_addr
func nxt_go_request_set_remote_addr(go_req C.nxt_go_request_t,
	addr *C.nxt_go_str_t) {

	get_request(go_req).req.RemoteAddr = C.GoStringN(addr.start, addr.length)
}

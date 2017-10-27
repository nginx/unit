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
	"net/http"
	"net/url"
	"sync"
)

type request struct {
	req   http.Request
	resp  *response
	c_req C.nxt_go_request_t
	id    C.uint32_t
	msgs  []*cmsg
	ch    chan *cmsg
}

func (r *request) Read(p []byte) (n int, err error) {
	c := C.size_t(cap(p))
	b := C.malloc(c)
	res := C.nxt_go_request_read(r.c_req, b, c)

	if res == -2 /* NXT_AGAIN */ {
		m := <-r.ch

		res = C.nxt_go_request_read_from(r.c_req, b, c, m.buf.b,
			m.buf.s)
		r.push(m)
	}

	if res > 0 {
		copy(p, C.GoBytes(b, res))
	}

	C.free(b)
	return int(res), nil
}

func (r *request) Close() error {
	C.nxt_go_request_close(r.c_req)
	return nil
}

type request_registry struct {
	sync.RWMutex
	m  map[C.nxt_go_request_t]*request
	id map[C.uint32_t]*request
}

var request_registry_ request_registry

func find_request(c_req C.nxt_go_request_t) *request {
	request_registry_.RLock()
	res := request_registry_.m[c_req]
	request_registry_.RUnlock()

	return res
}

func find_request_by_id(id C.uint32_t) *request {
	request_registry_.RLock()
	res := request_registry_.id[id]
	request_registry_.RUnlock()

	return res
}

func add_request(r *request) {
	request_registry_.Lock()
	if request_registry_.m == nil {
		request_registry_.m = make(map[C.nxt_go_request_t]*request)
		request_registry_.id = make(map[C.uint32_t]*request)
	}

	request_registry_.m[r.c_req] = r
	request_registry_.id[r.id] = r

	request_registry_.Unlock()
}

func remove_request(r *request) {
	request_registry_.Lock()
	if request_registry_.m != nil {
		delete(request_registry_.m, r.c_req)
		delete(request_registry_.id, r.id)
	}

	request_registry_.Unlock()
}

func (r *request) response() *response {
	if r.resp == nil {
		r.resp = new_response(r.c_req, &r.req)
	}

	return r.resp
}

func (r *request) done() {
	remove_request(r)

	C.nxt_go_request_done(r.c_req)

	for _, m := range r.msgs {
		m.Close()
	}

	if r.ch != nil {
		close(r.ch)
	}
}

func (r *request) push(m *cmsg) {
	r.msgs = append(r.msgs, m)
}

//export nxt_go_new_request
func nxt_go_new_request(c_req C.nxt_go_request_t, id C.uint32_t,
	c_method *C.nxt_go_str_t, c_uri *C.nxt_go_str_t) {

	uri := C.GoStringN(c_uri.start, c_uri.length)

	var URL *url.URL
	var err error
	if URL, err = url.ParseRequestURI(uri); err != nil {
		return
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
		msgs:  make([]*cmsg, 0, 1),
	}
	r.req.Body = r

	add_request(r)
}

//export nxt_go_find_request
func nxt_go_find_request(id C.uint32_t) C.nxt_go_request_t {
	r := find_request_by_id(id)

	if r != nil {
		return r.c_req
	}

	return 0
}

//export nxt_go_request_set_proto
func nxt_go_request_set_proto(c_req C.nxt_go_request_t, proto *C.nxt_go_str_t,
	maj C.int, min C.int) {

	r := find_request(c_req)
	r.req.Proto = C.GoStringN(proto.start, proto.length)
	r.req.ProtoMajor = int(maj)
	r.req.ProtoMinor = int(min)
}

//export nxt_go_request_add_header
func nxt_go_request_add_header(c_req C.nxt_go_request_t, name *C.nxt_go_str_t,
	value *C.nxt_go_str_t) {

	r := find_request(c_req)
	r.req.Header.Add(C.GoStringN(name.start, name.length),
		C.GoStringN(value.start, value.length))
}

//export nxt_go_request_set_content_length
func nxt_go_request_set_content_length(c_req C.nxt_go_request_t, l C.int64_t) {
	find_request(c_req).req.ContentLength = int64(l)
}

//export nxt_go_request_create_channel
func nxt_go_request_create_channel(c_req C.nxt_go_request_t) {
	find_request(c_req).ch = make(chan *cmsg)
}

//export nxt_go_request_set_host
func nxt_go_request_set_host(c_req C.nxt_go_request_t, host *C.nxt_go_str_t) {
	find_request(c_req).req.Host = C.GoStringN(host.start, host.length)
}

//export nxt_go_request_set_url
func nxt_go_request_set_url(c_req C.nxt_go_request_t, scheme *C.char) {
	find_request(c_req).req.URL.Scheme = C.GoString(scheme)
}

//export nxt_go_request_set_remote_addr
func nxt_go_request_set_remote_addr(c_req C.nxt_go_request_t,
	addr *C.nxt_go_str_t) {

	find_request(c_req).req.RemoteAddr = C.GoStringN(addr.start, addr.length)
}

//export nxt_go_request_serve
func nxt_go_request_serve(c_req C.nxt_go_request_t) {
	r := find_request(c_req)

	go func(r *request) {
		http.DefaultServeMux.ServeHTTP(r.response(), &r.req)
		r.done()
	}(r)
}

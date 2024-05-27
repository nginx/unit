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
	req    http.Request
	resp   response
	c_req  *C.nxt_unit_request_info_t
}

func (r *request) Read(p []byte) (n int, err error) {
	res := C.nxt_cgo_request_read(r.c_req, buf_ref(p), C.uint32_t(len(p)))

	if res == 0 && len(p) > 0 {
		return 0, io.EOF
	}

	return int(res), nil
}

func (r *request) Close() error {
	return nil
}

func new_request(c_req *C.nxt_unit_request_info_t) (r *request, err error) {
	req := c_req.request

	uri := GoStringN(&req.target, C.int(req.target_length))

	URL, err := url.ParseRequestURI(uri)
	if err != nil {
		return nil, err
	}

	proto := GoStringN(&req.version, C.int(req.version_length))

	r = &request{
		req: http.Request {
			URL: URL,
			Header: http.Header{},
			RequestURI: uri,
			Method: GoStringN(&req.method, C.int(req.method_length)),
			Proto: proto,
			ProtoMajor: 1,
			ProtoMinor: int(proto[7] - '0'),
			ContentLength: int64(req.content_length),
			Host: GoStringN(&req.server_name, C.int(req.server_name_length)),
			RemoteAddr: GoStringN(&req.remote, C.int(req.remote_length)),
		},
		resp: response{header: http.Header{}, c_req: c_req},
		c_req: c_req,
	}

	r.req.Body = r

	if req.tls != 0 {
		r.req.TLS = &tls.ConnectionState{ }
		r.req.URL.Scheme = "https"

	} else {
		r.req.URL.Scheme = "http"
	}

	fields := get_fields(req)

	for i := 0; i < len(fields); i++ {
		f := &fields[i]

		n := GoStringN(&f.name, C.int(f.name_length))
		v := GoStringN(&f.value, C.int(f.value_length))

		r.req.Header.Add(n, v)
	}

	return r, nil
}

func get_fields(req *C.nxt_unit_request_t) []C.nxt_unit_field_t {
	f := uintptr(unsafe.Pointer(req)) + uintptr(C.NXT_FIELDS_OFFSET)

	h := &slice_header{
		Data: unsafe.Pointer(f),
		Len: int(req.fields_count),
		Cap: int(req.fields_count),
	}

	return *(*[]C.nxt_unit_field_t)(unsafe.Pointer(h))
}

//export nxt_go_request_handler
func nxt_go_request_handler(c_req *C.nxt_unit_request_info_t) {

	go func(c_req *C.nxt_unit_request_info_t, handler http.Handler) {

		ctx := c_req.ctx

		for {
			r, err := new_request(c_req)

			if err == nil {
				handler.ServeHTTP(&r.resp, &r.req)

				if !r.resp.header_sent {
					r.resp.WriteHeader(http.StatusOK)
				}

				C.nxt_unit_request_done(c_req, C.NXT_UNIT_OK)

			} else {
				C.nxt_unit_request_done(c_req, C.NXT_UNIT_ERROR)
			}

			c_req = C.nxt_unit_dequeue_request(ctx)
			if c_req == nil {
				break
			}
		}

	}(c_req, get_handler(uintptr(c_req.unit.data)))
}

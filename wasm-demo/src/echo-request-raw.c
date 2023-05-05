/*
 * echo-request-raw.c - Raw example of writing a WASM module for use with Unit
 *
 * Download the wasi-sysroot tarball from https://github.com/WebAssembly/wasi-sdk/releases
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "unit-wasm-raw.h"

static u8 *request_buf;

__attribute__((import_module("env"), import_name("nxt_wasm_get_init_mem_size")))
u32 nxt_wasm_get_init_mem_size(void);
__attribute__((import_module("env"), import_name("nxt_wasm_response_end")))
void nxt_wasm_response_end(void);
__attribute__((import_module("env"), import_name("nxt_wasm_send_response")))
void nxt_wasm_send_response(u32 offset);

__attribute__((export_name("wasm_module_end_handler")))
void wasm_module_end_handler(void)
{
	free(request_buf);
}

__attribute__((export_name("wasm_module_init_handler")))
void wasm_module_init_handler(void)
{
	request_buf = malloc(nxt_wasm_get_init_mem_size());
}

__attribute__((export_name("wasm_free_handler")))
void wasm_free_handler(u32 addr)
{
	free((void *)addr);
}

__attribute__((export_name("wasm_malloc_handler")))
u32 wasm_malloc_handler(size_t size)
{
	return (u32)malloc(size);
}

static int echo_request(u8 *addr)
{
	u8 *p;
	const char *method;
	struct req *req;
	struct resp *resp;
	struct hdr_field *hf;
	struct hdr_field *hf_end;
	static const int resp_offs = 4096;

	printf("==[WASM RESP]== %s:\n", __func__);

	/*
	 * For convenience, we will return our headers at the start
	 * of the shared memory so leave a little space (resp_offs)
	 * before storing the main response.
	 *
	 * send_headers() will return the start of the shared memory,
	 * echo_request() will return the start of the shared memory
	 * plus resp_offs.
	 */
	resp = (struct resp *)(addr + resp_offs);

	req = (struct req *)request_buf;

#define BUF_ADD(name, member) \
	do { \
		p = mempcpy(p, name, strlen(name)); \
		p = mempcpy(p, (u8 *)req + req->member##_offs, req->member##_len); \
		p = mempcpy(p, "\n", 1); \
	} while (0)

#define BUF_ADD_HF() \
	do { \
		p = mempcpy(p, (u8 *)req + hf->name_offs, hf->name_len); \
		p = mempcpy(p, " = ", 3); \
		p = mempcpy(p, (u8 *)req + hf->value_offs, hf->value_len); \
		p = mempcpy(p, "\n", 1); \
	} while (0)

	p = resp->data;

	p = mempcpy(p, "Welcome to WebAssembly on Unit!\n\n", 33);

	p = mempcpy(p, "[Request Info]\n", 15);
	BUF_ADD("REQUEST_PATH = ", path);
	BUF_ADD("METHOD       = ", method);
	BUF_ADD("VERSION      = ", version);
	BUF_ADD("QUERY        = ", query);
	BUF_ADD("REMOTE       = ", remote);
	BUF_ADD("LOCAL_ADDR   = ", local_addr);
	BUF_ADD("LOCAL_PORT   = ", local_port);
	BUF_ADD("SERVER_NAME  = ", server_name);

	p = mempcpy(p, "\n[Request Headers]\n", 19);
	hf_end = req->fields + req->nr_fields;
	for (hf = req->fields; hf < hf_end; hf++)
		BUF_ADD_HF();

	method = (char *)req + req->method_offs;
	if (memcmp(method, "POST", req->method_len) == 0 ||
	    memcmp(method, "PUT", req->method_len) == 0) {
		p = mempcpy(p, "\n[", 2);
		p = mempcpy(p, method, req->method_len);
		p = mempcpy(p, " data]\n", 7);
		p = mempcpy(p, (u8 *)req + req->content_offs, req->content_len);
		p = mempcpy(p, "\n", 1);
	}

	p = memcpy(p, "\0", 1);

	resp->size = p - resp->data;

	send_headers(addr, "text/plain", resp->size);

	nxt_wasm_send_response(resp_offs);
	/* Tell Unit no more data to send */
	nxt_wasm_response_end();

	return 0;
}

__attribute__((export_name("wasm_request_handler")))
int wasm_request_handler(u8 *addr)
{
	struct req *req = (struct req *)addr;
	struct req *rb = (struct req *)request_buf;

	printf("==[WASM REQ]== %s:\n", __func__);

	/*
	 * This function _may_ be called multiple times during a single
	 * request if there is a large amount of data to transfer.
	 *
	 * In this simple demo, we are only expecting it to be called
	 * once per request.
	 *
	 * Some useful request meta data:
	 *
	 * req->content_len contains the overall size of the POST/PUT
	 * data.
	 * req->content_sent shows how much of the body content has been
	 * in _this_ request.
	 * req->total_content_sent shows how much of it has been sent in
	 * total.
	 * req->content_offs is the offset in the passed in memory where
	 * the body content starts.
	 *
	 * For new requests req->request_size shows the total size of
	 * _this_ request, incl the req structure itself.
	 * For continuation requests, req->request_size is just the amount
	 * of new content, i.e req->content_sent
	 *
	 * When req->content_len == req->total_content_sent, that's the end
	 * of that request.
	 */

	printf("==[WASM REQ]== req->request_size : %u\n", req->request_size);
	memcpy(request_buf, addr, req->request_size);

	rb = (struct req *)request_buf;
	printf("==[WASM REQ]== rb@%p\n", rb);
	printf("==[WASM REQ]== request_buf@%p\n", request_buf);
	printf("==[WASM REQ]== rb->content_offs : %u\n", rb->content_offs);
	printf("==[WASM REQ]== rb->content_len  : %u\n", rb->content_len);
	printf("==[WASM REQ]== rb->content_sent : %u\n", rb->content_sent);
	printf("==[WASM REQ]== rb->request_size : %u\n", rb->request_size);

	echo_request(addr);

	return 0;
}

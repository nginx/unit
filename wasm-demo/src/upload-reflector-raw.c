/*
 * upload-reflector-raw.c - Raw example of writing a WASM module for use with
 *			    Unit
 *
 * Download the wasi-sysroot tarball from https://github.com/WebAssembly/wasi-sdk/releases
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unit-wasm-raw.h"

static size_t total_response_sent;

static u8 *request_buf;

__attribute__((import_module("env"), import_name("nxt_wasm_get_init_mem_size")))
u32 nxt_wasm_get_init_mem_size(void);
__attribute__((import_module("env"), import_name("nxt_wasm_response_end")))
void nxt_wasm_response_end(void);
__attribute__((import_module("env"), import_name("nxt_wasm_send_response")))
void nxt_wasm_send_response(u32 offset);

__attribute__((export_name("wasm_response_end_handler")))
void wasm_response_end_handler(void)
{
	total_response_sent = 0;
}

__attribute__((export_name("wasm_request_end_handler")))
void wasm_request_end_handler(void)
{
	if (!request_buf)
		return;

	free(request_buf);
	request_buf = NULL;
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

static int upload_reflector(u8 *addr)
{
	size_t mem_size = nxt_wasm_get_init_mem_size();
	size_t rsize = sizeof(struct resp);
	size_t write_bytes;
	struct req *req;
	struct resp *resp;

	printf("==[WASM RESP]== %s:\n", __func__);

	resp = (struct resp *)addr;
	req = (struct req *)request_buf;

	printf("==[WASM RESP]== resp@%p\n", resp);
	printf("==[WASM RESP]== req@%p\n", req);
	printf("==[WASM RESP]== req->content_len    : %u\n", req->content_len);

	resp = (struct resp *)addr;

	/* Send headers */
	if (total_response_sent == 0) {
		const char *field;
		struct hdr_field *f;
		struct hdr_field *f_end;
		char ct[256];

		/* Try to set the Content-Type */
		f_end = req->fields + req->nr_fields;
		for (f = req->fields; f < f_end; f++) {
			field = (const char *)(u8 *)req + f->name_offs;

			if (strncasecmp(field, "Content-Type", 12) == 0) {
				snprintf(ct, sizeof(ct), "%.*s", f->value_len,
					 (u8 *)req + f->value_offs);
				break;
			}

			field = NULL;
		}
		if (!field)
			sprintf(ct, "application/octet-stream");

		send_headers(addr, ct, req->content_len);
	}

	write_bytes = req->content_sent;
	if (write_bytes > mem_size - rsize)
		write_bytes = mem_size - rsize;

	printf("==[WASM RESP]== write_bytes         : %lu\n", write_bytes);
	printf("==[WASM RESP]== req->content_len    : %u\n", req->content_len);
	printf("==[WASM RESP]== total_response_sent : %lu\n",
	       total_response_sent);

	printf("==[WASM RESP]== Copying (%lu) bytes of data from [%p+%lx] to "
	       "[%p]\n", write_bytes, req,
	       req->content_offs + total_response_sent, resp->data);
	memcpy(resp->data,
	       (u8 *)req + req->content_offs + total_response_sent,
	       write_bytes);

	total_response_sent += write_bytes;
	resp->size = write_bytes;
	printf("==[WASM RESP]== resp->size          : %u\n", resp->size);

	nxt_wasm_send_response(0);

	if (total_response_sent == req->content_len) {
		printf("==[WASM RESP]== All data sent. Cleaning up...\n");
		total_response_sent = 0;

		free(request_buf);
		request_buf = NULL;

		/* Tell Unit no more data to send */
		nxt_wasm_response_end();
	}

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

	if (!request_buf) {
		/*
		 * Just allocate memory for the total amount of data we
		 * expect to get, this includes the request structure
		 * itself as well as any body content.
		 */
		printf("==[WASM REQ]== malloc(%u)\n",
		       req->content_offs + req->content_len);
		request_buf = malloc(req->content_offs + req->content_len);

		/*
		 * Regardless of how much memory we allocated above, here
		 * we only want to copy the amount of data we actually
		 * received in this request.
		 */
		printf("==[WASM REQ]== req->request_size : %u\n",
		       req->request_size);
		memcpy(request_buf, addr, req->request_size);

		rb = (struct req *)request_buf;
		printf("==[WASM REQ]== rb@%p\n", rb);
		printf("==[WASM REQ]== request_buf@%p\n", request_buf);
		printf("==[WASM REQ]== rb->content_offs : %u\n",
		       rb->content_offs);
		printf("==[WASM REQ]== rb->content_len  : %u\n",
		       rb->content_len);
		printf("==[WASM REQ]== rb->content_sent : %u\n",
		       rb->content_sent);
		printf("==[WASM REQ]== rb->request_size : %u\n",
		       rb->request_size);
	} else {
		memcpy(request_buf + rb->request_size, addr + req->content_offs,
		       req->request_size);

		printf("==[WASM REQ +]== req->content_offs : %u\n",
		       req->content_offs);
		printf("==[WASM REQ +]== req->content_sent : %u\n",
		       req->content_sent);
		printf("==[WASM REQ +]== req->request_size : %u\n",
		       req->request_size);

		rb->content_sent = req->content_sent;
		rb->total_content_sent = req->total_content_sent;
	}

	upload_reflector(addr);

	return 0;
}

#define _GNU_SOURCE

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include "unit/unit-wasm.h"

/*
 * Some handlers are required some are optional.
 *
 * They are defined as _weak_ symbols so they can be overridden
 * in the module.
 */

/* Optional Handlers */
__attribute__((export_name("luw_module_init_handler"), __weak__))
void luw_module_init_handler(void)
{
}

__attribute__((export_name("luw_module_end_handler"), __weak__))
void luw_module_end_handler(void)
{
}

__attribute__((export_name("luw_request_init_handler"), __weak__))
void luw_request_init_handler(void)
{
}

__attribute__((export_name("luw_request_end_handler"), __weak__))
void luw_request_end_handler(void)
{
}

__attribute__((export_name("luw_response_end_handler"), __weak__))
void luw_response_end_handler(void)
{
}

/* Required Handlers */
__attribute__((export_name("luw_request_handler"), __weak__))
int luw_request_handler(u8 *addr)
{
	(void)addr;

	return 0;
}

__attribute__((export_name("luw_free_handler"), __weak__))
void luw_free_handler(u32 addr)
{
        free((void *)addr);
}

__attribute__((export_name("luw_malloc_handler"), __weak__))
u32 luw_malloc_handler(size_t size)
{
        return (u32)malloc(size);
}

void luw_init_ctx(luw_ctx_t *ctx, u8 *addr, size_t offset)
{
	*ctx = (luw_ctx_t){ };

	ctx->addr = addr;
	ctx->req = (struct luw_req *)addr;
	ctx->resp = (struct luw_resp *)(addr + offset);
	ctx->mem = ctx->resp->data;
	ctx->resp_offset = offset;
}

/*
 * Allows to set an external buffer to be used as a copy for
 * the request.
 *
 * The flags dictate a few behaviours
 *
 * LUW_SRB_NONE		- No specific action to be performed. It will
 *			  simply copy the request data into the specified
 *			  buffer.
 *
 * LUW_SRB_APPEND	- Sets up append mode whereby multiple successive
 *			  requests will be appended to the specified buffer.
 *
 *			  The first request will have all it's netadata
 *			  copied. Suvsequent requests will _only_ have the
 *			  actual body data appended.
 *
 * LUW_SRB_ALLOC	- Allocate memory for the specified buffer.
 *
 * LUW_SRB_FULL_SIZE	- Used in conjunction with LUW_SRB_ALLOC. By
 *			  default only ctx->req->request_size is
 *			  allocated. If this flag is present it says to
 *			  allocate memory for the _entire_ request that
 *			  will eventually be sent.
 */
int luw_set_req_buf(luw_ctx_t *ctx, u8 **buf, unsigned long flags)
{
	size_t alloc_size;
	size_t copy_bytes;

	/* Check for unknown flags */
	if (flags & ~LUW_SRB_FLAGS_ALL) {
		errno = EINVAL;
		return -1;
	}

	/* Check for invalid combinations of flags */
	if (flags & LUW_SRB_FULL_SIZE && !(flags & LUW_SRB_ALLOC)) {
		errno = EINVAL;
		return -1;
	}

	alloc_size = copy_bytes = ctx->req->request_size;

	if (flags & LUW_SRB_FULL_SIZE)
		alloc_size = ctx->req->content_offs + ctx->req->content_len;

	if (flags & LUW_SRB_ALLOC) {
		*buf = malloc(alloc_size);
		if (!*buf)
			return -1;
	}

	memcpy(*buf, ctx->addr, copy_bytes);
	ctx->req_buf = *buf;
	ctx->req = (struct luw_req *)ctx->req_buf;
	ctx->reqp = ctx->req_buf;

	if (flags & LUW_SRB_APPEND)
		ctx->reqp = ctx->req_buf + copy_bytes;

	return 0;
}

const char *luw_get_http_path(const luw_ctx_t *ctx)
{
	return (const char *)(u8 *)ctx->req + ctx->req->path_offs;
}

const char *luw_get_http_method(const luw_ctx_t *ctx)
{
	return (const char *)(u8 *)ctx->req + ctx->req->method_offs;
}

const char *luw_get_http_version(const luw_ctx_t *ctx)
{
	return (const char *)(u8 *)ctx->req + ctx->req->version_offs;
}

const char *luw_get_http_query(const luw_ctx_t *ctx)
{
	return (const char *)(u8 *)ctx->req + ctx->req->query_offs;
}

const char *luw_get_http_remote(const luw_ctx_t *ctx)
{
	return (const char *)(u8 *)ctx->req + ctx->req->remote_offs;
}

const char *luw_get_http_local_addr(const luw_ctx_t *ctx)
{
	return (const char *)(u8 *)ctx->req + ctx->req->local_addr_offs;
}

const char *luw_get_http_local_port(const luw_ctx_t *ctx)
{
	return (const char *)(u8 *)ctx->req + ctx->req->local_port_offs;
}

const char *luw_get_http_server_name(const luw_ctx_t *ctx)
{
	return (const char *)(u8 *)ctx->req + ctx->req->server_name_offs;
}

const u8 *luw_get_http_content(const luw_ctx_t *ctx)
{
	return (u8 *)ctx->req + ctx->req->content_offs;
}

/* Returns the size of the overall content length */
size_t luw_get_http_content_len(const luw_ctx_t *ctx)
{
	return ctx->req->content_len;
}

/* Returns the size of the content sent in _this_ request */
size_t luw_get_http_content_sent(const luw_ctx_t *ctx)
{
	return ctx->req->content_sent;
}

bool luw_http_is_tls(const luw_ctx_t *ctx)
{
	return ctx->req->tls;
}

/* Returns the size of ctx->resp->data[] */
size_t luw_get_response_data_size(const luw_ctx_t *ctx)
{
	return ctx->mem - ctx->resp->data;
}

/* Appends formatted nul terminated data to the response buffer */
__attribute__((__format__(printf, 2, 3)))
int luw_mem_writep(luw_ctx_t *ctx, const char *fmt, ...)
{
	int len;
	char *logbuf;
	va_list ap;

	va_start(ap, fmt);
	len = vasprintf(&logbuf, fmt, ap);
	if (len == -1) {
		va_end(ap);
		return 1;
	}
	va_end(ap);

	ctx->mem = mempcpy(ctx->mem, logbuf, len);
	ctx->resp->size += len;

	free(logbuf);

	return 0;
}

/* Appends data of length size to the response buffer */
size_t luw_mem_writep_data(luw_ctx_t *ctx, const u8 *src, size_t size)
{
	ctx->mem = mempcpy(ctx->mem, src, size);
	ctx->resp->size += size;

	return ctx->resp->size;
}

/* Append data from the request to the previously setup request_buffer. */
void luw_req_buf_append(luw_ctx_t *ctx, const u8 *src)
{
	struct luw_req *req = (struct luw_req *)src;

	ctx->reqp = mempcpy(ctx->reqp, src + req->content_offs,
			    req->request_size);
	ctx->req->content_sent = req->content_sent;
	ctx->req->total_content_sent = req->total_content_sent;
}

/*
 * Convenience function to fill the response buffer with data from
 * the request buffer.
 *
 * The runtime allocates NXT_WASM_MEM_SIZE + NXT_WASM_PAGE_SIZE
 * bytes so we don't need to worry about the size of the actual
 * response structures.
 */
size_t luw_mem_fill_buf_from_req(luw_ctx_t *ctx, size_t from)
{
	size_t write_bytes;
	size_t mem_size = nxt_wasm_get_init_mem_size();

	write_bytes = ctx->req->content_sent;
	if (write_bytes > mem_size)
		write_bytes = mem_size;

	memcpy(ctx->resp->data, ctx->req_buf + ctx->req->content_offs + from,
	       write_bytes);
	ctx->resp->size = write_bytes;

	return write_bytes;
}

void luw_mem_reset(luw_ctx_t *ctx)
{
	ctx->mem = ctx->resp->data;
	ctx->resp->size = 0;
}

void luw_http_send_response(const luw_ctx_t *ctx)
{
	nxt_wasm_send_response(ctx->resp_offset);
}

void luw_http_init_headers(luw_ctx_t *ctx, size_t nr, size_t offset)
{
	ctx->resp_hdr = (struct luw_resp_hdr *)(ctx->addr + offset);
	ctx->hdrp = (u8 *)ctx->resp_hdr + sizeof(struct luw_resp_hdr) +
		(nr * sizeof(struct luw_hdr_field));

	ctx->resp_hdr->nr_fields = nr;
}

void luw_http_add_header(luw_ctx_t *ctx, u16 idx, const char *name,
			 const char *value)
{
	ctx->resp_hdr->fields[idx].name_offs = ctx->hdrp - ctx->addr;
	ctx->resp_hdr->fields[idx].name_len = strlen(name);
	ctx->hdrp = mempcpy(ctx->hdrp, name, strlen(name));

	ctx->resp_hdr->fields[idx].value_offs = ctx->hdrp - ctx->addr;
	ctx->resp_hdr->fields[idx].value_len = strlen(value);
	ctx->hdrp = mempcpy(ctx->hdrp, value, strlen(value));
}

void luw_http_send_headers(const luw_ctx_t *ctx)
{
	nxt_wasm_send_headers((u8 *)ctx->resp_hdr - ctx->addr);
}

void luw_http_response_end(void)
{
	nxt_wasm_response_end();
}

u32 luw_mem_get_init_size(void)
{
	return nxt_wasm_get_init_mem_size();
}

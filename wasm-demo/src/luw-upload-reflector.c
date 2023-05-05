/*
 * luw-upload-reflector.c - Example of writing a WASM module for use with Unit
 *			    using libunit-wasm to make things nicer.
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unit/unit-wasm.h"

static luw_ctx_t ctx;

static size_t total_response_sent;

static u8 *request_buf;

__luw_export_name("luw_response_end_handler")
void luw_response_end_handler(void)
{
	total_response_sent = 0;
}

__luw_export_name("luw_request_end_handler")
void luw_request_end_handler(void)
{
	if (!request_buf)
		return;

	free(request_buf);
	request_buf = NULL;
}

__luw_export_name("luw_free_handler")
void luw_free_handler(u32 addr)
{
	free((void *)addr);
}

__luw_export_name("luw_malloc_handler")
u32 luw_malloc_handler(size_t size)
{
	return (u32)malloc(size);
}

static int upload_reflector(luw_ctx_t *ctx)
{
	size_t write_bytes;

	/* Send headers */
	if (total_response_sent == 0) {
		luw_http_hdr_iter_t *iter;
		const char *name;
		const char *value;
		char ct[256] = "application/octet-stream";
		char clen[32];

		/* Try to set the Content-Type */
		luw_foreach_http_hdr(ctx, iter, name, value) {
			if (strncasecmp(name, "Content-Type", 12) != 0)
				continue;

			snprintf(ct, sizeof(ct), "%s", value);
			break;
		}

		luw_http_init_headers(ctx, 2, 0);

		snprintf(clen, sizeof(clen), "%lu",
			 luw_get_http_content_len(ctx));
		luw_http_add_header(ctx, 0, "Content-Type", ct);
		luw_http_add_header(ctx, 1, "Content-Length", clen);

		luw_http_send_headers(ctx);
	}

	write_bytes = luw_mem_fill_buf_from_req(ctx, total_response_sent);
	total_response_sent += write_bytes;

	luw_http_send_response(ctx);

	if (total_response_sent == ctx->req->content_len) {
		total_response_sent = 0;

		free(request_buf);
		request_buf = NULL;

		/* Tell Unit no more data to send */
		luw_http_response_end();
	}

	return 0;
}

__luw_export_name("luw_request_handler")
int luw_request_handler(u8 *addr)
{
	if (!request_buf) {
		luw_init_ctx(&ctx, addr, 0 /* Response offset */);
		/*
		 * Take a copy of the request and use that, we do this
		 * in APPEND mode so we can build up request_buf from
		 * multiple requests.
		 *
		 * Just allocate memory for the total amount of data we
		 * expect to get, this includes the request structure
		 * itself as well as any body content.
		 */
		luw_set_req_buf(&ctx, &request_buf,
				LUW_SRB_APPEND|LUW_SRB_ALLOC|LUW_SRB_FULL_SIZE);
	} else {
		luw_req_buf_append(&ctx, addr);
	}

	upload_reflector(&ctx);

	return 0;
}

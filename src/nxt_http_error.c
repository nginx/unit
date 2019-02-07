
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


static void nxt_http_request_send_error_body(nxt_task_t *task, void *r,
    void *data);


static const nxt_http_request_state_t  nxt_http_request_send_error_body_state;


static const char  error[] =
    "<html><head><title>Error</title></head>"
    "<body>Error.</body></html>\r\n";


void
nxt_http_request_error(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_status_t status)
{
    nxt_http_field_t  *content_type;

    nxt_debug(task, "http request error: %d", status);

    if (r->header_sent || r->error) {
        goto fail;
    }

    r->error = (status == NXT_HTTP_INTERNAL_SERVER_ERROR);

    r->status = status;

    r->resp.fields = nxt_list_create(r->mem_pool, 8, sizeof(nxt_http_field_t));
    if (nxt_slow_path(r->resp.fields == NULL)) {
        goto fail;
    }

    content_type = nxt_list_zero_add(r->resp.fields);
    if (nxt_slow_path(content_type == NULL)) {
        goto fail;
    }

    nxt_http_field_set(content_type, "Content-Type", "text/html");

    r->resp.content_length = NULL;
    r->resp.content_length_n = nxt_length(error);

    r->state = &nxt_http_request_send_error_body_state;

    nxt_http_request_header_send(task, r);
    return;

fail:

    nxt_http_request_error_handler(task, r, r->proto.any);
}


static const nxt_http_request_state_t  nxt_http_request_send_error_body_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_http_request_send_error_body,
    .error_handler = nxt_http_request_error_handler,
};


static void
nxt_http_request_send_error_body(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t           *out;
    nxt_http_request_t  *r;

    r = obj;

    nxt_debug(task, "http request send error body");

    out = nxt_http_buf_mem(task, r, 0);
    if (nxt_slow_path(out == NULL)) {
        goto fail;
    }

    out->mem.start = (u_char *) error;
    out->mem.pos = out->mem.start;
    out->mem.free = out->mem.start + nxt_length(error);
    out->mem.end = out->mem.free;

    out->next = nxt_http_buf_last(r);

    nxt_http_request_send(task, r, out);

    return;

fail:

    nxt_http_request_error_handler(task, r, r->proto.any);
}

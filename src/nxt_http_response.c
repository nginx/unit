
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


static nxt_int_t nxt_http_response_status(void *ctx, nxt_http_field_t *field,
    uintptr_t data);
static nxt_int_t nxt_http_response_skip(void *ctx, nxt_http_field_t *field,
    uintptr_t data);
static nxt_int_t nxt_http_response_field(void *ctx, nxt_http_field_t *field,
    uintptr_t offset);


nxt_lvlhsh_t  nxt_response_fields_hash;

static nxt_http_field_proc_t   nxt_response_fields[] = {
    { nxt_string("Status"),         &nxt_http_response_status, 0 },
    { nxt_string("Server"),         &nxt_http_response_skip, 0 },
    { nxt_string("Date"),           &nxt_http_response_field,
        offsetof(nxt_http_request_t, resp.date) },
    { nxt_string("Connection"),     &nxt_http_response_skip, 0 },
    { nxt_string("Content-Type"),   &nxt_http_response_field,
        offsetof(nxt_http_request_t, resp.content_type) },
    { nxt_string("Content-Length"), &nxt_http_response_field,
        offsetof(nxt_http_request_t, resp.content_length) },
    { nxt_string("Upgrade"),        &nxt_http_response_skip, 0 },
    { nxt_string("Sec-WebSocket-Accept"), &nxt_http_response_skip, 0 },
};


nxt_int_t
nxt_http_response_hash_init(nxt_task_t *task)
{
    return nxt_http_fields_hash(&nxt_response_fields_hash,
                    nxt_response_fields, nxt_nitems(nxt_response_fields));
}


nxt_int_t
nxt_http_response_status(void *ctx, nxt_http_field_t *field,
    uintptr_t data)
{
    nxt_int_t           status;
    nxt_http_request_t  *r;

    r = ctx;

    field->skip = 1;

    if (field->value_length >= 3) {
        status = nxt_int_parse(field->value, 3);

        if (status >= 100 && status <= 999) {
            r->status = status;
            return NXT_OK;
        }
    }

    return NXT_ERROR;
}


nxt_int_t
nxt_http_response_skip(void *ctx, nxt_http_field_t *field, uintptr_t data)
{
    field->skip = 1;

    return NXT_OK;
}


nxt_int_t
nxt_http_response_field(void *ctx, nxt_http_field_t *field, uintptr_t offset)
{
    nxt_http_request_t  *r;

    r = ctx;

    nxt_value_at(nxt_http_field_t *, r, offset) = field;

    return NXT_OK;
}

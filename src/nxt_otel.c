
/*
 * Copyright (C) F5, Inc.
 */

#include <math.h>

#include <nxt_router.h>
#include <nxt_http.h>
#include <nxt_otel.h>
#include <nxt_mp.h>
#include <nxt_work_queue.h>
#include <nxt_main.h>
#include <nxt_conf.h>
#include <nxt_types.h>
#include <nxt_string.h>

#define NXT_OTEL_TRACEPARENT_LEN 55
#define NXT_OTEL_BODY_SIZE_TAG "body size"
#define NXT_OTEL_METHOD_TAG "method"
#define NXT_OTEL_PATH_TAG "path"


void
nxt_otel_state_transition(nxt_otel_state_t *state, nxt_otel_status_t status)
{
    if (status == NXT_OTEL_ERROR_STATE || state->status != NXT_OTEL_ERROR_STATE) {
        state->status = status;
    }
}


void
nxt_otel_span_add_headers(nxt_task_t *task, nxt_http_request_t *r)
{
    nxt_http_field_t *f, *cur;
    u_char *traceval, *name_cur, *val_cur;

    nxt_log(task, NXT_LOG_DEBUG, "adding headers to trace");

    if (r->otel == NULL || r->otel->trace == NULL)
    {
        nxt_log(task, NXT_LOG_ERR, "no trace to add events to!");
        nxt_otel_state_transition(r->otel, NXT_OTEL_ERROR_STATE);
        return;
    }

    nxt_list_each(cur, r->fields) {
        // we need this in a continguous and null terminated segment of memory for Rust FFI
        name_cur = nxt_mp_zalloc(r->mem_pool, cur->name_length + 1);
        val_cur = nxt_mp_zalloc(r->mem_pool, cur->value_length + 1);
        if (name_cur != NULL && val_cur != NULL) {
            nxt_cpystrn(name_cur, cur->name, cur->name_length);
            nxt_cpystrn(val_cur, cur->value, cur->value_length);
            nxt_otel_add_event_to_trace(r->otel->trace, name_cur, val_cur);
        }
    } nxt_list_loop;

    // Add method and path to the trace as well
    // 1. method first
    name_cur = nxt_mp_zalloc(r->mem_pool, sizeof(NXT_OTEL_METHOD_TAG) + 1);
    val_cur = nxt_mp_zalloc(r->mem_pool, r->method->length + 1);
    if (name_cur != NULL && val_cur != NULL) {
        nxt_cpystr(name_cur, (const u_char *) NXT_OTEL_METHOD_TAG);
        nxt_cpystrn(val_cur, r->method->start, r->method->length);

        nxt_otel_add_event_to_trace(r->otel->trace, name_cur, val_cur);
    }

    // 2. path second
    name_cur = nxt_mp_zalloc(r->mem_pool, sizeof(NXT_OTEL_PATH_TAG) + 1);
    val_cur = nxt_mp_zalloc(r->mem_pool, r->path->length + 1);
    if (name_cur != NULL && val_cur != NULL) {
        nxt_cpystr(name_cur, (const u_char *) NXT_OTEL_PATH_TAG);
        nxt_cpystrn(val_cur, r->path->start, r->path->length);

        nxt_otel_add_event_to_trace(r->otel->trace, name_cur, val_cur);
    }

    traceval = nxt_mp_zalloc(r->mem_pool, NXT_OTEL_TRACEPARENT_LEN + 1);
    if (traceval == NULL) {
        /* let it go blank here.
         * span still gets populated and sent
         * but data is not propagated to peer or app.
         */
        nxt_log(task, NXT_LOG_ERR,
                "couldnt allocate traceparent header. span will not propagate");
        return;
    }

    // if we didnt inherit a trace id then we need to add the
    // traceparent header to the request
    if (r->otel->trace_id == NULL) {
        nxt_otel_copy_traceparent(traceval, r->otel->trace);
        f = nxt_list_add(r->fields);
        if (f == NULL) {
            goto next;
        }

        nxt_http_field_name_set(f, "traceparent");
        f->value = traceval;
        f->value_length = nxt_strlen(traceval);
        nxt_otel_add_event_to_trace(r->otel->trace, f->name, traceval);
    } else {
        // copy in the pre-existing traceparent for the response
        sprintf((char *) traceval, "%s-%s-%s-%s",
                 (char *) r->otel->version,
                 (char *) r->otel->trace_id,
                 (char *) r->otel->parent_id,
                 (char *) r->otel->trace_flags);
    }

    f = nxt_list_add(r->resp.fields);
    if (f == NULL) {
        nxt_log(task, NXT_LOG_ERR,
                "couldnt allocate traceparent header in response");
        goto next;
    }

    nxt_http_field_name_set(f, "traceparent");
    f->value = traceval;
    f->value_length = nxt_strlen(traceval);

 next:
    nxt_otel_state_transition(r->otel, NXT_OTEL_BODY_STATE);
}


void
nxt_otel_span_add_body(nxt_http_request_t *r)
{
    size_t body_size, size_digits;
    u_char *body_size_buf, *body_tag_buf;

    body_size = (r->body != NULL) ? nxt_buf_used_size(r->body) : 0;
    size_digits = (body_size == 0) ? 1 : log10(body_size) + 1;
    body_size_buf = nxt_mp_zalloc(r->mem_pool, size_digits + 1);
    body_tag_buf = nxt_mp_zalloc(r->mem_pool, strlen(NXT_OTEL_BODY_SIZE_TAG) + 1);
    if (body_size_buf == NULL || body_tag_buf == NULL) {
        return;
    }

    sprintf((char *) body_size_buf, "%lu", body_size);
    nxt_cpystr(body_tag_buf, (const u_char *) NXT_OTEL_BODY_SIZE_TAG);
    nxt_otel_add_event_to_trace(r->otel->trace, body_tag_buf, body_size_buf);
    nxt_otel_state_transition(r->otel, NXT_OTEL_COLLECT_STATE);
}


void
nxt_otel_send_trace_and_span_data(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_request_t *r = obj;

    if (r->otel->trace == NULL) {
        nxt_log(task, NXT_LOG_ERR, "otel error: no trace to send!");
        nxt_otel_state_transition(r->otel, NXT_OTEL_ERROR_STATE);
        return;
    }

    nxt_otel_state_transition(r->otel, NXT_OTEL_UNINIT_STATE);
    nxt_otel_send_trace(r->otel->trace);

    r->otel->trace = NULL;
}


void
nxt_otel_error(nxt_task_t *task, nxt_http_request_t *r)
{
    // purposefully not using state transition helper
    r->otel->status = NXT_OTEL_UNINIT_STATE;
    nxt_log(task, NXT_LOG_ERR, "otel error condition");
    // if r->otel->trace it WILL leak here.
    // TODO Phase 2: drop trace without sending it somehow?
}


void
nxt_otel_trace_and_span_init(nxt_task_t *task, nxt_http_request_t *r)
{
    r->otel->trace =
        nxt_otel_get_or_create_trace(r->otel->trace_id);
    if (r->otel->trace == NULL) {
        nxt_log(task, NXT_LOG_ERR, "error generating otel span");
        nxt_otel_state_transition(r->otel, NXT_OTEL_ERROR_STATE);
        return;
    }

    nxt_otel_state_transition(r->otel, NXT_OTEL_HEADER_STATE);
}


void
nxt_otel_span_collect(nxt_task_t *task, nxt_http_request_t *r)
{
    nxt_log(task, NXT_LOG_DEBUG, "collecting span by adding the task to the fast work queue");
    nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                       nxt_otel_send_trace_and_span_data, task, r, NULL);
    nxt_otel_state_transition(r->otel, NXT_OTEL_UNINIT_STATE);
}


void
nxt_otel_test_and_call_state(nxt_task_t *task, nxt_http_request_t *r)
{
    if (r->otel == NULL) {
        return;
    }

    switch (r->otel->status) {
    case NXT_OTEL_UNINIT_STATE:
      return;
    case NXT_OTEL_INIT_STATE:
        nxt_otel_trace_and_span_init(task, r);
        break;
    case NXT_OTEL_HEADER_STATE:
        nxt_otel_span_add_headers(task, r);
        break;
    case NXT_OTEL_BODY_STATE:
        nxt_otel_span_add_body(r);
        break;
    case NXT_OTEL_COLLECT_STATE:
      nxt_otel_span_collect(task, r);
        break;
    case NXT_OTEL_ERROR_STATE:
        nxt_otel_error(task, r);
        break;
    }
}


nxt_int_t
nxt_otel_parse_traceparent(void *ctx, nxt_http_field_t *field, uintptr_t data)
{
    nxt_http_request_t *r;
    char               *copy;

    /* For information on parsing the traceparent header:
     * https://www.w3.org/TR/trace-context/#traceparent-header
     * A summary of the traceparent header value format follows:
     * Traceparent: "$a-$b-$c-$d"
     *   a. version (2 hex digits) (ff is forbidden)
     *   b. trace_id (32 hex digits) (all zeroes forbidden)
     *   c. parent_id (16 hex digits) (all zeroes forbidden)
     *   d. flags (2 hex digits)
     */

    r = ctx;
    if (field->value_length != NXT_OTEL_TRACEPARENT_LEN) {
        goto error_state;
    }

    /* strsep is destructive so we make a copy of the field
     */
    copy = nxt_mp_zalloc(r->mem_pool, field->value_length + 1);
    if (copy == NULL) {
        goto error_state;
    }
    memcpy(copy, field->value, field->value_length);

    r->otel->version = (u_char *) strsep(&copy, "-");
    r->otel->trace_id = (u_char *) strsep(&copy, "-");
    r->otel->parent_id = (u_char *) strsep(&copy, "-");
    r->otel->trace_flags = (u_char *) strsep(&copy, "-");

    if (r->otel->version     == NULL ||
        r->otel->trace_id    == NULL ||
        r->otel->parent_id   == NULL ||
        r->otel->trace_flags == NULL)
    {
        goto error_state;
    }

    return NXT_OK;

 error_state:
    nxt_otel_state_transition(r->otel, NXT_OTEL_ERROR_STATE);
    return NXT_ERROR;
}


nxt_int_t
nxt_otel_parse_tracestate(void *ctx, nxt_http_field_t *field, uintptr_t data)
{
    nxt_http_request_t *r;
    nxt_str_t     s;
    nxt_http_field_t *f;

    s.length = field->value_length;
    s.start = field->value;
    r = ctx;
    r->otel->trace_state = s;

    // maybe someday this should get sent down into the otel lib

    f = nxt_list_add(r->resp.fields);
    if (f != NULL) {
      *f = *field;
    }

    return NXT_OK;
}

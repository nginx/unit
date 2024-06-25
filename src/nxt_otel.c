
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

#define NXT_OTEL_TRACEPARENT_LEN 55
#define NXT_OTEL_BODY_SIZE_TAG "body size"

static inline void nxt_otel_trace_and_span_init(nxt_task_t *, nxt_http_request_t *);
static inline void nxt_otel_span_collect(nxt_task_t *, nxt_http_request_t *);
static void nxt_otel_span_add_headers(nxt_task_t *, nxt_http_request_t *);
static void nxt_otel_span_add_body(nxt_http_request_t *);
static void nxt_otel_error(nxt_task_t *, nxt_http_request_t *);

inline void
nxt_otel_test_and_call_state(nxt_task_t *t, nxt_http_request_t *r)
{
    // catches null state and unset flow status
    if (!r->otel || !r->otel->status) {
        return;
    }

    switch (r->otel->status) {
    case NXT_OTEL_INIT_STATE:
        nxt_otel_trace_and_span_init(t, r);
        break;
    case NXT_OTEL_HEADER_STATE:
        nxt_otel_span_add_headers(t, r);
        break;
    case NXT_OTEL_BODY_STATE:
        nxt_otel_span_add_body(r);
        break;
    case NXT_OTEL_COLLECT_STATE:
        nxt_otel_span_collect(t, r);
        break;
    case NXT_OTEL_ERROR_STATE:
        nxt_otel_error(t, r);
        break;
    }
}

static inline void
nxt_otel_state_transition(nxt_otel_state_t *state, nxt_otel_status_t status)
{
    if (status == NXT_OTEL_ERROR_STATE || state->status != NXT_OTEL_ERROR_STATE) {
        state->status = status;
    }
}

static inline void
nxt_otel_trace_and_span_init(nxt_task_t *t, nxt_http_request_t *r)
{
    r->otel->trace =
        nxt_otel_get_or_create_trace(r->otel->trace_id);
    if (!r->otel->trace)
    {
        nxt_log(t, NXT_LOG_ERR, "error generating otel span");
        nxt_otel_state_transition(r->otel, NXT_OTEL_ERROR_STATE);
        return;
    }

    nxt_otel_state_transition(r->otel, NXT_OTEL_HEADER_STATE);
}

static void
nxt_otel_span_add_headers(nxt_task_t *t, nxt_http_request_t *r)
{
    nxt_http_field_t *f, *cur;
    u_char *traceval, *name_cur, *val_cur;

    nxt_log(t, NXT_LOG_DEBUG, "adding headers to trace");

    if (!r->otel || !r->otel->trace)
    {
        nxt_log(t, NXT_LOG_ERR, "no trace to add events to!");
        nxt_otel_state_transition(r->otel, NXT_OTEL_ERROR_STATE);
        return;
    }

    nxt_list_each(cur, r->fields) {
        // we need this in a continguous and null terminated segment of memory for Rust FFI
        name_cur = nxt_mp_zalloc(r->mem_pool, cur->name_length + 1);
        val_cur = nxt_mp_zalloc(r->mem_pool, cur->value_length + 1);
        if (name_cur && val_cur) {
            strncpy((char *) name_cur, (char *) cur->name, cur->name_length);
            strncpy((char *) val_cur, (char *) cur->value, cur->value_length);
            nxt_otel_add_event_to_trace(r->otel->trace, name_cur, val_cur);
        }
    } nxt_list_loop;

    traceval = nxt_mp_zalloc(r->mem_pool, NXT_OTEL_TRACEPARENT_LEN + 1);
    if (!traceval) {
        /* let it go blank here.
         * span still gets populated and sent
         * but data is not propagated to peer or app.
         */
        nxt_log(t, NXT_LOG_ERR,
                "couldnt allocate traceparent header. span will not propagate");
        return;
    }

    // if we didnt inherit a trace id then we need to add the
    // traceparent header to the request
    if (!r->otel->trace_id) {
        nxt_otel_copy_traceparent(traceval, r->otel->trace);
        f = nxt_list_add(r->fields);
        if (f) {
            nxt_http_field_name_set(f, "traceparent");
            f->value = traceval;
            f->value_length = nxt_strlen(traceval);
            nxt_otel_add_event_to_trace(r->otel->trace, f->name, traceval);
        } else {
            nxt_log(t, NXT_LOG_ERR,
                    "couldnt allocate traceparent header in request");
        }
    } else {
        // copy in the pre-existing traceparent for the response
        snprintf((char *) traceval, NXT_OTEL_TRACEPARENT_LEN + 1, "%s-%s-%s-%s",
                 (char *) r->otel->version,
                 (char *) r->otel->trace_id,
                 (char *) r->otel->parent_id,
                 (char *) r->otel->trace_flags);
    }

    f = NULL;
    f = nxt_list_add(r->resp.fields);
    if (f) {
        nxt_http_field_name_set(f, "traceparent");
        f->value = traceval;
        f->value_length = nxt_strlen(traceval);
    } else {
        nxt_log(t, NXT_LOG_ERR,
                "couldnt allocate traceparent header in response");
    }

    nxt_otel_state_transition(r->otel, NXT_OTEL_BODY_STATE);
}

static void
nxt_otel_span_add_body(nxt_http_request_t *r)
{
    size_t body_size, size_digits;
    u_char *body_size_buf, *body_tag_buf;

    body_size = (r->body) ? nxt_buf_used_size(r->body) : 0;
    size_digits = (!body_size) ? 1 : log10(body_size) + 1;
    body_size_buf = nxt_mp_zalloc(r->mem_pool, size_digits + 1);
    body_tag_buf = nxt_mp_zalloc(r->mem_pool, sizeof(NXT_OTEL_BODY_SIZE_TAG) + 1);
    if (!body_size_buf || !body_tag_buf) {
        return;
    }

    sprintf((char *) body_tag_buf, NXT_OTEL_BODY_SIZE_TAG);
    sprintf((char *) body_size_buf, "%lu", body_size);
    nxt_otel_add_event_to_trace(r->otel->trace, body_tag_buf, body_size_buf);
    nxt_otel_state_transition(r->otel, NXT_OTEL_COLLECT_STATE);
}

static void
nxt_otel_send_trace_and_span_data(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_request_t *r;
    r = obj;


    if (!r->otel->trace) {
        nxt_log(task, NXT_LOG_ERR, "otel error: no trace to send!");
        nxt_otel_state_transition(r->otel, NXT_OTEL_ERROR_STATE);
        return;
    }

    nxt_otel_state_transition(r->otel, 0);
    nxt_otel_send_trace(r->otel->trace);
    r->otel->trace = NULL;
}

static inline void
nxt_otel_span_collect(nxt_task_t *t, nxt_http_request_t *r)
{
    nxt_log(t, NXT_LOG_DEBUG, "collecting span by adding the task to the fast work queue");
    nxt_work_queue_add(&t->thread->engine->fast_work_queue,
                       nxt_otel_send_trace_and_span_data, t, r, NULL);
    nxt_otel_state_transition(r->otel, 0);
}

static void
nxt_otel_error(nxt_task_t *t, nxt_http_request_t *r)
{
    // purposefully not using state transition helper
    r->otel->status = 0;
    nxt_log(t, NXT_LOG_ERR, "otel error condition");
    // if r->otel->trace it WILL leak here.
    // TODO Phase 2: drop trace without sending it somehow?
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
    copy = nxt_mp_zalloc(r->mem_pool, field->value_length+1);
    if (copy == NULL) {
        goto error_state;
    }
    memcpy(copy, field->value, field->value_length);

    r->otel->version = (u_char *) strsep(&copy, "-");
    r->otel->trace_id = (u_char *) strsep(&copy, "-");
    r->otel->parent_id = (u_char *) strsep(&copy, "-");
    r->otel->trace_flags = (u_char *) strsep(&copy, "-");

    if (!r->otel->version ||
        !r->otel->trace_id ||
        !r->otel->parent_id ||
        !r->otel->trace_flags) {
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
    if (f) {
      *f = *field;
    }

    return NXT_OK;
}

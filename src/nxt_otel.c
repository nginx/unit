
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
#include <nxt_clang.h>


#define NXT_OTEL_TRACEPARENT_LEN 55
#define NXT_OTEL_BODY_SIZE_TAG "body size"
#define NXT_OTEL_METHOD_TAG "method"
#define NXT_OTEL_PATH_TAG "path"
#define NXT_OTEL_STATUS_CODE_TAG "status"


void
nxt_otel_state_transition(nxt_otel_state_t *state, nxt_otel_status_t status)
{
    if (status == NXT_OTEL_ERROR_STATE || state->status != NXT_OTEL_ERROR_STATE) {
        state->status = status;
    }
}


void
nxt_otel_propagate_header(nxt_task_t *task, nxt_http_request_t *r)
{
    u_char      *traceval;
    nxt_str_t   traceparent_name, traceparent;
    nxt_http_field_t *f;

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

    if (r->otel->trace_id != NULL) {
        // copy in the pre-existing traceparent for the response
        sprintf((char *) traceval, "%s-%s-%s-%s",
                 (char *) r->otel->version,
                 (char *) r->otel->trace_id,
                 (char *) r->otel->parent_id,
                 (char *) r->otel->trace_flags);

    // if we didnt inherit a trace id then we need to add the
    // traceparent header to the request
    } else if (r->otel->trace_id == NULL) {
        nxt_otel_rs_copy_traceparent(traceval, r->otel->trace);
        f = nxt_list_add(r->fields);
        if (f == NULL) {
            return;
        }

        nxt_http_field_name_set(f, "traceparent");
        f->value = traceval;
        f->value_length = nxt_strlen(traceval);
        traceparent_name = (nxt_str_t){
            .start  = f->name,
            .length = f->name_length,
        };
        traceparent = (nxt_str_t){
            .start  = f->value,
            .length = f->value_length,
        };
        nxt_otel_rs_add_event_to_trace(r->otel->trace,
                                       &traceparent_name,
                                       &traceparent);

    // potentially nxt_http_request_error called before headers finished parsing
    } else {
        nxt_log(task, NXT_LOG_DEBUG,
                "not propagating tracing headers for missing trace");
        return;
    }

    f = nxt_list_add(r->resp.fields);
    if (f == NULL) {
        nxt_log(task, NXT_LOG_ERR,
                "couldnt allocate traceparent header in response");
        return;
    }

    nxt_http_field_name_set(f, "traceparent");
    f->value = traceval;
    f->value_length = nxt_strlen(traceval);
}


void
nxt_otel_span_add_headers(nxt_task_t *task, nxt_http_request_t *r)
{
    nxt_str_t        method_name, path_name;
    nxt_http_field_t *cur;

    nxt_log(task, NXT_LOG_DEBUG, "adding headers to trace");

    if (r->otel == NULL || r->otel->trace == NULL)
    {
        nxt_log(task, NXT_LOG_ERR, "no trace to add events to!");
        nxt_otel_state_transition(r->otel, NXT_OTEL_ERROR_STATE);
        return;
    }

    nxt_list_each(cur, r->fields) {
        nxt_str_t name, val;
        name = (nxt_str_t){
            .start  = cur->name,
            .length = cur->name_length,
        };

        val = (nxt_str_t){
            .start  = cur->value,
            .length = cur->value_length,
        };

        nxt_otel_rs_add_event_to_trace(r->otel->trace, &name, &val);
    } nxt_list_loop;

    method_name = (nxt_str_t){
        .start  = (u_char *) NXT_OTEL_METHOD_TAG,
        .length = nxt_length(NXT_OTEL_METHOD_TAG) + 1,
    };
    nxt_otel_rs_add_event_to_trace(r->otel->trace, &method_name, r->method);

    path_name = (nxt_str_t){
        .start  = (u_char *) NXT_OTEL_PATH_TAG,
        .length = nxt_length(NXT_OTEL_PATH_TAG) + 1,
    };
    nxt_otel_rs_add_event_to_trace(r->otel->trace, &path_name, r->path);
    nxt_otel_propagate_header(task, r);

    nxt_otel_state_transition(r->otel, NXT_OTEL_BODY_STATE);
}


void
nxt_otel_span_add_body(nxt_http_request_t *r)
{
    size_t    body_size, buf_size;
    u_char    *body_buf, *body_size_buf;
    nxt_str_t body_key, body_val;
    nxt_int_t cur;

    if (r->body != NULL) {
        body_size = nxt_buf_used_size(r->body);
    } else {
        body_size = 0;
    }

    buf_size = 1; // first digit
    if (body_size != 0) {
        buf_size += log10(body_size); // subsequent digits
    }
    buf_size += 1; // \0
    buf_size += nxt_length(NXT_OTEL_BODY_SIZE_TAG);
    buf_size += 1; // \0

    body_buf = nxt_mp_zalloc(r->mem_pool, buf_size);
    if (body_buf == NULL) {
        return;
    }

    cur = sprintf((char *) body_buf, "%lu", body_size);
    if (cur < 0) {
        return;
    }

    // (already was zero-alloc'ed)
    //body_buf[cur] = '\0';
    cur += 1;
    body_size_buf = body_buf + cur;

    nxt_cpystr(body_buf + cur, (const u_char *) NXT_OTEL_BODY_SIZE_TAG);
    // (already was zero-alloc'ed)
    //body_buf[cur] = '\0';

    body_key = (nxt_str_t){
        .start  = body_size_buf,
        .length = nxt_length(body_size_buf),
    };
    body_val = (nxt_str_t){
        .start  = body_buf,
        .length = nxt_length(body_buf),
    };

    nxt_otel_rs_add_event_to_trace(r->otel->trace, &body_key, &body_val);
    nxt_otel_state_transition(r->otel, NXT_OTEL_COLLECT_STATE);
}


void
nxt_otel_span_add_status(nxt_task_t *task, nxt_http_request_t *r) {
    u_char    *status_buf;
    nxt_str_t status_key, status_val;

    // dont bother logging an unset status
    if (r->status == 0) {
        return;
    }

    // add specific 3 character status to span
    status_buf = nxt_mp_zalloc(r->mem_pool, 4);
    if (status_buf == NULL) {
        return;
    }

    sprintf((char *) status_buf, "%i", r->status);

    // set up event
    status_key = (nxt_str_t){
        .start  = (u_char *) NXT_OTEL_STATUS_CODE_TAG,
        .length = nxt_length(NXT_OTEL_STATUS_CODE_TAG),
    };
    status_val = (nxt_str_t){
        .start  = status_buf,
        .length = 4,
    };
    nxt_otel_rs_add_event_to_trace(r->otel->trace, &status_key, &status_val);
}


void
nxt_otel_span_collect(nxt_task_t *task, nxt_http_request_t *r)
{
    if (r->otel->trace == NULL) {
        nxt_log(task, NXT_LOG_ERR, "otel error: no trace to send!");
        nxt_otel_state_transition(r->otel, NXT_OTEL_ERROR_STATE);
        return;
    }

    nxt_otel_span_add_status(task, r);
    nxt_otel_state_transition(r->otel, NXT_OTEL_UNINIT_STATE);
    nxt_otel_rs_send_trace(r->otel->trace);

    r->otel->trace = NULL;
}


void
nxt_otel_error(nxt_task_t *task, nxt_http_request_t *r)
{
    // purposefully not using state transition helper
    r->otel->status = NXT_OTEL_UNINIT_STATE;
    nxt_log(task, NXT_LOG_ERR, "otel error condition");

    /* assumable at time of writing that there is no
     * r->otel->trace to leak. This state is only set
     * in cases where trace fails to generate or is missing
     */
}


void
nxt_otel_trace_and_span_init(nxt_task_t *task, nxt_http_request_t *r)
{
    r->otel->trace =
        nxt_otel_rs_get_or_create_trace(r->otel->trace_id);
    if (r->otel->trace == NULL) {
        nxt_log(task, NXT_LOG_ERR, "error generating otel span");
        nxt_otel_state_transition(r->otel, NXT_OTEL_ERROR_STATE);
        return;
    }

    nxt_otel_state_transition(r->otel, NXT_OTEL_HEADER_STATE);
}


void
nxt_otel_test_and_call_state(nxt_task_t *task, nxt_http_request_t *r)
{
    if (r == NULL || r->otel == NULL) {
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


// called in nxt_http_request_error
void
nxt_otel_request_error_path(nxt_task_t *task, nxt_http_request_t *r) {
  if (r->otel->trace == NULL) {
        return;
    }

    // response headers have been cleared
    nxt_otel_propagate_header(task, r);

    // collect span immediately
    if (r->otel) {
        nxt_otel_state_transition(r->otel, NXT_OTEL_COLLECT_STATE);
    }
    nxt_otel_test_and_call_state(task, r);
}


nxt_int_t
nxt_otel_parse_traceparent(void *ctx, nxt_http_field_t *field, uintptr_t data)
{
    char               *copy;
    nxt_http_request_t *r;

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
    nxt_str_t     s;
    nxt_http_field_t *f;
    nxt_http_request_t *r;

    s.length = field->value_length;
    s.start = field->value;
    r = ctx;
    r->otel->trace_state = s;

    // maybe someday this should get sent down into the otel lib
    // when we can figure out what to do with it at least

    f = nxt_list_add(r->resp.fields);
    if (f != NULL) {
      *f = *field;
    }

    return NXT_OK;
}

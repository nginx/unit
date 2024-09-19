/*
 * Copyright (C) F5, Inc.
 */

#ifndef _NXT_OTEL_H_INCLUDED_
#define _NXT_OTEL_H_INCLUDED_

#include <nxt_router.h>

// forward declared
struct nxt_http_field_t;
struct nxt_conf_validation_t;
struct nxt_conf_value_t;
struct nxt_http_request_t;

extern void     nxt_otel_send_trace(void *);
extern void   * nxt_otel_get_or_create_trace(u_char *);
extern void     nxt_otel_init(void (*)(u_char*), const char *, const char *, double);
extern void     nxt_otel_copy_traceparent(u_char *, void *);
extern void     nxt_otel_add_event_to_trace(void *, u_char *, u_char *);
extern uint8_t  nxt_otel_is_init(void);
extern void     nxt_otel_uninit(void);


/* nxt_otel_status_t
 * more efficient than a single handler state struct
 */
typedef enum {
    NXT_OTEL_UNINIT_STATE = 0,
    NXT_OTEL_INIT_STATE,
    NXT_OTEL_HEADER_STATE,
    NXT_OTEL_BODY_STATE,
    NXT_OTEL_COLLECT_STATE,
    NXT_OTEL_ERROR_STATE,
} nxt_otel_status_t;

/* nxt_otel_state_t
 * cache of trace data needed per request and
 * includes indicator as to current flow state
 */
typedef struct {
    u_char            *trace_id;
    u_char            *version;
    u_char            *parent_id;
    u_char            *trace_flags;
    void              *trace;
    nxt_otel_status_t status;
    nxt_str_t         trace_state;
} nxt_otel_state_t;


nxt_int_t nxt_otel_parse_traceparent(void *ctx, nxt_http_field_t *field, uintptr_t data);
nxt_int_t nxt_otel_parse_tracestate(void *ctx, nxt_http_field_t *field, uintptr_t data);
void nxt_otel_span_add_headers(nxt_task_t *task, nxt_http_request_t *r);
void nxt_otel_span_add_body(nxt_http_request_t *r);
void nxt_otel_send_trace_and_span_data(nxt_task_t *task, void *obj, void *data);
void nxt_otel_error(nxt_task_t *task, nxt_http_request_t *r);
void nxt_otel_state_transition(nxt_otel_state_t *state, nxt_otel_status_t status);
void nxt_otel_test_and_call_state(nxt_task_t *task, nxt_http_request_t *r);
void nxt_otel_trace_and_span_init(nxt_task_t *task, nxt_http_request_t *r);
void nxt_otel_span_collect(nxt_task_t *task, nxt_http_request_t *r);


#endif // _NXT_OTEL_H_INCLUDED_

/*
 * Copyright (C) F5, Inc.
 */

#ifndef _NXT_OTEL_H_INCLUDED_
#define _NXT_OTEL_H_INCLUDED_

#if (NXT_HAVE_OTEL)

#include <nxt_router.h>

// forward declared
struct nxt_http_field_t;
struct nxt_conf_validation_t;
struct nxt_conf_value_t;

extern void     nxt_otel_send_trace(void *);
extern void   * nxt_otel_get_or_create_trace(u_char *);
extern void     nxt_otel_init(void (*)(u_char*), const char *, const char *, double);
extern void     nxt_otel_copy_traceparent(u_char *, void *);
extern void     nxt_otel_add_event_to_trace(void *, u_char *, u_char *);
extern uint8_t  nxt_otel_is_init();
extern void     nxt_otel_uninit();

void nxt_otel_test_and_call_state(nxt_task_t *, nxt_http_request_t *);
nxt_int_t nxt_otel_parse_traceparent(void *, nxt_http_field_t *, uintptr_t);
nxt_int_t nxt_otel_parse_tracestate(void *, nxt_http_field_t *, uintptr_t);
nxt_int_t nxt_otel_validate_endpoint(nxt_conf_validation_t *, nxt_conf_value_t *, void *);
nxt_int_t nxt_otel_validate_batch_size(nxt_conf_validation_t *, nxt_conf_value_t *, void *);
nxt_int_t nxt_otel_validate_protocol(nxt_conf_validation_t *, nxt_conf_value_t *, void *);

/* nxt_otel_status_t
 * more efficient than a single handler state struct
 */
typedef enum {
    // 0 = uninitialized and/or unset status
    NXT_OTEL_INIT_STATE = 1,
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
    u_char            *trace_id, *version, *parent_id, *trace_flags;
    void              *trace;
    nxt_otel_status_t status;
    nxt_str_t         trace_state;
} nxt_otel_state_t;

#endif // NXT_HAVE_OTEL

#endif // _NXT_OTEL_H_INCLUDED_

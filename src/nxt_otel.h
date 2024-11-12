/*
 * Copyright (C) F5, Inc.
 */

#ifndef _NXT_OTEL_H_INCLUDED_
#define _NXT_OTEL_H_INCLUDED_

#include <nxt_router.h>
#include <nxt_string.h>


#if (NXT_HAVE_OTEL)
#define NXT_OTEL_TRACE()  nxt_otel_test_and_call_state(task, r)
#else
#define NXT_OTEL_TRACE()
#endif


#if (NXT_HAVE_OTEL)
extern void nxt_otel_rs_send_trace(void *trace);
extern void * nxt_otel_rs_get_or_create_trace(u_char *trace_id);
extern void nxt_otel_rs_init(
    void (*log_callback)(nxt_uint_t log_level, const char *log_string),
    const nxt_str_t *endpoint, const nxt_str_t *protocol,
    double sample_fraction, double batch_size);
extern void nxt_otel_rs_copy_traceparent(u_char *buffer, void *span);
extern void nxt_otel_rs_add_event_to_trace(void *trace, nxt_str_t *key,
    nxt_str_t *val);
extern uint8_t nxt_otel_rs_is_init(void);
extern void nxt_otel_rs_uninit(void);
#endif


typedef enum nxt_otel_status_e   nxt_otel_status_t;
typedef struct nxt_otel_state_s  nxt_otel_state_t;


/*
 * nxt_otel_status_t
 * more efficient than a single handler state struct
 */
enum nxt_otel_status_e {
    NXT_OTEL_UNINIT_STATE = 0,
    NXT_OTEL_INIT_STATE,
    NXT_OTEL_HEADER_STATE,
    NXT_OTEL_BODY_STATE,
    NXT_OTEL_COLLECT_STATE,
    NXT_OTEL_ERROR_STATE,
};


/*
 * nxt_otel_state_t
 * cache of trace data needed per request and
 * includes indicator as to current flow state
 */
struct nxt_otel_state_s {
    u_char             *trace_id;
    u_char             *version;
    u_char             *parent_id;
    u_char             *trace_flags;
    void               *trace;
    nxt_otel_status_t  status;
    nxt_str_t          trace_state;
};


nxt_int_t nxt_otel_parse_traceparent(void *ctx, nxt_http_field_t *field,
    uintptr_t data);
nxt_int_t nxt_otel_parse_tracestate(void *ctx, nxt_http_field_t *field,
    uintptr_t data);
void nxt_otel_log_callback(nxt_uint_t log_level, const char *arg);


void nxt_otel_test_and_call_state(nxt_task_t *task, nxt_http_request_t *r);
void nxt_otel_request_error_path(nxt_task_t *task, nxt_http_request_t *r);


#endif /* _NXT_OTEL_H_INCLUDED_ */

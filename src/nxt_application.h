
/*
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_APPLICATION_H_INCLUDED_
#define _NXT_APPLICATION_H_INCLUDED_


typedef struct {
    nxt_str_t                  name;
    nxt_str_t                  value;
} nxt_app_header_field_t;


typedef struct {
    nxt_str_t                  method;
    nxt_str_t                  path;
    nxt_str_t                  version;
    nxt_uint_t                 fields_num;
    nxt_app_header_field_t     *fields;

    nxt_str_t                  *content_length;
    nxt_str_t                  *content_type;
} nxt_app_request_header_t;


typedef struct {
    nxt_event_engine_t         *engine;
    nxt_mem_pool_t             *mem_pool;
    nxt_event_conn_t           *event_conn;
    nxt_log_t                  *log;

    nxt_buf_t                  *output_buf;

    nxt_app_request_header_t   header;
    nxt_str_t                  body_preread;
    off_t                      body_rest;
    void                       *ctx;
} nxt_app_request_t;


typedef struct {
    nxt_int_t                  (*init)(nxt_thread_t *thr);
    nxt_int_t                  (*start)(nxt_app_request_t *r);
    nxt_int_t                  (*header)(nxt_app_request_t *r,
                                    nxt_app_header_field_t *field);
    nxt_int_t                  (*run)(nxt_app_request_t *r);
} nxt_application_module_t;


extern nxt_application_module_t  nxt_python_module;


nxt_int_t nxt_app_http_read_body(nxt_app_request_t *r, u_char *data,
    size_t len);
nxt_int_t nxt_app_write(nxt_app_request_t *r, const u_char *data, size_t len);


#endif /* _NXT_APPLICATION_H_INCLIDED_ */

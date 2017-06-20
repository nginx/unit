
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_HTTP_SOURCE_H_INCLUDED_
#define _NXT_HTTP_SOURCE_H_INCLUDED_


typedef struct {
    nxt_str_t                          copy;
    uintptr_t                          data[3];
} nxt_http_source_request_t;


typedef struct nxt_http_source_s  nxt_http_source_t;
typedef nxt_int_t (*nxt_http_source_request_create_t)(nxt_http_source_t *hs);


struct nxt_http_source_s {
    nxt_source_hook_t                  query;
    nxt_source_hook_t                  *next;

    nxt_upstream_source_t              *upstream;

    nxt_http_source_request_create_t   request_create;

    nxt_upstream_header_in_t           header_in;

    nxt_buf_t                          *rest;

    uint32_t                           chunked;  /* 1 bit */

    union {
        nxt_http_source_request_t      request;
    } u;
};


NXT_EXPORT void nxt_http_source_handler(nxt_task_t *task,
    nxt_upstream_source_t *us, nxt_http_source_request_create_t request_create);
NXT_EXPORT nxt_int_t nxt_http_source_hash_create(nxt_mp_t *mp,
    nxt_lvlhsh_t *lh);


#endif /* _NXT_HTTP_SOURCE_H_INCLUDED_ */

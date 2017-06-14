
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_STREAM_SOURCE_H_INCLUDED_
#define _NXT_STREAM_SOURCE_H_INCLUDED_


typedef struct nxt_stream_source_s  nxt_stream_source_t;

typedef void (*nxt_stream_source_handler_t)(nxt_task_t *task,
    nxt_stream_source_t *s);

struct nxt_stream_source_s {
    nxt_conn_t                   *conn;
    nxt_source_hook_t            *next;
    nxt_upstream_source_t        *upstream;

    nxt_buf_t                    *out;

    uint32_t                     read_queued;  /* 1 bit */

    nxt_stream_source_handler_t  error_handler;
};


void nxt_stream_source_connect(nxt_task_t *task, nxt_stream_source_t *stream);


#endif /* _NXT_STREAM_SOURCE_H_INCLUDED_ */

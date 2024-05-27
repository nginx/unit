
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_RECVBUF_H_INCLUDED_
#define _NXT_RECVBUF_H_INCLUDED_


typedef struct {
    nxt_buf_t    *buf;
    nxt_iobuf_t  *iobuf;

    int32_t      nmax;
    size_t       size;
} nxt_recvbuf_coalesce_t;


nxt_uint_t nxt_recvbuf_mem_coalesce(nxt_recvbuf_coalesce_t *rb);
void nxt_recvbuf_update(nxt_buf_t *b, size_t sent);


#endif /* _NXT_RECVBUF_H_INCLUDED_ */

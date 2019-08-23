
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */


#ifndef _NXT_SHA1_H_INCLUDED_
#define _NXT_SHA1_H_INCLUDED_


typedef struct {
    uint64_t  bytes;
    uint32_t  a, b, c, d, e;
    u_char    buffer[64];
} nxt_sha1_t;


NXT_EXPORT void nxt_sha1_init(nxt_sha1_t *ctx);
NXT_EXPORT void nxt_sha1_update(nxt_sha1_t *ctx, const void *data, size_t size);
NXT_EXPORT void nxt_sha1_final(u_char result[20], nxt_sha1_t *ctx);


#endif /* _NXT_SHA1_H_INCLUDED_ */

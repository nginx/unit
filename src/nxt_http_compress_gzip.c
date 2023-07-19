/*
 * Copyright (C) Alejandro Colomar
 * Copyright (C) NGINX, Inc.
 */


#include "nxt_http_compress_gzip.h"

#include <stddef.h>

#include <zlib.h>

#include <nxt_unit_cdefs.h>

#include "nxt_buf.h"
#include "nxt_clang.h"
#include "nxt_errno.h"
#include "nxt_http.h"
#include "nxt_http_compress.h"
#include "nxt_http_filter.h"
#include "nxt_main.h"
#include "nxt_mp.h"
#include "nxt_router.h"
#include "nxt_string.h"
#include "nxt_types.h"


typedef struct nxt_http_compress_gzip_ctx_s  nxt_http_compress_gzip_ctx_t;


struct nxt_http_compress_gzip_ctx_s {
    nxt_http_request_t  *r;
    nxt_buf_t           *b;

    z_stream            z;
};


static nxt_http_compress_gzip_ctx_t *nxt_http_compress_gzip_ctx(
    nxt_task_t *task, nxt_http_request_t *r, nxt_http_compress_conf_t *conf);

static void nxt_http_compress_gzip_filter(nxt_task_t *task, void *obj,
    void *data);


nxt_int_t
nxt_http_compress_gzip(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_compress_conf_t *conf)
{
    nxt_int_t                     ret;
    nxt_http_compress_gzip_ctx_t  *ctx;

    static nxt_str_t  ce = nxt_string("Content-Encoding");
    static nxt_str_t  gzip = nxt_string("gzip");

    if (r->body_handler == NULL
        || r->resp.content_length_n == 0
        || (r->resp.content_length != NULL
            && r->resp.content_length->value_length == 1
            && r->resp.content_length->value[0] == '0'))
    {
        return NXT_OK;
    }

    r->resp.content_length = NULL;
    r->resp.content_length_n = -1;

    ret = nxt_http_compress_append_field(task, r, &ce, &gzip);
    if (nxt_slow_path(ret == NXT_ERROR)) {
        return NXT_ERROR;
    }

    ctx = nxt_http_compress_gzip_ctx(task, r, conf);
    if (nxt_slow_path(ctx == NULL)) {
        return NXT_ERROR;
    }

    ret = nxt_http_filter_handler_add(r, nxt_http_compress_gzip_filter, ctx);
    if (nxt_slow_path(ret == NXT_ERROR)) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_http_compress_gzip_ctx_t *
nxt_http_compress_gzip_ctx(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_compress_conf_t *conf)
{
    int                           ret;
    z_stream                      *z;
    nxt_http_compress_gzip_ctx_t  *ctx;

    ctx = nxt_mp_zget(r->mem_pool, sizeof(nxt_http_compress_gzip_ctx_t));
    if (nxt_slow_path(ctx == NULL)) {
        return NULL;
    }

    ctx->r = r;

    z = &ctx->z;
    z->zalloc = NULL;
    z->zfree = NULL;
    z->opaque = NULL;
    ret = deflateInit2(z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS + 16,
                       MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
    if (nxt_slow_path(ret != 0)) {
        return NULL;
    }

    return ctx;
}


static void
nxt_http_compress_gzip_filter(nxt_task_t *task, void *obj, void *data)
{
    int                           ret;
    ssize_t                       size;
    z_stream                      *z;
    nxt_buf_t                     **b, *tmp;
    nxt_bool_t                    is_last;
    nxt_http_request_t            *r;
    nxt_http_compress_gzip_ctx_t  *ctx;

    b = obj;
    ctx = data;
    z = &ctx->z;

    r = ctx->r;

    is_last = ((*b)->next != NULL
               && (*b)->next->completion_handler != (*b)->completion_handler);

    z->next_in = (*b)->mem.pos;
    z->avail_in = (*b)->mem.free - (*b)->mem.pos;

    size = deflateBound(z, z->avail_in);

    tmp = nxt_buf_mem_alloc(r->mem_pool, size, 0);
    if (nxt_slow_path(tmp == NULL)) {
        return;
    }

    nxt_memcpy(tmp, *b, offsetof(nxt_buf_t, mem));
    tmp->data = r->mem_pool;

    z->next_out = tmp->mem.start;
    z->avail_out = tmp->mem.end - tmp->mem.start;

    ret = deflate(z, is_last ? Z_FINISH : Z_SYNC_FLUSH);
    if (nxt_slow_path(ret == Z_STREAM_ERROR || ret == Z_BUF_ERROR)) {
        goto fail;
    }

    tmp->mem.free = tmp->mem.end - z->avail_out;
    size = tmp->mem.free - tmp->mem.start;

    if ((*b)->mem.end - (*b)->mem.pos >= size) {
        (*b)->mem.free = nxt_cpymem((*b)->mem.pos, tmp->mem.start, size);

    } else {
        nxt_swap(b, &tmp);
    }

fail:

    nxt_mp_free(tmp->data, tmp);

    if (is_last) {
        ret = deflateEnd(z);
        if (ret != Z_OK) {
            return;
        }
    }

    return;
}

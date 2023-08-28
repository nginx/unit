/*
 * Copyright (C) Alejandro Colomar
 * Copyright (C) NGINX, Inc.
 */


#include "nxt_http_compress_gzip.h"

#include <stddef.h>
#include <stdint.h>

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

#if (NXT_WITH_ZLIB || __has_include(<zlib.h>))
#include <zlib.h>
#endif


typedef struct nxt_http_compress_gzip_ctx_s  nxt_http_compress_gzip_ctx_t;


struct nxt_http_compress_gzip_ctx_s {
    nxt_http_request_t  *r;
    nxt_buf_t           *b;

    int8_t              level;

#if (NXT_WITH_ZLIB)
    z_stream            z;
#endif
};


static nxt_http_compress_gzip_ctx_t *nxt_http_compress_gzip_ctx(
    nxt_task_t *task, nxt_http_request_t *r, nxt_http_compress_conf_t *conf);

static void nxt_http_compress_gzip_filter(nxt_task_t *task, void *obj,
    void *data);


nxt_int_t
nxt_http_compress_gzip(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_compress_conf_t *conf)
{
    size_t                        clen;
    nxt_int_t                     ret;
    nxt_http_compress_gzip_ctx_t  *ctx;

    static nxt_str_t  ce = nxt_string("Content-Encoding");
    static nxt_str_t  gzip = nxt_string("gzip");

    clen = nxt_http_compress_resp_content_length(&r->resp);
    if (clen < nxt_max(1u, conf->min_len) || r->body_handler == NULL) {
        return NXT_OK;
    }

    ret = nxt_http_compressible_mtype(task, r, conf->mtrule);
    switch (ret) {
    case NXT_ERROR:
        return NXT_ERROR;
    case 0:
        return NXT_OK;
    case 1:
        break;
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
#if (!NXT_WITH_ZLIB)
    return NULL;
#else
    int                           ret;
    z_stream                      *z;
    nxt_http_compress_gzip_ctx_t  *ctx;

    ctx = nxt_mp_zget(r->mem_pool, sizeof(nxt_http_compress_gzip_ctx_t));
    if (nxt_slow_path(ctx == NULL)) {
        return NULL;
    }

    ctx->level = conf->level;
    ctx->r = r;

    z = &ctx->z;
    z->zalloc = NULL;
    z->zfree = NULL;
    z->opaque = NULL;
    ret = deflateInit2(z, ctx->level, Z_DEFLATED, MAX_WBITS + 16, MAX_MEM_LEVEL,
                       Z_DEFAULT_STRATEGY);
    if (nxt_slow_path(ret != 0)) {
        return NULL;
    }

    return ctx;
#endif
}


static void
nxt_http_compress_gzip_filter(nxt_task_t *task, void *obj, void *data)
{
#if (NXT_WITH_ZLIB)
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
#endif
}

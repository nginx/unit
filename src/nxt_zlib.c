/*
 * Copyright (C) Andrew Clayton
 * Copyright (C) F5, Inc.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <zlib.h>

#include "nxt_http_compression.h"


static int
nxt_zlib_gzip_init(nxt_http_comp_compressor_ctx_t *ctx)
{
    z_stream  *z = &ctx->zlib_ctx;

    *z = (z_stream){};

    return deflateInit2(z, ctx->level, Z_DEFLATED, 9 + 16, 8,
                        Z_DEFAULT_STRATEGY);
}


static int
nxt_zlib_deflate_init(nxt_http_comp_compressor_ctx_t *ctx)
{
    z_stream  *z = &ctx->zlib_ctx;

    *z = (z_stream){};

    return deflateInit2(z, ctx->level, Z_DEFLATED, 9, 8, Z_DEFAULT_STRATEGY);
}


static size_t
nxt_zlib_bound(const nxt_http_comp_compressor_ctx_t *ctx, size_t in_len)
{
    z_stream  *z = (z_stream *)&ctx->zlib_ctx;

    return deflateBound(z, in_len);
}


static ssize_t
nxt_zlib_deflate(nxt_http_comp_compressor_ctx_t *ctx, const uint8_t *in_buf,
                 size_t in_len, uint8_t *out_buf, size_t out_len, bool last)
{
    int       ret;
    size_t    compressed_bytes;
    z_stream  *z = &ctx->zlib_ctx;

    z->avail_in = in_len;
    z->next_in = (z_const Bytef *)in_buf;

    z->avail_out = out_len;
    z->next_out = out_buf;

    compressed_bytes = z->total_out;

    ret = deflate(z, last ? Z_FINISH : Z_SYNC_FLUSH);
    if (ret == Z_STREAM_ERROR || ret == Z_BUF_ERROR) {
        deflateEnd(z);
        return -1;
    }

    if (last) {
        deflateEnd(z);
    }

    return z->total_out - compressed_bytes;
}


const nxt_http_comp_operations_t  nxt_http_comp_deflate_ops = {
    .init               = nxt_zlib_deflate_init,
    .bound              = nxt_zlib_bound,
    .deflate            = nxt_zlib_deflate,
};


const nxt_http_comp_operations_t  nxt_http_comp_gzip_ops = {
    .init               = nxt_zlib_gzip_init,
    .bound              = nxt_zlib_bound,
    .deflate            = nxt_zlib_deflate,
};

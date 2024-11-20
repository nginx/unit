/*
 * Copyright (C) Andrew Clayton
 * Copyright (C) F5, Inc.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <zstd.h>

#include "nxt_http_compression.h"


static int
nxt_zstd_init(nxt_http_comp_compressor_ctx_t *ctx)
{
    ZSTD_CStream  **zstd = &ctx->zstd_ctx;

    *zstd = ZSTD_createCStream();
    if (*zstd == NULL) {
        return -1;
    }
    ZSTD_initCStream(*zstd, ctx->level);

    return 0;
}


static size_t
nxt_zstd_bound(const nxt_http_comp_compressor_ctx_t *ctx, size_t in_len)
{
    return ZSTD_compressBound(in_len);
}


static ssize_t
nxt_zstd_compress(nxt_http_comp_compressor_ctx_t *ctx, const uint8_t *in_buf,
                  size_t in_len, uint8_t *out_buf, size_t out_len, bool last)
{
    size_t          ret;
    ZSTD_CStream    *zstd = ctx->zstd_ctx;
    ZSTD_inBuffer   zinb = { .src = in_buf, .size = in_len };
    ZSTD_outBuffer  zoutb = { .dst = out_buf, .size = out_len };

    ret = ZSTD_compressStream(zstd, &zoutb, &zinb);

    if (zinb.pos < zinb.size) {
        ret = ZSTD_flushStream(zstd, &zoutb);
    }

    if (last) {
        ret = ZSTD_endStream(zstd, &zoutb);
        ZSTD_freeCStream(zstd);
    }

    if (ZSTD_isError(ret)) {
        return -1;
    }

    return zoutb.pos;
}


const nxt_http_comp_operations_t  nxt_http_comp_zstd_ops = {
    .init               = nxt_zstd_init,
    .bound              = nxt_zstd_bound,
    .deflate            = nxt_zstd_compress,
};

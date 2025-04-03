/*
 * Copyright (C) Andrew Clayton
 * Copyright (C) F5, Inc.
 */

#define _GNU_SOURCE
#include <unistd.h>


#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <brotli/encode.h>

#include "nxt_http_compression.h"


static int
nxt_brotli_init(nxt_http_comp_compressor_ctx_t *ctx)
{
    BrotliEncoderState  **brotli = &ctx->brotli_ctx;

    *brotli = BrotliEncoderCreateInstance(NULL, NULL, NULL);
    if (*brotli == NULL) {
        return -1;
    }
    BrotliEncoderSetParameter(*brotli, BROTLI_PARAM_QUALITY, ctx->level);

    printf("%7d %s: brotli compression level [%d]\n", gettid(), __func__,
           ctx->level);

    return 0;
}


static size_t
nxt_brotli_bound(const nxt_http_comp_compressor_ctx_t *ctx, size_t in_len)
{
    return BrotliEncoderMaxCompressedSize(in_len);
}


static ssize_t
nxt_brotli_compress(nxt_http_comp_compressor_ctx_t *ctx, const uint8_t *in_buf,
                    size_t in_len, uint8_t *out_buf, size_t out_len, bool last)
{
    bool                ok;
    size_t              out_bytes = out_len;
    BrotliEncoderState  *brotli = ctx->brotli_ctx;

    printf("%7d %s: last/%s\n", gettid(), __func__, last ? "true" : "false");
    printf("%7d %s: in_len [%lu] out_len [%lu]\n", gettid(),  __func__,
           in_len, out_len);

    ok = BrotliEncoderCompressStream(brotli, BROTLI_OPERATION_PROCESS,
                                     &in_len, &in_buf, &out_bytes, &out_buf,
                                     NULL);
    if (!ok) {
        return -1;
    }

    ok = BrotliEncoderCompressStream(brotli, BROTLI_OPERATION_FLUSH,
                                     &in_len, &in_buf, &out_bytes, &out_buf,
                                     NULL);
    if (!ok) {
        return -1;
    }

    printf("%7d %s: in_len [%lu] out_len [%lu] out_bytes [%lu]\n", gettid(),
           __func__, in_len, out_len, out_bytes);
    if (last) {
        ok = BrotliEncoderCompressStream(brotli, BROTLI_OPERATION_FINISH,
                                         &in_len, &in_buf, &out_bytes,
                                         &out_buf, NULL);
        if (!ok) {
            return -1;
        }

        BrotliEncoderDestroyInstance(brotli);
    }

    printf("%7d %s: in_len [%lu] out_len [%lu] out_bytes [%lu]\n", gettid(),
           __func__, in_len, out_len, out_bytes);

    return out_len - out_bytes;
}


const nxt_http_comp_operations_t  nxt_comp_brotli_ops = {
    .init               = nxt_brotli_init,
    .bound              = nxt_brotli_bound,
    .deflate            = nxt_brotli_compress,
};

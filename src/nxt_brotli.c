/*
 *
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <brotli/encode.h>

#include "nxt_http_compression.h"


static void
nxt_brotli_init(nxt_http_comp_compressor_ctx_t *ctx)
{
    BrotliEncoderState  **brotli = &ctx->brotli_ctx;

    *brotli = BrotliEncoderCreateInstance(NULL, NULL, NULL);
    BrotliEncoderSetParameter(*brotli, BROTLI_PARAM_QUALITY, ctx->level);
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

    ok = BrotliEncoderCompressStream(brotli, BROTLI_OPERATION_PROCESS,
                                     &in_len, &in_buf, &out_bytes, &out_buf,
                                     NULL);

    ok = BrotliEncoderCompressStream(brotli, BROTLI_OPERATION_FLUSH,
                                     &in_len, &in_buf, &out_bytes, &out_buf,
                                     NULL);

    if (last) {
        ok = BrotliEncoderCompressStream(brotli, BROTLI_OPERATION_FINISH,
                                         &in_len, &in_buf, &out_bytes,
                                         &out_buf, NULL);
        BrotliEncoderDestroyInstance(brotli);
    }

    return out_len - out_bytes;
}


const nxt_http_comp_operations_t  nxt_comp_brotli_ops = {
    .init               = nxt_brotli_init,
    .bound              = nxt_brotli_bound,
    .deflate            = nxt_brotli_compress,
};

/*
 * Copyright (C) Andrew Clayton
 * Copyright (C) F5, Inc.
 */

#ifndef _NXT_COMPRESSION_H_INCLUDED_
#define _NXT_COMPRESSION_H_INCLUDED_

#include <nxt_auto_config.h>

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#if NXT_HAVE_ZLIB
#include <zlib.h>
#endif

#if NXT_HAVE_ZSTD
#include <zstd.h>
#endif

#include <nxt_main.h>
#include <nxt_router.h>
#include <nxt_string.h>
#include <nxt_conf.h>


#if NXT_HAVE_ZLIB
#define NXT_HTTP_COMP_ZLIB_DEFAULT_LEVEL       Z_DEFAULT_COMPRESSION
#define NXT_HTTP_COMP_ZLIB_COMP_MIN            Z_DEFAULT_COMPRESSION
#define NXT_HTTP_COMP_ZLIB_COMP_MAX            Z_BEST_COMPRESSION
#endif
#if NXT_HAVE_ZSTD
#define NXT_HTTP_COMP_ZSTD_DEFAULT_LEVEL       ZSTD_CLEVEL_DEFAULT
#define NXT_HTTP_COMP_ZSTD_COMP_MIN            (-7)
#define NXT_HTTP_COMP_ZSTD_COMP_MAX            22
#endif


typedef struct nxt_http_comp_compressor_ctx_s  nxt_http_comp_compressor_ctx_t;
typedef struct nxt_http_comp_operations_s      nxt_http_comp_operations_t;

struct nxt_http_comp_compressor_ctx_s {
    int8_t level;

    union {
#if NXT_HAVE_ZLIB
        z_stream zlib_ctx;
#endif
#if NXT_HAVE_ZSTD
        ZSTD_CStream *zstd_ctx;
#endif
    };
};

struct nxt_http_comp_operations_s {
    int      (*init)(nxt_http_comp_compressor_ctx_t *ctx);
    size_t   (*bound)(const nxt_http_comp_compressor_ctx_t *ctx,
                      size_t in_len);
    ssize_t  (*deflate)(nxt_http_comp_compressor_ctx_t *ctx,
                        const uint8_t *in_buf, size_t in_len,
                        uint8_t *out_buf, size_t out_len, bool last);
};


#if NXT_HAVE_ZLIB
extern const nxt_http_comp_operations_t  nxt_http_comp_deflate_ops;
extern const nxt_http_comp_operations_t  nxt_http_comp_gzip_ops;
#endif

#if NXT_HAVE_ZSTD
extern const nxt_http_comp_operations_t  nxt_http_comp_zstd_ops;
#endif


extern bool nxt_http_comp_wants_compression(void);
extern bool nxt_http_comp_compressor_is_valid(const nxt_str_t *token);
extern nxt_int_t nxt_http_comp_check_compression(nxt_task_t *task,
    nxt_http_request_t *r);
extern nxt_int_t nxt_http_comp_compression_init(nxt_task_t *task,
    nxt_router_conf_t *rtcf, const nxt_conf_value_t *comp_conf);

#endif  /* _NXT_COMPRESSION_H_INCLUDED_ */

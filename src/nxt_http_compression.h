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

#include <nxt_main.h>
#include <nxt_router.h>
#include <nxt_string.h>
#include <nxt_conf.h>


typedef struct nxt_http_comp_compressor_ctx_s  nxt_http_comp_compressor_ctx_t;
typedef struct nxt_http_comp_operations_s      nxt_http_comp_operations_t;

struct nxt_http_comp_compressor_ctx_s {
    int8_t level;

    union {
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


extern bool nxt_http_comp_wants_compression(void);
extern bool nxt_http_comp_compressor_is_valid(const nxt_str_t *token);
extern nxt_int_t nxt_http_comp_check_compression(nxt_task_t *task,
    nxt_http_request_t *r);
extern nxt_int_t nxt_http_comp_compression_init(nxt_task_t *task,
    nxt_router_conf_t *rtcf, const nxt_conf_value_t *comp_conf);

#endif  /* _NXT_COMPRESSION_H_INCLUDED_ */

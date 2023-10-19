/*
 * Copyright (C) Andrew Clayton
 * Copyright (C) F5, Inc.
 */

#ifndef _NXT_WASM_H_INCLUDED_
#define _NXT_WASM_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#include <nxt_unit.h>

#include <wasm.h>
#if defined(NXT_HAVE_WASM_WASMTIME)
#include <wasmtime.h>
#endif


#define NXT_WASM_PAGE_SIZE          (64 * 1024)
#define NXT_WASM_MEM_SIZE           (32UL * 1024 * 1024)

#if defined(NXT_HAVE_WASM_WASMTIME)
typedef wasmtime_func_t  nxt_wasm_func_t;
#endif


typedef struct nxt_wasm_http_field_s       nxt_wasm_http_field_t;
typedef struct nxt_wasm_request_s          nxt_wasm_request_t;
typedef struct nxt_wasm_response_s         nxt_wasm_response_t;
typedef struct nxt_wasm_response_fields_s  nxt_wasm_response_fields_t;
typedef enum nxt_wasm_fh_e                 nxt_wasm_fh_t;
typedef struct nxt_wasm_func_handler_s     nxt_wasm_func_handler_t;
typedef struct nxt_wasm_ctx_s              nxt_wasm_ctx_t;
typedef struct nxt_wasm_operations_s       nxt_wasm_operations_t;

struct nxt_wasm_http_field_s {
    uint32_t  name_off;
    uint32_t  name_len;
    uint32_t  value_off;
    uint32_t  value_len;
};

struct nxt_wasm_request_s {
    uint32_t               method_off;
    uint32_t               method_len;
    uint32_t               version_off;
    uint32_t               version_len;
    uint32_t               path_off;
    uint32_t               path_len;
    uint32_t               query_off;
    uint32_t               query_len;
    uint32_t               remote_off;
    uint32_t               remote_len;
    uint32_t               local_addr_off;
    uint32_t               local_addr_len;
    uint32_t               local_port_off;
    uint32_t               local_port_len;
    uint32_t               server_name_off;
    uint32_t               server_name_len;

    uint64_t               content_len;
    uint64_t               total_content_sent;
    uint32_t               content_sent;
    uint32_t               content_off;

    uint32_t               request_size;

    uint32_t               nfields;

    uint32_t               tls;

    char                   __pad[4];

    nxt_wasm_http_field_t  fields[];
};

struct nxt_wasm_response_s {
    uint32_t  size;

    uint8_t   data[];
};

struct nxt_wasm_response_fields_s {
    uint32_t               nfields;

    nxt_wasm_http_field_t  fields[];
};

enum nxt_wasm_fh_e {
    NXT_WASM_FH_REQUEST = 0,
    NXT_WASM_FH_MALLOC,
    NXT_WASM_FH_FREE,

    /* Optional handlers */
    NXT_WASM_FH_MODULE_INIT,
    NXT_WASM_FH_MODULE_END,
    NXT_WASM_FH_REQUEST_INIT,
    NXT_WASM_FH_REQUEST_END,
    NXT_WASM_FH_RESPONSE_END,

    NXT_WASM_FH_NR
};

struct nxt_wasm_func_handler_s {
    const char       *func_name;
    nxt_wasm_func_t  func;
};

struct nxt_wasm_ctx_s {
    const char               *module_path;

    nxt_wasm_func_handler_t  fh[NXT_WASM_FH_NR];

    char                     **dirs;

    nxt_unit_request_info_t  *req;

    uint8_t                  *baddr;
    size_t                   baddr_off;

    size_t                   response_off;

    uint16_t                 status;
};

struct nxt_wasm_operations_s {
    int   (*init)(nxt_wasm_ctx_t *ctx);
    void  (*destroy)(const nxt_wasm_ctx_t *ctx);
    int   (*exec_request)(const nxt_wasm_ctx_t *ctx);
    void  (*exec_hook)(const nxt_wasm_ctx_t *ctx, nxt_wasm_fh_t hook);
};

extern const nxt_wasm_operations_t  nxt_wasm_ops;


/* Exported to the WASM module */
extern void nxt_wasm_do_response_end(nxt_wasm_ctx_t *ctx);
extern void nxt_wasm_do_send_response(nxt_wasm_ctx_t *ctx, uint32_t offset);
extern void nxt_wasm_do_send_headers(nxt_wasm_ctx_t *ctx, uint32_t offset);

#endif  /* _NXT_WASM_H_INCLUDED_ */

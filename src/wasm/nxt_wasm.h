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

#define NXT_WASM_MEM_PAGES          512UL       /* 32 MiB */

#define NXT_WASM_MEM_SIZE           (NXT_WASM_PAGE_SIZE * NXT_WASM_MEM_PAGES)

#if defined(NXT_HAVE_WASM_WASMTIME)
typedef wasmtime_func_t  nxt_wasm_func_t;
#endif

typedef struct {
    uint32_t  name_offs;
    uint32_t  name_len;
    uint32_t  value_offs;
    uint32_t  value_len;
} nxt_wasm_http_hdr_field_t;

typedef struct {
    uint32_t                   method_offs;
    uint32_t                   method_len;
    uint32_t                   version_offs;
    uint32_t                   version_len;
    uint32_t                   path_offs;
    uint32_t                   path_len;
    uint32_t                   query_offs;
    uint32_t                   query_len;
    uint32_t                   remote_offs;
    uint32_t                   remote_len;
    uint32_t                   local_addr_offs;
    uint32_t                   local_addr_len;
    uint32_t                   local_port_offs;
    uint32_t                   local_port_len;
    uint32_t                   server_name_offs;
    uint32_t                   server_name_len;

    uint32_t                   content_offs;
    uint32_t                   content_len;
    uint32_t                   content_sent;
    uint32_t                   total_content_sent;

    uint32_t                   request_size;

    uint32_t                   nr_fields;

    uint32_t                   tls;

    nxt_wasm_http_hdr_field_t  fields[];
} nxt_wasm_request_t;

typedef struct {
    uint32_t  size;

    uint8_t   data[];
} nxt_wasm_response_t;

typedef struct {
    uint32_t                   nr_fields;

    nxt_wasm_http_hdr_field_t  fields[];
} nxt_wasm_response_hdr_t;

typedef enum {
    NXT_WASM_FH_REQUEST = 0,
    NXT_WASM_FH_MALLOC,
    NXT_WASM_FH_FREE,

    /* Optionsl handlers */
    NXT_WASM_FH_MODULE_INIT,
    NXT_WASM_FH_MODULE_END,
    NXT_WASM_FH_REQUEST_INIT,
    NXT_WASM_FH_REQUEST_END,
    NXT_WASM_FH_RESPONSE_END,

    NXT_WASM_FH_NR
} nxt_wasm_fh_t;

typedef struct {
    const char       *func_name;
    nxt_wasm_func_t  func;
} nxt_wasm_func_handler_t;

typedef struct {
    const char               *module_path;

    nxt_wasm_func_handler_t  fh[NXT_WASM_FH_NR];

    char                     **dirs;

    nxt_unit_request_info_t  *req;

    uint8_t                  *baddr;
    size_t                   baddr_offs;

    size_t                   response_offs;
} nxt_wasm_ctx_t;

typedef struct {
    int (*init)(nxt_wasm_ctx_t *);
    void (*destroy)(const nxt_wasm_ctx_t *);
    void (*exec_request)(const nxt_wasm_ctx_t *);
    void (*exec_hook)(const nxt_wasm_ctx_t *, nxt_wasm_fh_t hook);
    void (*meminfo)(const nxt_wasm_ctx_t *);
} nxt_wasm_operations_t;

extern const nxt_wasm_operations_t  wasm_ops;

/* Exported to the WASM module */
extern void nxt_wasm_do_response_end(nxt_wasm_ctx_t *ctx);
extern void nxt_wasm_do_send_response(uint32_t offs, nxt_wasm_ctx_t *ctx);
extern void nxt_wasm_do_send_headers(uint32_t offs, nxt_wasm_ctx_t *ctx);

#endif  /* _NXT_WASM_H_INCLUDED_ */

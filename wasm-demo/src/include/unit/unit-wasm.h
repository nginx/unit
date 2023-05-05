#ifndef _LIBUNIT_WASM_H_
#define _LIBUNIT_WASM_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LUW_VERSION_MAJOR	0
#define LUW_VERSION_MINOR	1
#define LUW_VERSION_PATCH	0

/* Version number in hex 0xMMmmpp00 */
#define LUW_VERSION_NUMBER \
	( (LUW_VERSION_MAJOR << 24) | \
	  (LUW_VERSION_MINOR << 16) | \
	  (LUW_VERSION_PATCH << 8) )

#define __luw_export_name(name)	__attribute__((export_name(name)))

typedef uint64_t u64;
typedef int64_t  s64;
typedef uint32_t u32;
typedef int32_t  s32;
typedef uint16_t u16;
typedef int16_t  s16;
typedef uint8_t   u8;
typedef int8_t    s8;

struct luw_hdr_field {
	u32 name_offs;
	u32 name_len;
	u32 value_offs;
	u32 value_len;
};

struct luw_req {
	u32 method_offs;
	u32 method_len;
	u32 version_offs;
	u32 version_len;
	u32 path_offs;
	u32 path_len;
	u32 query_offs;
	u32 query_len;
	u32 remote_offs;
	u32 remote_len;
	u32 local_addr_offs;
	u32 local_addr_len;
	u32 local_port_offs;
	u32 local_port_len;
	u32 server_name_offs;
	u32 server_name_len;

	u32 content_offs;
	u32 content_len;
	u32 content_sent;
	u32 total_content_sent;

	u32 request_size;

	u32 nr_fields;

	u32 tls;

	struct luw_hdr_field fields[];
};

struct luw_resp {
	u32 size;

	u8 data[];
};

struct luw_resp_hdr {
	u32 nr_fields;

	struct luw_hdr_field fields[];
};

typedef struct {
	/* pointer to the shared memory */
	u8 *addr;

	/* points to the end of ctx->resp->data */
	u8 *mem;

	/* struct luw_req representation of the shared memory */
	struct luw_req *req;

	/* struct luw_resp representation of the shared memory */
	struct luw_resp *resp;

	/* struct luw_resp_hdr represnetation of the shared memory */
	struct luw_resp_hdr *resp_hdr;

	/* offset to where the struct resp starts in the shared memory */
	size_t resp_offset;

	/* points to the external buffer used for a copy of the request */
	u8 *req_buf;

	/* points to the end of the fields array in struct luw_resp_hdr */
	u8 *hdrp;

	/* points to the end of ctx->req_buf */
	u8 *reqp;
} luw_ctx_t;

typedef enum {
	LUW_SRB_NONE = 0x00,
	LUW_SRB_APPEND = 0x01,
	LUW_SRB_ALLOC = 0x02,
	LUW_SRB_FULL_SIZE = 0x04,
} luw_srb_flags_t;
#define LUW_SRB_FLAGS_ALL \
	(LUW_SRB_NONE|LUW_SRB_APPEND|LUW_SRB_ALLOC|LUW_SRB_FULL_SIZE)

typedef struct luw_hdr_field luw_http_hdr_iter_t;

#define luw_foreach_http_hdr(ctx, iter, name, value) \
	for (iter = ctx->req->fields, \
	     name = (const char *)(u8 *)ctx->req + iter->name_offs; \
	     (iter < (ctx->req->fields + ctx->req->nr_fields)) && \
	     (value = (const char *)(u8 *)ctx->req + iter->value_offs); \
	     iter++, name = (const char *)(u8 *)ctx->req + iter->name_offs)

/* Imported functions from the host/runtime */
__attribute__((import_module("env"), import_name("nxt_wasm_get_init_mem_size")))
u32 nxt_wasm_get_init_mem_size(void);
__attribute__((import_module("env"), import_name("nxt_wasm_response_end")))
void nxt_wasm_response_end(void);
__attribute__((import_module("env"), import_name("nxt_wasm_send_headers")))
void nxt_wasm_send_headers(u32 offset);
__attribute__((import_module("env"), import_name("nxt_wasm_send_response")))
void nxt_wasm_send_response(u32 offset);

extern void luw_module_init_handler(void);
extern void luw_module_end_handler(void);
extern void luw_request_init_handler(void);
extern void luw_request_end_handler(void);
extern void luw_response_end_handler(void);
extern int luw_request_handler(u8 *addr);
extern void luw_free_handler(u32 addr);
extern u32 luw_malloc_handler(size_t size);

#pragma GCC visibility push(default)

extern void luw_init_ctx(luw_ctx_t *ctx, u8 *addr, size_t offset);
extern void luw_destroy_ctx(const luw_ctx_t *ctx);
extern int luw_set_req_buf(luw_ctx_t *ctx, u8 **buf, unsigned long flags);
extern const char *luw_get_http_path(const luw_ctx_t *ctx);
extern const char *luw_get_http_method(const luw_ctx_t *ctx);
extern const char *luw_get_http_version(const luw_ctx_t *ctx);
extern const char *luw_get_http_query(const luw_ctx_t *ctx);
extern const char *luw_get_http_remote(const luw_ctx_t *ctx);
extern const char *luw_get_http_local_addr(const luw_ctx_t *ctx);
extern const char *luw_get_http_local_port(const luw_ctx_t *ctx);
extern const char *luw_get_http_server_name(const luw_ctx_t *ctx);
extern const u8 *luw_get_http_content(const luw_ctx_t *ctx);
extern size_t luw_get_http_content_len(const luw_ctx_t *ctx);
extern size_t luw_get_http_content_sent(const luw_ctx_t *ctx);
extern bool luw_http_is_tls(const luw_ctx_t *ctx);
extern size_t luw_get_response_data_size(const luw_ctx_t *ctx);
extern int luw_mem_writep(luw_ctx_t *ctx, const char *fmt, ...);
extern size_t luw_mem_writep_data(luw_ctx_t *ctx, const u8 *src, size_t size);
extern void luw_req_buf_append(luw_ctx_t *ctx, const u8 *src);
extern size_t luw_mem_fill_buf_from_req(luw_ctx_t *ctx, size_t from);
extern void luw_mem_reset(luw_ctx_t *ctx);
extern void luw_http_send_response(const luw_ctx_t *ctx);
extern void luw_http_init_headers(luw_ctx_t *ctx, size_t nr, size_t offset);
extern void luw_http_add_header(luw_ctx_t *ctx, u16 idx, const char *name,
				const char *value);
extern void luw_http_send_headers(const luw_ctx_t *ctx);
extern void luw_http_response_end(void);
extern u32 luw_mem_get_init_size(void);

#pragma GCC visibility pop

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _LIBUNIT_WASM_H_ */

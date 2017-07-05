
/*
 * Copyright (C) Max Romanov
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_APPLICATION_H_INCLUDED_
#define _NXT_APPLICATION_H_INCLUDED_


typedef struct {
    nxt_str_t                  name;
    nxt_str_t                  value;
} nxt_app_header_field_t;


typedef struct {
    nxt_str_t                  method;
    nxt_str_t                  target;
    nxt_str_t                  version;
    nxt_str_t                  path;
    nxt_str_t                  query;

    nxt_list_t                 *fields;

    nxt_str_t                  cookie;
    nxt_str_t                  content_length;
    nxt_str_t                  content_type;
    nxt_str_t                  host;

    off_t                      parsed_content_length;
    nxt_bool_t                 done;
} nxt_app_request_header_t;


typedef struct {
    nxt_str_t                  preread;
    nxt_bool_t                 done;
} nxt_app_request_body_t;


typedef struct {
    nxt_app_request_header_t   header;
    nxt_app_request_body_t     body;
} nxt_app_request_t;


typedef struct {
    nxt_app_request_t         r;
    nxt_http_request_parse_t  parser;
    nxt_mp_t                  *mem_pool;
} nxt_app_parse_ctx_t;


nxt_int_t nxt_app_http_req_init(nxt_task_t *task, nxt_app_parse_ctx_t *ctx);

nxt_int_t nxt_app_http_req_parse(nxt_task_t *task, nxt_app_parse_ctx_t *ctx,
    nxt_buf_t *buf);

nxt_int_t nxt_app_http_req_done(nxt_task_t *task, nxt_app_parse_ctx_t *ctx);

nxt_int_t nxt_app_http_init(nxt_task_t *task, nxt_runtime_t *rt);


typedef struct nxt_app_wmsg_s  nxt_app_wmsg_t;
typedef struct nxt_app_rmsg_s  nxt_app_rmsg_t;

struct nxt_app_wmsg_s {
    nxt_port_t                 *port;  /* where prepared buf will be sent */
    nxt_buf_t                  *write;
    nxt_buf_t                  **buf;
    uint32_t                   stream;
};

struct nxt_app_rmsg_s {
    nxt_buf_t                 *buf;   /* current buffer to read */
};


nxt_inline u_char *
nxt_app_msg_write_length(u_char *dst, size_t length);

/* TODO asynchronous mmap buffer assignment */
u_char *nxt_app_msg_write_get_buf(nxt_task_t *task, nxt_app_wmsg_t *msg,
    size_t size);

nxt_int_t nxt_app_msg_write(nxt_task_t *task, nxt_app_wmsg_t *msg,
    u_char *c, size_t size);

nxt_int_t nxt_app_msg_write_prefixed_upcase(nxt_task_t *task,
    nxt_app_wmsg_t *msg, const nxt_str_t *prefix, const nxt_str_t *v);

nxt_inline nxt_int_t
nxt_app_msg_write_nvp_(nxt_task_t *task, nxt_app_wmsg_t *msg,
    u_char *n, size_t nsize, u_char *v, size_t vsize);


#define nxt_app_msg_write_const(task, msg, c)                                 \
    nxt_app_msg_write((task), (msg), (u_char *)(c), sizeof(c) - 1)

#define nxt_app_msg_write_str(task, msg, str)                                 \
    nxt_app_msg_write((task), (msg), (str)->start, (str)->length)

#define nxt_app_msg_write_cstr(task, msg, c)                                  \
    nxt_app_msg_write((task), (msg), (c), nxt_strlen(c))

#define nxt_app_msg_write_nvp(task, msg, n, v)                                \
    nxt_app_msg_write_nvp_((task), (msg), (u_char *)(n), sizeof(n) - 1,       \
                           (v)->start, (v)->length)

nxt_inline nxt_int_t nxt_app_msg_write_size(nxt_task_t *task,
    nxt_app_wmsg_t *msg, size_t size);

nxt_int_t nxt_app_msg_flush(nxt_task_t *task, nxt_app_wmsg_t *msg,
    nxt_bool_t last);

nxt_int_t nxt_app_msg_write_raw(nxt_task_t *task, nxt_app_wmsg_t *msg,
    const u_char *c, size_t size);

nxt_int_t nxt_app_msg_read_str(nxt_task_t *task, nxt_app_rmsg_t *msg,
    nxt_str_t *str);

nxt_int_t nxt_app_msg_read_nvp(nxt_task_t *task, nxt_app_rmsg_t *rmsg,
    nxt_str_t *n, nxt_str_t *v);

nxt_int_t nxt_app_msg_read_size(nxt_task_t *task, nxt_app_rmsg_t *rmsg,
    size_t *size);


typedef struct {
    nxt_int_t                  (*init)(nxt_task_t *task);
    nxt_int_t                  (*prepare_msg)(nxt_task_t *task,
                                    nxt_app_request_t *r,
                                    nxt_app_wmsg_t *wmsg);
    nxt_int_t                  (*run)(nxt_task_t *task,
                                    nxt_app_rmsg_t *rmsg,
                                    nxt_app_wmsg_t *wmsg);
} nxt_application_module_t;


extern nxt_application_module_t  *nxt_app;



nxt_int_t nxt_app_http_read_body(nxt_app_request_t *r, u_char *data,
    size_t len);
nxt_int_t nxt_app_write(nxt_app_request_t *r, const u_char *data, size_t len);

nxt_inline u_char *
nxt_app_msg_write_length(u_char *dst, size_t length)
{
    if (length < 128) {
        *dst = length;
        dst++;
    } else {
        dst[0] = 0x80U | (length >> 24);
        dst[1] = 0xFFU & (length >> 16);
        dst[2] = 0xFFU & (length >> 8);
        dst[3] = 0xFFU & length;
        dst += 4;
    }

    return dst;
}


nxt_inline nxt_int_t
nxt_app_msg_write_nvp_(nxt_task_t *task, nxt_app_wmsg_t *msg,
    u_char *n, size_t nsize, u_char *v, size_t vsize)
{
    nxt_int_t rc;

    rc = nxt_app_msg_write(task, msg, n, nsize);
    if (nxt_slow_path(rc != NXT_OK)) {
        return rc;
    }

    return nxt_app_msg_write(task, msg, v, vsize);
}


nxt_inline nxt_int_t
nxt_app_msg_write_size(nxt_task_t *task, nxt_app_wmsg_t *msg, size_t size)
{
    u_char  *dst;
    size_t  dst_length;

    dst_length = size < 128 ? 1 : 4;

    dst = nxt_app_msg_write_get_buf(task, msg, dst_length);
    if (nxt_slow_path(dst == NULL)) {
        return NXT_ERROR;
    }

    nxt_app_msg_write_length(dst, size);

    return NXT_OK;
}


nxt_inline u_char *
nxt_app_msg_read_length(u_char *src, size_t *length)
{
    if (src[0] < 128) {
        *length = src[0];
        src++;
    } else {
        *length = ((src[0] & 0x7fU) << 24) +
                  (src[1] << 16) +
                  (src[2] << 8) +
                  src[3];
        src += 4;
    }

    return src;
}


#endif /* _NXT_APPLICATION_H_INCLIDED_ */

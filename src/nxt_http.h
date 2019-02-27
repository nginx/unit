
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_HTTP_H_INCLUDED_
#define _NXT_HTTP_H_INCLUDED_


typedef enum {
    NXT_HTTP_INVALID = 0,

    NXT_HTTP_OK = 200,
    NXT_HTTP_NO_CONTENT = 204,

    NXT_HTTP_MULTIPLE_CHOICES = 300,
    NXT_HTTP_MOVED_PERMANENTLY = 301,
    NXT_HTTP_FOUND = 302,
    NXT_HTTP_SEE_OTHER = 303,
    NXT_HTTP_NOT_MODIFIED = 304,

    NXT_HTTP_BAD_REQUEST = 400,
    NXT_HTTP_NOT_FOUND = 404,
    NXT_HTTP_REQUEST_TIMEOUT = 408,
    NXT_HTTP_LENGTH_REQUIRED = 411,
    NXT_HTTP_PAYLOAD_TOO_LARGE = 413,
    NXT_HTTP_URI_TOO_LONG = 414,
    NXT_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,

    NXT_HTTP_TO_HTTPS = 497,

    NXT_HTTP_INTERNAL_SERVER_ERROR = 500,
    NXT_HTTP_NOT_IMPLEMENTED = 501,
    NXT_HTTP_BAD_GATEWAY = 502,
    NXT_HTTP_SERVICE_UNAVAILABLE = 503,
    NXT_HTTP_GATEWAY_TIMEOUT = 504,
    NXT_HTTP_VERSION_NOT_SUPPORTED = 505,
} nxt_http_status_t;


typedef enum {
    NXT_HTTP_TE_NONE = 0,
    NXT_HTTP_TE_CHUNKED = 1,
    NXT_HTTP_TE_UNSUPPORTED = 2,
} nxt_http_te_t;


typedef struct {
    nxt_work_handler_t              ready_handler;
    nxt_work_handler_t              error_handler;
} nxt_http_request_state_t;


typedef struct {
    nxt_http_request_parse_t        parser;

    uint8_t                         nbuffers;
    uint8_t                         keepalive;            /* 1 bit  */
    uint8_t                         chunked;              /* 1 bit  */
    nxt_http_te_t                   transfer_encoding:8;  /* 2 bits */

    uint32_t                        header_size;

    nxt_http_request_t              *request;
    nxt_buf_t                       *buffers;
    /*
     * All fields before the conn field will
     * be zeroed in a keep-alive connection.
     */
    nxt_conn_t                      *conn;
} nxt_h1proto_t;


typedef union {
    void                            *any;
    nxt_h1proto_t                   *h1;
} nxt_http_proto_t;


#define nxt_http_field_name_set(_field, _name)                                \
    do {                                                                      \
         (_field)->name_length = nxt_length(_name);                           \
         (_field)->name = (u_char *) _name;                                   \
    } while (0)


#define nxt_http_field_set(_field, _name, _value)                             \
    do {                                                                      \
         (_field)->name_length = nxt_length(_name);                           \
         (_field)->value_length = nxt_length(_value);                         \
         (_field)->name = (u_char *) _name;                                   \
         (_field)->value = (u_char *) _value;                                 \
    } while (0)


typedef struct {
    nxt_list_t                      *fields;
    nxt_http_field_t                *date;
    nxt_http_field_t                *content_type;
    nxt_http_field_t                *content_length;
    nxt_off_t                       content_length_n;
} nxt_http_response_t;


struct nxt_http_request_s {
    nxt_http_proto_t                proto;
    nxt_socket_conf_joint_t         *conf;

    nxt_mp_t                        *mem_pool;

    nxt_buf_t                       *body;
    nxt_buf_t                       *out;
    const nxt_http_request_state_t  *state;

    nxt_str_t                       host;
    nxt_str_t                       target;
    nxt_str_t                       version;
    nxt_str_t                       *method;
    nxt_str_t                       *path;
    nxt_str_t                       *args;

    nxt_list_t                      *fields;
    nxt_http_field_t                *content_type;
    nxt_http_field_t                *content_length;
    nxt_http_field_t                *cookie;
    nxt_http_field_t                *referer;
    nxt_http_field_t                *user_agent;
    nxt_off_t                       content_length_n;

    nxt_sockaddr_t                  *remote;
    nxt_sockaddr_t                  *local;

    nxt_buf_t                       *last;

    nxt_http_response_t             resp;

    nxt_http_status_t               status:16;

    uint8_t                         pass_count;   /* 8 bits */
    uint8_t                         protocol;     /* 2 bits */
    uint8_t                         logged;       /* 1 bit  */
    uint8_t                         header_sent;  /* 1 bit  */
    uint8_t                         error;        /* 1 bit  */
};


typedef struct nxt_http_route_s     nxt_http_route_t;


struct nxt_http_pass_s {
    nxt_http_pass_t                 *(*handler)(nxt_task_t *task,
                                        nxt_http_request_t *r,
                                        nxt_http_pass_t *pass);
    union {
        nxt_http_route_t            *route;
        nxt_app_t                   *application;
    } u;

    nxt_str_t                       name;
};


typedef void (*nxt_http_proto_body_read_t)(nxt_task_t *task,
    nxt_http_request_t *r);
typedef void (*nxt_http_proto_local_addr_t)(nxt_task_t *task,
    nxt_http_request_t *r);
typedef void (*nxt_http_proto_header_send_t)(nxt_task_t *task,
    nxt_http_request_t *r);
typedef void (*nxt_http_proto_send_t)(nxt_task_t *task, nxt_http_request_t *r,
    nxt_buf_t *out);
typedef nxt_off_t (*nxt_http_proto_body_bytes_sent_t)(nxt_task_t *task,
    nxt_http_proto_t proto);
typedef void (*nxt_http_proto_discard_t)(nxt_task_t *task,
    nxt_http_request_t *r, nxt_buf_t *last);
typedef void (*nxt_http_proto_close_t)(nxt_task_t *task,
    nxt_http_proto_t proto, nxt_socket_conf_joint_t *joint);


nxt_int_t nxt_http_init(nxt_task_t *task, nxt_runtime_t *rt);
nxt_int_t nxt_h1p_init(nxt_task_t *task, nxt_runtime_t *rt);
nxt_int_t nxt_http_response_hash_init(nxt_task_t *task, nxt_runtime_t *rt);

void nxt_http_conn_init(nxt_task_t *task, void *obj, void *data);
nxt_http_request_t *nxt_http_request_create(nxt_task_t *task);
void nxt_http_request_error(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_status_t status);
void nxt_http_request_read_body(nxt_task_t *task, nxt_http_request_t *r);
void nxt_http_request_local_addr(nxt_task_t *task, nxt_http_request_t *r);
void nxt_http_request_header_send(nxt_task_t *task, nxt_http_request_t *r);
void nxt_http_request_send(nxt_task_t *task, nxt_http_request_t *r,
    nxt_buf_t *out);
nxt_buf_t *nxt_http_buf_mem(nxt_task_t *task, nxt_http_request_t *r,
    size_t size);
nxt_buf_t *nxt_http_buf_last(nxt_http_request_t *r);
void nxt_http_request_error_handler(nxt_task_t *task, void *obj, void *data);

nxt_int_t nxt_http_request_host(void *ctx, nxt_http_field_t *field,
    uintptr_t data);
nxt_int_t nxt_http_request_field(void *ctx, nxt_http_field_t *field,
    uintptr_t offset);
nxt_int_t nxt_http_request_content_length(void *ctx, nxt_http_field_t *field,
    uintptr_t data);

nxt_http_routes_t *nxt_http_routes_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_conf_value_t *routes_conf);
nxt_http_pass_t *nxt_http_pass_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_str_t *name);
void nxt_http_routes_resolve(nxt_task_t *task, nxt_router_temp_conf_t *tmcf);
nxt_http_pass_t *nxt_http_pass_application(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_str_t *name);
void nxt_http_routes_cleanup(nxt_task_t *task, nxt_http_routes_t *routes);
void nxt_http_pass_cleanup(nxt_task_t *task, nxt_http_pass_t *pass);

nxt_http_pass_t *nxt_http_request_application(nxt_task_t *task,
    nxt_http_request_t *r, nxt_http_pass_t *pass);

extern nxt_time_string_t  nxt_http_date_cache;

extern nxt_lvlhsh_t                        nxt_response_fields_hash;

extern const nxt_http_proto_body_read_t        nxt_http_proto_body_read[];
extern const nxt_http_proto_local_addr_t       nxt_http_proto_local_addr[];
extern const nxt_http_proto_header_send_t      nxt_http_proto_header_send[];
extern const nxt_http_proto_send_t             nxt_http_proto_send[];
extern const nxt_http_proto_body_bytes_sent_t  nxt_http_proto_body_bytes_sent[];
extern const nxt_http_proto_discard_t          nxt_http_proto_discard[];
extern const nxt_http_proto_close_t            nxt_http_proto_close[];


#endif  /* _NXT_HTTP_H_INCLUDED_ */

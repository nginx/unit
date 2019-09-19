
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_HTTP_H_INCLUDED_
#define _NXT_HTTP_H_INCLUDED_


typedef enum {
    NXT_HTTP_INVALID = 0,

    NXT_HTTP_CONTINUE = 100,
    NXT_HTTP_SWITCHING_PROTOCOLS = 101,

    NXT_HTTP_OK = 200,
    NXT_HTTP_NO_CONTENT = 204,

    NXT_HTTP_MULTIPLE_CHOICES = 300,
    NXT_HTTP_MOVED_PERMANENTLY = 301,
    NXT_HTTP_FOUND = 302,
    NXT_HTTP_SEE_OTHER = 303,
    NXT_HTTP_NOT_MODIFIED = 304,

    NXT_HTTP_BAD_REQUEST = 400,
    NXT_HTTP_FORBIDDEN = 403,
    NXT_HTTP_NOT_FOUND = 404,
    NXT_HTTP_METHOD_NOT_ALLOWED = 405,
    NXT_HTTP_REQUEST_TIMEOUT = 408,
    NXT_HTTP_LENGTH_REQUIRED = 411,
    NXT_HTTP_PAYLOAD_TOO_LARGE = 413,
    NXT_HTTP_URI_TOO_LONG = 414,
    NXT_HTTP_UPGRADE_REQUIRED = 426,
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


typedef enum {
    NXT_HTTP_PROTO_H1 = 0,
    NXT_HTTP_PROTO_H2,
    NXT_HTTP_PROTO_DEVNULL,
} nxt_http_protocol_t;


typedef struct {
    nxt_work_handler_t              ready_handler;
    nxt_work_handler_t              error_handler;
} nxt_http_request_state_t;


typedef struct nxt_h1proto_s        nxt_h1proto_t;

struct nxt_h1p_websocket_timer_s {
    nxt_timer_t                     timer;
    nxt_h1proto_t                   *h1p;
    nxt_msec_t                      keepalive_interval;
};


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
    nxt_buf_t                       *ws_frame;
    nxt_buf_t                       *out;
    const nxt_http_request_state_t  *state;

    nxt_str_t                       host;
    nxt_str_t                       server_name;
    nxt_str_t                       target;
    nxt_str_t                       version;
    nxt_str_t                       *method;
    nxt_str_t                       *path;
    nxt_str_t                       *args;

    nxt_array_t                     *arguments;  /* of nxt_http_name_value_t */
    nxt_array_t                     *cookies;    /* of nxt_http_name_value_t */
    nxt_list_t                      *fields;
    nxt_http_field_t                *content_type;
    nxt_http_field_t                *content_length;
    nxt_http_field_t                *cookie;
    nxt_http_field_t                *referer;
    nxt_http_field_t                *user_agent;
    nxt_off_t                       content_length_n;

    nxt_sockaddr_t                  *remote;
    nxt_sockaddr_t                  *local;
    void                            *tls;

    nxt_timer_t                     timer;
    void                            *timer_data;

    void                            *req_rpc_data;

    nxt_buf_t                       *last;

    nxt_http_response_t             resp;

    nxt_http_status_t               status:16;

    uint8_t                         pass_count;   /* 8 bits */
    nxt_http_protocol_t             protocol:8;   /* 2 bits */
    uint8_t                         logged;       /* 1 bit  */
    uint8_t                         header_sent;  /* 1 bit  */
    uint8_t                         error;        /* 1 bit  */
    uint8_t                         websocket_handshake;  /* 1 bit */
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


typedef struct {
    void (*body_read)(nxt_task_t *task, nxt_http_request_t *r);
    void (*local_addr)(nxt_task_t *task, nxt_http_request_t *r);
    void (*header_send)(nxt_task_t *task, nxt_http_request_t *r,
         nxt_work_handler_t body_handler);
    void (*send)(nxt_task_t *task, nxt_http_request_t *r, nxt_buf_t *out);
    nxt_off_t (*body_bytes_sent)(nxt_task_t *task, nxt_http_proto_t proto);
    void (*discard)(nxt_task_t *task, nxt_http_request_t *r, nxt_buf_t *last);
    void (*close)(nxt_task_t *task, nxt_http_proto_t proto,
        nxt_socket_conf_joint_t *joint);
    void (*ws_frame_start)(nxt_task_t *task, nxt_http_request_t *r,
        nxt_buf_t *ws_frame);
} nxt_http_proto_table_t;


#define NXT_HTTP_DATE_LEN  nxt_length("Wed, 31 Dec 1986 16:40:00 GMT")

nxt_inline u_char *
nxt_http_date(u_char *buf, struct tm *tm)
{
    static const char  *week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri",
                                   "Sat" };

    static const char  *month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    return nxt_sprintf(buf, buf + NXT_HTTP_DATE_LEN,
                       "%s, %02d %s %4d %02d:%02d:%02d GMT",
                       week[tm->tm_wday], tm->tm_mday,
                       month[tm->tm_mon], tm->tm_year + 1900,
                       tm->tm_hour, tm->tm_min, tm->tm_sec);
}


nxt_int_t nxt_http_init(nxt_task_t *task, nxt_runtime_t *rt);
nxt_int_t nxt_h1p_init(nxt_task_t *task, nxt_runtime_t *rt);
nxt_int_t nxt_http_response_hash_init(nxt_task_t *task, nxt_runtime_t *rt);

void nxt_http_conn_init(nxt_task_t *task, void *obj, void *data);
nxt_http_request_t *nxt_http_request_create(nxt_task_t *task);
void nxt_http_request_error(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_status_t status);
void nxt_http_request_read_body(nxt_task_t *task, nxt_http_request_t *r);
void nxt_http_request_header_send(nxt_task_t *task, nxt_http_request_t *r,
    nxt_work_handler_t body_handler);
void nxt_http_request_ws_frame_start(nxt_task_t *task, nxt_http_request_t *r,
    nxt_buf_t *ws_frame);
void nxt_http_request_send(nxt_task_t *task, nxt_http_request_t *r,
    nxt_buf_t *out);
nxt_buf_t *nxt_http_buf_mem(nxt_task_t *task, nxt_http_request_t *r,
    size_t size);
nxt_buf_t *nxt_http_buf_last(nxt_http_request_t *r);
void nxt_http_request_error_handler(nxt_task_t *task, void *obj, void *data);
void nxt_http_request_close_handler(nxt_task_t *task, void *obj, void *data);

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

nxt_http_pass_t *nxt_http_static_handler(nxt_task_t *task,
    nxt_http_request_t *r, nxt_http_pass_t *pass);
nxt_int_t nxt_http_static_mtypes_init(nxt_mp_t *mp, nxt_lvlhsh_t *hash);
nxt_int_t nxt_http_static_mtypes_hash_add(nxt_mp_t *mp, nxt_lvlhsh_t *hash,
    nxt_str_t *extension, nxt_str_t *type);
nxt_str_t *nxt_http_static_mtypes_hash_find(nxt_lvlhsh_t *hash,
    nxt_str_t *extension);

nxt_http_pass_t *nxt_http_request_application(nxt_task_t *task,
    nxt_http_request_t *r, nxt_http_pass_t *pass);

extern nxt_time_string_t  nxt_http_date_cache;

extern nxt_lvlhsh_t                        nxt_response_fields_hash;

extern const nxt_http_proto_table_t  nxt_http_proto[];

void nxt_h1p_websocket_first_frame_start(nxt_task_t *task,
    nxt_http_request_t *r, nxt_buf_t *ws_frame);
void nxt_h1p_websocket_frame_start(nxt_task_t *task, nxt_http_request_t *r,
    nxt_buf_t *ws_frame);
void nxt_h1p_complete_buffers(nxt_task_t *task, nxt_h1proto_t *h1p);
nxt_msec_t nxt_h1p_conn_request_timer_value(nxt_conn_t *c, uintptr_t data);

extern const nxt_conn_state_t  nxt_h1p_idle_close_state;

#endif  /* _NXT_HTTP_H_INCLUDED_ */

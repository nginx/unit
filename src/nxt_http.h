
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_HTTP_H_INCLUDED_
#define _NXT_HTTP_H_INCLUDED_

#include <nxt_regex.h>


typedef enum {
    NXT_HTTP_UNSET = -1,
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
    NXT_HTTP_TEMPORARY_REDIRECT = 307,
    NXT_HTTP_PERMANENT_REDIRECT = 308,

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
    NXT_HTTP_SERVER_ERROR_MAX = 599,

    NXT_HTTP_STATUS_MAX = 999,
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
        (_field)->name_length = nxt_length(_name);                            \
        (_field)->name = (u_char *) _name;                                    \
    } while (0)


#define nxt_http_field_set(_field, _name, _value)                             \
    do {                                                                      \
        (_field)->name_length = nxt_length(_name);                            \
        (_field)->value_length = nxt_length(_value);                          \
        (_field)->name = (u_char *) _name;                                    \
        (_field)->value = (u_char *) _value;                                  \
    } while (0)


typedef struct {
    nxt_list_t                      *fields;
    nxt_http_field_t                *date;
    nxt_http_field_t                *content_type;
    nxt_http_field_t                *content_length;
    nxt_off_t                       content_length_n;
} nxt_http_response_t;


typedef struct nxt_upstream_server_s  nxt_upstream_server_t;

typedef struct {
    nxt_http_proto_t                proto;
    nxt_http_request_t              *request;
    nxt_upstream_server_t           *server;
    nxt_list_t                      *fields;
    nxt_buf_t                       *body;

    nxt_http_status_t               status:16;
    nxt_http_protocol_t             protocol:8;       /* 2 bits */
    uint8_t                         header_received;  /* 1 bit  */
    uint8_t                         closed;           /* 1 bit  */
} nxt_http_peer_t;


struct nxt_http_request_s {
    nxt_http_proto_t                proto;
    nxt_socket_conf_joint_t         *conf;

    nxt_mp_t                        *mem_pool;

    nxt_buf_t                       *body;
    nxt_buf_t                       *ws_frame;
    nxt_buf_t                       *out;
    const nxt_http_request_state_t  *state;

    nxt_nsec_t                      start_time;

    nxt_str_t                       host;
    nxt_str_t                       server_name;
    nxt_str_t                       request_line;
    nxt_str_t                       target;
    nxt_str_t                       version;
    nxt_str_t                       *method;
    nxt_str_t                       *path;
    nxt_str_t                       *args;

    nxt_str_t                       args_decoded;
    nxt_array_t                     *arguments;  /* of nxt_http_name_value_t */
    nxt_array_t                     *cookies;    /* of nxt_http_name_value_t */
    nxt_list_t                      *fields;
    nxt_http_field_t                *content_type;
    nxt_http_field_t                *content_length;
    nxt_http_field_t                *cookie;
    nxt_http_field_t                *referer;
    nxt_http_field_t                *user_agent;
    nxt_http_field_t                *authorization;
    nxt_off_t                       content_length_n;

    nxt_sockaddr_t                  *remote;
    nxt_sockaddr_t                  *local;
    nxt_task_t                      task;

    nxt_timer_t                     timer;
    void                            *timer_data;

    nxt_tstr_query_t                *tstr_query;
    nxt_tstr_cache_t                tstr_cache;

    nxt_http_action_t               *action;
    void                            *req_rpc_data;

#if (NXT_HAVE_REGEX)
    nxt_regex_match_t               *regex_match;
#endif

    nxt_http_peer_t                 *peer;
    nxt_buf_t                       *last;

    nxt_queue_link_t                app_link;   /* nxt_app_t.ack_waiting_req */
    nxt_event_engine_t              *engine;
    nxt_work_t                      err_work;

    nxt_http_response_t             resp;

    nxt_http_status_t               status:16;

    uint8_t                         log_route;    /* 1 bit */
    uint8_t                         quoted_target;  /* 1 bit */
    uint8_t                         uri_changed;  /* 1 bit */

    uint8_t                         pass_count;   /* 8 bits */
    uint8_t                         app_target;
    nxt_http_protocol_t             protocol:8;   /* 2 bits */
    uint8_t                         tls;          /* 1 bit  */
    uint8_t                         logged;       /* 1 bit  */
    uint8_t                         header_sent;  /* 1 bit  */
    uint8_t                         inconsistent; /* 1 bit  */
    uint8_t                         error;        /* 1 bit  */
    uint8_t                         websocket_handshake;  /* 1 bit */
};


typedef struct {
    uint16_t                        hash;
    uint16_t                        name_length;
    uint32_t                        value_length;
    u_char                          *name;
    u_char                          *value;
} nxt_http_name_value_t;


typedef enum {
    NXT_HTTP_URI_ENCODING_NONE = 0,
    NXT_HTTP_URI_ENCODING,
    NXT_HTTP_URI_ENCODING_PLUS
} nxt_http_uri_encoding_t;


typedef struct nxt_http_route_s            nxt_http_route_t;
typedef struct nxt_http_route_rule_s       nxt_http_route_rule_t;
typedef struct nxt_http_route_addr_rule_s  nxt_http_route_addr_rule_t;


typedef struct {
    nxt_conf_value_t                *rewrite;
    nxt_conf_value_t                *set_headers;
    nxt_conf_value_t                *pass;
    nxt_conf_value_t                *ret;
    nxt_conf_value_t                *location;
    nxt_conf_value_t                *proxy;
    nxt_conf_value_t                *share;
    nxt_conf_value_t                *index;
    nxt_str_t                       chroot;
    nxt_conf_value_t                *follow_symlinks;
    nxt_conf_value_t                *traverse_mounts;
    nxt_conf_value_t                *types;
    nxt_conf_value_t                *fallback;
} nxt_http_action_conf_t;


struct nxt_http_action_s {
    nxt_http_action_t               *(*handler)(nxt_task_t *task,
                                        nxt_http_request_t *r,
                                        nxt_http_action_t *action);
    union {
        void                        *conf;
        nxt_http_route_t            *route;
        nxt_upstream_t              *upstream;
        uint32_t                    upstream_number;
        nxt_tstr_t                  *tstr;
        nxt_str_t                   *pass;
    } u;

    nxt_tstr_t                      *rewrite;
    nxt_array_t                     *set_headers;  /* of nxt_http_field_t */
    nxt_http_action_t               *fallback;
};


typedef struct {
    void (*body_read)(nxt_task_t *task, nxt_http_request_t *r);
    void (*local_addr)(nxt_task_t *task, nxt_http_request_t *r);
    void (*header_send)(nxt_task_t *task, nxt_http_request_t *r,
        nxt_work_handler_t body_handler, void *data);
    void (*send)(nxt_task_t *task, nxt_http_request_t *r, nxt_buf_t *out);
    nxt_off_t (*body_bytes_sent)(nxt_task_t *task, nxt_http_proto_t proto);
    void (*discard)(nxt_task_t *task, nxt_http_request_t *r, nxt_buf_t *last);
    void (*close)(nxt_task_t *task, nxt_http_proto_t proto,
        nxt_socket_conf_joint_t *joint);

    void (*peer_connect)(nxt_task_t *task, nxt_http_peer_t *peer);
    void (*peer_header_send)(nxt_task_t *task, nxt_http_peer_t *peer);
    void (*peer_header_read)(nxt_task_t *task, nxt_http_peer_t *peer);
    void (*peer_read)(nxt_task_t *task, nxt_http_peer_t *peer);
    void (*peer_close)(nxt_task_t *task, nxt_http_peer_t *peer);

    void (*ws_frame_start)(nxt_task_t *task, nxt_http_request_t *r,
        nxt_buf_t *ws_frame);
} nxt_http_proto_table_t;


typedef struct {
    nxt_str_t                   *header;
    uint32_t                    header_hash;
} nxt_http_forward_header_t;


struct nxt_http_forward_s {
    nxt_http_forward_header_t   client_ip;
    nxt_http_forward_header_t   protocol;
    nxt_http_route_addr_rule_t  *source;
    uint8_t                     recursive;    /* 1 bit */
};


#define NXT_HTTP_DATE_LEN  nxt_length("Wed, 31 Dec 1986 16:40:00 GMT")

nxt_inline u_char *
nxt_http_date(u_char *buf, struct tm *tm)
{
    static const char * const  week[] = { "Sun", "Mon", "Tue", "Wed", "Thu",
                                          "Fri", "Sat" };

    static const char * const  month[] = { "Jan", "Feb", "Mar", "Apr", "May",
                                           "Jun", "Jul", "Aug", "Sep", "Oct",
                                           "Nov", "Dec" };

    return nxt_sprintf(buf, buf + NXT_HTTP_DATE_LEN,
                       "%s, %02d %s %4d %02d:%02d:%02d GMT",
                       week[tm->tm_wday], tm->tm_mday,
                       month[tm->tm_mon], tm->tm_year + 1900,
                       tm->tm_hour, tm->tm_min, tm->tm_sec);
}


nxt_int_t nxt_http_init(nxt_task_t *task);
nxt_int_t nxt_h1p_init(nxt_task_t *task);
nxt_int_t nxt_http_response_hash_init(nxt_task_t *task);

void nxt_http_conn_init(nxt_task_t *task, void *obj, void *data);
nxt_http_request_t *nxt_http_request_create(nxt_task_t *task);
void nxt_http_request_error(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_status_t status);
void nxt_http_request_read_body(nxt_task_t *task, nxt_http_request_t *r);
void nxt_http_request_header_send(nxt_task_t *task, nxt_http_request_t *r,
    nxt_work_handler_t body_handler, void *data);
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

nxt_array_t *nxt_http_arguments_parse(nxt_http_request_t *r);
nxt_array_t *nxt_http_cookies_parse(nxt_http_request_t *r);

int64_t nxt_http_field_hash(nxt_mp_t *mp, nxt_str_t *name,
    nxt_bool_t case_sensitive, uint8_t encoding);
int64_t nxt_http_argument_hash(nxt_mp_t *mp, nxt_str_t *name);
int64_t nxt_http_header_hash(nxt_mp_t *mp, nxt_str_t *name);
int64_t nxt_http_cookie_hash(nxt_mp_t *mp, nxt_str_t *name);

nxt_http_routes_t *nxt_http_routes_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_conf_value_t *routes_conf);
nxt_http_action_t *nxt_http_action_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_str_t *pass);
nxt_int_t nxt_http_routes_resolve(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf);
nxt_int_t nxt_http_pass_segments(nxt_mp_t *mp, nxt_str_t *pass,
    nxt_str_t *segments, nxt_uint_t n);
nxt_http_action_t *nxt_http_pass_application(nxt_task_t *task,
    nxt_router_conf_t *rtcf, nxt_str_t *name);
nxt_http_route_addr_rule_t *nxt_http_route_addr_rule_create(
    nxt_task_t *task, nxt_mp_t *mp, nxt_conf_value_t *cv);
nxt_int_t nxt_http_route_addr_rule(nxt_http_request_t *r,
    nxt_http_route_addr_rule_t *addr_rule, nxt_sockaddr_t *sockaddr);
nxt_http_route_rule_t *nxt_http_route_types_rule_create(nxt_task_t *task,
    nxt_mp_t *mp, nxt_conf_value_t *types);
nxt_int_t nxt_http_route_test_rule(nxt_http_request_t *r,
    nxt_http_route_rule_t *rule, u_char *start, size_t length);

nxt_int_t nxt_http_action_init(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_conf_value_t *cv, nxt_http_action_t *action);
void nxt_http_request_action(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_action_t *action);

nxt_int_t nxt_upstreams_create(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_conf_value_t *conf);
nxt_int_t nxt_upstreams_joint_create(nxt_router_temp_conf_t *tmcf,
    nxt_upstream_t ***upstream_joint);

nxt_int_t nxt_http_rewrite_init(nxt_router_conf_t *rtcf,
    nxt_http_action_t *action, nxt_http_action_conf_t *acf);
nxt_int_t nxt_http_rewrite(nxt_task_t *task, nxt_http_request_t *r);

nxt_int_t nxt_http_set_headers_init(nxt_router_conf_t *rtcf,
    nxt_http_action_t *action, nxt_http_action_conf_t *acf);
nxt_int_t nxt_http_set_headers(nxt_http_request_t *r);

nxt_int_t nxt_http_return_init(nxt_router_conf_t *rtcf,
    nxt_http_action_t *action, nxt_http_action_conf_t *acf);

nxt_int_t nxt_http_static_init(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_http_action_t *action, nxt_http_action_conf_t *acf);
nxt_int_t nxt_http_static_mtypes_init(nxt_mp_t *mp, nxt_lvlhsh_t *hash);
nxt_int_t nxt_http_static_mtypes_hash_add(nxt_mp_t *mp, nxt_lvlhsh_t *hash,
    const nxt_str_t *exten, nxt_str_t *type);
nxt_str_t *nxt_http_static_mtype_get(nxt_lvlhsh_t *hash,
    const nxt_str_t *exten);

nxt_http_action_t *nxt_http_application_handler(nxt_task_t *task,
    nxt_http_request_t *r, nxt_http_action_t *action);
nxt_int_t nxt_upstream_find(nxt_upstreams_t *upstreams, nxt_str_t *name,
    nxt_http_action_t *action);
nxt_http_action_t *nxt_upstream_proxy_handler(nxt_task_t *task,
    nxt_http_request_t *r, nxt_upstream_t *upstream);

nxt_int_t nxt_http_proxy_init(nxt_mp_t *mp, nxt_http_action_t *action,
    nxt_http_action_conf_t *acf);
nxt_int_t nxt_http_proxy_date(void *ctx, nxt_http_field_t *field,
    uintptr_t data);
nxt_int_t nxt_http_proxy_content_length(void *ctx, nxt_http_field_t *field,
    uintptr_t data);
nxt_int_t nxt_http_proxy_skip(void *ctx, nxt_http_field_t *field,
    uintptr_t data);
nxt_buf_t *nxt_http_proxy_buf_mem_alloc(nxt_task_t *task, nxt_http_request_t *r,
    size_t size);
void nxt_http_proxy_buf_mem_free(nxt_task_t *task, nxt_http_request_t *r,
    nxt_buf_t *b);

extern nxt_time_string_t  nxt_http_date_cache;

extern nxt_lvlhsh_t                        nxt_response_fields_hash;

extern const nxt_http_proto_table_t  nxt_http_proto[];

void nxt_h1p_websocket_first_frame_start(nxt_task_t *task,
    nxt_http_request_t *r, nxt_buf_t *ws_frame);
void nxt_h1p_websocket_frame_start(nxt_task_t *task, nxt_http_request_t *r,
    nxt_buf_t *ws_frame);
void nxt_h1p_complete_buffers(nxt_task_t *task, nxt_h1proto_t *h1p,
    nxt_bool_t all);
nxt_msec_t nxt_h1p_conn_request_timer_value(nxt_conn_t *c, uintptr_t data);

extern const nxt_conn_state_t  nxt_h1p_idle_close_state;

#endif  /* _NXT_HTTP_H_INCLUDED_ */

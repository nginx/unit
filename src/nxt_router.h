
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_ROUTER_H_INCLUDED_
#define _NXT_ROUTER_H_INCLUDED_


#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_main_process.h>

typedef struct nxt_http_request_s  nxt_http_request_t;
#include <nxt_application.h>


typedef struct nxt_http_action_s        nxt_http_action_t;
typedef struct nxt_http_routes_s        nxt_http_routes_t;
typedef struct nxt_http_forward_s       nxt_http_forward_t;
typedef struct nxt_upstream_s           nxt_upstream_t;
typedef struct nxt_upstreams_s          nxt_upstreams_t;
typedef struct nxt_router_access_log_s  nxt_router_access_log_t;


#define NXT_HTTP_ACTION_ERROR  ((nxt_http_action_t *) -1)


typedef struct {
    nxt_thread_spinlock_t    lock;
    nxt_queue_t              engines;

    nxt_queue_t              sockets;  /* of nxt_socket_conf_t */
    nxt_queue_t              apps;     /* of nxt_app_t */

    nxt_router_access_log_t  *access_log;
} nxt_router_t;


typedef struct {
    uint32_t                 count;
    uint32_t                 threads;

    nxt_mp_t                 *mem_pool;
    nxt_tstr_state_t         *tstr_state;

    nxt_router_t             *router;
    nxt_http_routes_t        *routes;
    nxt_upstreams_t          *upstreams;

    nxt_lvlhsh_t             mtypes_hash;
    nxt_lvlhsh_t             apps_hash;

    nxt_router_access_log_t  *access_log;
    nxt_tstr_t               *log_format;
    nxt_tstr_t               *log_expr;
    uint8_t                  log_negate;  /* 1 bit */
} nxt_router_conf_t;


typedef struct {
    nxt_event_engine_t     *engine;
    nxt_work_t             *jobs;

    enum {
        NXT_ROUTER_ENGINE_KEEP = 0,
        NXT_ROUTER_ENGINE_ADD,
        NXT_ROUTER_ENGINE_DELETE,
    }                      action;
} nxt_router_engine_conf_t;


typedef struct {
#if (NXT_TLS)
    nxt_queue_t            tls;        /* of nxt_router_tlssock_t */
#endif

#if (NXT_HAVE_NJS)
    nxt_queue_t            js_modules;
#endif

    nxt_queue_t            apps;       /* of nxt_app_t */
    nxt_queue_t            previous;   /* of nxt_app_t */

    uint32_t               new_threads;
    uint32_t               stream;
    uint32_t               count;

    nxt_event_engine_t     *engine;
    nxt_port_t             *port;
    nxt_array_t            *engines;
    nxt_router_conf_t      *router_conf;
    nxt_mp_t               *mem_pool;
} nxt_router_temp_conf_t;


typedef struct {
    nxt_task_t              task;
    nxt_work_t              work;
    nxt_router_temp_conf_t  *tmcf;
} nxt_joint_job_t;


typedef struct {
    uint32_t               use_count;
    nxt_app_t              *app;
    nxt_timer_t            idle_timer;
    nxt_work_t             free_app_work;
} nxt_app_joint_t;


struct nxt_app_s {
    nxt_thread_mutex_t     mutex;       /* Protects ports queue. */
    nxt_queue_t            ports;       /* of nxt_port_t.app_link */
    nxt_lvlhsh_t           port_hash;   /* of nxt_port_t */

    nxt_queue_t            spare_ports; /* of nxt_port_t.idle_link */
    nxt_queue_t            idle_ports;  /* of nxt_port_t.idle_link */
    nxt_work_t             adjust_idle_work;
    nxt_event_engine_t     *engine;

    nxt_str_t              name;

    uint32_t               port_hash_count;

    uint32_t               active_requests;
    uint32_t               pending_processes;
    uint32_t               processes;
    uint32_t               idle_processes;

    uint32_t               max_processes;
    uint32_t               spare_processes;
    uint32_t               max_pending_processes;

    uint32_t               generation;
    uint32_t               proto_port_requests;

    nxt_msec_t             timeout;
    nxt_msec_t             idle_timeout;

    nxt_str_t              *targets;

    nxt_app_type_t         type:8;

    nxt_mp_t               *mem_pool;
    nxt_queue_link_t       link;

    nxt_str_t              conf;

    nxt_atomic_t           use_count;
    nxt_queue_t            ack_waiting_req; /* of nxt_http_request_t.app_link */

    nxt_app_joint_t        *joint;
    nxt_port_t             *shared_port;
    nxt_port_t             *proto_port;

    nxt_port_mmaps_t       outgoing;
};


typedef struct {
    size_t                 max_frame_size;
    nxt_msec_t             read_timeout;
    nxt_msec_t             keepalive_interval;
} nxt_websocket_conf_t;


typedef struct {
    uint32_t               count;
    nxt_queue_link_t       link;
    nxt_router_conf_t      *router_conf;

    nxt_http_action_t      *action;

    /*
     * A listen socket time can be shorter than socket configuration life
     * time, so a copy of the non-wildcard socket sockaddr is stored here
     * to be used as a local sockaddr in connections.
     */
    nxt_sockaddr_t         *sockaddr;

    nxt_listen_socket_t    *listen;

    size_t                 header_buffer_size;
    size_t                 large_header_buffer_size;
    size_t                 large_header_buffers;
    size_t                 body_buffer_size;
    size_t                 max_body_size;
    size_t                 proxy_header_buffer_size;
    size_t                 proxy_buffer_size;
    size_t                 proxy_buffers;

    nxt_msec_t             idle_timeout;
    nxt_msec_t             header_read_timeout;
    nxt_msec_t             body_read_timeout;
    nxt_msec_t             send_timeout;
    nxt_msec_t             proxy_timeout;
    nxt_msec_t             proxy_send_timeout;
    nxt_msec_t             proxy_read_timeout;

    nxt_websocket_conf_t   websocket_conf;

    nxt_str_t              body_temp_path;

    uint8_t                log_route;  /* 1 bit */

    uint8_t                discard_unsafe_fields;  /* 1 bit */

    uint8_t                server_version;         /* 1 bit */

    nxt_http_forward_t     *forwarded;
    nxt_http_forward_t     *client_ip;

#if (NXT_TLS)
    nxt_tls_conf_t         *tls;
#endif
} nxt_socket_conf_t;


typedef struct {
    uint32_t               count;
    nxt_queue_link_t       link;
    nxt_event_engine_t     *engine;
    nxt_socket_conf_t      *socket_conf;

    nxt_joint_job_t        *close_job;

    nxt_upstream_t         **upstreams;

    /* Modules configuraitons. */
} nxt_socket_conf_joint_t;


struct nxt_router_access_log_s {
    void                   (*handler)(nxt_task_t *task, nxt_http_request_t *r,
                                      nxt_router_access_log_t *access_log,
                                      nxt_tstr_t *format);
    nxt_fd_t               fd;
    nxt_str_t              path;
    uint32_t               count;
};


void nxt_router_process_http_request(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_action_t *action);
void nxt_router_app_port_close(nxt_task_t *task, nxt_port_t *port);
nxt_int_t nxt_router_application_init(nxt_router_conf_t *rtcf, nxt_str_t *name,
    nxt_str_t *target, nxt_http_action_t *action);
void nxt_router_listen_event_release(nxt_task_t *task, nxt_listen_event_t *lev,
    nxt_socket_conf_joint_t *joint);

void nxt_router_conf_apply(nxt_task_t *task, void *obj, void *data);
void nxt_router_conf_error(nxt_task_t *task, nxt_router_temp_conf_t *tmcf);
void nxt_router_conf_release(nxt_task_t *task, nxt_socket_conf_joint_t *joint);

nxt_int_t nxt_router_access_log_create(nxt_task_t *task,
    nxt_router_conf_t *rtcf, nxt_conf_value_t *value);
void nxt_router_access_log_open(nxt_task_t *task, nxt_router_temp_conf_t *tmcf);
void nxt_router_access_log_use(nxt_thread_spinlock_t *lock,
    nxt_router_access_log_t *access_log);
void nxt_router_access_log_release(nxt_task_t *task,
    nxt_thread_spinlock_t *lock, nxt_router_access_log_t *access_log);
void nxt_router_access_log_reopen_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);


extern nxt_router_t  *nxt_router;


#endif  /* _NXT_ROUTER_H_INCLUDED_ */

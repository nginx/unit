
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_ROUTER_H_INCLUDED_
#define _NXT_ROUTER_H_INCLUDED_


#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_main_process.h>
#include <nxt_application.h>


typedef struct {
    nxt_thread_spinlock_t  lock;
    nxt_queue_t            engines;

    nxt_queue_t            sockets;    /* of nxt_socket_conf_t */
    nxt_queue_t            apps;       /* of nxt_app_t */
} nxt_router_t;


typedef struct {
    uint32_t               count;
    uint32_t               threads;
    nxt_router_t           *router;
    nxt_mp_t               *mem_pool;
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
    nxt_queue_t            creating;   /* of nxt_socket_conf_t */
    nxt_queue_t            pending;    /* of nxt_socket_conf_t */
    nxt_queue_t            updating;   /* of nxt_socket_conf_t */
    nxt_queue_t            keeping;    /* of nxt_socket_conf_t */
    nxt_queue_t            deleting;   /* of nxt_socket_conf_t */

    nxt_queue_t            apps;       /* of nxt_app_t */
    nxt_queue_t            previous;   /* of nxt_app_t */

    uint32_t               new_threads;
    uint32_t               stream;
    uint32_t               count;

    nxt_event_engine_t     *engine;
    nxt_port_t             *port;
    nxt_array_t            *engines;
    nxt_router_conf_t      *conf;
    nxt_mp_t               *mem_pool;
} nxt_router_temp_conf_t;


typedef struct {
    nxt_task_t              task;
    nxt_work_t              work;
    nxt_router_temp_conf_t  *tmcf;
} nxt_joint_job_t;



typedef nxt_int_t (*nxt_app_prepare_msg_t)(nxt_task_t *task,
    nxt_app_request_t *r, nxt_app_wmsg_t *wmsg);


struct nxt_app_s {
    nxt_thread_mutex_t     mutex;    /* Protects ports queue. */
    nxt_queue_t            ports;    /* of nxt_port_t.app_link */

    nxt_queue_t            requests; /* of nxt_req_conn_link_t */
    nxt_str_t              name;

    uint32_t               pending_workers;
    uint32_t               workers;
    uint32_t               max_workers;
    uint32_t               max_pending_responses;

    nxt_msec_t             timeout;

    nxt_app_type_t         type:8;
    uint8_t                live;   /* 1 bit */

    nxt_queue_link_t       link;

    nxt_str_t              conf;
    nxt_app_prepare_msg_t  prepare_msg;

    nxt_atomic_t           use_count;
};


typedef struct {
    uint32_t               count;
    nxt_queue_link_t       link;
    nxt_router_conf_t      *router_conf;

    nxt_app_t              *application;

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
    nxt_msec_t             header_read_timeout;
    nxt_msec_t             body_read_timeout;
} nxt_socket_conf_t;


typedef struct {
    uint32_t               count;
    nxt_queue_link_t       link;
    nxt_event_engine_t     *engine;
    nxt_socket_conf_t      *socket_conf;

    /* Modules configuraitons. */
} nxt_socket_conf_joint_t;


void nxt_router_new_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_router_conf_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_router_remove_pid_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);

void nxt_router_app_port_close(nxt_task_t *task, nxt_port_t *port);
void nxt_router_app_use(nxt_task_t *task, nxt_app_t *app, int i);

#endif  /* _NXT_ROUTER_H_INCLUDED_ */

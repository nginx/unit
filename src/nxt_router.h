
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_ROUTER_H_INCLUDED_
#define _NXT_ROUTER_H_INCLUDED_


#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_master_process.h>
#include <nxt_application.h>


typedef struct {
    nxt_thread_spinlock_t  lock;
    nxt_queue_t            engines;

    nxt_queue_t            sockets;    /* of nxt_socket_conf_t */
    nxt_queue_t            apps;       /* of nxt_app_t */

    nxt_lvlhsh_t           start_workers; /* stream to nxt_start_worker_t */
} nxt_router_t;


typedef struct {
    uint32_t               count;
    uint32_t               threads;
    nxt_router_t           *router;
    nxt_mp_t               *mem_pool;
} nxt_router_conf_t;


typedef struct {
    nxt_event_engine_t     *engine;
    nxt_array_t            *creating;  /* of nxt_work_t */
    nxt_array_t            *updating;  /* of nxt_work_t */
    nxt_array_t            *deleting;  /* of nxt_work_t */
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


typedef struct nxt_app_module_s  nxt_app_module_t;
typedef struct nxt_app_s  nxt_app_t;

struct nxt_app_s {
    nxt_thread_mutex_t     mutex;
    nxt_queue_t            ports;
    nxt_queue_t            requests; /* of nxt_req_conn_link_t */
    nxt_str_t              name;

    uint32_t               workers;
    uint32_t               max_workers;

    nxt_app_type_t         type:8;
    uint8_t                live;   /* 1 bit */

    nxt_queue_link_t       link;

    nxt_str_t              conf;
    nxt_app_module_t       *module;
};


typedef struct {
    uint32_t               count;
    nxt_socket_t           fd;
} nxt_router_socket_t;


typedef struct {
    uint32_t               count;
    nxt_queue_link_t       link;
    nxt_router_socket_t    *socket;
    nxt_router_conf_t      *router_conf;
    nxt_sockaddr_t         *sockaddr;

    nxt_app_t              *application;

    nxt_listen_socket_t    listen;

    size_t                 header_buffer_size;
    size_t                 large_header_buffer_size;
    nxt_msec_t             header_read_timeout;
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

void nxt_router_app_remove_port(nxt_port_t *port);

#endif  /* _NXT_ROUTER_H_INCLUDED_ */

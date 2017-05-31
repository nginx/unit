
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_ROUTER_H_INCLUDED_
#define _NXT_ROUTER_H_INCLUDED_


#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_master_process.h>


typedef struct {
    nxt_thread_spinlock_t  lock;
    nxt_queue_t            engines;

    nxt_queue_t            sockets;
} nxt_router_t;


typedef struct {
    uint32_t               count;
    uint32_t               threads;
    nxt_router_t           *router;
    nxt_mem_pool_t         *mem_pool;
} nxt_router_conf_t;


typedef struct {
    nxt_event_engine_t     *engine;
    nxt_task_t             task;
    nxt_array_t            *creating;  /* of nxt_work_t */
    nxt_array_t            *updating;  /* of nxt_work_t */
    nxt_array_t            *deleting;  /* of nxt_work_t */
} nxt_router_engine_conf_t;


typedef struct {
    nxt_queue_t            creating;
    nxt_queue_t            pending;
    nxt_queue_t            updating;
    nxt_queue_t            keeping;
    nxt_queue_t            deleting;

    uint32_t               new_threads;

    nxt_array_t            *engines;
    nxt_router_conf_t      *conf;
    nxt_mem_pool_t         *mem_pool;
} nxt_router_temp_conf_t;


typedef struct {
    uint32_t               count;
    nxt_listen_socket_t    listen;
    nxt_queue_link_t       link;
    nxt_router_conf_t      *router_conf;

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


#endif  /* _NXT_ROUTER_H_INCLUDED_ */

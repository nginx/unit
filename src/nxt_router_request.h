
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_ROUTER_REQUEST_H_INCLUDED_
#define _NXT_ROUTER_REQUEST_H_INCLUDED_


typedef struct nxt_msg_info_s {
    nxt_buf_t                 *buf;
    nxt_port_mmap_tracking_t  tracking;
    nxt_work_handler_t        completion_handler;
} nxt_msg_info_t;


typedef struct nxt_request_app_link_s  nxt_request_app_link_t;


typedef enum {
    NXT_APR_NEW_PORT,
    NXT_APR_REQUEST_FAILED,
    NXT_APR_GOT_RESPONSE,
    NXT_APR_UPGRADE,
    NXT_APR_CLOSE,
} nxt_apr_action_t;


typedef struct {
    uint32_t                stream;
    nxt_app_t               *app;

    nxt_port_t              *app_port;
    nxt_apr_action_t        apr_action;

    nxt_http_request_t      *request;
    nxt_msg_info_t          msg_info;
    nxt_request_app_link_t  *req_app_link;
} nxt_request_rpc_data_t;


struct nxt_request_app_link_s {
    uint32_t                stream;
    nxt_atomic_t            use_count;

    nxt_port_t              *app_port;
    nxt_apr_action_t        apr_action;

    nxt_port_t              *reply_port;
    nxt_http_request_t      *request;
    nxt_msg_info_t          msg_info;
    nxt_request_rpc_data_t  *req_rpc_data;

    nxt_nsec_t              res_time;

    nxt_queue_link_t        link_app_requests; /* for nxt_app_t.requests */
    /* for nxt_port_t.pending_requests */
    nxt_queue_link_t        link_port_pending;
    nxt_queue_link_t        link_app_pending;  /* for nxt_app_t.pending */
    /* for nxt_port_t.active_websockets */
    nxt_queue_link_t        link_port_websockets;

    nxt_mp_t                *mem_pool;
    nxt_work_t              work;

    int                     err_code;
    const char              *err_str;
};


#endif /* _NXT_ROUTER_REQUEST_H_INCLUDED_ */

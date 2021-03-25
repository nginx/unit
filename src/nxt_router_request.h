
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_ROUTER_REQUEST_H_INCLUDED_
#define _NXT_ROUTER_REQUEST_H_INCLUDED_


typedef struct {
    nxt_buf_t                 *buf;
    nxt_fd_t                  body_fd;
    uint32_t                  tracking_cookie;
} nxt_msg_info_t;


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

    nxt_bool_t              rpc_cancel;
} nxt_request_rpc_data_t;


#endif /* _NXT_ROUTER_REQUEST_H_INCLUDED_ */

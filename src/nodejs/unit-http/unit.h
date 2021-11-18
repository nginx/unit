
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_NODEJS_UNIT_H_INCLUDED_
#define _NXT_NODEJS_UNIT_H_INCLUDED_

#include "nxt_napi.h"


class Unit : public nxt_napi {
public:
    static napi_value init(napi_env env, napi_value exports);

private:
    Unit(napi_env env, napi_value jsthis);
    ~Unit();

    static napi_value create(napi_env env, napi_callback_info info);
    static void destroy(napi_env env, void *nativeObject, void *finalize_hint);
    static void conn_destroy(napi_env env, void *nativeObject, void *finalize_hint);
    static void sock_destroy(napi_env env, void *nativeObject, void *finalize_hint);
    static void req_destroy(napi_env env, void *nativeObject, void *finalize_hint);
    static void resp_destroy(napi_env env, void *nativeObject, void *finalize_hint);

    static napi_value create_server(napi_env env, napi_callback_info info);
    static napi_value listen(napi_env env, napi_callback_info info);
    static napi_value _read(napi_env env, napi_callback_info info);

    static void request_handler_cb(nxt_unit_request_info_t *req);
    void request_handler(nxt_unit_request_info_t *req);

    static void websocket_handler_cb(nxt_unit_websocket_frame_t *ws);
    void websocket_handler(nxt_unit_websocket_frame_t *ws);

    static void close_handler_cb(nxt_unit_request_info_t *req);
    void close_handler(nxt_unit_request_info_t *req);

    static void shm_ack_handler_cb(nxt_unit_ctx_t *ctx);
    void shm_ack_handler(nxt_unit_ctx_t *ctx);

    static int add_port(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port);
    static void remove_port(nxt_unit_t *unit, nxt_unit_ctx_t *ctx,
                            nxt_unit_port_t *port);

    static void quit_cb(nxt_unit_ctx_t *ctx);
    void quit(nxt_unit_ctx_t *ctx);

    napi_value get_server_object();

    napi_value create_socket(napi_value server_obj,
                             nxt_unit_request_info_t *req);

    napi_value create_request(napi_value server_obj, napi_value socket,
                              nxt_unit_request_info_t *req);

    napi_value create_response(napi_value server_obj, napi_value request,
                               nxt_unit_request_info_t *req);

    napi_value create_websocket_frame(napi_value server_obj,
                                      nxt_unit_websocket_frame_t *ws);

    static napi_value request_read(napi_env env, napi_callback_info info);

    static napi_value response_send_headers(napi_env env,
                                            napi_callback_info info);

    static napi_value response_write(napi_env env, napi_callback_info info);
    static napi_value response_end(napi_env env, napi_callback_info info);
    static napi_value websocket_send_frame(napi_env env,
                                           napi_callback_info info);
    static napi_value websocket_set_sock(napi_env env, napi_callback_info info);

    void create_headers(nxt_unit_request_info_t *req, napi_value request);

    void append_header(nxt_unit_field_t *f, napi_value headers,
                       napi_value raw_headers, uint32_t idx);

    static napi_ref constructor_;

    napi_ref        wrapper_;
    nxt_unit_ctx_t  *unit_ctx_;
};


#endif /* _NXT_NODEJS_UNIT_H_INCLUDED_ */

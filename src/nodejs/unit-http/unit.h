
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_NODEJS_UNIT_H_INCLUDED_
#define _NXT_NODEJS_UNIT_H_INCLUDED_

#include <node_api.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "version.h"
#include <nxt_unit.h>

#if NXT_VERNUM != NXT_NODE_VERNUM
#error "libunit version mismatch."
#endif

#include <nxt_unit_response.h>
#include <nxt_unit_request.h>


#ifdef __cplusplus
} /* extern "C" */
#endif


class Unit {
public:
    static napi_value init(napi_env env, napi_value exports);

private:
    Unit(napi_env env);
    ~Unit();

    static napi_value create(napi_env env, napi_callback_info info);
    static void destroy(napi_env env, void *nativeObject, void *finalize_hint);

    static napi_value create_server(napi_env env, napi_callback_info info);
    static napi_value listen(napi_env env, napi_callback_info info);
    static napi_value _read(napi_env env, napi_callback_info info);
    static void request_handler(nxt_unit_request_info_t *req);
    static int add_port(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port);
    static void remove_port(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id);
    static void quit(nxt_unit_ctx_t *ctx);

    napi_value get_server_object();

    napi_value create_socket(napi_value server_obj,
                             nxt_unit_request_info_t *req);

    napi_value create_request(napi_value server_obj, napi_value socket);

    napi_value create_response(napi_value server_obj, napi_value socket,
                               napi_value request,
                               nxt_unit_request_info_t *req, Unit *obj);

    static napi_value response_send_headers(napi_env env,
                                            napi_callback_info info);

    static napi_value response_write(napi_env env, napi_callback_info info);
    static napi_value response_end(napi_env env, napi_callback_info info);

    napi_status create_headers(nxt_unit_request_info_t *req,
                               napi_value request);

    inline napi_status append_header(nxt_unit_field_t *f, napi_value headers,
                                     napi_value raw_headers, uint32_t idx);

    static napi_ref constructor_;

    napi_env        env_;
    napi_ref        wrapper_;
    nxt_unit_ctx_t  *unit_ctx_;
};


#endif /* _NXT_NODEJS_H_INCLUDED_ */

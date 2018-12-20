
/*
 * Copyright (C) NGINX, Inc.
 */

#include "unit.h"

#include <unistd.h>
#include <fcntl.h>

#include <uv.h>


napi_ref Unit::constructor_;


struct nxt_nodejs_ctx_t {
    nxt_unit_port_id_t  port_id;
    uv_poll_t           poll;
};


Unit::Unit(napi_env env):
    env_(env),
    wrapper_(nullptr),
    unit_ctx_(nullptr)
{
}


Unit::~Unit()
{
    napi_delete_reference(env_, wrapper_);
}


napi_value
Unit::init(napi_env env, napi_value exports)
{
    napi_value   cons, fn;
    napi_status  status;

    napi_property_descriptor  properties[] = {
        { "createServer", 0, create_server, 0, 0, 0, napi_default, 0 },
        { "listen", 0, listen, 0, 0, 0, napi_default, 0 },
        { "_read", 0, _read, 0, 0, 0, napi_default, 0 }
    };

    status = napi_define_class(env, "Unit", NAPI_AUTO_LENGTH, create, nullptr,
                               3, properties, &cons);
    if (status != napi_ok) {
        goto failed;
    }

    status = napi_create_reference(env, cons, 1, &constructor_);
    if (status != napi_ok) {
        goto failed;
    }

    status = napi_set_named_property(env, exports, "Unit", cons);
    if (status != napi_ok) {
        goto failed;
    }

    status = napi_create_function(env, NULL, 0, response_send_headers, NULL,
                                  &fn);
    if (status != napi_ok) {
        goto failed;
    }

    status = napi_set_named_property(env, exports,
                                     "unit_response_headers", fn);
    if (status != napi_ok) {
        goto failed;
    }

    status = napi_create_function(env, NULL, 0, response_write, NULL, &fn);
    if (status != napi_ok) {
        goto failed;
    }

    status = napi_set_named_property(env, exports, "unit_response_write", fn);
    if (status != napi_ok) {
        goto failed;
    }

    status = napi_create_function(env, NULL, 0, response_end, NULL, &fn);
    if (status != napi_ok) {
        goto failed;
    }

    status = napi_set_named_property(env, exports, "unit_response_end", fn);
    if (status != napi_ok) {
        goto failed;
    }

    return exports;

failed:

    napi_throw_error(env, NULL, "Failed to define Unit class");

    return nullptr;
}


void
Unit::destroy(napi_env env, void *nativeObject, void *finalize_hint)
{
    Unit  *obj = reinterpret_cast<Unit *>(nativeObject);

    delete obj;
}


napi_value
Unit::create(napi_env env, napi_callback_info info)
{
    Unit         *obj;
    napi_ref     ref;
    napi_value   target, cons, instance, jsthis;
    napi_status  status;

    status = napi_get_new_target(env, info, &target);
    if (status != napi_ok) {
        goto failed;
    }

    if (target != nullptr) {
        /* Invoked as constructor: `new Unit(...)` */
        status = napi_get_cb_info(env, info, nullptr, nullptr, &jsthis,
                                  nullptr);
        if (status != napi_ok) {
            goto failed;
        }

        obj = new Unit(env);

        status = napi_wrap(env, jsthis, reinterpret_cast<void *>(obj),
                           destroy, nullptr, &obj->wrapper_);
        if (status != napi_ok) {
            goto failed;
        }

        status = napi_create_reference(env, jsthis, 1, &ref);
        if (status != napi_ok) {
            goto failed;
        }

        return jsthis;
    }

    /* Invoked as plain function `Unit(...)`, turn into construct call. */
    status = napi_get_reference_value(env, constructor_, &cons);
    if (status != napi_ok) {
        goto failed;
    }

    status = napi_new_instance(env, cons, 0, nullptr, &instance);
    if (status != napi_ok) {
        goto failed;
    }

    status = napi_create_reference(env, instance, 1, &ref);
    if (status != napi_ok) {
        goto failed;
    }

    return instance;

failed:

    napi_throw_error(env, NULL, "Failed to create Unit object");

    return nullptr;
}


napi_value
Unit::create_server(napi_env env, napi_callback_info info)
{
    Unit             *obj;
    size_t           argc;
    napi_value       jsthis, argv;
    napi_status      status;
    nxt_unit_init_t  unit_init;

    argc = 1;

    status = napi_get_cb_info(env, info, &argc, &argv, &jsthis, nullptr);
    if (status != napi_ok) {
        goto failed;
    }

    status = napi_unwrap(env, jsthis, reinterpret_cast<void **>(&obj));
    if (status != napi_ok) {
        goto failed;
    }

    memset(&unit_init, 0, sizeof(nxt_unit_init_t));

    unit_init.data = obj;
    unit_init.callbacks.request_handler = request_handler;
    unit_init.callbacks.add_port        = add_port;
    unit_init.callbacks.remove_port     = remove_port;
    unit_init.callbacks.quit            = quit;

    obj->unit_ctx_ = nxt_unit_init(&unit_init);
    if (obj->unit_ctx_ == NULL) {
        goto failed;
    }

    return nullptr;

failed:

    napi_throw_error(env, NULL, "Failed to create Unit object");

    return nullptr;
}


napi_value
Unit::listen(napi_env env, napi_callback_info info)
{
    return nullptr;
}


napi_value
Unit::_read(napi_env env, napi_callback_info info)
{
    Unit                     *obj;
    void                     *data;
    size_t                   argc;
    int64_t                  req_pointer;
    napi_value               jsthis, buffer, argv;
    napi_status              status;
    nxt_unit_request_info_t  *req;

    argc = 1;

    status = napi_get_cb_info(env, info, &argc, &argv, &jsthis, nullptr);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get arguments from js");
        return nullptr;
    }

    status = napi_unwrap(env, jsthis, reinterpret_cast<void **>(&obj));
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get Unit object form js");
        return nullptr;
    }

    status = napi_get_value_int64(env, argv, &req_pointer);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get request pointer");
        return nullptr;
    }

    req = (nxt_unit_request_info_t *) (uintptr_t) req_pointer;

    status = napi_create_buffer(env, (size_t) req->content_length,
                                &data, &buffer);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to create request buffer");
        return nullptr;
    }

    nxt_unit_request_read(req, data, req->content_length);

    return buffer;
}


void
Unit::request_handler(nxt_unit_request_info_t *req)
{
    Unit                 *obj;
    napi_value           socket, request, response, global, server_obj, except;
    napi_value           emit_events, events_res, async_name, resource_object;
    napi_status          status;
    napi_async_context   async_context;
    napi_callback_scope  async_scope;
    napi_value           events_args[3];

    obj = reinterpret_cast<Unit *>(req->unit->data);

    napi_handle_scope scope;
    status = napi_open_handle_scope(obj->env_, &scope);
    if (status != napi_ok) {
        napi_throw_error(obj->env_, NULL, "Failed to create handle scope");
        return;
    }

    server_obj = obj->get_server_object();
    if (server_obj == nullptr) {
        napi_throw_error(obj->env_, NULL, "Failed to get server object");
        return;
    }

    status = napi_get_global(obj->env_, &global);
    if (status != napi_ok) {
        napi_throw_error(obj->env_, NULL, "Failed to get global variable");
        return;
    }

    socket = obj->create_socket(server_obj, req);
    if (socket == nullptr) {
        napi_throw_error(obj->env_, NULL, "Failed to create socket object");
        return;
    }

    request = obj->create_request(server_obj, socket);
    if (request == nullptr) {
        napi_throw_error(obj->env_, NULL, "Failed to create request object");
        return;
    }

    response = obj->create_response(server_obj, socket, request, req, obj);
    if (response == nullptr) {
        napi_throw_error(obj->env_, NULL, "Failed to create response object");
        return;
    }

    status = obj->create_headers(req, request);
    if (status != napi_ok) {
        napi_throw_error(obj->env_, NULL, "Failed to create headers");
        return;
    }

    status = napi_get_named_property(obj->env_, server_obj, "emit_events",
                                     &emit_events);
    if (status != napi_ok) {
        napi_throw_error(obj->env_, NULL, "Failed to get "
                         "'emit_events' function");
        return;
    }

    events_args[0] = server_obj;
    events_args[1] = request;
    events_args[2] = response;

    status = napi_create_string_utf8(obj->env_, "unit_request_handler",
                                     sizeof("unit_request_handler") - 1,
                                     &async_name);
    if (status != napi_ok) {
        napi_throw_error(obj->env_, NULL, "Failed to create utf-8 string");
        return;
    }

    status = napi_async_init(obj->env_, NULL, async_name, &async_context);
    if (status != napi_ok) {
        napi_throw_error(obj->env_, NULL, "Failed to init async object");
        return;
    }

    status = napi_create_object(obj->env_, &resource_object);
    if (status != napi_ok) {
        napi_throw_error(obj->env_, NULL, "Failed to create object for "
                         "callback scope");
        return;
    }

    status = napi_open_callback_scope(obj->env_, resource_object, async_context,
                                      &async_scope);
    if (status != napi_ok) {
        napi_throw_error(obj->env_, NULL, "Failed to open callback scope");
        return;
    }

    status = napi_make_callback(obj->env_, async_context, server_obj,
                                emit_events, 3, events_args, &events_res);
    if (status != napi_ok) {
        if (status != napi_pending_exception) {
            napi_throw_error(obj->env_, NULL, "Failed to make callback");
            return;
        }

        status = napi_get_and_clear_last_exception(obj->env_, &except);
        if (status != napi_ok) {
            napi_throw_error(obj->env_, NULL,
                             "Failed to get and clear last exception");
            return;
        }

        /* Logging a description of the error and call stack. */
        status = napi_fatal_exception(obj->env_, except);
        if (status != napi_ok) {
            napi_throw_error(obj->env_, NULL, "Failed to call "
                             "napi_fatal_exception() function");
            return;
        }
    }

    status = napi_close_callback_scope(obj->env_, async_scope);
    if (status != napi_ok) {
        napi_throw_error(obj->env_, NULL, "Failed to close callback scope");
        return;
    }

    status = napi_async_destroy(obj->env_, async_context);
    if (status != napi_ok) {
        napi_throw_error(obj->env_, NULL, "Failed to destroy async object");
        return;
    }

    status = napi_close_handle_scope(obj->env_, scope);
    if (status != napi_ok) {
        napi_throw_error(obj->env_, NULL, "Failed to close handle scope");
    }
}


void
nxt_uv_read_callback(uv_poll_t *handle, int status, int events)
{
    nxt_unit_run_once((nxt_unit_ctx_t *) handle->data);
}


int
Unit::add_port(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port)
{
    int               err;
    Unit              *obj;
    uv_loop_t         *loop;
    napi_status       status;
    nxt_nodejs_ctx_t  *node_ctx;

    if (port->in_fd != -1) {
        obj = reinterpret_cast<Unit *>(ctx->unit->data);

        if (fcntl(port->in_fd, F_SETFL, O_NONBLOCK) == -1) {
            napi_throw_error(obj->env_, NULL, "Failed to upgrade read"
                             " file descriptor to O_NONBLOCK");
            return -1;
        }

        status = napi_get_uv_event_loop(obj->env_, &loop);
        if (status != napi_ok) {
            napi_throw_error(obj->env_, NULL, "Failed to get uv.loop");
            return NXT_UNIT_ERROR;
        }

        node_ctx = new nxt_nodejs_ctx_t;

        err = uv_poll_init(loop, &node_ctx->poll, port->in_fd);
        if (err < 0) {
            napi_throw_error(obj->env_, NULL, "Failed to init uv.poll");
            return NXT_UNIT_ERROR;
        }

        err = uv_poll_start(&node_ctx->poll, UV_READABLE, nxt_uv_read_callback);
        if (err < 0) {
            napi_throw_error(obj->env_, NULL, "Failed to start uv.poll");
            return NXT_UNIT_ERROR;
        }

        ctx->data = node_ctx;

        node_ctx->port_id = port->id;
        node_ctx->poll.data = ctx;
    }

    return nxt_unit_add_port(ctx, port);
}


inline bool 
operator == (const nxt_unit_port_id_t &p1, const nxt_unit_port_id_t &p2)
{
    return p1.pid == p2.pid && p1.id == p2.id;
}


void
Unit::remove_port(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id)
{
    nxt_nodejs_ctx_t  *node_ctx;

    if (ctx->data != NULL) {
        node_ctx = (nxt_nodejs_ctx_t *) ctx->data;

        if (node_ctx->port_id == *port_id) {
            uv_poll_stop(&node_ctx->poll);

            delete node_ctx;

            ctx->data = NULL;
        }
    }

    nxt_unit_remove_port(ctx, port_id);
}


void
Unit::quit(nxt_unit_ctx_t *ctx)
{
    nxt_unit_done(ctx);
}


napi_value
Unit::get_server_object()
{
    napi_value   unit_obj, server_obj;
    napi_status  status;

    status = napi_get_reference_value(env_, wrapper_, &unit_obj);
    if (status != napi_ok) {
        return nullptr;
    }

    status = napi_get_named_property(env_, unit_obj, "server", &server_obj);
    if (status != napi_ok) {
        return nullptr;
    }

    return server_obj;
}


napi_status
Unit::create_headers(nxt_unit_request_info_t *req, napi_value request)
{
    uint32_t            i;
    const char          *p;
    napi_value          headers, raw_headers, str;
    napi_status         status;
    nxt_unit_field_t    *f;
    nxt_unit_request_t  *r;

    r = req->request;

    status = napi_create_object(env_, &headers);
    if (status != napi_ok) {
        return status;
    }

    status = napi_create_array_with_length(env_, r->fields_count * 2,
                                           &raw_headers);
    if (status != napi_ok) {
        return status;
    }

    for (i = 0; i < r->fields_count; i++) {
        f = r->fields + i;

        status = this->append_header(f, headers, raw_headers, i);
        if (status != napi_ok) {
            return status;
        }
    }

    status = napi_set_named_property(env_, request, "headers", headers);
    if (status != napi_ok) {
        return status;
    }

    status = napi_set_named_property(env_, request, "rawHeaders", raw_headers);
    if (status != napi_ok) {
        return status;
    }

    p = (const char *) nxt_unit_sptr_get(&r->version);

    status = napi_create_string_latin1(env_, p, r->version_length, &str);
    if (status != napi_ok) {
        return status;
    }

    status = napi_set_named_property(env_, request, "httpVersion", str);
    if (status != napi_ok) {
        return status;
    }

    p = (const char *) nxt_unit_sptr_get(&r->method);

    status = napi_create_string_latin1(env_, p, r->method_length, &str);
    if (status != napi_ok) {
        return status;
    }

    status = napi_set_named_property(env_, request, "method", str);
    if (status != napi_ok) {
        return status;
    }

    p = (const char *) nxt_unit_sptr_get(&r->target);

    status = napi_create_string_latin1(env_, p, r->target_length, &str);
    if (status != napi_ok) {
        return status;
    }

    status = napi_set_named_property(env_, request, "url", str);
    if (status != napi_ok) {
        return status;
    }

    return napi_ok;
}


inline napi_status
Unit::append_header(nxt_unit_field_t *f, napi_value headers,
                    napi_value raw_headers, uint32_t idx)
{
    const char   *name, *value;
    napi_value   str, vstr;
    napi_status  status;

    value = (const char *) nxt_unit_sptr_get(&f->value);

    status = napi_create_string_latin1(env_, value, f->value_length, &vstr);
    if (status != napi_ok) {
        return status;
    }

    name = (const char *) nxt_unit_sptr_get(&f->name);

    status = napi_set_named_property(env_, headers, name, vstr);
    if (status != napi_ok) {
        return status;
    }

    status = napi_create_string_latin1(env_, name, f->name_length, &str);
    if (status != napi_ok) {
        return status;
    }

    status = napi_set_element(env_, raw_headers, idx * 2, str);
    if (status != napi_ok) {
        return status;
    }

    status = napi_set_element(env_, raw_headers, idx * 2 + 1, vstr);
    if (status != napi_ok) {
        return status;
    }

    return napi_ok;
}


napi_value
Unit::create_socket(napi_value server_obj, nxt_unit_request_info_t *req)
{
    napi_value   constructor, return_val, req_pointer;
    napi_status  status;

    status = napi_get_named_property(env_, server_obj, "socket",
                                     &constructor);
    if (status != napi_ok) {
        return nullptr;
    }

    status = napi_new_instance(env_, constructor, 0, NULL, &return_val);
    if (status != napi_ok) {
        return nullptr;
    }

    status = napi_create_int64(env_, (uintptr_t) req, &req_pointer);
    if (status != napi_ok) {
        return nullptr;
    }

    status = napi_set_named_property(env_, return_val, "req_pointer",
                                     req_pointer);
    if (status != napi_ok) {
        return nullptr;
    }

    return return_val;
}


napi_value
Unit::create_request(napi_value server_obj, napi_value socket)
{
    napi_value   constructor, return_val;
    napi_status  status;

    status = napi_get_named_property(env_, server_obj, "request",
                                     &constructor);
    if (status != napi_ok) {
        return nullptr;
    }

    status = napi_new_instance(env_, constructor, 1, &server_obj,
                               &return_val);
    if (status != napi_ok) {
        return nullptr;
    }

    status = napi_set_named_property(env_, return_val, "socket", socket);
    if (status != napi_ok) {
        return nullptr;
    }

    return return_val;
}


napi_value
Unit::create_response(napi_value server_obj, napi_value socket,
                      napi_value request, nxt_unit_request_info_t *req,
                      Unit *obj)
{
    napi_value   constructor, return_val, req_num;
    napi_status  status;

    status = napi_get_named_property(env_, server_obj, "response",
                                     &constructor);
    if (status != napi_ok) {
        return nullptr;
    }

    status = napi_new_instance(env_, constructor, 1, &request, &return_val);
    if (status != napi_ok) {
        return nullptr;
    }

    status = napi_set_named_property(env_, return_val, "socket", socket);
    if (status != napi_ok) {
        return nullptr;
    }

    status = napi_create_int64(env_, (int64_t) (uintptr_t) req, &req_num);
    if (status != napi_ok) {
        return nullptr;
    }

    status = napi_set_named_property(env_, return_val, "_req_point", req_num);
    if (status != napi_ok) {
        return nullptr;
    }

    return return_val;
}


napi_value
Unit::response_send_headers(napi_env env, napi_callback_info info)
{
    int                      ret;
    char                     *ptr, *name_ptr;
    bool                     is_array;
    size_t                   argc, name_len, value_len;
    int64_t                  req_p;
    uint32_t                 status_code, header_len, keys_len, array_len;
    uint32_t                 keys_count, i, j;
    uint16_t                 hash;
    napi_value               this_arg, headers, keys, name, value, array_val;
    napi_value               req_num, array_entry;
    napi_status              status;
    napi_valuetype           val_type;
    nxt_unit_field_t         *f;
    nxt_unit_request_info_t  *req;
    napi_value               argv[5];

    argc = 5;

    status = napi_get_cb_info(env, info, &argc, argv, &this_arg, NULL);
    if (status != napi_ok) {
        return nullptr;
    }

    if (argc != 5) {
        napi_throw_error(env, NULL, "Wrong args count. Need three: "
                         "statusCode, headers, headers count, headers length");
        return nullptr;
    }

    status = napi_get_named_property(env, argv[0], "_req_point", &req_num);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get request pointer");
        return nullptr;
    }

    status = napi_get_value_int64(env, req_num, &req_p);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get request pointer");
        return nullptr;
    }

    req = (nxt_unit_request_info_t *) (uintptr_t) req_p;

    status = napi_get_value_uint32(env, argv[1], &status_code);
    if (status != napi_ok) {
        goto failed;
    }

    status = napi_get_value_uint32(env, argv[3], &keys_count);
    if (status != napi_ok) {
        goto failed;
    }

    status = napi_get_value_uint32(env, argv[4], &header_len);
    if (status != napi_ok) {
        goto failed;
    }

    /* Need to reserve extra byte for C-string 0-termination. */
    header_len++;

    headers = argv[2];

    ret = nxt_unit_response_init(req, status_code, keys_count, header_len);
    if (ret != NXT_UNIT_OK) {
        goto failed;
    }

    status = napi_get_property_names(env, headers, &keys);
    if (status != napi_ok) {
        goto failed;
    }

    status = napi_get_array_length(env, keys, &keys_len);
    if (status != napi_ok) {
        goto failed;
    }

    ptr = req->response_buf->free;

    for (i = 0; i < keys_len; i++) {
        status = napi_get_element(env, keys, i, &name);
        if (status != napi_ok) {
            goto failed;
        }

        status = napi_get_property(env, headers, name, &array_entry);
        if (status != napi_ok) {
            goto failed;
        }

        status = napi_get_element(env, array_entry, 0, &name);
        if (status != napi_ok) {
            goto failed;
        }

        status = napi_get_element(env, array_entry, 1, &value);
        if (status != napi_ok) {
            goto failed;
        }

        status = napi_get_value_string_latin1(env, name, ptr, header_len,
                                              &name_len);
        if (status != napi_ok) {
            goto failed;
        }

        name_ptr = ptr;

        ptr += name_len;
        header_len -= name_len;

        hash = nxt_unit_field_hash(name_ptr, name_len);

        status = napi_is_array(env, value, &is_array);
        if (status != napi_ok) {
            goto failed;
        }

        if (is_array) {
            status = napi_get_array_length(env, value, &array_len);
            if (status != napi_ok) {
                goto failed;
            }

            for (j = 0; j < array_len; j++) {
                status = napi_get_element(env, value, j, &array_val);
                if (status != napi_ok) {
                    goto failed;
                }

                napi_typeof(env, array_val, &val_type);
                if (status != napi_ok) {
                    goto failed;
                }

                if (val_type != napi_string) {
                    status = napi_coerce_to_string(env, array_val, &array_val);
                    if (status != napi_ok) {
                        goto failed;
                    }
                }

                status = napi_get_value_string_latin1(env, array_val, ptr,
                                                      header_len,
                                                      &value_len);
                if (status != napi_ok) {
                    goto failed;
                }

                f = req->response->fields + req->response->fields_count;
                f->skip = 0;

                nxt_unit_sptr_set(&f->name, name_ptr);

                f->name_length = name_len;
                f->hash = hash;

                nxt_unit_sptr_set(&f->value, ptr);
                f->value_length = (uint32_t) value_len;

                ptr += value_len;
                header_len -= value_len;

                req->response->fields_count++;
            }

        } else {
            napi_typeof(env, value, &val_type);
            if (status != napi_ok) {
                goto failed;
            }

            if (val_type != napi_string) {
                status = napi_coerce_to_string(env, value, &value);
                if (status != napi_ok) {
                    goto failed;
                }
            }

            status = napi_get_value_string_latin1(env, value, ptr, header_len,
                                                  &value_len);
            if (status != napi_ok) {
                goto failed;
            }

            f = req->response->fields + req->response->fields_count;
            f->skip = 0;

            nxt_unit_sptr_set(&f->name, name_ptr);

            f->name_length = name_len;
            f->hash = hash;

            nxt_unit_sptr_set(&f->value, ptr);
            f->value_length = (uint32_t) value_len;

            ptr += value_len;
            header_len -= value_len;

            req->response->fields_count++;
        }
    }

    req->response_buf->free = ptr;

    ret = nxt_unit_response_send(req);
    if (ret != NXT_UNIT_OK) {
        goto failed;
    }

    return this_arg;

failed:

    req->response->fields_count = 0;

    napi_throw_error(env, NULL, "Failed to write headers");

    return nullptr;
}


napi_value
Unit::response_write(napi_env env, napi_callback_info info)
{
    int                      ret;
    char                     *ptr;
    size_t                   argc, have_buf_len;
    int64_t                  req_p;
    uint32_t                 buf_len;
    napi_value               this_arg, req_num;
    napi_status              status;
    nxt_unit_buf_t           *buf;
    napi_valuetype           buf_type;
    nxt_unit_request_info_t  *req;
    napi_value               argv[3];

    argc = 3;

    status = napi_get_cb_info(env, info, &argc, argv, &this_arg, NULL);
    if (status != napi_ok) {
        goto failed;
    }

    if (argc != 3) {
        napi_throw_error(env, NULL, "Wrong args count. Need two: "
                         "chunk, chunk length");
        return nullptr;
    }

    status = napi_get_named_property(env, argv[0], "_req_point", &req_num);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get request pointer");
        return nullptr;
    }

    status = napi_get_value_int64(env, req_num, &req_p);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get request pointer");
        return nullptr;
    }

    req = (nxt_unit_request_info_t *) (uintptr_t) req_p;

    status = napi_get_value_uint32(env, argv[2], &buf_len);
    if (status != napi_ok) {
        goto failed;
    }

    status = napi_typeof(env, argv[1], &buf_type);
    if (status != napi_ok) {
        goto failed;
    }

    buf_len++;

    buf = nxt_unit_response_buf_alloc(req, buf_len);
    if (buf == NULL) {
        goto failed;
    }

    if (buf_type == napi_string) {
        /* TODO: will work only for utf8 content-type */

        status = napi_get_value_string_utf8(env, argv[1], buf->free,
                                            buf_len, &have_buf_len);

    } else {
        status = napi_get_buffer_info(env, argv[1], (void **) &ptr,
                                      &have_buf_len);

        memcpy(buf->free, ptr, have_buf_len);
    }

    if (status != napi_ok) {
        goto failed;
    }

    buf->free += have_buf_len;

    ret = nxt_unit_buf_send(buf);
    if (ret != NXT_UNIT_OK) {
        goto failed;
    }

    return this_arg;

failed:

    napi_throw_error(env, NULL, "Failed to write body");

    return nullptr;
}


napi_value
Unit::response_end(napi_env env, napi_callback_info info)
{
    size_t                   argc;
    int64_t                  req_p;
    napi_value               resp, this_arg, req_num;
    napi_status              status;
    nxt_unit_request_info_t  *req;

    argc = 1;

    status = napi_get_cb_info(env, info, &argc, &resp, &this_arg, NULL);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to finalize sending body");
        return nullptr;
    }

    status = napi_get_named_property(env, resp, "_req_point", &req_num);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get request pointer");
        return nullptr;
    }

    status = napi_get_value_int64(env, req_num, &req_p);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get request pointer");
        return nullptr;
    }

    req = (nxt_unit_request_info_t *) (uintptr_t) req_p;

    nxt_unit_request_done(req, NXT_UNIT_OK);

    return this_arg;
}

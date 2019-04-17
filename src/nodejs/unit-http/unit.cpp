
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


Unit::Unit(napi_env env, napi_value jsthis):
    nxt_napi(env),
    wrapper_(wrap(jsthis, this, destroy)),
    unit_ctx_(nullptr)
{
}


Unit::~Unit()
{
    delete_reference(wrapper_);
}


napi_value
Unit::init(napi_env env, napi_value exports)
{
    nxt_napi    napi(env);
    napi_value  cons;

    napi_property_descriptor  properties[] = {
        { "createServer", 0, create_server, 0, 0, 0, napi_default, 0 },
        { "listen", 0, listen, 0, 0, 0, napi_default, 0 },
        { "_read", 0, _read, 0, 0, 0, napi_default, 0 }
    };

    try {
        cons = napi.define_class("Unit", create, 3, properties);
        constructor_ = napi.create_reference(cons);

        napi.set_named_property(exports, "Unit", cons);
        napi.set_named_property(exports, "unit_response_headers",
                                response_send_headers);
        napi.set_named_property(exports, "unit_response_write", response_write);
        napi.set_named_property(exports, "unit_response_end", response_end);

    } catch (exception &e) {
        napi.throw_error(e);
        return nullptr;
    }

    return exports;
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
    nxt_napi    napi(env);
    napi_value  target, cons, instance, jsthis;

    try {
        target = napi.get_new_target(info);

        if (target != nullptr) {
            /* Invoked as constructor: `new Unit(...)`. */
            jsthis = napi.get_cb_info(info);

            new Unit(env, jsthis);
            napi.create_reference(jsthis);

            return jsthis;
        }

        /* Invoked as plain function `Unit(...)`, turn into construct call. */
        cons = napi.get_reference_value(constructor_);
        instance = napi.new_instance(cons);
        napi.create_reference(instance);

    } catch (exception &e) {
        napi.throw_error(e);
        return nullptr;
    }

    return instance;
}


napi_value
Unit::create_server(napi_env env, napi_callback_info info)
{
    Unit             *obj;
    size_t           argc;
    nxt_napi         napi(env);
    napi_value       jsthis, argv;
    nxt_unit_init_t  unit_init;

    argc = 1;

    try {
        jsthis = napi.get_cb_info(info, argc, &argv);
        obj = (Unit *) napi.unwrap(jsthis);

    } catch (exception &e) {
        napi.throw_error(e);
        return nullptr;
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
    void                     *data;
    size_t                   argc;
    nxt_napi                 napi(env);
    napi_value               buffer, argv;
    nxt_unit_request_info_t  *req;

    argc = 1;

    try {
        napi.get_cb_info(info, argc, &argv);

        req = napi.get_request_info(argv);
        buffer = napi.create_buffer((size_t) req->content_length, &data);

    } catch (exception &e) {
        napi.throw_error(e);
        return nullptr;
    }

    nxt_unit_request_read(req, data, req->content_length);

    return buffer;
}


void
Unit::request_handler(nxt_unit_request_info_t *req)
{
    Unit         *obj;
    napi_value   socket, request, response, server_obj;
    napi_value   emit_events;
    napi_value   events_args[3];

    obj = reinterpret_cast<Unit *>(req->unit->data);

    try {
        nxt_handle_scope  scope(obj->env());

        server_obj = obj->get_server_object();

        socket = obj->create_socket(server_obj, req);
        request = obj->create_request(server_obj, socket);
        response = obj->create_response(server_obj, socket, request, req);

        obj->create_headers(req, request);

        emit_events = obj->get_named_property(server_obj, "emit_events");

        events_args[0] = server_obj;
        events_args[1] = request;
        events_args[2] = response;

        nxt_async_context   async_context(obj->env(), "unit_request_handler");
        nxt_callback_scope  async_scope(async_context);

        obj->make_callback(async_context, server_obj, emit_events,
                           3, events_args);

    } catch (exception &e) {
        obj->throw_error(e);
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
            obj->throw_error("Failed to upgrade read"
                             " file descriptor to O_NONBLOCK");
            return -1;
        }

        status = napi_get_uv_event_loop(obj->env(), &loop);
        if (status != napi_ok) {
            obj->throw_error("Failed to get uv.loop");
            return NXT_UNIT_ERROR;
        }

        node_ctx = new nxt_nodejs_ctx_t;

        err = uv_poll_init(loop, &node_ctx->poll, port->in_fd);
        if (err < 0) {
            obj->throw_error("Failed to init uv.poll");
            return NXT_UNIT_ERROR;
        }

        err = uv_poll_start(&node_ctx->poll, UV_READABLE, nxt_uv_read_callback);
        if (err < 0) {
            obj->throw_error("Failed to start uv.poll");
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
    Unit        *obj;
    napi_value  server_obj, emit_close;

    obj = reinterpret_cast<Unit *>(ctx->unit->data);

    try {
        nxt_handle_scope  scope(obj->env());

        server_obj = obj->get_server_object();

        emit_close = obj->get_named_property(server_obj, "emit_close");

        nxt_async_context   async_context(obj->env(), "unit_quit");
        nxt_callback_scope  async_scope(async_context);

        obj->make_callback(async_context, server_obj, emit_close, 0, NULL);

    } catch (exception &e) {
        obj->throw_error(e);
    }

    nxt_unit_done(ctx);
}


napi_value
Unit::get_server_object()
{
    napi_value  unit_obj;

    unit_obj = get_reference_value(wrapper_);

    return get_named_property(unit_obj, "server");
}


void
Unit::create_headers(nxt_unit_request_info_t *req, napi_value request)
{
    uint32_t            i;
    napi_value          headers, raw_headers;
    napi_status         status;
    nxt_unit_request_t  *r;

    r = req->request;

    headers = create_object();

    status = napi_create_array_with_length(env(), r->fields_count * 2,
                                           &raw_headers);
    if (status != napi_ok) {
        throw exception("Failed to create array");
    }

    for (i = 0; i < r->fields_count; i++) {
        append_header(r->fields + i, headers, raw_headers, i);
    }

    set_named_property(request, "headers", headers);
    set_named_property(request, "rawHeaders", raw_headers);
    set_named_property(request, "httpVersion", r->version, r->version_length);
    set_named_property(request, "method", r->method, r->method_length);
    set_named_property(request, "url", r->target, r->target_length);
}


inline char
lowcase(char c)
{
    return (c >= 'A' && c <= 'Z') ? (c | 0x20) : c;
}


inline void
Unit::append_header(nxt_unit_field_t *f, napi_value headers,
    napi_value raw_headers, uint32_t idx)
{
    char        *name;
    uint8_t     i;
    napi_value  str, vstr;

    name = (char *) nxt_unit_sptr_get(&f->name);

    str = create_string_latin1(name, f->name_length);

    for (i = 0; i < f->name_length; i++) {
        name[i] = lowcase(name[i]);
    }

    vstr = set_named_property(headers, name, f->value, f->value_length);

    set_element(raw_headers, idx * 2, str);
    set_element(raw_headers, idx * 2 + 1, vstr);
}


napi_value
Unit::create_socket(napi_value server_obj, nxt_unit_request_info_t *req)
{
    napi_value          constructor, res;
    nxt_unit_request_t  *r;

    r = req->request;

    constructor = get_named_property(server_obj, "socket");

    res = new_instance(constructor);

    set_named_property(res, "req_pointer", (intptr_t) req);
    set_named_property(res, "remoteAddress", r->remote, r->remote_length);
    set_named_property(res, "localAddress", r->local, r->local_length);

    return res;
}


napi_value
Unit::create_request(napi_value server_obj, napi_value socket)
{
    napi_value  constructor, return_val;

    constructor = get_named_property(server_obj, "request");

    return_val = new_instance(constructor, server_obj);

    set_named_property(return_val, "socket", socket);
    set_named_property(return_val, "connection", socket);

    return return_val;
}


napi_value
Unit::create_response(napi_value server_obj, napi_value socket,
    napi_value request, nxt_unit_request_info_t *req)
{
    napi_value  constructor, return_val;

    constructor = get_named_property(server_obj, "response");

    return_val = new_instance(constructor, request);

    set_named_property(return_val, "socket", socket);
    set_named_property(return_val, "connection", socket);
    set_named_property(return_val, "_req_point", (intptr_t) req);

    return return_val;
}


napi_value
Unit::response_send_headers(napi_env env, napi_callback_info info)
{
    int                      ret;
    char                     *ptr, *name_ptr;
    bool                     is_array;
    size_t                   argc, name_len, value_len;
    uint32_t                 status_code, header_len, keys_len, array_len;
    uint32_t                 keys_count, i, j;
    uint16_t                 hash;
    nxt_napi                 napi(env);
    napi_value               this_arg, headers, keys, name, value, array_val;
    napi_value               req_num, array_entry;
    napi_valuetype           val_type;
    nxt_unit_field_t         *f;
    nxt_unit_request_info_t  *req;
    napi_value               argv[5];

    argc = 5;

    try {
        this_arg = napi.get_cb_info(info, argc, argv);
        if (argc != 5) {
            napi.throw_error("Wrong args count. Expected: "
                             "statusCode, headers, headers count, "
                             "headers length");
            return nullptr;
        }

        req_num = napi.get_named_property(argv[0], "_req_point");

        req = napi.get_request_info(req_num);

        status_code = napi.get_value_uint32(argv[1]);
        keys_count = napi.get_value_uint32(argv[3]);
        header_len = napi.get_value_uint32(argv[4]);

        /* Need to reserve extra byte for C-string 0-termination. */
        header_len++;

        headers = argv[2];

        ret = nxt_unit_response_init(req, status_code, keys_count, header_len);
        if (ret != NXT_UNIT_OK) {
            napi.throw_error("Failed to create response");
            return nullptr;
        }

        keys = napi.get_property_names(headers);
        keys_len = napi.get_array_length(keys);

        ptr = req->response_buf->free;

        for (i = 0; i < keys_len; i++) {
            name = napi.get_element(keys, i);

            array_entry = napi.get_property(headers, name);

            name = napi.get_element(array_entry, 0);
            value = napi.get_element(array_entry, 1);

            name_len = napi.get_value_string_latin1(name, ptr, header_len);
            name_ptr = ptr;

            ptr += name_len;
            header_len -= name_len;

            hash = nxt_unit_field_hash(name_ptr, name_len);

            is_array = napi.is_array(value);

            if (is_array) {
                array_len = napi.get_array_length(value);

                for (j = 0; j < array_len; j++) {
                    array_val = napi.get_element(value, j);

                    val_type = napi.type_of(array_val);

                    if (val_type != napi_string) {
                        array_val = napi.coerce_to_string(array_val);
                    }

                    value_len = napi.get_value_string_latin1(array_val, ptr,
                                                             header_len);

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
                val_type = napi.type_of(value);

                if (val_type != napi_string) {
                    value = napi.coerce_to_string(value);
                }

                value_len = napi.get_value_string_latin1(value, ptr, header_len);

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

    } catch (exception &e) {
        napi.throw_error(e);
        return nullptr;
    }

    req->response_buf->free = ptr;

    ret = nxt_unit_response_send(req);
    if (ret != NXT_UNIT_OK) {
        napi.throw_error("Failed to send response");
        return nullptr;
    }

    return this_arg;
}


napi_value
Unit::response_write(napi_env env, napi_callback_info info)
{
    int                      ret;
    char                     *ptr;
    size_t                   argc, have_buf_len;
    uint32_t                 buf_len;
    nxt_napi                 napi(env);
    napi_value               this_arg, req_num;
    napi_status              status;
    nxt_unit_buf_t           *buf;
    napi_valuetype           buf_type;
    nxt_unit_request_info_t  *req;
    napi_value               argv[3];

    argc = 3;

    try {
        this_arg = napi.get_cb_info(info, argc, argv);
        if (argc != 3) {
            throw exception("Wrong args count. Expected: "
                            "chunk, chunk length");
        }

        req_num = napi.get_named_property(argv[0], "_req_point");
        req = napi.get_request_info(req_num);

        buf_len = napi.get_value_uint32(argv[2]);

        buf_type = napi.type_of(argv[1]);

    } catch (exception &e) {
        napi.throw_error(e);
        return nullptr;
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

    napi.throw_error("Failed to write body");

    return nullptr;
}


napi_value
Unit::response_end(napi_env env, napi_callback_info info)
{
    size_t                   argc;
    nxt_napi                 napi(env);
    napi_value               resp, this_arg, req_num;
    nxt_unit_request_info_t  *req;

    argc = 1;

    try {
        this_arg = napi.get_cb_info(info, argc, &resp);

        req_num = napi.get_named_property(resp, "_req_point");
        req = napi.get_request_info(req_num);

    } catch (exception &e) {
        napi.throw_error(e);
        return nullptr;
    }

    nxt_unit_request_done(req, NXT_UNIT_OK);

    return this_arg;
}

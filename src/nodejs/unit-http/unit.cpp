
/*
 * Copyright (C) NGINX, Inc.
 */

#include "unit.h"

#include <unistd.h>
#include <fcntl.h>

#include <uv.h>

#include <nxt_unit_websocket.h>


napi_ref Unit::constructor_;


struct port_data_t {
    port_data_t(nxt_unit_ctx_t *c, nxt_unit_port_t *p);

    void process_port_msg();
    void stop();

    template<typename T>
    static port_data_t *get(T *handle);

    static void read_callback(uv_poll_t *handle, int status, int events);
    static void timer_callback(uv_timer_t *handle);
    static void delete_data(uv_handle_t* handle);

    nxt_unit_ctx_t   *ctx;
    nxt_unit_port_t  *port;
    uv_poll_t        poll;
    uv_timer_t       timer;
    int              ref_count;
    bool             scheduled;
    bool             stopped;
};


struct req_data_t {
    napi_ref  sock_ref;
    napi_ref  req_ref;
    napi_ref  resp_ref;
    napi_ref  conn_ref;
};


port_data_t::port_data_t(nxt_unit_ctx_t *c, nxt_unit_port_t *p) :
    ctx(c), port(p), ref_count(0), scheduled(false), stopped(false)
{
    timer.type = UV_UNKNOWN_HANDLE;
}


void
port_data_t::process_port_msg()
{
    int  rc, err;

    rc = nxt_unit_process_port_msg(ctx, port);

    if (rc != NXT_UNIT_OK) {
        return;
    }

    if (timer.type == UV_UNKNOWN_HANDLE) {
        err = uv_timer_init(poll.loop, &timer);
        if (err < 0) {
            nxt_unit_warn(ctx, "Failed to init uv.poll");
            return;
        }

        ref_count++;
        timer.data = this;
    }

    if (!scheduled && !stopped) {
        uv_timer_start(&timer, timer_callback, 0, 0);

        scheduled = true;
    }
}


void
port_data_t::stop()
{
    stopped = true;

    uv_poll_stop(&poll);

    uv_close((uv_handle_t *) &poll, delete_data);

    if (timer.type == UV_UNKNOWN_HANDLE) {
        return;
    }

    uv_timer_stop(&timer);

    uv_close((uv_handle_t *) &timer, delete_data);
}


template<typename T>
port_data_t *
port_data_t::get(T *handle)
{
    return (port_data_t *) handle->data;
}


void
port_data_t::read_callback(uv_poll_t *handle, int status, int events)
{
    get(handle)->process_port_msg();
}


void
port_data_t::timer_callback(uv_timer_t *handle)
{
    port_data_t  *data;

    data = get(handle);

    data->scheduled = false;
    if (data->stopped) {
        return;
    }

    data->process_port_msg();
}


void
port_data_t::delete_data(uv_handle_t* handle)
{
    port_data_t  *data;

    data = get(handle);

    if (--data->ref_count <= 0) {
        delete data;
    }
}


Unit::Unit(napi_env env, napi_value jsthis):
    nxt_napi(env),
    wrapper_(wrap(jsthis, this, destroy)),
    unit_ctx_(nullptr)
{
    nxt_unit_debug(NULL, "Unit::Unit()");
}


Unit::~Unit()
{
    delete_reference(wrapper_);

    nxt_unit_debug(NULL, "Unit::~Unit()");
}


napi_value
Unit::init(napi_env env, napi_value exports)
{
    nxt_napi    napi(env);
    napi_value  ctor;

    napi_property_descriptor  unit_props[] = {
        { "createServer", 0, create_server, 0, 0, 0, napi_default, 0 },
        { "listen", 0, listen, 0, 0, 0, napi_default, 0 },
    };

    try {
        ctor = napi.define_class("Unit", create, 2, unit_props);
        constructor_ = napi.create_reference(ctor);

        napi.set_named_property(exports, "Unit", ctor);
        napi.set_named_property(exports, "request_read", request_read);
        napi.set_named_property(exports, "response_send_headers",
                                response_send_headers);
        napi.set_named_property(exports, "response_write", response_write);
        napi.set_named_property(exports, "response_end", response_end);
        napi.set_named_property(exports, "websocket_send_frame",
                                websocket_send_frame);
        napi.set_named_property(exports, "websocket_set_sock",
                                websocket_set_sock);
        napi.set_named_property(exports, "buf_min", nxt_unit_buf_min());
        napi.set_named_property(exports, "buf_max", nxt_unit_buf_max());

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
    napi_value  target, ctor, instance, jsthis;

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
        ctor = napi.get_reference_value(constructor_);
        instance = napi.new_instance(ctor);
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
    unit_init.callbacks.request_handler   = request_handler_cb;
    unit_init.callbacks.websocket_handler = websocket_handler_cb;
    unit_init.callbacks.close_handler     = close_handler_cb;
    unit_init.callbacks.shm_ack_handler   = shm_ack_handler_cb;
    unit_init.callbacks.add_port          = add_port;
    unit_init.callbacks.remove_port       = remove_port;
    unit_init.callbacks.quit              = quit_cb;

    unit_init.request_data_size = sizeof(req_data_t);

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


void
Unit::request_handler_cb(nxt_unit_request_info_t *req)
{
    Unit  *obj;

    obj = reinterpret_cast<Unit *>(req->unit->data);

    obj->request_handler(req);
}


void
Unit::request_handler(nxt_unit_request_info_t *req)
{
    napi_value  socket, request, response, server_obj, emit_request;

    memset(req->data, 0, sizeof(req_data_t));

    try {
        nxt_handle_scope  scope(env());

        server_obj = get_server_object();

        socket = create_socket(server_obj, req);
        request = create_request(server_obj, socket, req);
        response = create_response(server_obj, request, req);

        create_headers(req, request);

        emit_request = get_named_property(server_obj, "emit_request");

        nxt_async_context   async_context(env(), "request_handler");
        nxt_callback_scope  async_scope(async_context);

        make_callback(async_context, server_obj, emit_request, request,
                      response);

    } catch (exception &e) {
        nxt_unit_req_warn(req, "request_handler: %s", e.str);
    }
}


void
Unit::websocket_handler_cb(nxt_unit_websocket_frame_t *ws)
{
    Unit  *obj;

    obj = reinterpret_cast<Unit *>(ws->req->unit->data);

    obj->websocket_handler(ws);
}


void
Unit::websocket_handler(nxt_unit_websocket_frame_t *ws)
{
    napi_value  frame, server_obj, process_frame, conn;
    req_data_t  *req_data;

    req_data = (req_data_t *) ws->req->data;

    try {
        nxt_handle_scope  scope(env());

        server_obj = get_server_object();

        frame = create_websocket_frame(server_obj, ws);

        conn = get_reference_value(req_data->conn_ref);

        process_frame = get_named_property(conn, "processFrame");

        nxt_async_context   async_context(env(), "websocket_handler");
        nxt_callback_scope  async_scope(async_context);

        make_callback(async_context, conn, process_frame, frame);

    } catch (exception &e) {
        nxt_unit_req_warn(ws->req, "websocket_handler: %s", e.str);
    }

    nxt_unit_websocket_done(ws);
}


void
Unit::close_handler_cb(nxt_unit_request_info_t *req)
{
    Unit  *obj;

    obj = reinterpret_cast<Unit *>(req->unit->data);

    obj->close_handler(req);
}


void
Unit::close_handler(nxt_unit_request_info_t *req)
{
    napi_value  conn_handle_close, conn;
    req_data_t  *req_data;

    req_data = (req_data_t *) req->data;

    try {
        nxt_handle_scope  scope(env());

        conn = get_reference_value(req_data->conn_ref);

        conn_handle_close = get_named_property(conn, "handleSocketClose");

        nxt_async_context   async_context(env(), "close_handler");
        nxt_callback_scope  async_scope(async_context);

        make_callback(async_context, conn, conn_handle_close,
                      nxt_napi::create(0));

        remove_wrap(req_data->sock_ref);
        remove_wrap(req_data->req_ref);
        remove_wrap(req_data->resp_ref);
        remove_wrap(req_data->conn_ref);

    } catch (exception &e) {
        nxt_unit_req_warn(req, "close_handler: %s", e.str);

        nxt_unit_request_done(req, NXT_UNIT_ERROR);

        return;
    }

    nxt_unit_request_done(req, NXT_UNIT_OK);
}


void
Unit::shm_ack_handler_cb(nxt_unit_ctx_t *ctx)
{
    Unit  *obj;

    obj = reinterpret_cast<Unit *>(ctx->unit->data);

    obj->shm_ack_handler(ctx);
}


void
Unit::shm_ack_handler(nxt_unit_ctx_t *ctx)
{
    napi_value  server_obj, emit_drain;

    try {
        nxt_handle_scope  scope(env());

        server_obj = get_server_object();

        emit_drain = get_named_property(server_obj, "emit_drain");

        nxt_async_context   async_context(env(), "shm_ack_handler");
        nxt_callback_scope  async_scope(async_context);

        make_callback(async_context, server_obj, emit_drain);

    } catch (exception &e) {
        nxt_unit_warn(ctx, "shm_ack_handler: %s", e.str);
    }
}


int
Unit::add_port(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port)
{
    int          err;
    Unit         *obj;
    uv_loop_t    *loop;
    port_data_t  *data;
    napi_status  status;

    if (port->in_fd != -1) {
        if (fcntl(port->in_fd, F_SETFL, O_NONBLOCK) == -1) {
            nxt_unit_warn(ctx, "fcntl(%d, O_NONBLOCK) failed: %s (%d)",
                          port->in_fd, strerror(errno), errno);
            return -1;
        }

        obj = reinterpret_cast<Unit *>(ctx->unit->data);

        status = napi_get_uv_event_loop(obj->env(), &loop);
        if (status != napi_ok) {
            nxt_unit_warn(ctx, "Failed to get uv.loop");
            return NXT_UNIT_ERROR;
        }

        data = new port_data_t(ctx, port);

        err = uv_poll_init(loop, &data->poll, port->in_fd);
        if (err < 0) {
            nxt_unit_warn(ctx, "Failed to init uv.poll");
            delete data;
            return NXT_UNIT_ERROR;
        }

        err = uv_poll_start(&data->poll, UV_READABLE,
                            port_data_t::read_callback);
        if (err < 0) {
            nxt_unit_warn(ctx, "Failed to start uv.poll");
            delete data;
            return NXT_UNIT_ERROR;
        }

        port->data = data;

        data->ref_count++;
        data->poll.data = data;
    }

    return NXT_UNIT_OK;
}


void
Unit::remove_port(nxt_unit_t *unit, nxt_unit_ctx_t *ctx, nxt_unit_port_t *port)
{
    port_data_t  *data;

    if (port->data != NULL && ctx != NULL) {
        data = (port_data_t *) port->data;

        data->stop();
    }
}


void
Unit::quit_cb(nxt_unit_ctx_t *ctx)
{
    Unit  *obj;

    obj = reinterpret_cast<Unit *>(ctx->unit->data);

    obj->quit(ctx);
}


void
Unit::quit(nxt_unit_ctx_t *ctx)
{
    napi_value  server_obj, emit_close;

    try {
        nxt_handle_scope  scope(env());

        server_obj = get_server_object();

        emit_close = get_named_property(server_obj, "emit_close");

        nxt_async_context   async_context(env(), "unit_quit");
        nxt_callback_scope  async_scope(async_context);

        make_callback(async_context, server_obj, emit_close);

    } catch (exception &e) {
        nxt_unit_debug(ctx, "quit: %s", e.str);
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
    char                *p;
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

    // trim the "HTTP/" protocol prefix
    p = (char *) nxt_unit_sptr_get(&r->version);
    p += 5;

    set_named_property(request, "httpVersion", create_string_latin1(p, 3));
    set_named_property(request, "method", r->method, r->method_length);
    set_named_property(request, "url", r->target, r->target_length);

    set_named_property(request, "_websocket_handshake", r->websocket_handshake);
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
    req_data_t          *req_data;
    nxt_unit_request_t  *r;

    r = req->request;

    constructor = get_named_property(server_obj, "Socket");

    res = new_instance(constructor);

    req_data = (req_data_t *) req->data;
    req_data->sock_ref = wrap(res, req, sock_destroy);

    set_named_property(res, "remoteAddress", r->remote, r->remote_length);
    set_named_property(res, "localAddress", r->local_addr,
                       r->local_addr_length);

    return res;
}


napi_value
Unit::create_request(napi_value server_obj, napi_value socket,
    nxt_unit_request_info_t *req)
{
    napi_value  constructor, res;
    req_data_t  *req_data;

    constructor = get_named_property(server_obj, "ServerRequest");

    res = new_instance(constructor, server_obj, socket);

    req_data = (req_data_t *) req->data;
    req_data->req_ref = wrap(res, req, req_destroy);

    return res;
}


napi_value
Unit::create_response(napi_value server_obj, napi_value request,
    nxt_unit_request_info_t *req)
{
    napi_value  constructor, res;
    req_data_t  *req_data;

    constructor = get_named_property(server_obj, "ServerResponse");

    res = new_instance(constructor, request);

    req_data = (req_data_t *) req->data;
    req_data->resp_ref = wrap(res, req, resp_destroy);

    return res;
}


napi_value
Unit::create_websocket_frame(napi_value server_obj,
                             nxt_unit_websocket_frame_t *ws)
{
    void        *data;
    napi_value  constructor, res, buffer;
    uint8_t     sc[2];

    constructor = get_named_property(server_obj, "WebSocketFrame");

    res = new_instance(constructor);

    set_named_property(res, "fin", (bool) ws->header->fin);
    set_named_property(res, "opcode", ws->header->opcode);
    set_named_property(res, "length", (int64_t) ws->payload_len);

    if (ws->header->opcode == NXT_WEBSOCKET_OP_CLOSE) {
        if (ws->payload_len >= 2) {
            nxt_unit_websocket_read(ws, sc, 2);

            set_named_property(res, "closeStatus",
                               (((uint16_t) sc[0]) << 8) | sc[1]);

        } else {
            set_named_property(res, "closeStatus", -1);
        }
    }

    buffer = create_buffer((size_t) ws->content_length, &data);
    nxt_unit_websocket_read(ws, data, ws->content_length);

    set_named_property(res, "binaryPayload", buffer);

    return res;
}


napi_value
Unit::request_read(napi_env env, napi_callback_info info)
{
    void                     *data;
    uint32_t                 wm;
    nxt_napi                 napi(env);
    napi_value               this_arg, argv, buffer;
    nxt_unit_request_info_t  *req;

    try {
        this_arg = napi.get_cb_info(info, argv);

        try {
            req = napi.get_request_info(this_arg);

        } catch (exception &e) {
            return nullptr;
        }

        if (req->content_length == 0) {
            return nullptr;
        }

        wm = napi.get_value_uint32(argv);

        if (wm > req->content_length) {
            wm = req->content_length;
        }

        buffer = napi.create_buffer((size_t) wm, &data);
        nxt_unit_request_read(req, data, wm);

    } catch (exception &e) {
        napi.throw_error(e);
        return nullptr;
    }

    return buffer;
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
    napi_value               array_entry;
    napi_valuetype           val_type;
    nxt_unit_field_t         *f;
    nxt_unit_request_info_t  *req;
    napi_value               argv[4];

    argc = 4;

    try {
        this_arg = napi.get_cb_info(info, argc, argv);
        if (argc != 4) {
            napi.throw_error("Wrong args count. Expected: "
                             "statusCode, headers, headers count, "
                             "headers length");
            return nullptr;
        }

        req = napi.get_request_info(this_arg);
        status_code = napi.get_value_uint32(argv[0]);
        keys_count = napi.get_value_uint32(argv[2]);
        header_len = napi.get_value_uint32(argv[3]);

        headers = argv[1];

        ret = nxt_unit_response_init(req, status_code, keys_count, header_len);
        if (ret != NXT_UNIT_OK) {
            napi.throw_error("Failed to create response");
            return nullptr;
        }

        /*
         * Each name and value are 0-terminated by libunit.
         * Need to add extra 2 bytes for each header.
         */
        header_len += keys_count * 2;

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

            ptr += name_len + 1;
            header_len -= name_len + 1;

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

                    ptr += value_len + 1;
                    header_len -= value_len + 1;

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

                ptr += value_len + 1;
                header_len -= value_len + 1;

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
    void                     *ptr;
    size_t                   argc, have_buf_len;
    ssize_t                  res_len;
    uint32_t                 buf_start, buf_len;
    nxt_napi                 napi(env);
    napi_value               this_arg;
    nxt_unit_buf_t           *buf;
    napi_valuetype           buf_type;
    nxt_unit_request_info_t  *req;
    napi_value               argv[3];

    argc = 3;

    try {
        this_arg = napi.get_cb_info(info, argc, argv);
        if (argc != 3) {
            throw exception("Wrong args count. Expected: "
                            "chunk, start, length");
        }

        req = napi.get_request_info(this_arg);
        buf_type = napi.type_of(argv[0]);
        buf_start = napi.get_value_uint32(argv[1]);
        buf_len = napi.get_value_uint32(argv[2]) + 1;

        if (buf_type == napi_string) {
            /* TODO: will work only for utf8 content-type */

            if (req->response_buf != NULL
                && req->response_buf->end >= req->response_buf->free + buf_len)
            {
                buf = req->response_buf;

            } else {
                buf = nxt_unit_response_buf_alloc(req, buf_len);
                if (buf == NULL) {
                    throw exception("Failed to allocate response buffer");
                }
            }

            have_buf_len = napi.get_value_string_utf8(argv[0], buf->free,
                                                      buf_len);

            buf->free += have_buf_len;

            ret = nxt_unit_buf_send(buf);
            if (ret == NXT_UNIT_OK) {
                res_len = have_buf_len;
            }

        } else {
            ptr = napi.get_buffer_info(argv[0], have_buf_len);

            if (buf_start > 0) {
                ptr = ((uint8_t *) ptr) + buf_start;
                have_buf_len -= buf_start;
            }

            res_len = nxt_unit_response_write_nb(req, ptr, have_buf_len, 0);

            ret = res_len < 0 ? -res_len : (int) NXT_UNIT_OK;
        }

        if (ret != NXT_UNIT_OK) {
            throw exception("Failed to send body buf");
        }
    } catch (exception &e) {
        napi.throw_error(e);
        return nullptr;
    }

    return napi.create((int64_t) res_len);
}


napi_value
Unit::response_end(napi_env env, napi_callback_info info)
{
    nxt_napi                 napi(env);
    napi_value               this_arg;
    req_data_t               *req_data;
    nxt_unit_request_info_t  *req;

    try {
        this_arg = napi.get_cb_info(info);

        req = napi.get_request_info(this_arg);

        req_data = (req_data_t *) req->data;

        napi.remove_wrap(req_data->sock_ref);
        napi.remove_wrap(req_data->req_ref);
        napi.remove_wrap(req_data->resp_ref);
        napi.remove_wrap(req_data->conn_ref);

    } catch (exception &e) {
        napi.throw_error(e);
        return nullptr;
    }

    nxt_unit_request_done(req, NXT_UNIT_OK);

    return this_arg;
}


napi_value
Unit::websocket_send_frame(napi_env env, napi_callback_info info)
{
    int                      ret, iovec_len;
    bool                     fin;
    size_t                   buf_len;
    uint32_t                 opcode, sc;
    nxt_napi                 napi(env);
    napi_value               this_arg, frame, payload;
    nxt_unit_request_info_t  *req;
    char                     status_code[2];
    struct iovec             iov[2];

    iovec_len = 0;

    try {
        this_arg = napi.get_cb_info(info, frame);

        req = napi.get_request_info(this_arg);

        opcode = napi.get_value_uint32(napi.get_named_property(frame,
                                                               "opcode"));
        if (opcode == NXT_WEBSOCKET_OP_CLOSE) {
            sc = napi.get_value_uint32(napi.get_named_property(frame,
                                                               "closeStatus"));
            status_code[0] = (sc >> 8) & 0xFF;
            status_code[1] = sc & 0xFF;

            iov[iovec_len].iov_base = status_code;
            iov[iovec_len].iov_len = 2;
            iovec_len++;
        }

        try {
            fin = napi.get_value_bool(napi.get_named_property(frame, "fin"));

        } catch (exception &e) {
            fin = true;
        }

        payload = napi.get_named_property(frame, "binaryPayload");

        if (napi.is_buffer(payload)) {
            iov[iovec_len].iov_base = napi.get_buffer_info(payload, buf_len);

        } else {
            buf_len = 0;
        }

    } catch (exception &e) {
        napi.throw_error(e);
        return nullptr;
    }

    if (buf_len > 0) {
        iov[iovec_len].iov_len = buf_len;
        iovec_len++;
    }

    ret = nxt_unit_websocket_sendv(req, opcode, fin ? 1 : 0, iov, iovec_len);
    if (ret != NXT_UNIT_OK) {
        goto failed;
    }

    return this_arg;

failed:

    napi.throw_error("Failed to send frame");

    return nullptr;
}


napi_value
Unit::websocket_set_sock(napi_env env, napi_callback_info info)
{
    nxt_napi                 napi(env);
    napi_value               this_arg, sock;
    req_data_t               *req_data;
    nxt_unit_request_info_t  *req;

    try {
        this_arg = napi.get_cb_info(info, sock);

        req = napi.get_request_info(sock);

        req_data = (req_data_t *) req->data;
        req_data->conn_ref = napi.wrap(this_arg, req, conn_destroy);

    } catch (exception &e) {
        napi.throw_error(e);
        return nullptr;
    }

    return this_arg;
}


void
Unit::conn_destroy(napi_env env, void *r, void *finalize_hint)
{
    nxt_unit_req_debug(NULL, "conn_destroy: %p", r);
}


void
Unit::sock_destroy(napi_env env, void *r, void *finalize_hint)
{
    nxt_unit_req_debug(NULL, "sock_destroy: %p", r);
}


void
Unit::req_destroy(napi_env env, void *r, void *finalize_hint)
{
    nxt_unit_req_debug(NULL, "req_destroy: %p", r);
}


void
Unit::resp_destroy(napi_env env, void *r, void *finalize_hint)
{
    nxt_unit_req_debug(NULL, "resp_destroy: %p", r);
}

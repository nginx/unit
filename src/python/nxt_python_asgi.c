
/*
 * Copyright (C) NGINX, Inc.
 */


#include <python/nxt_python.h>

#if (NXT_HAVE_ASGI)

#include <nxt_main.h>
#include <nxt_unit.h>
#include <nxt_unit_request.h>
#include <nxt_unit_response.h>
#include <python/nxt_python_asgi.h>
#include <python/nxt_python_asgi_str.h>


static void nxt_py_asgi_request_handler(nxt_unit_request_info_t *req);

static PyObject *nxt_py_asgi_create_http_scope(nxt_unit_request_info_t *req);
static PyObject *nxt_py_asgi_create_address(nxt_unit_sptr_t *sptr, uint8_t len,
    uint16_t port);
static PyObject *nxt_py_asgi_create_header(nxt_unit_field_t *f);
static PyObject *nxt_py_asgi_create_subprotocols(nxt_unit_field_t *f);

static int nxt_py_asgi_add_port(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port);
static void nxt_py_asgi_remove_port(nxt_unit_t *lib, nxt_unit_port_t *port);
static void nxt_py_asgi_quit(nxt_unit_ctx_t *ctx);
static void nxt_py_asgi_shm_ack_handler(nxt_unit_ctx_t *ctx);

static PyObject *nxt_py_asgi_port_read(PyObject *self, PyObject *args);


PyObject  *nxt_py_loop_run_until_complete;
PyObject  *nxt_py_loop_create_future;
PyObject  *nxt_py_loop_create_task;

nxt_queue_t  nxt_py_asgi_drain_queue;

static PyObject  *nxt_py_loop_call_soon;
static PyObject  *nxt_py_quit_future;
static PyObject  *nxt_py_quit_future_set_result;
static PyObject  *nxt_py_loop_add_reader;
static PyObject  *nxt_py_loop_remove_reader;
static PyObject  *nxt_py_port_read;

static PyMethodDef        nxt_py_port_read_method =
    {"unit_port_read", nxt_py_asgi_port_read, METH_VARARGS, ""};

#define NXT_UNIT_HASH_WS_PROTOCOL  0xED0A


int
nxt_python_asgi_check(PyObject *obj)
{
    int           res;
    PyObject      *call;
    PyCodeObject  *code;

    if (PyFunction_Check(obj)) {
        code = (PyCodeObject *) PyFunction_GET_CODE(obj);

        return (code->co_flags & CO_COROUTINE) != 0;
    }

    if (PyMethod_Check(obj)) {
        obj = PyMethod_GET_FUNCTION(obj);

        code = (PyCodeObject *) PyFunction_GET_CODE(obj);

        return (code->co_flags & CO_COROUTINE) != 0;
    }

    call = PyObject_GetAttrString(obj, "__call__");

    if (call == NULL) {
        return 0;
    }

    if (PyFunction_Check(call)) {
        code = (PyCodeObject *) PyFunction_GET_CODE(call);

        res = (code->co_flags & CO_COROUTINE) != 0;

    } else {
        if (PyMethod_Check(call)) {
            obj = PyMethod_GET_FUNCTION(call);

            code = (PyCodeObject *) PyFunction_GET_CODE(obj);

            res = (code->co_flags & CO_COROUTINE) != 0;

        } else {
            res = 0;
        }
    }

    Py_DECREF(call);

    return res;
}


nxt_int_t
nxt_python_asgi_init(nxt_task_t *task, nxt_unit_init_t *init)
{
    PyObject   *asyncio, *loop, *get_event_loop;
    nxt_int_t  rc;

    nxt_debug(task, "asgi_init");

    if (nxt_slow_path(nxt_py_asgi_str_init() != NXT_OK)) {
        nxt_alert(task, "Python failed to init string objects");
        return NXT_ERROR;
    }

    asyncio = PyImport_ImportModule("asyncio");
    if (nxt_slow_path(asyncio == NULL)) {
        nxt_alert(task, "Python failed to import module 'asyncio'");
        nxt_python_print_exception();
        return NXT_ERROR;
    }

    loop = NULL;
    get_event_loop = PyDict_GetItemString(PyModule_GetDict(asyncio),
                                          "get_event_loop");
    if (nxt_slow_path(get_event_loop == NULL)) {
        nxt_alert(task,
                 "Python failed to get 'get_event_loop' from module 'asyncio'");
        goto fail;
    }

    if (nxt_slow_path(PyCallable_Check(get_event_loop) == 0)) {
        nxt_alert(task, "'asyncio.get_event_loop' is not a callable object");
        goto fail;
    }

    loop = PyObject_CallObject(get_event_loop, NULL);
    if (nxt_slow_path(loop == NULL)) {
        nxt_alert(task, "Python failed to call 'asyncio.get_event_loop'");
        goto fail;
    }

    nxt_py_loop_create_task = PyObject_GetAttrString(loop, "create_task");
    if (nxt_slow_path(nxt_py_loop_create_task == NULL)) {
        nxt_alert(task, "Python failed to get 'loop.create_task'");
        goto fail;
    }

    if (nxt_slow_path(PyCallable_Check(nxt_py_loop_create_task) == 0)) {
        nxt_alert(task, "'loop.create_task' is not a callable object");
        goto fail;
    }

    nxt_py_loop_add_reader = PyObject_GetAttrString(loop, "add_reader");
    if (nxt_slow_path(nxt_py_loop_add_reader == NULL)) {
        nxt_alert(task, "Python failed to get 'loop.add_reader'");
        goto fail;
    }

    if (nxt_slow_path(PyCallable_Check(nxt_py_loop_add_reader) == 0)) {
        nxt_alert(task, "'loop.add_reader' is not a callable object");
        goto fail;
    }

    nxt_py_loop_remove_reader = PyObject_GetAttrString(loop, "remove_reader");
    if (nxt_slow_path(nxt_py_loop_remove_reader == NULL)) {
        nxt_alert(task, "Python failed to get 'loop.remove_reader'");
        goto fail;
    }

    if (nxt_slow_path(PyCallable_Check(nxt_py_loop_remove_reader) == 0)) {
        nxt_alert(task, "'loop.remove_reader' is not a callable object");
        goto fail;
    }

    nxt_py_loop_call_soon = PyObject_GetAttrString(loop, "call_soon");
    if (nxt_slow_path(nxt_py_loop_call_soon == NULL)) {
        nxt_alert(task, "Python failed to get 'loop.call_soon'");
        goto fail;
    }

    if (nxt_slow_path(PyCallable_Check(nxt_py_loop_call_soon) == 0)) {
        nxt_alert(task, "'loop.call_soon' is not a callable object");
        goto fail;
    }

    nxt_py_loop_run_until_complete = PyObject_GetAttrString(loop,
                                                          "run_until_complete");
    if (nxt_slow_path(nxt_py_loop_run_until_complete == NULL)) {
        nxt_alert(task, "Python failed to get 'loop.run_until_complete'");
        goto fail;
    }

    if (nxt_slow_path(PyCallable_Check(nxt_py_loop_run_until_complete) == 0)) {
        nxt_alert(task, "'loop.run_until_complete' is not a callable object");
        goto fail;
    }

    nxt_py_loop_create_future = PyObject_GetAttrString(loop, "create_future");
    if (nxt_slow_path(nxt_py_loop_create_future == NULL)) {
        nxt_alert(task, "Python failed to get 'loop.create_future'");
        goto fail;
    }

    if (nxt_slow_path(PyCallable_Check(nxt_py_loop_create_future) == 0)) {
        nxt_alert(task, "'loop.create_future' is not a callable object");
        goto fail;
    }

    nxt_py_quit_future = PyObject_CallObject(nxt_py_loop_create_future, NULL);
    if (nxt_slow_path(nxt_py_quit_future == NULL)) {
        nxt_alert(task, "Python failed to create Future ");
        nxt_python_print_exception();
        goto fail;
    }

    nxt_py_quit_future_set_result = PyObject_GetAttrString(nxt_py_quit_future,
                                                           "set_result");
    if (nxt_slow_path(nxt_py_quit_future_set_result == NULL)) {
        nxt_alert(task, "Python failed to get 'future.set_result'");
        goto fail;
    }

    if (nxt_slow_path(PyCallable_Check(nxt_py_quit_future_set_result) == 0)) {
        nxt_alert(task, "'future.set_result' is not a callable object");
        goto fail;
    }

    nxt_py_port_read = PyCFunction_New(&nxt_py_port_read_method, NULL);
    if (nxt_slow_path(nxt_py_port_read == NULL)) {
        nxt_alert(task, "Python failed to initialize the 'port_read' function");
        goto fail;
    }

    nxt_queue_init(&nxt_py_asgi_drain_queue);

    if (nxt_slow_path(nxt_py_asgi_http_init(task) == NXT_ERROR)) {
        goto fail;
    }

    if (nxt_slow_path(nxt_py_asgi_websocket_init(task) == NXT_ERROR)) {
        goto fail;
    }

    rc = nxt_py_asgi_lifespan_startup(task);
    if (nxt_slow_path(rc == NXT_ERROR)) {
        goto fail;
    }

    init->callbacks.request_handler = nxt_py_asgi_request_handler;
    init->callbacks.data_handler = nxt_py_asgi_http_data_handler;
    init->callbacks.websocket_handler = nxt_py_asgi_websocket_handler;
    init->callbacks.close_handler = nxt_py_asgi_websocket_close_handler;
    init->callbacks.quit = nxt_py_asgi_quit;
    init->callbacks.shm_ack_handler = nxt_py_asgi_shm_ack_handler;
    init->callbacks.add_port = nxt_py_asgi_add_port;
    init->callbacks.remove_port = nxt_py_asgi_remove_port;

    Py_DECREF(loop);
    Py_DECREF(asyncio);

    return NXT_OK;

fail:

    Py_XDECREF(loop);
    Py_DECREF(asyncio);

    return NXT_ERROR;
}


nxt_int_t
nxt_python_asgi_run(nxt_unit_ctx_t *ctx)
{
    PyObject  *res;

    res = PyObject_CallFunctionObjArgs(nxt_py_loop_run_until_complete,
                                       nxt_py_quit_future, NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_unit_alert(ctx, "Python failed to call loop.run_until_complete");
        nxt_python_print_exception();

        return NXT_ERROR;
    }

    Py_DECREF(res);

    nxt_py_asgi_lifespan_shutdown();

    return NXT_OK;
}


static void
nxt_py_asgi_request_handler(nxt_unit_request_info_t *req)
{
    PyObject  *scope, *res, *task, *receive, *send, *done, *asgi;

    if (req->request->websocket_handshake) {
        asgi = nxt_py_asgi_websocket_create(req);

    } else {
        asgi = nxt_py_asgi_http_create(req);
    }

    if (nxt_slow_path(asgi == NULL)) {
        nxt_unit_req_alert(req, "Python failed to create asgi object");
        nxt_unit_request_done(req, NXT_UNIT_ERROR);

        return;
    }

    receive = PyObject_GetAttrString(asgi, "receive");
    if (nxt_slow_path(receive == NULL)) {
        nxt_unit_req_alert(req, "Python failed to get 'receive' method");
        nxt_unit_request_done(req, NXT_UNIT_ERROR);

        goto release_asgi;
    }

    send = PyObject_GetAttrString(asgi, "send");
    if (nxt_slow_path(receive == NULL)) {
        nxt_unit_req_alert(req, "Python failed to get 'send' method");
        nxt_unit_request_done(req, NXT_UNIT_ERROR);

        goto release_receive;
    }

    done = PyObject_GetAttrString(asgi, "_done");
    if (nxt_slow_path(receive == NULL)) {
        nxt_unit_req_alert(req, "Python failed to get '_done' method");
        nxt_unit_request_done(req, NXT_UNIT_ERROR);

        goto release_send;
    }

    scope = nxt_py_asgi_create_http_scope(req);
    if (nxt_slow_path(scope == NULL)) {
        nxt_unit_request_done(req, NXT_UNIT_ERROR);

        goto release_done;
    }

    req->data = asgi;

    res = PyObject_CallFunctionObjArgs(nxt_py_application,
                                       scope, receive, send, NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_unit_req_error(req, "Python failed to call the application");
        nxt_python_print_exception();
        nxt_unit_request_done(req, NXT_UNIT_ERROR);

        goto release_scope;
    }

    if (nxt_slow_path(!PyCoro_CheckExact(res))) {
        nxt_unit_req_error(req, "Application result type is not a coroutine");
        nxt_unit_request_done(req, NXT_UNIT_ERROR);

        Py_DECREF(res);

        goto release_scope;
    }

    task = PyObject_CallFunctionObjArgs(nxt_py_loop_create_task, res, NULL);
    if (nxt_slow_path(task == NULL)) {
        nxt_unit_req_error(req, "Python failed to call the create_task");
        nxt_python_print_exception();
        nxt_unit_request_done(req, NXT_UNIT_ERROR);

        Py_DECREF(res);

        goto release_scope;
    }

    Py_DECREF(res);

    res = PyObject_CallMethodObjArgs(task, nxt_py_add_done_callback_str, done,
                                     NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_unit_req_error(req,
                           "Python failed to call 'task.add_done_callback'");
        nxt_python_print_exception();
        nxt_unit_request_done(req, NXT_UNIT_ERROR);

        goto release_task;
    }

    Py_DECREF(res);
release_task:
    Py_DECREF(task);
release_scope:
    Py_DECREF(scope);
release_done:
    Py_DECREF(done);
release_send:
    Py_DECREF(send);
release_receive:
    Py_DECREF(receive);
release_asgi:
    Py_DECREF(asgi);
}


static PyObject *
nxt_py_asgi_create_http_scope(nxt_unit_request_info_t *req)
{
    char                *p, *target, *query;
    uint32_t            target_length, i;
    PyObject            *scope, *v, *type, *scheme;
    PyObject            *headers, *header;
    nxt_unit_field_t    *f;
    nxt_unit_request_t  *r;

    static const nxt_str_t  ws_protocol = nxt_string("sec-websocket-protocol");

#define SET_ITEM(dict, key, value) \
    if (nxt_slow_path(PyDict_SetItem(dict, nxt_py_ ## key ## _str, value)      \
                      == -1))                                                  \
    {                                                                          \
        nxt_unit_req_alert(req, "Python failed to set '"                       \
                                #dict "." #key "' item");                      \
        goto fail;                                                             \
    }

    v = NULL;
    headers = NULL;

    r = req->request;

    if (r->websocket_handshake) {
        type = nxt_py_websocket_str;
        scheme = r->tls ? nxt_py_wss_str : nxt_py_ws_str;

    } else {
        type = nxt_py_http_str;
        scheme = r->tls ? nxt_py_https_str : nxt_py_http_str;
    }

    scope = nxt_py_asgi_new_scope(req, type, nxt_py_2_1_str);
    if (nxt_slow_path(scope == NULL)) {
        return NULL;
    }

    p = nxt_unit_sptr_get(&r->version);
    SET_ITEM(scope, http_version, p[7] == '1' ? nxt_py_1_1_str
                                              : nxt_py_1_0_str)
    SET_ITEM(scope, scheme, scheme)

    v = PyString_FromStringAndSize(nxt_unit_sptr_get(&r->method),
                                   r->method_length);
    if (nxt_slow_path(v == NULL)) {
        nxt_unit_req_alert(req, "Python failed to create 'method' string");
        goto fail;
    }

    SET_ITEM(scope, method, v)
    Py_DECREF(v);

    v = PyUnicode_DecodeUTF8(nxt_unit_sptr_get(&r->path), r->path_length,
                             "replace");
    if (nxt_slow_path(v == NULL)) {
        nxt_unit_req_alert(req, "Python failed to create 'path' string");
        goto fail;
    }

    SET_ITEM(scope, path, v)
    Py_DECREF(v);

    target = nxt_unit_sptr_get(&r->target);
    query = nxt_unit_sptr_get(&r->query);

    if (r->query.offset != 0) {
        target_length = query - target - 1;

    } else {
        target_length = r->target_length;
    }

    v = PyBytes_FromStringAndSize(target, target_length);
    if (nxt_slow_path(v == NULL)) {
        nxt_unit_req_alert(req, "Python failed to create 'raw_path' string");
        goto fail;
    }

    SET_ITEM(scope, raw_path, v)
    Py_DECREF(v);

    v = PyBytes_FromStringAndSize(query, r->query_length);
    if (nxt_slow_path(v == NULL)) {
        nxt_unit_req_alert(req, "Python failed to create 'query' string");
        goto fail;
    }

    SET_ITEM(scope, query_string, v)
    Py_DECREF(v);

    v = nxt_py_asgi_create_address(&r->remote, r->remote_length, 0);
    if (nxt_slow_path(v == NULL)) {
        nxt_unit_req_alert(req, "Python failed to create 'client' pair");
        goto fail;
    }

    SET_ITEM(scope, client, v)
    Py_DECREF(v);

    v = nxt_py_asgi_create_address(&r->local, r->local_length, 80);
    if (nxt_slow_path(v == NULL)) {
        nxt_unit_req_alert(req, "Python failed to create 'server' pair");
        goto fail;
    }

    SET_ITEM(scope, server, v)
    Py_DECREF(v);

    v = NULL;

    headers = PyTuple_New(r->fields_count);
    if (nxt_slow_path(headers == NULL)) {
        nxt_unit_req_alert(req, "Python failed to create 'headers' object");
        goto fail;
    }

    for (i = 0; i < r->fields_count; i++) {
        f = r->fields + i;

        header = nxt_py_asgi_create_header(f);
        if (nxt_slow_path(header == NULL)) {
            nxt_unit_req_alert(req, "Python failed to create 'header' pair");
            goto fail;
        }

        PyTuple_SET_ITEM(headers, i, header);

        if (f->hash == NXT_UNIT_HASH_WS_PROTOCOL
            && f->name_length == ws_protocol.length
            && f->value_length > 0
            && r->websocket_handshake)
        {
            v = nxt_py_asgi_create_subprotocols(f);
            if (nxt_slow_path(v == NULL)) {
                nxt_unit_req_alert(req, "Failed to create subprotocols");
                goto fail;
            }

            SET_ITEM(scope, subprotocols, v);
            Py_DECREF(v);
        }
    }

    SET_ITEM(scope, headers, headers)
    Py_DECREF(headers);

    return scope;

fail:

    Py_XDECREF(v);
    Py_XDECREF(headers);
    Py_DECREF(scope);

    return NULL;

#undef SET_ITEM
}


static PyObject *
nxt_py_asgi_create_address(nxt_unit_sptr_t *sptr, uint8_t len, uint16_t port)
{
    char      *p, *s;
    PyObject  *pair, *v;

    pair = PyTuple_New(2);
    if (nxt_slow_path(pair == NULL)) {
        return NULL;
    }

    p = nxt_unit_sptr_get(sptr);
    s = memchr(p, ':', len);

    v = PyString_FromStringAndSize(p, s == NULL ? len : s - p);
    if (nxt_slow_path(v == NULL)) {
        Py_DECREF(pair);

        return NULL;
    }

    PyTuple_SET_ITEM(pair, 0, v);

    if (s != NULL) {
        p += len;
        v = PyLong_FromString(s + 1, &p, 10);

    } else {
        v = PyLong_FromLong(port);
    }

    if (nxt_slow_path(v == NULL)) {
        Py_DECREF(pair);

        return NULL;
    }

    PyTuple_SET_ITEM(pair, 1, v);

    return pair;
}


static PyObject *
nxt_py_asgi_create_header(nxt_unit_field_t *f)
{
    char      c, *name;
    uint8_t   pos;
    PyObject  *header, *v;

    header = PyTuple_New(2);
    if (nxt_slow_path(header == NULL)) {
        return NULL;
    }

    name = nxt_unit_sptr_get(&f->name);

    for (pos = 0; pos < f->name_length; pos++) {
        c = name[pos];
        if (c >= 'A' && c <= 'Z') {
            name[pos] = (c | 0x20);
        }
    }

    v = PyBytes_FromStringAndSize(name, f->name_length);
    if (nxt_slow_path(v == NULL)) {
        Py_DECREF(header);

        return NULL;
    }

    PyTuple_SET_ITEM(header, 0, v);

    v = PyBytes_FromStringAndSize(nxt_unit_sptr_get(&f->value),
                                  f->value_length);
    if (nxt_slow_path(v == NULL)) {
        Py_DECREF(header);

        return NULL;
    }

    PyTuple_SET_ITEM(header, 1, v);

    return header;
}


static PyObject *
nxt_py_asgi_create_subprotocols(nxt_unit_field_t *f)
{
    char      *v;
    uint32_t  i, n, start;
    PyObject  *res, *proto;

    v = nxt_unit_sptr_get(&f->value);
    n = 1;

    for (i = 0; i < f->value_length; i++) {
        if (v[i] == ',') {
            n++;
        }
    }

    res = PyTuple_New(n);
    if (nxt_slow_path(res == NULL)) {
        return NULL;
    }

    n = 0;
    start = 0;

    for (i = 0; i < f->value_length; ) {
        if (v[i] != ',') {
            i++;

            continue;
        }

        if (i - start > 0) {
            proto = PyString_FromStringAndSize(v + start, i - start);
            if (nxt_slow_path(proto == NULL)) {
                goto fail;
            }

            PyTuple_SET_ITEM(res, n, proto);

            n++;
        }

        do {
            i++;
        } while (i < f->value_length && v[i] == ' ');

        start = i;
    }

    if (i - start > 0) {
        proto = PyString_FromStringAndSize(v + start, i - start);
        if (nxt_slow_path(proto == NULL)) {
            goto fail;
        }

        PyTuple_SET_ITEM(res, n, proto);
    }

    return res;

fail:

    Py_DECREF(res);

    return NULL;
}


static int
nxt_py_asgi_add_port(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port)
{
    int       nb;
    PyObject  *res;

    if (port->in_fd == -1) {
        return NXT_UNIT_OK;
    }

    nb = 1;

    if (nxt_slow_path(ioctl(port->in_fd, FIONBIO, &nb) == -1)) {
        nxt_unit_alert(ctx, "ioctl(%d, FIONBIO, 0) failed: %s (%d)",
                       port->in_fd, strerror(errno), errno);

        return NXT_UNIT_ERROR;
    }

    nxt_unit_debug(ctx, "asgi_add_port %d %p %p", port->in_fd, ctx, port);

    res = PyObject_CallFunctionObjArgs(nxt_py_loop_add_reader,
                                       PyLong_FromLong(port->in_fd),
                                       nxt_py_port_read,
                                       PyLong_FromVoidPtr(ctx),
                                       PyLong_FromVoidPtr(port), NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_unit_alert(ctx, "Python failed to add_reader");

        return NXT_UNIT_ERROR;
    }

    Py_DECREF(res);

    return NXT_UNIT_OK;
}


static void
nxt_py_asgi_remove_port(nxt_unit_t *lib, nxt_unit_port_t *port)
{
    PyObject  *res;

    nxt_unit_debug(NULL, "asgi_remove_port %d %p", port->in_fd, port);

    if (port->in_fd == -1) {
        return;
    }

    res = PyObject_CallFunctionObjArgs(nxt_py_loop_remove_reader,
                                       PyLong_FromLong(port->in_fd), NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_unit_alert(NULL, "Python failed to remove_reader");
    }

    Py_DECREF(res);
}


static void
nxt_py_asgi_quit(nxt_unit_ctx_t *ctx)
{
    PyObject  *res;

    nxt_unit_debug(ctx, "asgi_quit %p", ctx);

    res = PyObject_CallFunctionObjArgs(nxt_py_quit_future_set_result,
                                       PyLong_FromLong(0), NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_unit_alert(ctx, "Python failed to set_result");
    }

    Py_DECREF(res);
}


static void
nxt_py_asgi_shm_ack_handler(nxt_unit_ctx_t *ctx)
{
    int               rc;
    nxt_queue_link_t  *lnk;

    while (!nxt_queue_is_empty(&nxt_py_asgi_drain_queue)) {
        lnk = nxt_queue_first(&nxt_py_asgi_drain_queue);

        rc = nxt_py_asgi_http_drain(lnk);
        if (rc == NXT_UNIT_AGAIN) {
            break;
        }

        nxt_queue_remove(lnk);
    }
}


static PyObject *
nxt_py_asgi_port_read(PyObject *self, PyObject *args)
{
    int              rc;
    PyObject         *arg;
    Py_ssize_t       n;
    nxt_unit_ctx_t   *ctx;
    nxt_unit_port_t  *port;

    n = PyTuple_GET_SIZE(args);

    if (n != 2) {
        nxt_unit_alert(NULL,
                       "nxt_py_asgi_port_read: invalid number of arguments %d",
                       (int) n);

        return PyErr_Format(PyExc_TypeError, "invalid number of arguments");
    }

    arg = PyTuple_GET_ITEM(args, 0);
    if (nxt_slow_path(arg == NULL || PyLong_Check(arg) == 0)) {
        return PyErr_Format(PyExc_TypeError,
                            "the first argument is not a long");
    }

    ctx = PyLong_AsVoidPtr(arg);

    arg = PyTuple_GET_ITEM(args, 1);
    if (nxt_slow_path(arg == NULL || PyLong_Check(arg) == 0)) {
        return PyErr_Format(PyExc_TypeError,
                            "the second argument is not a long");
    }

    port = PyLong_AsVoidPtr(arg);

    nxt_unit_debug(ctx, "asgi_port_read %p %p", ctx, port);

    rc = nxt_unit_process_port_msg(ctx, port);

    if (nxt_slow_path(rc == NXT_UNIT_ERROR)) {
        return PyErr_Format(PyExc_RuntimeError,
                            "error processing port message");
    }

    Py_RETURN_NONE;
}


PyObject *
nxt_py_asgi_enum_headers(PyObject *headers, nxt_py_asgi_enum_header_cb cb,
    void *data)
{
    int       i;
    PyObject  *iter, *header, *h_iter, *name, *val, *res;

    iter = PyObject_GetIter(headers);
    if (nxt_slow_path(iter == NULL)) {
        return PyErr_Format(PyExc_TypeError, "'headers' is not an iterable");
    }

    for (i = 0; /* void */; i++) {
        header = PyIter_Next(iter);
        if (header == NULL) {
            break;
        }

        h_iter = PyObject_GetIter(header);
        if (nxt_slow_path(h_iter == NULL)) {
            Py_DECREF(header);
            Py_DECREF(iter);

            return PyErr_Format(PyExc_TypeError,
                                "'headers' item #%d is not an iterable", i);
        }

        name = PyIter_Next(h_iter);
        if (nxt_slow_path(name == NULL || !PyBytes_Check(name))) {
            Py_XDECREF(name);
            Py_DECREF(h_iter);
            Py_DECREF(header);
            Py_DECREF(iter);

            return PyErr_Format(PyExc_TypeError,
                          "'headers' item #%d 'name' is not a byte string", i);
        }

        val = PyIter_Next(h_iter);
        if (nxt_slow_path(val == NULL || !PyBytes_Check(val))) {
            Py_XDECREF(val);
            Py_DECREF(h_iter);
            Py_DECREF(header);
            Py_DECREF(iter);

            return PyErr_Format(PyExc_TypeError,
                         "'headers' item #%d 'value' is not a byte string", i);
        }

        res = cb(data, i, name, val);

        Py_DECREF(name);
        Py_DECREF(val);
        Py_DECREF(h_iter);
        Py_DECREF(header);

        if (nxt_slow_path(res == NULL)) {
            Py_DECREF(iter);

            return NULL;
        }

        Py_DECREF(res);
    }

    Py_DECREF(iter);

    Py_RETURN_NONE;
}


PyObject *
nxt_py_asgi_calc_size(void *data, int i, PyObject *name, PyObject *val)
{
    nxt_py_asgi_calc_size_ctx_t  *ctx;

    ctx = data;

    ctx->fields_count++;
    ctx->fields_size += PyBytes_GET_SIZE(name) + PyBytes_GET_SIZE(val);

    Py_RETURN_NONE;
}


PyObject *
nxt_py_asgi_add_field(void *data, int i, PyObject *name, PyObject *val)
{
    int                          rc;
    char                         *name_str, *val_str;
    uint32_t                     name_len, val_len;
    nxt_off_t                    content_length;
    nxt_unit_request_info_t      *req;
    nxt_py_asgi_add_field_ctx_t  *ctx;

    name_str = PyBytes_AS_STRING(name);
    name_len = PyBytes_GET_SIZE(name);

    val_str = PyBytes_AS_STRING(val);
    val_len = PyBytes_GET_SIZE(val);

    ctx = data;
    req = ctx->req;

    rc = nxt_unit_response_add_field(req, name_str, name_len,
                                     val_str, val_len);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return PyErr_Format(PyExc_RuntimeError,
                            "failed to add header #%d", i);
    }

    if (req->response->fields[i].hash == NXT_UNIT_HASH_CONTENT_LENGTH) {
        content_length = nxt_off_t_parse((u_char *) val_str, val_len);
        if (nxt_slow_path(content_length < 0)) {
            nxt_unit_req_error(req, "failed to parse Content-Length "
                               "value %.*s", (int) val_len, val_str);

            return PyErr_Format(PyExc_ValueError,
                                "Failed to parse Content-Length: '%.*s'",
                                (int) val_len, val_str);
        }

        ctx->content_length = content_length;
    }

    Py_RETURN_NONE;
}


PyObject *
nxt_py_asgi_set_result_soon(nxt_unit_request_info_t *req, PyObject *future,
    PyObject *result)
{
    PyObject  *set_result, *res;

    if (nxt_slow_path(result == NULL)) {
        Py_DECREF(future);

        return NULL;
    }

    set_result = PyObject_GetAttrString(future, "set_result");
    if (nxt_slow_path(set_result == NULL)) {
        nxt_unit_req_alert(req, "failed to get 'set_result' for future");

        Py_CLEAR(future);

        goto cleanup;
    }

    if (nxt_slow_path(PyCallable_Check(set_result) == 0)) {
        nxt_unit_req_alert(req, "'future.set_result' is not a callable");

        Py_CLEAR(future);

        goto cleanup;
    }

    res = PyObject_CallFunctionObjArgs(nxt_py_loop_call_soon, set_result,
                                       result, NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_unit_req_alert(req, "Python failed to call 'loop.call_soon'");
        nxt_python_print_exception();

        Py_CLEAR(future);
    }

    Py_XDECREF(res);

cleanup:

    Py_DECREF(set_result);
    Py_DECREF(result);

    return future;
}


PyObject *
nxt_py_asgi_new_msg(nxt_unit_request_info_t *req, PyObject *type)
{
    PyObject  *msg;

    msg = PyDict_New();
    if (nxt_slow_path(msg == NULL)) {
        nxt_unit_req_alert(req, "Python failed to create message dict");
        nxt_python_print_exception();

        return PyErr_Format(PyExc_RuntimeError,
                            "failed to create message dict");
    }

    if (nxt_slow_path(PyDict_SetItem(msg, nxt_py_type_str, type) == -1)) {
        nxt_unit_req_alert(req, "Python failed to set 'msg.type' item");

        Py_DECREF(msg);

        return PyErr_Format(PyExc_RuntimeError,
                            "failed to set 'msg.type' item");
    }

    return msg;
}


PyObject *
nxt_py_asgi_new_scope(nxt_unit_request_info_t *req, PyObject *type,
    PyObject *spec_version)
{
    PyObject  *scope, *asgi;

    scope = PyDict_New();
    if (nxt_slow_path(scope == NULL)) {
        nxt_unit_req_alert(req, "Python failed to create 'scope' dict");
        nxt_python_print_exception();

        return PyErr_Format(PyExc_RuntimeError,
                            "failed to create 'scope' dict");
    }

    if (nxt_slow_path(PyDict_SetItem(scope, nxt_py_type_str, type) == -1)) {
        nxt_unit_req_alert(req, "Python failed to set 'scope.type' item");

        Py_DECREF(scope);

        return PyErr_Format(PyExc_RuntimeError,
                            "failed to set 'scope.type' item");
    }

    asgi = PyDict_New();
    if (nxt_slow_path(asgi == NULL)) {
        nxt_unit_req_alert(req, "Python failed to create 'asgi' dict");
        nxt_python_print_exception();

        Py_DECREF(scope);

        return PyErr_Format(PyExc_RuntimeError,
                            "failed to create 'asgi' dict");
    }

    if (nxt_slow_path(PyDict_SetItem(scope, nxt_py_asgi_str, asgi) == -1)) {
        nxt_unit_req_alert(req, "Python failed to set 'scope.asgi' item");

        Py_DECREF(asgi);
        Py_DECREF(scope);

        return PyErr_Format(PyExc_RuntimeError,
                            "failed to set 'scope.asgi' item");
    }

    if (nxt_slow_path(PyDict_SetItem(asgi, nxt_py_version_str,
                                     nxt_py_3_0_str) == -1))
    {
        nxt_unit_req_alert(req, "Python failed to set 'asgi.version' item");

        Py_DECREF(asgi);
        Py_DECREF(scope);

        return PyErr_Format(PyExc_RuntimeError,
                            "failed to set 'asgi.version' item");
    }

    if (nxt_slow_path(PyDict_SetItem(asgi, nxt_py_spec_version_str,
                                     spec_version) == -1))
    {
        nxt_unit_req_alert(req,
                           "Python failed to set 'asgi.spec_version' item");

        Py_DECREF(asgi);
        Py_DECREF(scope);

        return PyErr_Format(PyExc_RuntimeError,
                            "failed to set 'asgi.spec_version' item");
    }

    Py_DECREF(asgi);

    return scope;
}


void
nxt_py_asgi_dealloc(PyObject *self)
{
    PyObject_Del(self);
}


PyObject *
nxt_py_asgi_await(PyObject *self)
{
    Py_INCREF(self);
    return self;
}


PyObject *
nxt_py_asgi_iter(PyObject *self)
{
    Py_INCREF(self);
    return self;
}


PyObject *
nxt_py_asgi_next(PyObject *self)
{
    return NULL;
}


void
nxt_python_asgi_done(void)
{
    nxt_py_asgi_str_done();

    Py_XDECREF(nxt_py_quit_future);
    Py_XDECREF(nxt_py_quit_future_set_result);
    Py_XDECREF(nxt_py_loop_run_until_complete);
    Py_XDECREF(nxt_py_loop_create_future);
    Py_XDECREF(nxt_py_loop_create_task);
    Py_XDECREF(nxt_py_loop_call_soon);
    Py_XDECREF(nxt_py_loop_add_reader);
    Py_XDECREF(nxt_py_loop_remove_reader);
    Py_XDECREF(nxt_py_port_read);
}

#else /* !(NXT_HAVE_ASGI) */


int
nxt_python_asgi_check(PyObject *obj)
{
    return 0;
}


nxt_int_t
nxt_python_asgi_init(nxt_task_t *task, nxt_unit_init_t *init)
{
    nxt_alert(task, "ASGI not implemented");
    return NXT_ERROR;
}


nxt_int_t
nxt_python_asgi_run(nxt_unit_ctx_t *ctx)
{
    nxt_unit_alert(ctx, "ASGI not implemented");
    return NXT_ERROR;
}


void
nxt_python_asgi_done(void)
{
}

#endif /* NXT_HAVE_ASGI */

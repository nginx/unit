
/*
 * Copyright (C) NGINX, Inc.
 */


#include <python/nxt_python.h>

#if (NXT_HAVE_ASGI)

#include <nxt_main.h>
#include <nxt_unit.h>
#include <nxt_unit_request.h>
#include <python/nxt_python_asgi.h>
#include <python/nxt_python_asgi_str.h>


typedef struct {
    PyObject_HEAD
    nxt_unit_request_info_t  *req;
    nxt_queue_link_t         link;
    PyObject                 *receive_future;
    PyObject                 *send_future;
    uint64_t                 content_length;
    uint64_t                 bytes_sent;
    PyObject                 *send_body;
    Py_ssize_t               send_body_off;
    uint8_t                  complete;
    uint8_t                  closed;
    uint8_t                  request_received;
} nxt_py_asgi_http_t;


static PyObject *nxt_py_asgi_http_receive(PyObject *self, PyObject *none);
static PyObject *nxt_py_asgi_http_read_msg(nxt_py_asgi_http_t *http);
static PyObject *nxt_py_asgi_http_send(PyObject *self, PyObject *dict);
static PyObject *nxt_py_asgi_http_response_start(nxt_py_asgi_http_t *http,
    PyObject *dict);
static PyObject *nxt_py_asgi_http_response_body(nxt_py_asgi_http_t *http,
    PyObject *dict);
static void nxt_py_asgi_http_emit_disconnect(nxt_py_asgi_http_t *http);
static void nxt_py_asgi_http_set_result(nxt_py_asgi_http_t *http,
    PyObject *future, PyObject *msg);
static PyObject *nxt_py_asgi_http_done(PyObject *self, PyObject *future);


static PyMethodDef nxt_py_asgi_http_methods[] = {
    { "receive",   nxt_py_asgi_http_receive, METH_NOARGS, 0 },
    { "send",      nxt_py_asgi_http_send,    METH_O,      0 },
    { "_done",     nxt_py_asgi_http_done,    METH_O,      0 },
    { NULL, NULL, 0, 0 }
};

static PyAsyncMethods nxt_py_asgi_async_methods = {
    .am_await = nxt_py_asgi_await,
};

static PyTypeObject nxt_py_asgi_http_type = {
    PyVarObject_HEAD_INIT(NULL, 0)

    .tp_name      = "unit._asgi_http",
    .tp_basicsize = sizeof(nxt_py_asgi_http_t),
    .tp_dealloc   = nxt_py_asgi_dealloc,
    .tp_as_async  = &nxt_py_asgi_async_methods,
    .tp_flags     = Py_TPFLAGS_DEFAULT,
    .tp_doc       = "unit ASGI HTTP request object",
    .tp_iter      = nxt_py_asgi_iter,
    .tp_iternext  = nxt_py_asgi_next,
    .tp_methods   = nxt_py_asgi_http_methods,
};

static Py_ssize_t  nxt_py_asgi_http_body_buf_size = 32 * 1024 * 1024;


int
nxt_py_asgi_http_init(void)
{
    if (nxt_slow_path(PyType_Ready(&nxt_py_asgi_http_type) != 0)) {
        nxt_unit_alert(NULL,
                       "Python failed to initialize the 'http' type object");
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


PyObject *
nxt_py_asgi_http_create(nxt_unit_request_info_t *req)
{
    nxt_py_asgi_http_t  *http;

    http = PyObject_New(nxt_py_asgi_http_t, &nxt_py_asgi_http_type);

    if (nxt_fast_path(http != NULL)) {
        http->req = req;
        http->receive_future = NULL;
        http->send_future = NULL;
        http->content_length = -1;
        http->bytes_sent = 0;
        http->send_body = NULL;
        http->send_body_off = 0;
        http->complete = 0;
        http->closed = 0;
        http->request_received = 0;
    }

    return (PyObject *) http;
}


static PyObject *
nxt_py_asgi_http_receive(PyObject *self, PyObject *none)
{
    PyObject                 *msg, *future;
    nxt_py_asgi_http_t       *http;
    nxt_py_asgi_ctx_data_t   *ctx_data;
    nxt_unit_request_info_t  *req;

    http = (nxt_py_asgi_http_t *) self;
    req = http->req;

    nxt_unit_req_debug(req, "asgi_http_receive");

    if (nxt_slow_path(http->closed || http->complete )) {
        msg = nxt_py_asgi_new_msg(req, nxt_py_http_disconnect_str);

    } else {
        msg = nxt_py_asgi_http_read_msg(http);
    }

    if (nxt_slow_path(msg == NULL)) {
        return NULL;
    }

    ctx_data = req->ctx->data;

    future = PyObject_CallObject(ctx_data->loop_create_future, NULL);
    if (nxt_slow_path(future == NULL)) {
        nxt_unit_req_alert(req, "Python failed to create Future object");
        nxt_python_print_exception();

        Py_DECREF(msg);

        return PyErr_Format(PyExc_RuntimeError,
                            "failed to create Future object");
    }

    if (msg != Py_None) {
        return nxt_py_asgi_set_result_soon(req, ctx_data, future, msg);
    }

    http->receive_future = future;
    Py_INCREF(http->receive_future);

    Py_DECREF(msg);

    return future;
}


static PyObject *
nxt_py_asgi_http_read_msg(nxt_py_asgi_http_t *http)
{
    char                     *body_buf;
    ssize_t                  read_res;
    PyObject                 *msg, *body;
    Py_ssize_t               size;
    nxt_unit_request_info_t  *req;

    req = http->req;

    size = req->content_length;

    if (size > nxt_py_asgi_http_body_buf_size) {
        size = nxt_py_asgi_http_body_buf_size;
    }

    if (size == 0) {
        if (http->request_received) {
            Py_RETURN_NONE;
        }
    }

    if (size > 0) {
        body = PyBytes_FromStringAndSize(NULL, size);
        if (nxt_slow_path(body == NULL)) {
            nxt_unit_req_alert(req, "Python failed to create body byte string");
            nxt_python_print_exception();

            return PyErr_Format(PyExc_RuntimeError,
                                "failed to create Bytes object");
        }

        body_buf = PyBytes_AS_STRING(body);

        read_res = nxt_unit_request_read(req, body_buf, size);

    } else {
        body = NULL;
        read_res = 0;
    }

    if (read_res > 0 || read_res == size) {
        msg = nxt_py_asgi_new_msg(req, nxt_py_http_request_str);
        if (nxt_slow_path(msg == NULL)) {
            Py_XDECREF(body);

            return NULL;
        }

#define SET_ITEM(dict, key, value) \
    if (nxt_slow_path(PyDict_SetItem(dict, nxt_py_ ## key ## _str, value)      \
                        == -1))                                                \
    {                                                                          \
        nxt_unit_req_alert(req,                                                \
                           "Python failed to set '" #dict "." #key "' item");  \
        PyErr_SetString(PyExc_RuntimeError,                                    \
                        "Python failed to set '" #dict "." #key "' item");     \
        goto fail;                                                             \
    }

        if (body != NULL) {
            SET_ITEM(msg, body, body)
        }

        if (req->content_length > 0) {
            SET_ITEM(msg, more_body, Py_True)
        }

#undef SET_ITEM

        Py_XDECREF(body);

        http->request_received = 1;

        return msg;
    }

    Py_XDECREF(body);

    Py_RETURN_NONE;

fail:

    Py_DECREF(msg);
    Py_XDECREF(body);

    return NULL;
}


static PyObject *
nxt_py_asgi_http_send(PyObject *self, PyObject *dict)
{
    PyObject            *type;
    const char          *type_str;
    Py_ssize_t          type_len;
    nxt_py_asgi_http_t  *http;

    static const nxt_str_t  response_start = nxt_string("http.response.start");
    static const nxt_str_t  response_body = nxt_string("http.response.body");

    http = (nxt_py_asgi_http_t *) self;

    type = PyDict_GetItem(dict, nxt_py_type_str);
    if (nxt_slow_path(type == NULL || !PyUnicode_Check(type))) {
        nxt_unit_req_error(http->req, "asgi_http_send: "
                                      "'type' is not a unicode string");
        return PyErr_Format(PyExc_TypeError, "'type' is not a unicode string");
    }

    type_str = PyUnicode_AsUTF8AndSize(type, &type_len);

    nxt_unit_req_debug(http->req, "asgi_http_send type is '%.*s'",
                       (int) type_len, type_str);

    if (nxt_unit_response_is_init(http->req)) {
        if (nxt_str_eq(&response_body, type_str, (size_t) type_len)) {
            return nxt_py_asgi_http_response_body(http, dict);
        }

        return PyErr_Format(PyExc_RuntimeError,
                            "Expected ASGI message 'http.response.body', "
                            "but got '%U'", type);
    }

    if (nxt_str_eq(&response_start, type_str, (size_t) type_len)) {
        return nxt_py_asgi_http_response_start(http, dict);
    }

    return PyErr_Format(PyExc_RuntimeError,
                        "Expected ASGI message 'http.response.start', "
                        "but got '%U'", type);
}


static PyObject *
nxt_py_asgi_http_response_start(nxt_py_asgi_http_t *http, PyObject *dict)
{
    int                          rc;
    PyObject                     *status, *headers, *res;
    nxt_py_asgi_calc_size_ctx_t  calc_size_ctx;
    nxt_py_asgi_add_field_ctx_t  add_field_ctx;

    status = PyDict_GetItem(dict, nxt_py_status_str);
    if (nxt_slow_path(status == NULL || !PyLong_Check(status))) {
        nxt_unit_req_error(http->req, "asgi_http_response_start: "
                                      "'status' is not an integer");
        return PyErr_Format(PyExc_TypeError, "'status' is not an integer");
    }

    calc_size_ctx.fields_size = 0;
    calc_size_ctx.fields_count = 0;

    headers = PyDict_GetItem(dict, nxt_py_headers_str);
    if (headers != NULL) {
        res = nxt_py_asgi_enum_headers(headers, nxt_py_asgi_calc_size,
                                       &calc_size_ctx);
        if (nxt_slow_path(res == NULL)) {
            return NULL;
        }

        Py_DECREF(res);
    }

    rc = nxt_unit_response_init(http->req, PyLong_AsLong(status),
                                calc_size_ctx.fields_count,
                                calc_size_ctx.fields_size);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return PyErr_Format(PyExc_RuntimeError,
                            "failed to allocate response object");
    }

    add_field_ctx.req = http->req;
    add_field_ctx.content_length = -1;

    if (headers != NULL) {
        res = nxt_py_asgi_enum_headers(headers, nxt_py_asgi_add_field,
                                       &add_field_ctx);
        if (nxt_slow_path(res == NULL)) {
            return NULL;
        }

        Py_DECREF(res);
    }

    http->content_length = add_field_ctx.content_length;

    Py_INCREF(http);
    return (PyObject *) http;
}


static PyObject *
nxt_py_asgi_http_response_body(nxt_py_asgi_http_t *http, PyObject *dict)
{
    int                     rc;
    char                    *body_str;
    ssize_t                 sent;
    PyObject                *body, *more_body, *future;
    Py_ssize_t              body_len, body_off;
    nxt_py_asgi_ctx_data_t  *ctx_data;

    if (nxt_slow_path(http->complete)) {
        return PyErr_Format(PyExc_RuntimeError,
                            "Unexpected ASGI message 'http.response.body' "
                            "sent, after response already completed");
    }

    if (nxt_slow_path(http->send_future != NULL)) {
        return PyErr_Format(PyExc_RuntimeError, "Concurrent send");
    }

    more_body = PyDict_GetItem(dict, nxt_py_more_body_str);
    if (nxt_slow_path(more_body != NULL && !PyBool_Check(more_body))) {
        return PyErr_Format(PyExc_TypeError, "'more_body' is not a bool");
    }

    body = PyDict_GetItem(dict, nxt_py_body_str);

    if (body != NULL) {
        if (PyBytes_Check(body)) {
            body_str = PyBytes_AS_STRING(body);
            body_len = PyBytes_GET_SIZE(body);

        } else if (PyByteArray_Check(body)) {
            body_str = PyByteArray_AS_STRING(body);
            body_len = PyByteArray_GET_SIZE(body);

        } else {
            return PyErr_Format(PyExc_TypeError,
                                "'body' is not a byte string or bytearray");
        }

        nxt_unit_req_debug(http->req, "asgi_http_response_body: %d, %d",
                           (int) body_len, (more_body == Py_True) );

        if (nxt_slow_path(http->bytes_sent + body_len
                              > http->content_length))
        {
            return PyErr_Format(PyExc_RuntimeError,
                                "Response content longer than Content-Length");
        }

        body_off = 0;

        ctx_data = http->req->ctx->data;

        while (body_len > 0) {
            sent = nxt_unit_response_write_nb(http->req, body_str, body_len, 0);
            if (nxt_slow_path(sent < 0)) {
                return PyErr_Format(PyExc_RuntimeError, "failed to send body");
            }

            if (nxt_slow_path(sent == 0)) {
                nxt_unit_req_debug(http->req, "asgi_http_response_body: "
                                   "out of shared memory, %d",
                                   (int) body_len);

                future = PyObject_CallObject(ctx_data->loop_create_future,
                                             NULL);
                if (nxt_slow_path(future == NULL)) {
                    nxt_unit_req_alert(http->req,
                                       "Python failed to create Future object");
                    nxt_python_print_exception();

                    return PyErr_Format(PyExc_RuntimeError,
                                        "failed to create Future object");
                }

                http->send_body = body;
                Py_INCREF(http->send_body);
                http->send_body_off = body_off;

                nxt_py_asgi_drain_wait(http->req, &http->link);

                http->send_future = future;
                Py_INCREF(http->send_future);

                return future;
            }

            body_str += sent;
            body_len -= sent;
            body_off += sent;
            http->bytes_sent += sent;
        }

    } else {
        nxt_unit_req_debug(http->req, "asgi_http_response_body: 0, %d",
                           (more_body == Py_True) );

        if (!nxt_unit_response_is_sent(http->req)) {
            rc = nxt_unit_response_send(http->req);
            if (nxt_slow_path(rc != NXT_UNIT_OK)) {
                return PyErr_Format(PyExc_RuntimeError,
                                    "failed to send response");
            }
        }
    }

    if (more_body == NULL || more_body == Py_False) {
        http->complete = 1;

        nxt_py_asgi_http_emit_disconnect(http);
    }

    Py_INCREF(http);
    return (PyObject *) http;
}


static void
nxt_py_asgi_http_emit_disconnect(nxt_py_asgi_http_t *http)
{
    PyObject  *msg, *future;

    if (http->receive_future == NULL) {
        return;
    }

    msg = nxt_py_asgi_new_msg(http->req, nxt_py_http_disconnect_str);
    if (nxt_slow_path(msg == NULL)) {
        return;
    }

    if (msg == Py_None) {
        Py_DECREF(msg);
        return;
    }

    future = http->receive_future;
    http->receive_future = NULL;

    nxt_py_asgi_http_set_result(http, future, msg);

    Py_DECREF(msg);
}


static void
nxt_py_asgi_http_set_result(nxt_py_asgi_http_t *http, PyObject *future,
    PyObject *msg)
{
    PyObject  *res;

    res = PyObject_CallMethodObjArgs(future, nxt_py_done_str, NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_unit_req_alert(http->req, "'done' call failed");
        nxt_python_print_exception();
    }

    if (nxt_fast_path(res == Py_False)) {
        res = PyObject_CallMethodObjArgs(future, nxt_py_set_result_str, msg,
                                         NULL);
        if (nxt_slow_path(res == NULL)) {
            nxt_unit_req_alert(http->req, "'set_result' call failed");
            nxt_python_print_exception();
        }

    } else {
        res = NULL;
    }

    Py_XDECREF(res);
    Py_DECREF(future);
}


void
nxt_py_asgi_http_data_handler(nxt_unit_request_info_t *req)
{
    PyObject            *msg, *future;
    nxt_py_asgi_http_t  *http;

    http = req->data;

    nxt_unit_req_debug(req, "asgi_http_data_handler");

    if (http->receive_future == NULL) {
        return;
    }

    msg = nxt_py_asgi_http_read_msg(http);
    if (nxt_slow_path(msg == NULL)) {
        return;
    }

    if (msg == Py_None) {
        Py_DECREF(msg);
        return;
    }

    future = http->receive_future;
    http->receive_future = NULL;

    nxt_py_asgi_http_set_result(http, future, msg);

    Py_DECREF(msg);
}


int
nxt_py_asgi_http_drain(nxt_queue_link_t *lnk)
{
    char                *body_str;
    ssize_t             sent;
    PyObject            *future, *exc, *res;
    Py_ssize_t          body_len;
    nxt_py_asgi_http_t  *http;

    http = nxt_container_of(lnk, nxt_py_asgi_http_t, link);

    body_str = PyBytes_AS_STRING(http->send_body) + http->send_body_off;
    body_len = PyBytes_GET_SIZE(http->send_body) - http->send_body_off;

    nxt_unit_req_debug(http->req, "asgi_http_drain: %d", (int) body_len);

    while (body_len > 0) {
        sent = nxt_unit_response_write_nb(http->req, body_str, body_len, 0);
        if (nxt_slow_path(sent < 0)) {
            goto fail;
        }

        if (nxt_slow_path(sent == 0)) {
            return NXT_UNIT_AGAIN;
        }

        body_str += sent;
        body_len -= sent;

        http->send_body_off += sent;
        http->bytes_sent += sent;
    }

    Py_CLEAR(http->send_body);

    future = http->send_future;
    http->send_future = NULL;

    nxt_py_asgi_http_set_result(http, future, Py_None);

    return NXT_UNIT_OK;

fail:

    exc = PyObject_CallFunctionObjArgs(PyExc_RuntimeError,
                                       nxt_py_failed_to_send_body_str,
                                       NULL);
    if (nxt_slow_path(exc == NULL)) {
        nxt_unit_req_alert(http->req, "RuntimeError create failed");
        nxt_python_print_exception();

        exc = Py_None;
        Py_INCREF(exc);
    }

    future = http->send_future;
    http->send_future = NULL;

    res = PyObject_CallMethodObjArgs(future, nxt_py_set_exception_str, exc,
                                     NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_unit_req_alert(http->req, "'set_exception' call failed");
        nxt_python_print_exception();
    }

    Py_XDECREF(res);
    Py_DECREF(future);
    Py_DECREF(exc);

    return NXT_UNIT_ERROR;
}


void
nxt_py_asgi_http_close_handler(nxt_unit_request_info_t *req)
{
    nxt_py_asgi_http_t  *http;

    http = req->data;

    nxt_unit_req_debug(req, "asgi_http_close_handler");

    if (nxt_fast_path(http != NULL)) {
        http->closed = 1;

        nxt_py_asgi_http_emit_disconnect(http);
    }
}


static PyObject *
nxt_py_asgi_http_done(PyObject *self, PyObject *future)
{
    int                 rc;
    PyObject            *res;
    nxt_py_asgi_http_t  *http;

    http = (nxt_py_asgi_http_t *) self;

    nxt_unit_req_debug(http->req, "asgi_http_done");

    /*
     * Get Future.result() and it raises an exception, if coroutine exited
     * with exception.
     */
    res = PyObject_CallMethodObjArgs(future, nxt_py_result_str, NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_unit_req_error(http->req,
                           "Python failed to call 'future.result()'");
        nxt_python_print_exception();

        rc = NXT_UNIT_ERROR;

    } else {
        Py_DECREF(res);

        rc = NXT_UNIT_OK;
    }

    nxt_unit_request_done(http->req, rc);

    Py_RETURN_NONE;
}


#endif /* NXT_HAVE_ASGI */

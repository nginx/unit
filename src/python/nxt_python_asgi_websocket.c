
/*
 * Copyright (C) NGINX, Inc.
 */


#include <python/nxt_python.h>

#if (NXT_HAVE_ASGI)

#include <nxt_main.h>
#include <nxt_unit.h>
#include <nxt_unit_request.h>
#include <nxt_unit_websocket.h>
#include <nxt_websocket_header.h>
#include <python/nxt_python_asgi.h>
#include <python/nxt_python_asgi_str.h>


enum {
    NXT_WS_INIT,
    NXT_WS_CONNECT,
    NXT_WS_ACCEPTED,
    NXT_WS_DISCONNECTED,
    NXT_WS_CLOSED,
};


typedef struct {
    nxt_queue_link_t            link;
    nxt_unit_websocket_frame_t  *frame;
} nxt_py_asgi_penging_frame_t;


typedef struct {
    PyObject_HEAD
    nxt_unit_request_info_t  *req;
    PyObject                 *receive_future;
    PyObject                 *receive_exc_str;
    int                      state;
    nxt_queue_t              pending_frames;
    uint64_t                 pending_payload_len;
    uint64_t                 pending_frame_len;
    int                      pending_fins;
} nxt_py_asgi_websocket_t;


static PyObject *nxt_py_asgi_websocket_receive(PyObject *self, PyObject *none);
static PyObject *nxt_py_asgi_websocket_send(PyObject *self, PyObject *dict);
static PyObject *nxt_py_asgi_websocket_accept(nxt_py_asgi_websocket_t *ws,
    PyObject *dict);
static PyObject *nxt_py_asgi_websocket_close(nxt_py_asgi_websocket_t *ws,
    PyObject *dict);
static PyObject *nxt_py_asgi_websocket_send_frame(nxt_py_asgi_websocket_t *ws,
    PyObject *dict);
static void nxt_py_asgi_websocket_receive_done(nxt_py_asgi_websocket_t *ws,
    PyObject *msg);
static void nxt_py_asgi_websocket_receive_fail(nxt_py_asgi_websocket_t *ws,
    PyObject *exc);
static void nxt_py_asgi_websocket_suspend_frame(nxt_unit_websocket_frame_t *f);
static PyObject *nxt_py_asgi_websocket_pop_msg(nxt_py_asgi_websocket_t *ws,
    nxt_unit_websocket_frame_t *frame);
static uint64_t nxt_py_asgi_websocket_pending_len(
    nxt_py_asgi_websocket_t *ws);
static nxt_unit_websocket_frame_t *nxt_py_asgi_websocket_pop_frame(
    nxt_py_asgi_websocket_t *ws);
static PyObject *nxt_py_asgi_websocket_disconnect_msg(
    nxt_py_asgi_websocket_t *ws);
static PyObject *nxt_py_asgi_websocket_done(PyObject *self, PyObject *future);


static PyMethodDef nxt_py_asgi_websocket_methods[] = {
    { "receive",   nxt_py_asgi_websocket_receive, METH_NOARGS, 0 },
    { "send",      nxt_py_asgi_websocket_send,    METH_O,      0 },
    { "_done",     nxt_py_asgi_websocket_done,    METH_O,      0 },
    { NULL, NULL, 0, 0 }
};

static PyAsyncMethods nxt_py_asgi_async_methods = {
    .am_await = nxt_py_asgi_await,
};

static PyTypeObject nxt_py_asgi_websocket_type = {
    PyVarObject_HEAD_INIT(NULL, 0)

    .tp_name      = "unit._asgi_websocket",
    .tp_basicsize = sizeof(nxt_py_asgi_websocket_t),
    .tp_dealloc   = nxt_py_asgi_dealloc,
    .tp_as_async  = &nxt_py_asgi_async_methods,
    .tp_flags     = Py_TPFLAGS_DEFAULT,
    .tp_doc       = "unit ASGI WebSocket connection object",
    .tp_iter      = nxt_py_asgi_iter,
    .tp_iternext  = nxt_py_asgi_next,
    .tp_methods   = nxt_py_asgi_websocket_methods,
};

static uint64_t  nxt_py_asgi_ws_max_frame_size = 1024 * 1024;
static uint64_t  nxt_py_asgi_ws_max_buffer_size = 10 * 1024 * 1024;


int
nxt_py_asgi_websocket_init(void)
{
    if (nxt_slow_path(PyType_Ready(&nxt_py_asgi_websocket_type) != 0)) {
        nxt_unit_alert(NULL,
              "Python failed to initialize the \"asgi_websocket\" type object");
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


PyObject *
nxt_py_asgi_websocket_create(nxt_unit_request_info_t *req)
{
    nxt_py_asgi_websocket_t  *ws;

    ws = PyObject_New(nxt_py_asgi_websocket_t, &nxt_py_asgi_websocket_type);

    if (nxt_fast_path(ws != NULL)) {
        ws->req = req;
        ws->receive_future = NULL;
        ws->receive_exc_str = NULL;
        ws->state = NXT_WS_INIT;
        nxt_queue_init(&ws->pending_frames);
        ws->pending_payload_len = 0;
        ws->pending_frame_len = 0;
        ws->pending_fins = 0;
    }

    return (PyObject *) ws;
}


static PyObject *
nxt_py_asgi_websocket_receive(PyObject *self, PyObject *none)
{
    PyObject                 *future, *msg;
    nxt_py_asgi_ctx_data_t   *ctx_data;
    nxt_py_asgi_websocket_t  *ws;

    ws = (nxt_py_asgi_websocket_t *) self;

    nxt_unit_req_debug(ws->req, "asgi_websocket_receive");

    /* If exception happened out of receive() call, raise it now. */
    if (nxt_slow_path(ws->receive_exc_str != NULL)) {
        PyErr_SetObject(PyExc_RuntimeError, ws->receive_exc_str);

        ws->receive_exc_str = NULL;

        return NULL;
    }

    if (nxt_slow_path(ws->state == NXT_WS_CLOSED)) {
        nxt_unit_req_error(ws->req,
                           "receive() called for closed WebSocket");

        return PyErr_Format(PyExc_RuntimeError,
                            "WebSocket already closed");
    }

    ctx_data = ws->req->ctx->data;

    future = PyObject_CallObject(ctx_data->loop_create_future, NULL);
    if (nxt_slow_path(future == NULL)) {
        nxt_unit_req_alert(ws->req, "Python failed to create Future object");
        nxt_python_print_exception();

        return PyErr_Format(PyExc_RuntimeError,
                            "failed to create Future object");
    }

    if (nxt_slow_path(ws->state == NXT_WS_INIT)) {
        ws->state = NXT_WS_CONNECT;

        msg = nxt_py_asgi_new_msg(ws->req, nxt_py_websocket_connect_str);

        return nxt_py_asgi_set_result_soon(ws->req, ctx_data, future, msg);
    }

    if (ws->pending_fins > 0) {
        msg = nxt_py_asgi_websocket_pop_msg(ws, NULL);

        return nxt_py_asgi_set_result_soon(ws->req, ctx_data, future, msg);
    }

    if (nxt_slow_path(ws->state == NXT_WS_DISCONNECTED)) {
        msg = nxt_py_asgi_websocket_disconnect_msg(ws);

        return nxt_py_asgi_set_result_soon(ws->req, ctx_data, future, msg);
    }

    ws->receive_future = future;
    Py_INCREF(ws->receive_future);

    return future;
}


static PyObject *
nxt_py_asgi_websocket_send(PyObject *self, PyObject *dict)
{
    PyObject                 *type;
    const char               *type_str;
    Py_ssize_t               type_len;
    nxt_py_asgi_websocket_t  *ws;

    static const nxt_str_t  websocket_accept = nxt_string("websocket.accept");
    static const nxt_str_t  websocket_close = nxt_string("websocket.close");
    static const nxt_str_t  websocket_send = nxt_string("websocket.send");

    ws = (nxt_py_asgi_websocket_t *) self;

    type = PyDict_GetItem(dict, nxt_py_type_str);
    if (nxt_slow_path(type == NULL || !PyUnicode_Check(type))) {
        nxt_unit_req_error(ws->req, "asgi_websocket_send: "
                           "'type' is not a unicode string");
        return PyErr_Format(PyExc_TypeError,
                            "'type' is not a unicode string");
    }

    type_str = PyUnicode_AsUTF8AndSize(type, &type_len);

    nxt_unit_req_debug(ws->req, "asgi_websocket_send type is '%.*s'",
                       (int) type_len, type_str);

    if (type_len == (Py_ssize_t) websocket_accept.length
        && memcmp(type_str, websocket_accept.start, type_len) == 0)
    {
        return nxt_py_asgi_websocket_accept(ws, dict);
    }

    if (type_len == (Py_ssize_t) websocket_close.length
        && memcmp(type_str, websocket_close.start, type_len) == 0)
    {
        return nxt_py_asgi_websocket_close(ws, dict);
    }

    if (type_len == (Py_ssize_t) websocket_send.length
        && memcmp(type_str, websocket_send.start, type_len) == 0)
    {
        return nxt_py_asgi_websocket_send_frame(ws, dict);
    }

    nxt_unit_req_error(ws->req, "asgi_websocket_send: "
                       "unexpected 'type': '%.*s'", (int) type_len, type_str);
    return PyErr_Format(PyExc_AssertionError, "unexpected 'type': '%U'", type);
}


static PyObject *
nxt_py_asgi_websocket_accept(nxt_py_asgi_websocket_t *ws, PyObject *dict)
{
    int                          rc;
    char                         *subprotocol_str;
    PyObject                     *res, *headers, *subprotocol;
    Py_ssize_t                   subprotocol_len;
    nxt_py_asgi_calc_size_ctx_t  calc_size_ctx;
    nxt_py_asgi_add_field_ctx_t  add_field_ctx;

    static const nxt_str_t  ws_protocol = nxt_string("sec-websocket-protocol");

    switch(ws->state) {
    case NXT_WS_INIT:
        return PyErr_Format(PyExc_RuntimeError,
                            "WebSocket connect not received");
    case NXT_WS_CONNECT:
        break;

    case NXT_WS_ACCEPTED:
        return PyErr_Format(PyExc_RuntimeError, "WebSocket already accepted");

    case NXT_WS_DISCONNECTED:
        return PyErr_Format(PyExc_RuntimeError, "WebSocket disconnected");

    case NXT_WS_CLOSED:
        return PyErr_Format(PyExc_RuntimeError, "WebSocket already closed");
    }

    if (nxt_slow_path(nxt_unit_response_is_websocket(ws->req))) {
        return PyErr_Format(PyExc_RuntimeError, "WebSocket already accepted");
    }

    if (nxt_slow_path(nxt_unit_response_is_sent(ws->req))) {
        return PyErr_Format(PyExc_RuntimeError, "response already sent");
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
    }

    subprotocol = PyDict_GetItem(dict, nxt_py_subprotocol_str);
    if (subprotocol != NULL && PyUnicode_Check(subprotocol)) {
        subprotocol_str = PyUnicode_DATA(subprotocol);
        subprotocol_len = PyUnicode_GET_LENGTH(subprotocol);

        calc_size_ctx.fields_size += ws_protocol.length + subprotocol_len;
        calc_size_ctx.fields_count++;

    } else {
        subprotocol_str = NULL;
        subprotocol_len = 0;
    }

    rc = nxt_unit_response_init(ws->req, 101,
                                calc_size_ctx.fields_count,
                                calc_size_ctx.fields_size);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return PyErr_Format(PyExc_RuntimeError,
                            "failed to allocate response object");
    }

    add_field_ctx.req = ws->req;
    add_field_ctx.content_length = -1;

    if (headers != NULL) {
        res = nxt_py_asgi_enum_headers(headers, nxt_py_asgi_add_field,
                                       &add_field_ctx);
        if (nxt_slow_path(res == NULL)) {
            return NULL;
        }
    }

    if (subprotocol_len > 0) {
        rc = nxt_unit_response_add_field(ws->req,
                                         (const char *) ws_protocol.start,
                                         ws_protocol.length,
                                         subprotocol_str, subprotocol_len);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return PyErr_Format(PyExc_RuntimeError,
                                "failed to add header");
        }
    }

    rc = nxt_unit_response_send(ws->req);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return PyErr_Format(PyExc_RuntimeError, "failed to send response");
    }

    ws->state = NXT_WS_ACCEPTED;

    Py_INCREF(ws);

    return (PyObject *) ws;
}


static PyObject *
nxt_py_asgi_websocket_close(nxt_py_asgi_websocket_t *ws, PyObject *dict)
{
    int       rc;
    uint16_t  status_code;
    PyObject  *code;

    if (nxt_slow_path(ws->state == NXT_WS_INIT)) {
        return PyErr_Format(PyExc_RuntimeError,
                            "WebSocket connect not received");
    }

    if (nxt_slow_path(ws->state == NXT_WS_DISCONNECTED)) {
        return PyErr_Format(PyExc_RuntimeError, "WebSocket disconnected");
    }

    if (nxt_slow_path(ws->state == NXT_WS_CLOSED)) {
        return PyErr_Format(PyExc_RuntimeError, "WebSocket already closed");
    }

    if (nxt_unit_response_is_websocket(ws->req)) {
        code = PyDict_GetItem(dict, nxt_py_code_str);
        if (nxt_slow_path(code != NULL && !PyLong_Check(code))) {
            return PyErr_Format(PyExc_TypeError, "'code' is not integer");
        }

        status_code = (code != NULL) ? htons(PyLong_AsLong(code))
                                     : htons(NXT_WEBSOCKET_CR_NORMAL);

        rc = nxt_unit_websocket_send(ws->req, NXT_WEBSOCKET_OP_CLOSE,
                                     1, &status_code, 2);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return PyErr_Format(PyExc_RuntimeError,
                                "failed to send close frame");
        }

    } else {
        rc = nxt_unit_response_init(ws->req, 403, 0, 0);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return PyErr_Format(PyExc_RuntimeError,
                                "failed to allocate response object");
        }

        rc = nxt_unit_response_send(ws->req);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return PyErr_Format(PyExc_RuntimeError,
                                "failed to send response");
        }
    }

    ws->state = NXT_WS_CLOSED;

    Py_INCREF(ws);

    return (PyObject *) ws;
}


static PyObject *
nxt_py_asgi_websocket_send_frame(nxt_py_asgi_websocket_t *ws, PyObject *dict)
{
    int         rc;
    uint8_t     opcode;
    PyObject    *bytes, *text;
    const void  *buf;
    Py_ssize_t  buf_size;

    if (nxt_slow_path(ws->state == NXT_WS_INIT)) {
        return PyErr_Format(PyExc_RuntimeError,
                            "WebSocket connect not received");
    }

    if (nxt_slow_path(ws->state == NXT_WS_CONNECT)) {
        return PyErr_Format(PyExc_RuntimeError,
                            "WebSocket not accepted yet");
    }

    if (nxt_slow_path(ws->state == NXT_WS_DISCONNECTED)) {
        return PyErr_Format(PyExc_RuntimeError, "WebSocket disconnected");
    }

    if (nxt_slow_path(ws->state == NXT_WS_CLOSED)) {
        return PyErr_Format(PyExc_RuntimeError, "WebSocket already closed");
    }

    bytes = PyDict_GetItem(dict, nxt_py_bytes_str);
    if (bytes == Py_None) {
        bytes = NULL;
    }

    if (nxt_slow_path(bytes != NULL && !PyBytes_Check(bytes))) {
        return PyErr_Format(PyExc_TypeError,
                            "'bytes' is not a byte string");
    }

    text = PyDict_GetItem(dict, nxt_py_text_str);
    if (text == Py_None) {
        text = NULL;
    }

    if (nxt_slow_path(text != NULL && !PyUnicode_Check(text))) {
        return PyErr_Format(PyExc_TypeError,
                            "'text' is not a unicode string");
    }

    if (nxt_slow_path(((bytes != NULL) ^ (text != NULL)) == 0)) {
        return PyErr_Format(PyExc_ValueError,
                       "Exactly one of 'bytes' or 'text' must be non-None");
    }

    if (bytes != NULL) {
        buf = PyBytes_AS_STRING(bytes);
        buf_size = PyBytes_GET_SIZE(bytes);
        opcode = NXT_WEBSOCKET_OP_BINARY;

    } else {
        buf = PyUnicode_AsUTF8AndSize(text, &buf_size);
        opcode = NXT_WEBSOCKET_OP_TEXT;
    }

    rc = nxt_unit_websocket_send(ws->req, opcode, 1, buf, buf_size);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return PyErr_Format(PyExc_RuntimeError, "failed to send close frame");
    }

    Py_INCREF(ws);
    return (PyObject *) ws;
}


void
nxt_py_asgi_websocket_handler(nxt_unit_websocket_frame_t *frame)
{
    uint8_t                  opcode;
    uint16_t                 status_code;
    uint64_t                 rest;
    PyObject                 *msg, *exc;
    nxt_py_asgi_websocket_t  *ws;

    ws = frame->req->data;

    nxt_unit_req_debug(ws->req, "asgi_websocket_handler");

    opcode = frame->header->opcode;
    if (nxt_slow_path(opcode != NXT_WEBSOCKET_OP_CONT
                      && opcode != NXT_WEBSOCKET_OP_TEXT
                      && opcode != NXT_WEBSOCKET_OP_BINARY
                      && opcode != NXT_WEBSOCKET_OP_CLOSE))
    {
        nxt_unit_websocket_done(frame);

        nxt_unit_req_debug(ws->req,
                          "asgi_websocket_handler: ignore frame with opcode %d",
                           opcode);

        return;
    }

    if (nxt_slow_path(ws->state != NXT_WS_ACCEPTED)) {
        nxt_unit_websocket_done(frame);

        goto bad_state;
    }

    rest = nxt_py_asgi_ws_max_frame_size - ws->pending_frame_len;

    if (nxt_slow_path(frame->payload_len > rest)) {
        nxt_unit_websocket_done(frame);

        goto too_big;
    }

    rest = nxt_py_asgi_ws_max_buffer_size - ws->pending_payload_len;

    if (nxt_slow_path(frame->payload_len > rest)) {
        nxt_unit_websocket_done(frame);

        goto too_big;
    }

    if (ws->receive_future == NULL || frame->header->fin == 0) {
        nxt_py_asgi_websocket_suspend_frame(frame);

        return;
    }

    if (!nxt_queue_is_empty(&ws->pending_frames)) {
        if (nxt_slow_path(opcode == NXT_WEBSOCKET_OP_TEXT
                          || opcode == NXT_WEBSOCKET_OP_BINARY))
        {
            nxt_unit_req_alert(ws->req,
                         "Invalid state: pending frames with active receiver. "
                         "CONT frame expected. (%d)", opcode);

            PyErr_SetString(PyExc_AssertionError,
                         "Invalid state: pending frames with active receiver. "
                         "CONT frame expected.");

            nxt_unit_websocket_done(frame);

            return;
        }
    }

    msg = nxt_py_asgi_websocket_pop_msg(ws, frame);
    if (nxt_slow_path(msg == NULL)) {
        exc = PyErr_Occurred();
        Py_INCREF(exc);

        goto raise;
    }

    nxt_py_asgi_websocket_receive_done(ws, msg);

    return;

bad_state:

    if (ws->receive_future == NULL) {
        ws->receive_exc_str = nxt_py_bad_state_str;

        return;
    }

    exc = PyObject_CallFunctionObjArgs(PyExc_RuntimeError,
                                       nxt_py_bad_state_str,
                                       NULL);
    if (nxt_slow_path(exc == NULL)) {
        nxt_unit_req_alert(ws->req, "RuntimeError create failed");
        nxt_python_print_exception();

        exc = Py_None;
        Py_INCREF(exc);
    }

    goto raise;

too_big:

    status_code = htons(NXT_WEBSOCKET_CR_MESSAGE_TOO_BIG);

    (void) nxt_unit_websocket_send(ws->req, NXT_WEBSOCKET_OP_CLOSE,
                                   1, &status_code, 2);

    ws->state = NXT_WS_CLOSED;

    if (ws->receive_future == NULL) {
        ws->receive_exc_str = nxt_py_message_too_big_str;

        return;
    }

    exc = PyObject_CallFunctionObjArgs(PyExc_RuntimeError,
                                       nxt_py_message_too_big_str,
                                       NULL);
    if (nxt_slow_path(exc == NULL)) {
        nxt_unit_req_alert(ws->req, "RuntimeError create failed");
        nxt_python_print_exception();

        exc = Py_None;
        Py_INCREF(exc);
    }

raise:

    nxt_py_asgi_websocket_receive_fail(ws, exc);
}


static void
nxt_py_asgi_websocket_receive_done(nxt_py_asgi_websocket_t *ws, PyObject *msg)
{
    PyObject  *future, *res;

    future = ws->receive_future;
    ws->receive_future = NULL;

    res = PyObject_CallMethodObjArgs(future, nxt_py_set_result_str, msg, NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_unit_req_alert(ws->req, "'set_result' call failed");
        nxt_python_print_exception();
    }

    Py_XDECREF(res);
    Py_DECREF(future);

    Py_DECREF(msg);
}


static void
nxt_py_asgi_websocket_receive_fail(nxt_py_asgi_websocket_t *ws, PyObject *exc)
{
    PyObject  *future, *res;

    future = ws->receive_future;
    ws->receive_future = NULL;

    res = PyObject_CallMethodObjArgs(future, nxt_py_set_exception_str, exc,
                                     NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_unit_req_alert(ws->req, "'set_exception' call failed");
        nxt_python_print_exception();
    }

    Py_XDECREF(res);
    Py_DECREF(future);

    Py_DECREF(exc);
}


static void
nxt_py_asgi_websocket_suspend_frame(nxt_unit_websocket_frame_t *frame)
{
    int                          rc;
    nxt_py_asgi_websocket_t      *ws;
    nxt_py_asgi_penging_frame_t  *p;

    nxt_unit_req_debug(frame->req, "asgi_websocket_suspend_frame: "
                       "%d, %"PRIu64", %d",
                       frame->header->opcode, frame->payload_len,
                       frame->header->fin);

    ws = frame->req->data;

    rc = nxt_unit_websocket_retain(frame);
    if (nxt_slow_path(rc == NXT_UNIT_ERROR)) {
        nxt_unit_req_alert(ws->req, "Failed to retain frame for suspension.");

        nxt_unit_websocket_done(frame);

        PyErr_SetString(PyExc_RuntimeError,
                        "Failed to retain frame for suspension.");

        return;
    }

    p = nxt_unit_malloc(frame->req->ctx, sizeof(nxt_py_asgi_penging_frame_t));
    if (nxt_slow_path(p == NULL)) {
        nxt_unit_req_alert(ws->req,
                           "Failed to allocate buffer to suspend frame.");

        nxt_unit_websocket_done(frame);

        PyErr_SetString(PyExc_RuntimeError,
                        "Failed to allocate buffer to suspend frame.");

        return;
    }

    p->frame = frame;
    nxt_queue_insert_tail(&ws->pending_frames, &p->link);

    ws->pending_payload_len += frame->payload_len;
    ws->pending_fins += frame->header->fin;

    if (frame->header->fin) {
        ws->pending_frame_len = 0;

    } else {
        if (frame->header->opcode == NXT_WEBSOCKET_OP_CONT) {
            ws->pending_frame_len += frame->payload_len;

        } else {
            ws->pending_frame_len = frame->payload_len;
        }
    }
}


static PyObject *
nxt_py_asgi_websocket_pop_msg(nxt_py_asgi_websocket_t *ws,
    nxt_unit_websocket_frame_t *frame)
{
    int                         fin;
    char                        *buf;
    uint8_t                     code_buf[2], opcode;
    uint16_t                    code;
    PyObject                    *msg, *data, *type, *data_key;
    uint64_t                    payload_len;
    nxt_unit_websocket_frame_t  *fin_frame;

    nxt_unit_req_debug(ws->req, "asgi_websocket_pop_msg");

    fin_frame = NULL;

    if (nxt_queue_is_empty(&ws->pending_frames)
        || (frame != NULL
            && frame->header->opcode == NXT_WEBSOCKET_OP_CLOSE))
    {
        payload_len = frame->payload_len;

    } else {
        if (frame != NULL) {
            payload_len = ws->pending_payload_len + frame->payload_len;
            fin_frame = frame;

        } else {
            payload_len = nxt_py_asgi_websocket_pending_len(ws);
        }

        frame = nxt_py_asgi_websocket_pop_frame(ws);
    }

    opcode = frame->header->opcode;

    if (nxt_slow_path(opcode == NXT_WEBSOCKET_OP_CONT)) {
        nxt_unit_req_alert(ws->req,
                           "Invalid state: attempt to process CONT frame.");

        nxt_unit_websocket_done(frame);

        return PyErr_Format(PyExc_AssertionError,
                            "Invalid state: attempt to process CONT frame.");
    }

    type = nxt_py_websocket_receive_str;

    switch (opcode) {
    case NXT_WEBSOCKET_OP_TEXT:
        buf = nxt_unit_malloc(frame->req->ctx, payload_len);
        if (nxt_slow_path(buf == NULL)) {
            nxt_unit_req_alert(ws->req,
                               "Failed to allocate buffer for payload (%d).",
                               (int) payload_len);

            nxt_unit_websocket_done(frame);

            return PyErr_Format(PyExc_RuntimeError,
                                "Failed to allocate buffer for payload (%d).",
                                (int) payload_len);
        }

        data = NULL;
        data_key = nxt_py_text_str;

        break;

    case NXT_WEBSOCKET_OP_BINARY:
        data = PyBytes_FromStringAndSize(NULL, payload_len);
        if (nxt_slow_path(data == NULL)) {
            nxt_unit_req_alert(ws->req,
                               "Failed to create Bytes for payload (%d).",
                               (int) payload_len);
            nxt_python_print_exception();

            nxt_unit_websocket_done(frame);

            return PyErr_Format(PyExc_RuntimeError,
                                "Failed to create Bytes for payload.");
        }

        buf = (char *) PyBytes_AS_STRING(data);
        data_key = nxt_py_bytes_str;

        break;

    case NXT_WEBSOCKET_OP_CLOSE:
        if (frame->payload_len >= 2) {
            nxt_unit_websocket_read(frame, code_buf, 2);
            code = ((uint16_t) code_buf[0]) << 8 | code_buf[1];

        } else {
            code = NXT_WEBSOCKET_CR_NORMAL;
        }

        nxt_unit_websocket_done(frame);

        data = PyLong_FromLong(code);
        if (nxt_slow_path(data == NULL)) {
            nxt_unit_req_alert(ws->req,
                               "Failed to create Long from code %d.",
                               (int) code);
            nxt_python_print_exception();

            return PyErr_Format(PyExc_RuntimeError,
                                "Failed to create Long from code %d.",
                                (int) code);
        }

        buf = NULL;
        type = nxt_py_websocket_disconnect_str;
        data_key = nxt_py_code_str;

        break;

    default:
        nxt_unit_req_alert(ws->req, "Unexpected opcode %d", opcode);

        nxt_unit_websocket_done(frame);

        return PyErr_Format(PyExc_AssertionError, "Unexpected opcode %d",
                            opcode);
    }

    if (buf != NULL) {
        fin = frame->header->fin;
        buf += nxt_unit_websocket_read(frame, buf, frame->payload_len);

        nxt_unit_websocket_done(frame);

        if (!fin) {
            while (!nxt_queue_is_empty(&ws->pending_frames)) {
                frame = nxt_py_asgi_websocket_pop_frame(ws);
                fin = frame->header->fin;

                buf += nxt_unit_websocket_read(frame, buf, frame->payload_len);

                nxt_unit_websocket_done(frame);

                if (fin) {
                    break;
                }
            }

            if (fin_frame != NULL) {
                buf += nxt_unit_websocket_read(fin_frame, buf,
                                               fin_frame->payload_len);
                nxt_unit_websocket_done(fin_frame);
            }
        }

        if (opcode == NXT_WEBSOCKET_OP_TEXT) {
            buf -= payload_len;

            data = PyUnicode_DecodeUTF8(buf, payload_len, NULL);

            nxt_unit_free(ws->req->ctx, buf);

            if (nxt_slow_path(data == NULL)) {
                nxt_unit_req_alert(ws->req,
                                   "Failed to create Unicode for payload (%d).",
                                   (int) payload_len);
                nxt_python_print_exception();

                return PyErr_Format(PyExc_RuntimeError,
                                    "Failed to create Unicode.");
            }
        }
    }

    msg = nxt_py_asgi_new_msg(ws->req, type);
    if (nxt_slow_path(msg == NULL)) {
        Py_DECREF(data);
        return NULL;
    }

    if (nxt_slow_path(PyDict_SetItem(msg, data_key, data) == -1)) {
        nxt_unit_req_alert(ws->req, "Python failed to set 'msg.data' item");

        Py_DECREF(msg);
        Py_DECREF(data);

        return PyErr_Format(PyExc_RuntimeError,
                            "Python failed to set 'msg.data' item");
    }

    Py_DECREF(data);

    return msg;
}


static uint64_t
nxt_py_asgi_websocket_pending_len(nxt_py_asgi_websocket_t *ws)
{
    uint64_t                     res;
    nxt_py_asgi_penging_frame_t  *p;

    res = 0;

    nxt_queue_each(p, &ws->pending_frames, nxt_py_asgi_penging_frame_t, link) {
        res += p->frame->payload_len;

        if (p->frame->header->fin) {
            nxt_unit_req_debug(ws->req, "asgi_websocket_pending_len: %d",
                               (int) res);
            return res;
        }
    } nxt_queue_loop;

    nxt_unit_req_debug(ws->req, "asgi_websocket_pending_len: %d (all)",
                       (int) res);
    return res;
}


static nxt_unit_websocket_frame_t *
nxt_py_asgi_websocket_pop_frame(nxt_py_asgi_websocket_t *ws)
{
    nxt_queue_link_t             *lnk;
    nxt_unit_websocket_frame_t   *frame;
    nxt_py_asgi_penging_frame_t  *p;

    lnk = nxt_queue_first(&ws->pending_frames);
    nxt_queue_remove(lnk);

    p = nxt_queue_link_data(lnk, nxt_py_asgi_penging_frame_t, link);

    frame = p->frame;
    ws->pending_payload_len -= frame->payload_len;
    ws->pending_fins -= frame->header->fin;

    nxt_unit_free(frame->req->ctx, p);

    nxt_unit_req_debug(frame->req, "asgi_websocket_pop_frame: "
                       "%d, %"PRIu64", %d",
                       frame->header->opcode, frame->payload_len,
                       frame->header->fin);

    return frame;
}


void
nxt_py_asgi_websocket_close_handler(nxt_unit_request_info_t *req)
{
    PyObject                 *msg, *exc;
    nxt_py_asgi_websocket_t  *ws;

    ws = req->data;

    nxt_unit_req_debug(req, "asgi_websocket_close_handler");

    if (nxt_slow_path(ws == NULL)) {
        return;
    }

    if (ws->receive_future == NULL) {
        ws->state = NXT_WS_DISCONNECTED;

        return;
    }

    msg = nxt_py_asgi_websocket_disconnect_msg(ws);
    if (nxt_slow_path(msg == NULL)) {
        exc = PyErr_Occurred();
        Py_INCREF(exc);

        nxt_py_asgi_websocket_receive_fail(ws, exc);

    } else {
        nxt_py_asgi_websocket_receive_done(ws, msg);
    }
}


static PyObject *
nxt_py_asgi_websocket_disconnect_msg(nxt_py_asgi_websocket_t *ws)
{
    PyObject  *msg, *code;

    msg = nxt_py_asgi_new_msg(ws->req, nxt_py_websocket_disconnect_str);
    if (nxt_slow_path(msg == NULL)) {
        return NULL;
    }

    code = PyLong_FromLong(NXT_WEBSOCKET_CR_GOING_AWAY);
    if (nxt_slow_path(code == NULL)) {
        nxt_unit_req_alert(ws->req, "Python failed to create long");
        nxt_python_print_exception();

        Py_DECREF(msg);

        return PyErr_Format(PyExc_RuntimeError, "failed to create long");
    }

    if (nxt_slow_path(PyDict_SetItem(msg, nxt_py_code_str, code) == -1)) {
        nxt_unit_req_alert(ws->req, "Python failed to set 'msg.code' item");

        Py_DECREF(msg);
        Py_DECREF(code);

        return PyErr_Format(PyExc_RuntimeError,
                            "Python failed to set 'msg.code' item");
    }

    Py_DECREF(code);

    return msg;
}


static PyObject *
nxt_py_asgi_websocket_done(PyObject *self, PyObject *future)
{
    int                      rc;
    uint16_t                 status_code;
    PyObject                 *res;
    nxt_py_asgi_websocket_t  *ws;

    ws = (nxt_py_asgi_websocket_t *) self;

    nxt_unit_req_debug(ws->req, "asgi_websocket_done: %p", self);

    /*
     * Get Future.result() and it raises an exception, if coroutine exited
     * with exception.
     */
    res = PyObject_CallMethodObjArgs(future, nxt_py_result_str, NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_unit_req_error(ws->req,
                           "Python failed to call 'future.result()'");
        nxt_python_print_exception();

        rc = NXT_UNIT_ERROR;

    } else {
        Py_DECREF(res);

        rc = NXT_UNIT_OK;
    }

    if (ws->state == NXT_WS_ACCEPTED) {
        status_code = (rc == NXT_UNIT_OK)
                      ? htons(NXT_WEBSOCKET_CR_NORMAL)
                      : htons(NXT_WEBSOCKET_CR_INTERNAL_SERVER_ERROR);

        rc = nxt_unit_websocket_send(ws->req, NXT_WEBSOCKET_OP_CLOSE,
                                     1, &status_code, 2);
    }

    while (!nxt_queue_is_empty(&ws->pending_frames)) {
        nxt_unit_websocket_done(nxt_py_asgi_websocket_pop_frame(ws));
    }

    nxt_unit_request_done(ws->req, rc);

    Py_RETURN_NONE;
}


#endif /* NXT_HAVE_ASGI */

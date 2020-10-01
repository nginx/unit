
/*
 * Copyright (C) NGINX, Inc.
 */


#include <python/nxt_python.h>

#if (NXT_HAVE_ASGI)

#include <nxt_main.h>
#include <python/nxt_python_asgi.h>
#include <python/nxt_python_asgi_str.h>


typedef struct  {
    PyObject_HEAD
    int       disabled;
    int       startup_received;
    int       startup_sent;
    int       shutdown_received;
    int       shutdown_sent;
    int       shutdown_called;
    PyObject  *startup_future;
    PyObject  *shutdown_future;
    PyObject  *receive_future;
} nxt_py_asgi_lifespan_t;


static PyObject *nxt_py_asgi_lifespan_receive(PyObject *self, PyObject *none);
static PyObject *nxt_py_asgi_lifespan_send(PyObject *self, PyObject *dict);
static PyObject *nxt_py_asgi_lifespan_send_startup(
    nxt_py_asgi_lifespan_t *lifespan, int v, PyObject *dict);
static PyObject *nxt_py_asgi_lifespan_send_(nxt_py_asgi_lifespan_t *lifespan,
    int v, int *sent, PyObject **future);
static PyObject *nxt_py_asgi_lifespan_send_shutdown(
    nxt_py_asgi_lifespan_t *lifespan, int v, PyObject *dict);
static PyObject *nxt_py_asgi_lifespan_disable(nxt_py_asgi_lifespan_t *lifespan);
static PyObject *nxt_py_asgi_lifespan_done(PyObject *self, PyObject *future);


static nxt_py_asgi_lifespan_t  *nxt_py_lifespan;

static PyMethodDef nxt_py_asgi_lifespan_methods[] = {
    { "receive",   nxt_py_asgi_lifespan_receive, METH_NOARGS, 0 },
    { "send",      nxt_py_asgi_lifespan_send,    METH_O,      0 },
    { "_done",     nxt_py_asgi_lifespan_done,    METH_O,      0 },
    { NULL, NULL, 0, 0 }
};

static PyAsyncMethods nxt_py_asgi_async_methods = {
    .am_await = nxt_py_asgi_await,
};

static PyTypeObject nxt_py_asgi_lifespan_type = {
    PyVarObject_HEAD_INIT(NULL, 0)

    .tp_name      = "unit._asgi_lifespan",
    .tp_basicsize = sizeof(nxt_py_asgi_lifespan_t),
    .tp_dealloc   = nxt_py_asgi_dealloc,
    .tp_as_async  = &nxt_py_asgi_async_methods,
    .tp_flags     = Py_TPFLAGS_DEFAULT,
    .tp_doc       = "unit ASGI Lifespan object",
    .tp_iter      = nxt_py_asgi_iter,
    .tp_iternext  = nxt_py_asgi_next,
    .tp_methods   = nxt_py_asgi_lifespan_methods,
};


nxt_int_t
nxt_py_asgi_lifespan_startup(nxt_task_t *task)
{
    PyObject                *scope, *res, *py_task, *receive, *send, *done;
    nxt_int_t               rc;
    nxt_py_asgi_lifespan_t  *lifespan;

    if (nxt_slow_path(PyType_Ready(&nxt_py_asgi_lifespan_type) != 0)) {
        nxt_alert(task,
                 "Python failed to initialize the 'asgi_lifespan' type object");
        return NXT_ERROR;
    }

    lifespan = PyObject_New(nxt_py_asgi_lifespan_t, &nxt_py_asgi_lifespan_type);
    if (nxt_slow_path(lifespan == NULL)) {
        nxt_alert(task, "Python failed to create lifespan object");
        return NXT_ERROR;
    }

    rc = NXT_ERROR;

    receive = PyObject_GetAttrString((PyObject *) lifespan, "receive");
    if (nxt_slow_path(receive == NULL)) {
        nxt_alert(task, "Python failed to get 'receive' method");
        goto release_lifespan;
    }

    send = PyObject_GetAttrString((PyObject *) lifespan, "send");
    if (nxt_slow_path(receive == NULL)) {
        nxt_alert(task, "Python failed to get 'send' method");
        goto release_receive;
    }

    done = PyObject_GetAttrString((PyObject *) lifespan, "_done");
    if (nxt_slow_path(receive == NULL)) {
        nxt_alert(task, "Python failed to get '_done' method");
        goto release_send;
    }

    lifespan->startup_future = PyObject_CallObject(nxt_py_loop_create_future,
                                                   NULL);
    if (nxt_slow_path(lifespan->startup_future == NULL)) {
        nxt_unit_alert(NULL, "Python failed to create Future object");
        nxt_python_print_exception();

        goto release_done;
    }

    lifespan->disabled = 0;
    lifespan->startup_received = 0;
    lifespan->startup_sent = 0;
    lifespan->shutdown_received = 0;
    lifespan->shutdown_sent = 0;
    lifespan->shutdown_called = 0;
    lifespan->shutdown_future = NULL;
    lifespan->receive_future = NULL;

    scope = nxt_py_asgi_new_scope(NULL, nxt_py_lifespan_str, nxt_py_2_0_str);
    if (nxt_slow_path(scope == NULL)) {
        goto release_future;
    }

    res = PyObject_CallFunctionObjArgs(nxt_py_application,
                                       scope, receive, send, NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_log(task, NXT_LOG_ERR, "Python failed to call the application");
        nxt_python_print_exception();
        goto release_scope;
    }

    if (nxt_slow_path(!PyCoro_CheckExact(res))) {
        nxt_log(task, NXT_LOG_ERR,
                "Application result type is not a coroutine");
        Py_DECREF(res);
        goto release_scope;
    }

    py_task = PyObject_CallFunctionObjArgs(nxt_py_loop_create_task, res, NULL);
    if (nxt_slow_path(py_task == NULL)) {
        nxt_log(task, NXT_LOG_ERR, "Python failed to call the create_task");
        nxt_python_print_exception();
        Py_DECREF(res);
        goto release_scope;
    }

    Py_DECREF(res);

    res = PyObject_CallMethodObjArgs(py_task, nxt_py_add_done_callback_str,
                                     done, NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_log(task, NXT_LOG_ERR,
                              "Python failed to call 'task.add_done_callback'");
        nxt_python_print_exception();
        goto release_task;
    }

    Py_DECREF(res);

    res = PyObject_CallFunctionObjArgs(nxt_py_loop_run_until_complete,
                                       lifespan->startup_future, NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_alert(task, "Python failed to call loop.run_until_complete");
        nxt_python_print_exception();
        goto release_task;
    }

    Py_DECREF(res);

    if (lifespan->startup_sent == 1 || lifespan->disabled) {
        nxt_py_lifespan = lifespan;
        Py_INCREF(nxt_py_lifespan);

        rc = NXT_OK;
    }

release_task:
    Py_DECREF(py_task);
release_scope:
    Py_DECREF(scope);
release_future:
    Py_CLEAR(lifespan->startup_future);
release_done:
    Py_DECREF(done);
release_send:
    Py_DECREF(send);
release_receive:
    Py_DECREF(receive);
release_lifespan:
    Py_DECREF(lifespan);

    return rc;
}


nxt_int_t
nxt_py_asgi_lifespan_shutdown(void)
{
    PyObject                *msg, *future, *res;
    nxt_py_asgi_lifespan_t  *lifespan;

    if (nxt_slow_path(nxt_py_lifespan == NULL || nxt_py_lifespan->disabled)) {
        return NXT_OK;
    }

    lifespan = nxt_py_lifespan;
    lifespan->shutdown_called = 1;

    if (lifespan->receive_future != NULL) {
        future = lifespan->receive_future;
        lifespan->receive_future = NULL;

        msg = nxt_py_asgi_new_msg(NULL, nxt_py_lifespan_shutdown_str);

        if (nxt_fast_path(msg != NULL)) {
            res = PyObject_CallMethodObjArgs(future, nxt_py_set_result_str,
                                             msg, NULL);
            Py_XDECREF(res);
            Py_DECREF(msg);
        }

        Py_DECREF(future);
    }

    if (lifespan->shutdown_sent) {
        return NXT_OK;
    }

    lifespan->shutdown_future = PyObject_CallObject(nxt_py_loop_create_future,
                                                    NULL);
    if (nxt_slow_path(lifespan->shutdown_future == NULL)) {
        nxt_unit_alert(NULL, "Python failed to create Future object");
        nxt_python_print_exception();
        return NXT_ERROR;
    }

    res = PyObject_CallFunctionObjArgs(nxt_py_loop_run_until_complete,
                                       lifespan->shutdown_future, NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_unit_alert(NULL, "Python failed to call loop.run_until_complete");
        nxt_python_print_exception();
        return NXT_ERROR;
    }

    Py_DECREF(res);
    Py_CLEAR(lifespan->shutdown_future);

    return NXT_OK;
}


static PyObject *
nxt_py_asgi_lifespan_receive(PyObject *self, PyObject *none)
{
    PyObject                *msg, *future;
    nxt_py_asgi_lifespan_t  *lifespan;

    lifespan = (nxt_py_asgi_lifespan_t *) self;

    nxt_unit_debug(NULL, "asgi_lifespan_receive");

    future = PyObject_CallObject(nxt_py_loop_create_future, NULL);
    if (nxt_slow_path(future == NULL)) {
        nxt_unit_alert(NULL, "Python failed to create Future object");
        nxt_python_print_exception();

        return PyErr_Format(PyExc_RuntimeError,
                            "failed to create Future object");
    }

    if (!lifespan->startup_received) {
        lifespan->startup_received = 1;

        msg = nxt_py_asgi_new_msg(NULL, nxt_py_lifespan_startup_str);

        return nxt_py_asgi_set_result_soon(NULL, future, msg);
    }

    if (lifespan->shutdown_called && !lifespan->shutdown_received) {
        lifespan->shutdown_received = 1;

        msg = nxt_py_asgi_new_msg(NULL, nxt_py_lifespan_shutdown_str);

        return nxt_py_asgi_set_result_soon(NULL, future, msg);
    }

    Py_INCREF(future);
    lifespan->receive_future = future;

    return future;
}


static PyObject *
nxt_py_asgi_lifespan_send(PyObject *self, PyObject *dict)
{
    PyObject                *type, *msg;
    const char              *type_str;
    Py_ssize_t              type_len;
    nxt_py_asgi_lifespan_t  *lifespan;

    static const nxt_str_t  startup_complete
                                = nxt_string("lifespan.startup.complete");
    static const nxt_str_t  startup_failed
                                = nxt_string("lifespan.startup.failed");
    static const nxt_str_t  shutdown_complete
                                = nxt_string("lifespan.shutdown.complete");
    static const nxt_str_t  shutdown_failed
                                = nxt_string("lifespan.shutdown.failed");

    lifespan = (nxt_py_asgi_lifespan_t *) self;

    type = PyDict_GetItem(dict, nxt_py_type_str);
    if (nxt_slow_path(type == NULL || !PyUnicode_Check(type))) {
        nxt_unit_error(NULL,
                       "asgi_lifespan_send: 'type' is not a unicode string");
        return PyErr_Format(PyExc_TypeError,
                            "'type' is not a unicode string");
    }

    type_str = PyUnicode_AsUTF8AndSize(type, &type_len);

    nxt_unit_debug(NULL, "asgi_lifespan_send type is '%.*s'",
                   (int) type_len, type_str);

    if (type_len == (Py_ssize_t) startup_complete.length
        && memcmp(type_str, startup_complete.start, type_len) == 0)
    {
        return nxt_py_asgi_lifespan_send_startup(lifespan, 0, NULL);
    }

    if (type_len == (Py_ssize_t) startup_failed.length
        && memcmp(type_str, startup_failed.start, type_len) == 0)
    {
        msg = PyDict_GetItem(dict, nxt_py_message_str);
        return nxt_py_asgi_lifespan_send_startup(lifespan, 1, msg);
    }

    if (type_len == (Py_ssize_t) shutdown_complete.length
        && memcmp(type_str, shutdown_complete.start, type_len) == 0)
    {
        return nxt_py_asgi_lifespan_send_shutdown(lifespan, 0, NULL);
    }

    if (type_len == (Py_ssize_t) shutdown_failed.length
        && memcmp(type_str, shutdown_failed.start, type_len) == 0)
    {
        msg = PyDict_GetItem(dict, nxt_py_message_str);
        return nxt_py_asgi_lifespan_send_shutdown(lifespan, 1, msg);
    }

    return nxt_py_asgi_lifespan_disable(lifespan);
}


static PyObject *
nxt_py_asgi_lifespan_send_startup(nxt_py_asgi_lifespan_t *lifespan, int v,
    PyObject *message)
{
    const char  *message_str;
    Py_ssize_t  message_len;

    if (nxt_slow_path(v != 0)) {
        nxt_unit_error(NULL, "Application startup failed");

        if (nxt_fast_path(message != NULL && PyUnicode_Check(message))) {
            message_str = PyUnicode_AsUTF8AndSize(message, &message_len);

            nxt_unit_error(NULL, "%.*s", (int) message_len, message_str);
        }
    }

    return nxt_py_asgi_lifespan_send_(lifespan, v,
                                      &lifespan->startup_sent,
                                      &lifespan->startup_future);
}


static PyObject *
nxt_py_asgi_lifespan_send_(nxt_py_asgi_lifespan_t *lifespan, int v, int *sent,
    PyObject **pfuture)
{
    PyObject  *future, *res;

    if (*sent) {
        return nxt_py_asgi_lifespan_disable(lifespan);
    }

    *sent = 1 + v;

    if (*pfuture != NULL) {
        future = *pfuture;
        *pfuture = NULL;

        res = PyObject_CallMethodObjArgs(future, nxt_py_set_result_str,
                                         Py_None, NULL);
        if (nxt_slow_path(res == NULL)) {
            nxt_unit_alert(NULL, "Failed to call 'future.set_result'");
            nxt_python_print_exception();

            return nxt_py_asgi_lifespan_disable(lifespan);
        }

        Py_DECREF(res);
        Py_DECREF(future);
    }

    Py_INCREF(lifespan);

    return (PyObject *) lifespan;
}


static PyObject *
nxt_py_asgi_lifespan_disable(nxt_py_asgi_lifespan_t *lifespan)
{
    nxt_unit_warn(NULL, "Got invalid state transition on lifespan protocol");

    lifespan->disabled = 1;

    return PyErr_Format(PyExc_AssertionError,
                        "Got invalid state transition on lifespan protocol");
}


static PyObject *
nxt_py_asgi_lifespan_send_shutdown(nxt_py_asgi_lifespan_t *lifespan, int v,
    PyObject *message)
{
    return nxt_py_asgi_lifespan_send_(lifespan, v,
                                      &lifespan->shutdown_sent,
                                      &lifespan->shutdown_future);
}


static PyObject *
nxt_py_asgi_lifespan_done(PyObject *self, PyObject *future)
{
    PyObject                *res;
    nxt_py_asgi_lifespan_t  *lifespan;

    nxt_unit_debug(NULL, "asgi_lifespan_done");

    lifespan = (nxt_py_asgi_lifespan_t *) self;

    if (lifespan->startup_sent == 0) {
        lifespan->disabled = 1;
    }

    /*
     * Get Future.result() and it raises an exception, if coroutine exited
     * with exception.
     */
    res = PyObject_CallMethodObjArgs(future, nxt_py_result_str, NULL);
    if (nxt_slow_path(res == NULL)) {
        nxt_unit_log(NULL, NXT_UNIT_LOG_INFO,
                     "ASGI Lifespan processing exception");
        nxt_python_print_exception();
    }

    Py_XDECREF(res);

    if (lifespan->startup_future != NULL) {
        future = lifespan->startup_future;
        lifespan->startup_future = NULL;

        res = PyObject_CallMethodObjArgs(future, nxt_py_set_result_str,
                                         Py_None, NULL);
        if (nxt_slow_path(res == NULL)) {
            nxt_unit_alert(NULL, "Failed to call 'future.set_result'");
            nxt_python_print_exception();
        }

        Py_XDECREF(res);
        Py_DECREF(future);
    }

    if (lifespan->shutdown_future != NULL) {
        future = lifespan->shutdown_future;
        lifespan->shutdown_future = NULL;

        res = PyObject_CallMethodObjArgs(future, nxt_py_set_result_str,
                                         Py_None, NULL);
        if (nxt_slow_path(res == NULL)) {
            nxt_unit_alert(NULL, "Failed to call 'future.set_result'");
            nxt_python_print_exception();
        }

        Py_XDECREF(res);
        Py_DECREF(future);
    }

    Py_RETURN_NONE;
}


#endif /* NXT_HAVE_ASGI */

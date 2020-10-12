
/*
 * Copyright (C) Max Romanov
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */


#include <Python.h>

#include <nxt_main.h>
#include <nxt_router.h>
#include <nxt_unit.h>
#include <nxt_unit_field.h>
#include <nxt_unit_request.h>
#include <nxt_unit_response.h>

#include <python/nxt_python.h>

#include NXT_PYTHON_MOUNTS_H

/*
 * According to "PEP 3333 / A Note On String Types"
 * [https://www.python.org/dev/peps/pep-3333/#a-note-on-string-types]
 *
 * WSGI therefore defines two kinds of "string":
 *
 * - "Native" strings (which are always implemented using the type named str )
 *   that are used for request/response headers and metadata
 *
 *   will use PyString_* or corresponding PyUnicode_* functions
 *
 * - "Bytestrings" (which are implemented using the bytes type in Python 3, and
 *   str elsewhere), that are used for the bodies of requests and responses
 *   (e.g. POST/PUT input data and HTML page outputs).
 *
 *   will use PyString_* or corresponding PyBytes_* functions
 */


typedef struct nxt_python_run_ctx_s  nxt_python_run_ctx_t;

typedef struct {
    PyObject_HEAD
} nxt_py_input_t;


typedef struct {
    PyObject_HEAD
} nxt_py_error_t;

static void nxt_python_request_handler(nxt_unit_request_info_t *req);

static PyObject *nxt_python_create_environ(nxt_task_t *task);
static PyObject *nxt_python_get_environ(nxt_python_run_ctx_t *ctx);
static int nxt_python_add_sptr(nxt_python_run_ctx_t *ctx, PyObject *name,
    nxt_unit_sptr_t *sptr, uint32_t size);
static int nxt_python_add_field(nxt_python_run_ctx_t *ctx,
    nxt_unit_field_t *field, int n, uint32_t vl);
static PyObject *nxt_python_field_name(const char *name, uint8_t len);
static PyObject *nxt_python_field_value(nxt_unit_field_t *f, int n,
    uint32_t vl);
static int nxt_python_add_obj(nxt_python_run_ctx_t *ctx, PyObject *name,
    PyObject *value);

static PyObject *nxt_py_start_resp(PyObject *self, PyObject *args);
static int nxt_python_response_add_field(nxt_python_run_ctx_t *ctx,
    PyObject *name, PyObject *value, int i);
static int nxt_python_str_buf(PyObject *str, char **buf, uint32_t *len,
    PyObject **bytes);
static PyObject *nxt_py_write(PyObject *self, PyObject *args);

static void nxt_py_input_dealloc(nxt_py_input_t *self);
static PyObject *nxt_py_input_read(nxt_py_input_t *self, PyObject *args);
static PyObject *nxt_py_input_readline(nxt_py_input_t *self, PyObject *args);
static PyObject *nxt_py_input_getline(nxt_python_run_ctx_t *ctx, size_t size);
static PyObject *nxt_py_input_readlines(nxt_py_input_t *self, PyObject *args);

static PyObject *nxt_py_input_iter(PyObject *self);
static PyObject *nxt_py_input_next(PyObject *self);

static int nxt_python_write(nxt_python_run_ctx_t *ctx, PyObject *bytes);

struct nxt_python_run_ctx_s {
    uint64_t                 content_length;
    uint64_t                 bytes_sent;
    PyObject                 *environ;
    nxt_unit_request_info_t  *req;
};


static PyMethodDef nxt_py_start_resp_method[] = {
    {"unit_start_response", nxt_py_start_resp, METH_VARARGS, ""}
};


static PyMethodDef nxt_py_write_method[] = {
    {"unit_write", nxt_py_write, METH_O, ""}
};


static PyMethodDef nxt_py_input_methods[] = {
    { "read",      (PyCFunction) nxt_py_input_read,      METH_VARARGS, 0 },
    { "readline",  (PyCFunction) nxt_py_input_readline,  METH_VARARGS, 0 },
    { "readlines", (PyCFunction) nxt_py_input_readlines, METH_VARARGS, 0 },
    { NULL, NULL, 0, 0 }
};


static PyTypeObject nxt_py_input_type = {
    PyVarObject_HEAD_INIT(NULL, 0)

    .tp_name      = "unit._input",
    .tp_basicsize = sizeof(nxt_py_input_t),
    .tp_dealloc   = (destructor) nxt_py_input_dealloc,
    .tp_flags     = Py_TPFLAGS_DEFAULT,
    .tp_doc       = "unit input object.",
    .tp_iter      = nxt_py_input_iter,
    .tp_iternext  = nxt_py_input_next,
    .tp_methods   = nxt_py_input_methods,
};


static PyObject           *nxt_py_start_resp_obj;
static PyObject           *nxt_py_write_obj;
static PyObject           *nxt_py_environ_ptyp;

static PyThreadState         *nxt_python_thread_state;
static nxt_python_run_ctx_t  *nxt_python_run_ctx;

static PyObject  *nxt_py_80_str;
static PyObject  *nxt_py_close_str;
static PyObject  *nxt_py_content_length_str;
static PyObject  *nxt_py_content_type_str;
static PyObject  *nxt_py_http_str;
static PyObject  *nxt_py_https_str;
static PyObject  *nxt_py_path_info_str;
static PyObject  *nxt_py_query_string_str;
static PyObject  *nxt_py_remote_addr_str;
static PyObject  *nxt_py_request_method_str;
static PyObject  *nxt_py_request_uri_str;
static PyObject  *nxt_py_server_addr_str;
static PyObject  *nxt_py_server_name_str;
static PyObject  *nxt_py_server_port_str;
static PyObject  *nxt_py_server_protocol_str;
static PyObject  *nxt_py_wsgi_uri_scheme_str;

static nxt_python_string_t nxt_python_strings[] = {
    { nxt_string("80"), &nxt_py_80_str },
    { nxt_string("close"), &nxt_py_close_str },
    { nxt_string("CONTENT_LENGTH"), &nxt_py_content_length_str },
    { nxt_string("CONTENT_TYPE"), &nxt_py_content_type_str },
    { nxt_string("http"), &nxt_py_http_str },
    { nxt_string("https"), &nxt_py_https_str },
    { nxt_string("PATH_INFO"), &nxt_py_path_info_str },
    { nxt_string("QUERY_STRING"), &nxt_py_query_string_str },
    { nxt_string("REMOTE_ADDR"), &nxt_py_remote_addr_str },
    { nxt_string("REQUEST_METHOD"), &nxt_py_request_method_str },
    { nxt_string("REQUEST_URI"), &nxt_py_request_uri_str },
    { nxt_string("SERVER_ADDR"), &nxt_py_server_addr_str },
    { nxt_string("SERVER_NAME"), &nxt_py_server_name_str },
    { nxt_string("SERVER_PORT"), &nxt_py_server_port_str },
    { nxt_string("SERVER_PROTOCOL"), &nxt_py_server_protocol_str },
    { nxt_string("wsgi.url_scheme"), &nxt_py_wsgi_uri_scheme_str },
    { nxt_null_string, NULL },
};


nxt_int_t
nxt_python_wsgi_init(nxt_task_t *task, nxt_unit_init_t *init)
{
    PyObject  *obj;

    obj = NULL;

    if (nxt_slow_path(nxt_python_init_strings(nxt_python_strings) != NXT_OK)) {
        nxt_alert(task, "Python failed to init string objects");
        goto fail;
    }

    obj = PyCFunction_New(nxt_py_start_resp_method, NULL);
    if (nxt_slow_path(obj == NULL)) {
        nxt_alert(task,
                "Python failed to initialize the \"start_response\" function");
        goto fail;
    }

    nxt_py_start_resp_obj = obj;

    obj = PyCFunction_New(nxt_py_write_method, NULL);
    if (nxt_slow_path(obj == NULL)) {
        nxt_alert(task, "Python failed to initialize the \"write\" function");
        goto fail;
    }

    nxt_py_write_obj = obj;

    obj = nxt_python_create_environ(task);
    if (nxt_slow_path(obj == NULL)) {
        goto fail;
    }

    nxt_py_environ_ptyp = obj;
    obj = NULL;

    init->callbacks.request_handler = nxt_python_request_handler;

    return NXT_OK;

fail:

    Py_XDECREF(obj);

    return NXT_ERROR;
}


int
nxt_python_wsgi_run(nxt_unit_ctx_t *ctx)
{
    int  rc;

    nxt_python_thread_state = PyEval_SaveThread();

    rc = nxt_unit_run(ctx);

    PyEval_RestoreThread(nxt_python_thread_state);

    return rc;
}


void
nxt_python_wsgi_done(void)
{
    nxt_python_done_strings(nxt_python_strings);

    Py_XDECREF(nxt_py_start_resp_obj);
    Py_XDECREF(nxt_py_write_obj);
    Py_XDECREF(nxt_py_environ_ptyp);
}


static void
nxt_python_request_handler(nxt_unit_request_info_t *req)
{
    int                   rc;
    PyObject              *environ, *args, *response, *iterator, *item;
    PyObject              *close, *result;
    nxt_python_run_ctx_t  run_ctx = {-1, 0, NULL, req};

    PyEval_RestoreThread(nxt_python_thread_state);

    environ = nxt_python_get_environ(&run_ctx);
    if (nxt_slow_path(environ == NULL)) {
        rc = NXT_UNIT_ERROR;
        goto done;
    }

    args = PyTuple_New(2);
    if (nxt_slow_path(args == NULL)) {
        Py_DECREF(environ);

        nxt_unit_req_error(req, "Python failed to create arguments tuple");

        rc = NXT_UNIT_ERROR;
        goto done;
    }

    PyTuple_SET_ITEM(args, 0, environ);

    Py_INCREF(nxt_py_start_resp_obj);
    PyTuple_SET_ITEM(args, 1, nxt_py_start_resp_obj);

    nxt_python_run_ctx = &run_ctx;

    response = PyObject_CallObject(nxt_py_application, args);

    Py_DECREF(args);

    if (nxt_slow_path(response == NULL)) {
        nxt_unit_req_error(req, "Python failed to call the application");
        nxt_python_print_exception();

        rc = NXT_UNIT_ERROR;
        goto done;
    }

    /* Shortcut: avoid iterate over response string symbols. */
    if (PyBytes_Check(response)) {
        rc = nxt_python_write(&run_ctx, response);

    } else {
        iterator = PyObject_GetIter(response);

        if (nxt_fast_path(iterator != NULL)) {
            rc = NXT_UNIT_OK;

            while (run_ctx.bytes_sent < run_ctx.content_length) {
                item = PyIter_Next(iterator);

                if (item == NULL) {
                    if (nxt_slow_path(PyErr_Occurred() != NULL)) {
                        nxt_unit_req_error(req, "Python failed to iterate over "
                                           "the application response object");
                        nxt_python_print_exception();

                        rc = NXT_UNIT_ERROR;
                    }

                    break;
                }

                if (nxt_fast_path(PyBytes_Check(item))) {
                    rc = nxt_python_write(&run_ctx, item);

                } else {
                    nxt_unit_req_error(req, "the application returned "
                                            "not a bytestring object");
                    rc = NXT_UNIT_ERROR;
                }

                Py_DECREF(item);

                if (nxt_slow_path(rc != NXT_UNIT_OK)) {
                    break;
                }
            }

            Py_DECREF(iterator);

        } else {
            nxt_unit_req_error(req,
                            "the application returned not an iterable object");
            nxt_python_print_exception();

            rc = NXT_UNIT_ERROR;
        }

        close = PyObject_GetAttr(response, nxt_py_close_str);

        if (close != NULL) {
            result = PyObject_CallFunction(close, NULL);
            if (nxt_slow_path(result == NULL)) {
                nxt_unit_req_error(req, "Python failed to call the close() "
                                        "method of the application response");
                nxt_python_print_exception();

            } else {
                Py_DECREF(result);
            }

            Py_DECREF(close);

        } else {
            PyErr_Clear();
        }
    }

    Py_DECREF(response);

done:

    nxt_python_thread_state = PyEval_SaveThread();

    nxt_python_run_ctx = NULL;
    nxt_unit_request_done(req, rc);
}


static PyObject *
nxt_python_create_environ(nxt_task_t *task)
{
    PyObject  *obj, *err, *environ;

    environ = PyDict_New();

    if (nxt_slow_path(environ == NULL)) {
        nxt_alert(task, "Python failed to create the \"environ\" dictionary");
        return NULL;
    }

    obj = PyString_FromStringAndSize((char *) nxt_server.start,
                                     nxt_server.length);
    if (nxt_slow_path(obj == NULL)) {
        nxt_alert(task,
              "Python failed to create the \"SERVER_SOFTWARE\" environ value");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "SERVER_SOFTWARE", obj)
        != 0))
    {
        nxt_alert(task,
                  "Python failed to set the \"SERVER_SOFTWARE\" environ value");
        goto fail;
    }

    Py_DECREF(obj);

    obj = Py_BuildValue("(ii)", 1, 0);

    if (nxt_slow_path(obj == NULL)) {
        nxt_alert(task,
                  "Python failed to build the \"wsgi.version\" environ value");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "wsgi.version", obj) != 0))
    {
        nxt_alert(task,
                  "Python failed to set the \"wsgi.version\" environ value");
        goto fail;
    }

    Py_DECREF(obj);
    obj = NULL;


    if (nxt_slow_path(PyDict_SetItemString(environ, "wsgi.multithread",
                                           Py_False)
        != 0))
    {
        nxt_alert(task,
                "Python failed to set the \"wsgi.multithread\" environ value");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "wsgi.multiprocess",
                                           Py_True)
        != 0))
    {
        nxt_alert(task,
               "Python failed to set the \"wsgi.multiprocess\" environ value");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "wsgi.run_once",
                                           Py_False)
        != 0))
    {
        nxt_alert(task,
                  "Python failed to set the \"wsgi.run_once\" environ value");
        goto fail;
    }


    if (nxt_slow_path(PyType_Ready(&nxt_py_input_type) != 0)) {
        nxt_alert(task,
                  "Python failed to initialize the \"wsgi.input\" type object");
        goto fail;
    }

    obj = (PyObject *) PyObject_New(nxt_py_input_t, &nxt_py_input_type);

    if (nxt_slow_path(obj == NULL)) {
        nxt_alert(task, "Python failed to create the \"wsgi.input\" object");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "wsgi.input", obj) != 0)) {
        nxt_alert(task,
                  "Python failed to set the \"wsgi.input\" environ value");
        goto fail;
    }

    Py_DECREF(obj);
    obj = NULL;


    err = PySys_GetObject((char *) "stderr");

    if (nxt_slow_path(err == NULL)) {
        nxt_alert(task, "Python failed to get \"sys.stderr\" object");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "wsgi.errors", err) != 0))
    {
        nxt_alert(task,
                  "Python failed to set the \"wsgi.errors\" environ value");
        goto fail;
    }

    return environ;

fail:

    Py_XDECREF(obj);
    Py_DECREF(environ);

    return NULL;
}


static PyObject *
nxt_python_get_environ(nxt_python_run_ctx_t *ctx)
{
    int                 rc;
    uint32_t            i, j, vl;
    PyObject            *environ;
    nxt_unit_field_t    *f, *f2;
    nxt_unit_request_t  *r;

    environ = PyDict_Copy(nxt_py_environ_ptyp);
    if (nxt_slow_path(environ == NULL)) {
        nxt_unit_req_error(ctx->req,
                           "Python failed to copy the \"environ\" dictionary");

        return NULL;
    }

    ctx->environ = environ;

    r = ctx->req->request;

#define RC(S)                                                                 \
    do {                                                                      \
        rc = (S);                                                             \
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {                               \
            goto fail;                                                        \
        }                                                                     \
    } while(0)

    RC(nxt_python_add_sptr(ctx, nxt_py_request_method_str, &r->method,
                           r->method_length));
    RC(nxt_python_add_sptr(ctx, nxt_py_request_uri_str, &r->target,
                           r->target_length));
    RC(nxt_python_add_sptr(ctx, nxt_py_query_string_str, &r->query,
                           r->query_length));
    RC(nxt_python_add_sptr(ctx, nxt_py_path_info_str, &r->path,
                           r->path_length));

    RC(nxt_python_add_sptr(ctx, nxt_py_remote_addr_str, &r->remote,
                           r->remote_length));
    RC(nxt_python_add_sptr(ctx, nxt_py_server_addr_str, &r->local,
                           r->local_length));

    if (r->tls) {
        RC(nxt_python_add_obj(ctx, nxt_py_wsgi_uri_scheme_str,
                              nxt_py_https_str));
    } else {
        RC(nxt_python_add_obj(ctx, nxt_py_wsgi_uri_scheme_str,
                              nxt_py_http_str));
    }

    RC(nxt_python_add_sptr(ctx, nxt_py_server_protocol_str, &r->version,
                           r->version_length));

    RC(nxt_python_add_sptr(ctx, nxt_py_server_name_str, &r->server_name,
                           r->server_name_length));
    RC(nxt_python_add_obj(ctx, nxt_py_server_port_str, nxt_py_80_str));

    nxt_unit_request_group_dup_fields(ctx->req);

    for (i = 0; i < r->fields_count;) {
        f = r->fields + i;
        vl = f->value_length;

        for (j = i + 1; j < r->fields_count; j++) {
            f2 = r->fields + j;

            if (f2->hash != f->hash
                || nxt_unit_sptr_get(&f2->name) != nxt_unit_sptr_get(&f->name))
            {
                break;
            }

            vl += 2 + f2->value_length;
        }

        RC(nxt_python_add_field(ctx, f, j - i, vl));

        i = j;
    }

    if (r->content_length_field != NXT_UNIT_NONE_FIELD) {
        f = r->fields + r->content_length_field;

        RC(nxt_python_add_sptr(ctx, nxt_py_content_length_str, &f->value,
                               f->value_length));
    }

    if (r->content_type_field != NXT_UNIT_NONE_FIELD) {
        f = r->fields + r->content_type_field;

        RC(nxt_python_add_sptr(ctx, nxt_py_content_type_str, &f->value,
                               f->value_length));
    }

#undef RC

    return environ;

fail:

    Py_DECREF(environ);

    return NULL;
}


static int
nxt_python_add_sptr(nxt_python_run_ctx_t *ctx, PyObject *name,
    nxt_unit_sptr_t *sptr, uint32_t size)
{
    char      *src;
    PyObject  *value;

    src = nxt_unit_sptr_get(sptr);

    value = PyString_FromStringAndSize(src, size);
    if (nxt_slow_path(value == NULL)) {
        nxt_unit_req_error(ctx->req,
                           "Python failed to create value string \"%.*s\"",
                           (int) size, src);
        nxt_python_print_exception();

        return NXT_UNIT_ERROR;
    }

    if (nxt_slow_path(PyDict_SetItem(ctx->environ, name, value) != 0)) {
        nxt_unit_req_error(ctx->req,
                           "Python failed to set the \"%s\" environ value",
                           PyUnicode_AsUTF8(name));
        Py_DECREF(value);

        return NXT_UNIT_ERROR;
    }

    Py_DECREF(value);

    return NXT_UNIT_OK;
}


static int
nxt_python_add_field(nxt_python_run_ctx_t *ctx, nxt_unit_field_t *field, int n,
    uint32_t vl)
{
    char      *src;
    PyObject  *name, *value;

    src = nxt_unit_sptr_get(&field->name);

    name = nxt_python_field_name(src, field->name_length);
    if (nxt_slow_path(name == NULL)) {
        nxt_unit_req_error(ctx->req,
                           "Python failed to create name string \"%.*s\"",
                           (int) field->name_length, src);
        nxt_python_print_exception();

        return NXT_UNIT_ERROR;
    }

    value = nxt_python_field_value(field, n, vl);

    if (nxt_slow_path(value == NULL)) {
        nxt_unit_req_error(ctx->req,
                           "Python failed to create value string \"%.*s\"",
                           (int) field->value_length,
                           (char *) nxt_unit_sptr_get(&field->value));
        nxt_python_print_exception();

        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItem(ctx->environ, name, value) != 0)) {
        nxt_unit_req_error(ctx->req,
                           "Python failed to set the \"%s\" environ value",
                           PyUnicode_AsUTF8(name));
        goto fail;
    }

    Py_DECREF(name);
    Py_DECREF(value);

    return NXT_UNIT_OK;

fail:

    Py_DECREF(name);
    Py_XDECREF(value);

    return NXT_UNIT_ERROR;
}


static PyObject *
nxt_python_field_name(const char *name, uint8_t len)
{
    char      *p, c;
    uint8_t   i;
    PyObject  *res;

#if PY_MAJOR_VERSION == 3
    res = PyUnicode_New(len + 5, 255);
#else
    res = PyString_FromStringAndSize(NULL, len + 5);
#endif

    if (nxt_slow_path(res == NULL)) {
        return NULL;
    }

    p = PyString_AS_STRING(res);

    p = nxt_cpymem(p, "HTTP_", 5);

    for (i = 0; i < len; i++) {
        c = name[i];

        if (c >= 'a' && c <= 'z') {
            *p++ = (c & ~0x20);
            continue;
        }

        if (c == '-') {
            *p++ = '_';
            continue;
        }

        *p++ = c;
    }

    return res;
}


static PyObject *
nxt_python_field_value(nxt_unit_field_t *f, int n, uint32_t vl)
{
    int       i;
    char      *p, *src;
    PyObject  *res;

#if PY_MAJOR_VERSION == 3
    res = PyUnicode_New(vl, 255);
#else
    res = PyString_FromStringAndSize(NULL, vl);
#endif

    if (nxt_slow_path(res == NULL)) {
        return NULL;
    }

    p = PyString_AS_STRING(res);

    src = nxt_unit_sptr_get(&f->value);
    p = nxt_cpymem(p, src, f->value_length);

    for (i = 1; i < n; i++) {
        p = nxt_cpymem(p, ", ", 2);

        src = nxt_unit_sptr_get(&f[i].value);
        p = nxt_cpymem(p, src, f[i].value_length);
    }

    return res;
}


static int
nxt_python_add_obj(nxt_python_run_ctx_t *ctx, PyObject *name, PyObject *value)
{
    if (nxt_slow_path(PyDict_SetItem(ctx->environ, name, value) != 0)) {
        nxt_unit_req_error(ctx->req,
                           "Python failed to set the \"%s\" environ value",
                           PyUnicode_AsUTF8(name));

        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


static PyObject *
nxt_py_start_resp(PyObject *self, PyObject *args)
{
    int                   rc, status;
    char                  *status_str, *space_ptr;
    uint32_t              status_len;
    PyObject              *headers, *tuple, *string, *status_bytes;
    Py_ssize_t            i, n, fields_size, fields_count;
    nxt_python_run_ctx_t  *ctx;

    ctx = nxt_python_run_ctx;
    if (nxt_slow_path(ctx == NULL)) {
        return PyErr_Format(PyExc_RuntimeError,
                            "start_response() is called "
                            "outside of WSGI request processing");
    }

    n = PyTuple_GET_SIZE(args);

    if (n < 2 || n > 3) {
        return PyErr_Format(PyExc_TypeError, "invalid number of arguments");
    }

    string = PyTuple_GET_ITEM(args, 0);
    if (!PyBytes_Check(string) && !PyUnicode_Check(string)) {
        return PyErr_Format(PyExc_TypeError,
                            "failed to write first argument (not a string?)");
    }

    headers = PyTuple_GET_ITEM(args, 1);
    if (!PyList_Check(headers)) {
        return PyErr_Format(PyExc_TypeError,
                         "the second argument is not a response headers list");
    }

    fields_size = 0;
    fields_count = PyList_GET_SIZE(headers);

    for (i = 0; i < fields_count; i++) {
        tuple = PyList_GET_ITEM(headers, i);

        if (!PyTuple_Check(tuple)) {
            return PyErr_Format(PyExc_TypeError,
                              "the response headers must be a list of tuples");
        }

        if (PyTuple_GET_SIZE(tuple) != 2) {
            return PyErr_Format(PyExc_TypeError,
                                "each header must be a tuple of two items");
        }

        string = PyTuple_GET_ITEM(tuple, 0);
        if (PyBytes_Check(string)) {
            fields_size += PyBytes_GET_SIZE(string);

        } else if (PyUnicode_Check(string)) {
            fields_size += PyUnicode_GET_LENGTH(string);

        } else {
            return PyErr_Format(PyExc_TypeError,
                                "header #%d name is not a string", (int) i);
        }

        string = PyTuple_GET_ITEM(tuple, 1);
        if (PyBytes_Check(string)) {
            fields_size += PyBytes_GET_SIZE(string);

        } else if (PyUnicode_Check(string)) {
            fields_size += PyUnicode_GET_LENGTH(string);

        } else {
            return PyErr_Format(PyExc_TypeError,
                                "header #%d value is not a string", (int) i);
        }
    }

    ctx->content_length = -1;

    string = PyTuple_GET_ITEM(args, 0);
    rc = nxt_python_str_buf(string, &status_str, &status_len, &status_bytes);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return PyErr_Format(PyExc_TypeError, "status is not a string");
    }

    space_ptr = memchr(status_str, ' ', status_len);
    if (space_ptr != NULL) {
        status_len = space_ptr - status_str;
    }

    status = nxt_int_parse((u_char *) status_str, status_len);
    if (nxt_slow_path(status < 0)) {
        return PyErr_Format(PyExc_TypeError, "failed to parse status code");
    }

    Py_XDECREF(status_bytes);

    /*
     * PEP 3333:
     *
     * ... applications can replace their originally intended output with error
     * output, up until the last possible moment.
     */
    rc = nxt_unit_response_init(ctx->req, status, fields_count, fields_size);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return PyErr_Format(PyExc_RuntimeError,
                            "failed to allocate response object");
    }

    for (i = 0; i < fields_count; i++) {
        tuple = PyList_GET_ITEM(headers, i);

        rc = nxt_python_response_add_field(ctx, PyTuple_GET_ITEM(tuple, 0),
                                           PyTuple_GET_ITEM(tuple, 1), i);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return PyErr_Format(PyExc_RuntimeError,
                                "failed to add header #%d", (int) i);
        }
    }

    /*
     * PEP 3333:
     *
     * However, the start_response callable must not actually transmit the
     * response headers. Instead, it must store them for the server or gateway
     * to transmit only after the first iteration of the application return
     * value that yields a non-empty bytestring, or upon the application's
     * first invocation of the write() callable. In other words, response
     * headers must not be sent until there is actual body data available, or
     * until the application's returned iterable is exhausted. (The only
     * possible exception to this rule is if the response headers explicitly
     * include a Content-Length of zero.)
     */
    if (ctx->content_length == 0) {
        rc = nxt_unit_response_send(ctx->req);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return PyErr_Format(PyExc_RuntimeError,
                                "failed to send response headers");
        }
    }

    Py_INCREF(nxt_py_write_obj);
    return nxt_py_write_obj;
}


static int
nxt_python_response_add_field(nxt_python_run_ctx_t *ctx, PyObject *name,
    PyObject *value, int i)
{
    int        rc;
    char       *name_str, *value_str;
    uint32_t   name_length, value_length;
    PyObject   *name_bytes, *value_bytes;
    nxt_off_t  content_length;

    name_bytes = NULL;
    value_bytes = NULL;

    rc = nxt_python_str_buf(name, &name_str, &name_length, &name_bytes);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    rc = nxt_python_str_buf(value, &value_str, &value_length, &value_bytes);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    rc = nxt_unit_response_add_field(ctx->req, name_str, name_length,
                                     value_str, value_length);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    if (ctx->req->response->fields[i].hash == NXT_UNIT_HASH_CONTENT_LENGTH) {
        content_length = nxt_off_t_parse((u_char *) value_str, value_length);
        if (nxt_slow_path(content_length < 0)) {
            nxt_unit_req_error(ctx->req, "failed to parse Content-Length "
                               "value %.*s", (int) value_length, value_str);

        } else {
            ctx->content_length = content_length;
        }
    }

fail:

    Py_XDECREF(name_bytes);
    Py_XDECREF(value_bytes);

    return rc;
}


static int
nxt_python_str_buf(PyObject *str, char **buf, uint32_t *len, PyObject **bytes)
{
    if (PyBytes_Check(str)) {
        *buf = PyBytes_AS_STRING(str);
        *len = PyBytes_GET_SIZE(str);
        *bytes = NULL;

    } else {
        *bytes = PyUnicode_AsLatin1String(str);
        if (nxt_slow_path(*bytes == NULL)) {
            return NXT_UNIT_ERROR;
        }

        *buf = PyBytes_AS_STRING(*bytes);
        *len = PyBytes_GET_SIZE(*bytes);
    }

    return NXT_UNIT_OK;
}


static PyObject *
nxt_py_write(PyObject *self, PyObject *str)
{
    int  rc;

    if (nxt_fast_path(!PyBytes_Check(str))) {
        return PyErr_Format(PyExc_TypeError, "the argument is not a %s",
                            NXT_PYTHON_BYTES_TYPE);
    }

    rc = nxt_python_write(nxt_python_run_ctx, str);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return PyErr_Format(PyExc_RuntimeError,
                            "failed to write response value");
    }

    Py_RETURN_NONE;
}


static void
nxt_py_input_dealloc(nxt_py_input_t *self)
{
    PyObject_Del(self);
}


static PyObject *
nxt_py_input_read(nxt_py_input_t *self, PyObject *args)
{
    char                  *buf;
    PyObject              *content, *obj;
    Py_ssize_t            size, n;
    nxt_python_run_ctx_t  *ctx;

    ctx = nxt_python_run_ctx;
    if (nxt_slow_path(ctx == NULL)) {
        return PyErr_Format(PyExc_RuntimeError,
                            "wsgi.input.read() is called "
                            "outside of WSGI request processing");
    }

    size = ctx->req->content_length;

    n = PyTuple_GET_SIZE(args);

    if (n > 0) {
        if (n != 1) {
            return PyErr_Format(PyExc_TypeError, "invalid number of arguments");
        }

        obj = PyTuple_GET_ITEM(args, 0);

        size = PyNumber_AsSsize_t(obj, PyExc_OverflowError);

        if (nxt_slow_path(size < 0)) {
            if (size == -1 && PyErr_Occurred()) {
                return NULL;
            }

            if (size != -1) {
                return PyErr_Format(PyExc_ValueError,
                                  "the read body size cannot be zero or less");
            }
        }

        if (size == -1 || size > (Py_ssize_t) ctx->req->content_length) {
            size = ctx->req->content_length;
        }
    }

    content = PyBytes_FromStringAndSize(NULL, size);
    if (nxt_slow_path(content == NULL)) {
        return NULL;
    }

    buf = PyBytes_AS_STRING(content);

    size = nxt_unit_request_read(ctx->req, buf, size);

    return content;
}


static PyObject *
nxt_py_input_readline(nxt_py_input_t *self, PyObject *args)
{
    ssize_t               ssize;
    PyObject              *obj;
    Py_ssize_t            n;
    nxt_python_run_ctx_t  *ctx;

    ctx = nxt_python_run_ctx;
    if (nxt_slow_path(ctx == NULL)) {
        return PyErr_Format(PyExc_RuntimeError,
                            "wsgi.input.readline() is called "
                            "outside of WSGI request processing");
    }

    n = PyTuple_GET_SIZE(args);

    if (n > 0) {
        if (n != 1) {
            return PyErr_Format(PyExc_TypeError, "invalid number of arguments");
        }

        obj = PyTuple_GET_ITEM(args, 0);

        ssize = PyNumber_AsSsize_t(obj, PyExc_OverflowError);

        if (nxt_fast_path(ssize > 0)) {
            return nxt_py_input_getline(ctx, ssize);
        }

        if (ssize == 0) {
            return PyBytes_FromStringAndSize("", 0);
        }

        if (ssize != -1) {
            return PyErr_Format(PyExc_ValueError,
                                "the read line size cannot be zero or less");
        }

        if (PyErr_Occurred()) {
            return NULL;
        }
    }

    return nxt_py_input_getline(ctx, SSIZE_MAX);
}


static PyObject *
nxt_py_input_getline(nxt_python_run_ctx_t *ctx, size_t size)
{
    void      *buf;
    ssize_t   res;
    PyObject  *content;

    res = nxt_unit_request_readline_size(ctx->req, size);
    if (nxt_slow_path(res < 0)) {
        return NULL;
    }

    if (res == 0) {
        return PyBytes_FromStringAndSize("", 0);
    }

    content = PyBytes_FromStringAndSize(NULL, res);
    if (nxt_slow_path(content == NULL)) {
        return NULL;
    }

    buf = PyBytes_AS_STRING(content);

    res = nxt_unit_request_read(ctx->req, buf, res);

    return content;
}


static PyObject *
nxt_py_input_readlines(nxt_py_input_t *self, PyObject *args)
{
    PyObject              *res;
    nxt_python_run_ctx_t  *ctx;

    ctx = nxt_python_run_ctx;
    if (nxt_slow_path(ctx == NULL)) {
        return PyErr_Format(PyExc_RuntimeError,
                            "wsgi.input.readlines() is called "
                            "outside of WSGI request processing");
    }

    res = PyList_New(0);
    if (nxt_slow_path(res == NULL)) {
        return NULL;
    }

    for ( ;; ) {
        PyObject *line = nxt_py_input_getline(ctx, SSIZE_MAX);
        if (nxt_slow_path(line == NULL)) {
            Py_DECREF(res);
            return NULL;
        }

        if (PyBytes_GET_SIZE(line) == 0) {
            Py_DECREF(line);
            return res;
        }

        PyList_Append(res, line);	
        Py_DECREF(line);
    }

    return res;
}


static PyObject *
nxt_py_input_iter(PyObject *self)
{
    Py_INCREF(self);
    return self;
}


static PyObject *
nxt_py_input_next(PyObject *self)
{
    PyObject              *line;
    nxt_python_run_ctx_t  *ctx;

    ctx = nxt_python_run_ctx;
    if (nxt_slow_path(ctx == NULL)) {
        return PyErr_Format(PyExc_RuntimeError,
                            "wsgi.input.next() is called "
                            "outside of WSGI request processing");
    }

    line = nxt_py_input_getline(ctx, SSIZE_MAX);
    if (nxt_slow_path(line == NULL)) {
        return NULL;
    }

    if (PyBytes_GET_SIZE(line) == 0) {
        Py_DECREF(line);
        PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }

    return line;
}


static int
nxt_python_write(nxt_python_run_ctx_t *ctx, PyObject *bytes)
{
    int       rc;
    char      *str_buf;
    uint32_t  str_length;

    str_buf = PyBytes_AS_STRING(bytes);
    str_length = PyBytes_GET_SIZE(bytes);

    if (nxt_slow_path(str_length == 0)) {
        return NXT_UNIT_OK;
    }

    /*
     * PEP 3333:
     *
     * If the application supplies a Content-Length header, the server should
     * not transmit more bytes to the client than the header allows, and should
     * stop iterating over the response when enough data has been sent, or raise
     * an error if the application tries to write() past that point.
     */
    if (nxt_slow_path(str_length > ctx->content_length - ctx->bytes_sent)) {
        nxt_unit_req_error(ctx->req, "content length %"PRIu64" exceeded",
                           ctx->content_length);

        return NXT_UNIT_ERROR;
    }

    rc = nxt_unit_response_write(ctx->req, str_buf, str_length);
    if (nxt_fast_path(rc == NXT_UNIT_OK)) {
        ctx->bytes_sent += str_length;
    }

    return rc;
}


/*
 * Copyright (C) Max Romanov
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */


#include <Python.h>

#include <compile.h>
#include <node.h>

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_router.h>
#include <nxt_unit.h>
#include <nxt_unit_field.h>
#include <nxt_unit_request.h>
#include <nxt_unit_response.h>

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


#if PY_MAJOR_VERSION == 3
#define NXT_PYTHON_BYTES_TYPE       "bytestring"

#define PyString_FromStringAndSize(str, size)                                 \
            PyUnicode_DecodeLatin1((str), (size), "strict")
#else
#define NXT_PYTHON_BYTES_TYPE       "string"

#define PyBytes_FromStringAndSize   PyString_FromStringAndSize
#define PyBytes_Check               PyString_Check
#define PyBytes_GET_SIZE            PyString_GET_SIZE
#define PyBytes_AS_STRING           PyString_AS_STRING
#endif

typedef struct nxt_python_run_ctx_s  nxt_python_run_ctx_t;

typedef struct {
    PyObject_HEAD
} nxt_py_input_t;


typedef struct {
    PyObject_HEAD
} nxt_py_error_t;

static nxt_int_t nxt_python_init(nxt_task_t *task, nxt_common_app_conf_t *conf);
static void nxt_python_request_handler(nxt_unit_request_info_t *req);
static void nxt_python_atexit(void);

static PyObject *nxt_python_create_environ(nxt_task_t *task);
static PyObject *nxt_python_get_environ(nxt_python_run_ctx_t *ctx);
static int nxt_python_add_sptr(nxt_python_run_ctx_t *ctx, const char *name,
    nxt_unit_sptr_t *sptr, uint32_t size);
static int nxt_python_add_str(nxt_python_run_ctx_t *ctx, const char *name,
    const char *str, uint32_t size);

static PyObject *nxt_py_start_resp(PyObject *self, PyObject *args);
static int nxt_python_response_add_field(nxt_python_run_ctx_t *ctx,
    PyObject *name, PyObject *value, int i);
static int nxt_python_str_buf(PyObject *str, char **buf, uint32_t *len,
    PyObject **bytes);
static PyObject *nxt_py_write(PyObject *self, PyObject *args);

static void nxt_py_input_dealloc(nxt_py_input_t *self);
static PyObject *nxt_py_input_read(nxt_py_input_t *self, PyObject *args);
static PyObject *nxt_py_input_readline(nxt_py_input_t *self, PyObject *args);
static PyObject *nxt_py_input_readlines(nxt_py_input_t *self, PyObject *args);

static int nxt_python_write(nxt_python_run_ctx_t *ctx, PyObject *bytes);

struct nxt_python_run_ctx_s {
    uint64_t                 content_length;
    uint64_t                 bytes_sent;
    PyObject                 *environ;
    nxt_unit_request_info_t  *req;
};

static uint32_t  compat[] = {
    NXT_VERNUM, NXT_DEBUG,
};


NXT_EXPORT nxt_app_module_t  nxt_app_module = {
    sizeof(compat),
    compat,
    nxt_string("python"),
    PY_VERSION,
    NULL,
    nxt_python_init,
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
    "unit._input",                      /* tp_name              */
    (int) sizeof(nxt_py_input_t),       /* tp_basicsize         */
    0,                                  /* tp_itemsize          */
    (destructor) nxt_py_input_dealloc,  /* tp_dealloc           */
    0,                                  /* tp_print             */
    0,                                  /* tp_getattr           */
    0,                                  /* tp_setattr           */
    0,                                  /* tp_compare           */
    0,                                  /* tp_repr              */
    0,                                  /* tp_as_number         */
    0,                                  /* tp_as_sequence       */
    0,                                  /* tp_as_mapping        */
    0,                                  /* tp_hash              */
    0,                                  /* tp_call              */
    0,                                  /* tp_str               */
    0,                                  /* tp_getattro          */
    0,                                  /* tp_setattro          */
    0,                                  /* tp_as_buffer         */
    Py_TPFLAGS_DEFAULT,                 /* tp_flags             */
    "unit input object.",               /* tp_doc               */
    0,                                  /* tp_traverse          */
    0,                                  /* tp_clear             */
    0,                                  /* tp_richcompare       */
    0,                                  /* tp_weaklistoffset    */
    0,                                  /* tp_iter              */
    0,                                  /* tp_iternext          */
    nxt_py_input_methods,               /* tp_methods           */
    0,                                  /* tp_members           */
    0,                                  /* tp_getset            */
    0,                                  /* tp_base              */
    0,                                  /* tp_dict              */
    0,                                  /* tp_descr_get         */
    0,                                  /* tp_descr_set         */
    0,                                  /* tp_dictoffset        */
    0,                                  /* tp_init              */
    0,                                  /* tp_alloc             */
    0,                                  /* tp_new               */
    0,                                  /* tp_free              */
    0,                                  /* tp_is_gc             */
    0,                                  /* tp_bases             */
    0,                                  /* tp_mro - method resolution order */
    0,                                  /* tp_cache             */
    0,                                  /* tp_subclasses        */
    0,                                  /* tp_weaklist          */
    0,                                  /* tp_del               */
    0,                                  /* tp_version_tag       */
#if PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION > 3
    0,                                  /* tp_finalize          */
#endif
};


static PyObject           *nxt_py_application;
static PyObject           *nxt_py_start_resp_obj;
static PyObject           *nxt_py_write_obj;
static PyObject           *nxt_py_environ_ptyp;

#if PY_MAJOR_VERSION == 3
static wchar_t            *nxt_py_home;
#else
static char               *nxt_py_home;
#endif

static nxt_python_run_ctx_t  *nxt_python_run_ctx;


static nxt_int_t
nxt_python_init(nxt_task_t *task, nxt_common_app_conf_t *conf)
{
    int                    rc;
    char                   *nxt_py_module;
    size_t                 len;
    PyObject               *obj, *pypath, *module;
    nxt_unit_ctx_t         *unit_ctx;
    nxt_unit_init_t        python_init;
    nxt_python_app_conf_t  *c;
#if PY_MAJOR_VERSION == 3
    char                   *path;
    size_t                 size;
    nxt_int_t              pep405;

    static const char pyvenv[] = "/pyvenv.cfg";
    static const char bin_python[] = "/bin/python";
#endif

    c = &conf->u.python;

    if (c->module.length == 0) {
        nxt_alert(task, "python module is empty");
        return NXT_ERROR;
    }

    if (c->home != NULL) {
        len = nxt_strlen(c->home);

#if PY_MAJOR_VERSION == 3

        path = nxt_malloc(len + sizeof(pyvenv));
        if (nxt_slow_path(path == NULL)) {
            nxt_alert(task, "Failed to allocate memory");
            return NXT_ERROR;
        }

        nxt_memcpy(path, c->home, len);
        nxt_memcpy(path + len, pyvenv, sizeof(pyvenv));

        pep405 = (access(path, R_OK) == 0);

        nxt_free(path);

        if (pep405) {
            size = (len + sizeof(bin_python)) * sizeof(wchar_t);

        } else {
            size = (len + 1) * sizeof(wchar_t);
        }

        nxt_py_home = nxt_malloc(size);
        if (nxt_slow_path(nxt_py_home == NULL)) {
            nxt_alert(task, "Failed to allocate memory");
            return NXT_ERROR;
        }

        if (pep405) {
            mbstowcs(nxt_py_home, c->home, len);
            mbstowcs(nxt_py_home + len, bin_python, sizeof(bin_python));
            Py_SetProgramName(nxt_py_home);

        } else {
            mbstowcs(nxt_py_home, c->home, len + 1);
            Py_SetPythonHome(nxt_py_home);
        }

#else
        nxt_py_home = nxt_malloc(len + 1);
        if (nxt_slow_path(nxt_py_home == NULL)) {
            nxt_alert(task, "Failed to allocate memory");
            return NXT_ERROR;
        }

        nxt_memcpy(nxt_py_home, c->home, len + 1);
        Py_SetPythonHome(nxt_py_home);
#endif
    }

    Py_InitializeEx(0);

    module = NULL;

    if (c->path.length > 0) {
        obj = PyString_FromStringAndSize((char *) c->path.start,
                                         c->path.length);

        if (nxt_slow_path(obj == NULL)) {
            nxt_alert(task, "Python failed to create string object \"%V\"",
                      &c->path);
            goto fail;
        }

        pypath = PySys_GetObject((char *) "path");

        if (nxt_slow_path(pypath == NULL)) {
            nxt_alert(task, "Python failed to get \"sys.path\" list");
            goto fail;
        }

        if (nxt_slow_path(PyList_Insert(pypath, 0, obj) != 0)) {
            nxt_alert(task, "Python failed to insert \"%V\" into \"sys.path\"",
                      &c->path);
            goto fail;
        }

        Py_DECREF(obj);
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

    obj = Py_BuildValue("[s]", "unit");
    if (nxt_slow_path(obj == NULL)) {
        nxt_alert(task, "Python failed to create the \"sys.argv\" list");
        goto fail;
    }

    if (nxt_slow_path(PySys_SetObject((char *) "argv", obj) != 0)) {
        nxt_alert(task, "Python failed to set the \"sys.argv\" list");
        goto fail;
    }

    Py_CLEAR(obj);

    nxt_py_module = nxt_alloca(c->module.length + 1);
    nxt_memcpy(nxt_py_module, c->module.start, c->module.length);
    nxt_py_module[c->module.length] = '\0';

    module = PyImport_ImportModule(nxt_py_module);
    if (nxt_slow_path(module == NULL)) {
        nxt_alert(task, "Python failed to import module \"%s\"", nxt_py_module);
        PyErr_Print();
        goto fail;
    }

    obj = PyDict_GetItemString(PyModule_GetDict(module), "application");
    if (nxt_slow_path(obj == NULL)) {
        nxt_alert(task, "Python failed to get \"application\" "
                  "from module \"%s\"", nxt_py_module);
        goto fail;
    }

    if (nxt_slow_path(PyCallable_Check(obj) == 0)) {
        nxt_alert(task, "\"application\" in module \"%s\" "
                  "is not a callable object", nxt_py_module);
        PyErr_Print();
        goto fail;
    }

    Py_INCREF(obj);
    Py_CLEAR(module);

    nxt_py_application = obj;
    obj = NULL;

    nxt_unit_default_init(task, &python_init);

    python_init.callbacks.request_handler = nxt_python_request_handler;

    unit_ctx = nxt_unit_init(&python_init);
    if (nxt_slow_path(unit_ctx == NULL)) {
        goto fail;
    }

    rc = nxt_unit_run(unit_ctx);

    nxt_unit_done(unit_ctx);

    nxt_python_atexit();

    exit(rc);

    return NXT_OK;

fail:

    Py_XDECREF(obj);
    Py_XDECREF(module);

    nxt_python_atexit();

    return NXT_ERROR;
}


static void
nxt_python_request_handler(nxt_unit_request_info_t *req)
{
    int                   rc;
    PyObject              *result, *iterator, *item, *args, *environ;
    nxt_python_run_ctx_t  run_ctx = {-1, 0, NULL, req};

    environ = nxt_python_get_environ(&run_ctx);
    if (nxt_slow_path(environ == NULL)) {
        nxt_unit_request_done(req, NXT_UNIT_ERROR);

        return;
    }

    args = PyTuple_New(2);
    if (nxt_slow_path(args == NULL)) {
        nxt_unit_req_error(req, "Python failed to create arguments tuple");

        nxt_unit_request_done(req, NXT_UNIT_ERROR);
        return;
    }

    PyTuple_SET_ITEM(args, 0, environ);

    Py_INCREF(nxt_py_start_resp_obj);
    PyTuple_SET_ITEM(args, 1, nxt_py_start_resp_obj);

    nxt_python_run_ctx = &run_ctx;

    result = PyObject_CallObject(nxt_py_application, args);

    Py_DECREF(args);

    if (nxt_slow_path(result == NULL)) {
        nxt_unit_req_error(req, "Python failed to call the application");
        PyErr_Print();

        nxt_unit_request_done(req, NXT_UNIT_ERROR);
        nxt_python_run_ctx = NULL;

        return;
    }

    item = NULL;
    iterator = NULL;

    /* Shortcut: avoid iterate over result string symbols. */
    if (PyBytes_Check(result)) {

        rc = nxt_python_write(&run_ctx, result);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            goto fail;
        }

    } else {
        iterator = PyObject_GetIter(result);

        if (nxt_slow_path(iterator == NULL)) {
            nxt_unit_req_error(req, "the application returned "
                               "not an iterable object");

            goto fail;
        }

        while (run_ctx.bytes_sent < run_ctx.content_length
               && (item = PyIter_Next(iterator)))
        {
            if (nxt_slow_path(!PyBytes_Check(item))) {
                nxt_unit_req_error(req, "the application returned "
                                   "not a bytestring object");

                goto fail;
            }

            rc = nxt_python_write(&run_ctx, item);
            if (nxt_slow_path(rc != NXT_UNIT_OK)) {
                goto fail;
            }

            Py_DECREF(item);
        }

        Py_DECREF(iterator);

        if (PyObject_HasAttrString(result, "close")) {
            PyObject_CallMethod(result, (char *) "close", NULL);
        }
    }

    if (nxt_slow_path(PyErr_Occurred() != NULL)) {
        nxt_unit_req_error(req, "an application error occurred");
        PyErr_Print();
    }

    nxt_unit_request_done(req, NXT_UNIT_OK);

    Py_DECREF(result);

    nxt_python_run_ctx = NULL;

    return;

fail:

    if (item != NULL) {
        Py_DECREF(item);
    }

    if (iterator != NULL) {
        Py_DECREF(iterator);
    }

    if (PyObject_HasAttrString(result, "close")) {
        PyObject_CallMethod(result, (char *) "close", NULL);
    }

    Py_DECREF(result);
    nxt_python_run_ctx = NULL;

    nxt_unit_request_done(req, NXT_UNIT_ERROR);
}


static void
nxt_python_atexit(void)
{
    Py_XDECREF(nxt_py_application);
    Py_XDECREF(nxt_py_start_resp_obj);
    Py_XDECREF(nxt_py_write_obj);
    Py_XDECREF(nxt_py_environ_ptyp);

    Py_Finalize();

    if (nxt_py_home != NULL) {
        nxt_free(nxt_py_home);
    }
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


    obj = PyString_FromStringAndSize("http", nxt_length("http"));

    if (nxt_slow_path(obj == NULL)) {
        nxt_alert(task,
              "Python failed to create the \"wsgi.url_scheme\" environ value");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "wsgi.url_scheme", obj)
        != 0))
    {
        nxt_alert(task,
                  "Python failed to set the \"wsgi.url_scheme\" environ value");
        goto fail;
    }

    Py_DECREF(obj);
    obj = NULL;


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
    char                *name;
    uint32_t            i;
    PyObject            *environ;
    nxt_unit_field_t    *f;
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

    RC(nxt_python_add_sptr(ctx, "REQUEST_METHOD", &r->method,
                           r->method_length));
    RC(nxt_python_add_sptr(ctx, "REQUEST_URI", &r->target, r->target_length));

    if (r->query.offset) {
        RC(nxt_python_add_sptr(ctx, "QUERY_STRING", &r->query,
                               r->query_length));
    }
    RC(nxt_python_add_sptr(ctx, "PATH_INFO", &r->path, r->path_length));

    RC(nxt_python_add_sptr(ctx, "REMOTE_ADDR", &r->remote, r->remote_length));
    RC(nxt_python_add_sptr(ctx, "SERVER_ADDR", &r->local, r->local_length));

    RC(nxt_python_add_sptr(ctx, "SERVER_PROTOCOL", &r->version,
                           r->version_length));

    RC(nxt_python_add_sptr(ctx, "SERVER_NAME", &r->server_name,
                           r->server_name_length));
    RC(nxt_python_add_str(ctx, "SERVER_PORT", "80", 2));

    for (i = 0; i < r->fields_count; i++) {
        f = r->fields + i;
        name = nxt_unit_sptr_get(&f->name);

        RC(nxt_python_add_sptr(ctx, name, &f->value, f->value_length));
    }

    if (r->content_length_field != NXT_UNIT_NONE_FIELD) {
        f = r->fields + r->content_length_field;

        RC(nxt_python_add_sptr(ctx, "CONTENT_LENGTH", &f->value,
                               f->value_length));
    }

    if (r->content_type_field != NXT_UNIT_NONE_FIELD) {
        f = r->fields + r->content_type_field;

        RC(nxt_python_add_sptr(ctx, "CONTENT_TYPE", &f->value,
                               f->value_length));
    }

#undef RC

    return environ;

fail:

    Py_DECREF(environ);

    return NULL;
}


static int
nxt_python_add_sptr(nxt_python_run_ctx_t *ctx, const char *name,
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
        PyErr_Print();

        return NXT_UNIT_ERROR;
    }

    if (nxt_slow_path(PyDict_SetItemString(ctx->environ, name, value) != 0)) {
        nxt_unit_req_error(ctx->req,
                           "Python failed to set the \"%s\" environ value",
                           name);
        Py_DECREF(value);

        return NXT_UNIT_ERROR;
    }

    Py_DECREF(value);

    return NXT_UNIT_OK;
}


static int
nxt_python_add_str(nxt_python_run_ctx_t *ctx, const char *name,
    const char *str, uint32_t size)
{
    PyObject  *value;

    if (nxt_slow_path(str == NULL)) {
        return NXT_UNIT_OK;
    }

    value = PyString_FromStringAndSize(str, size);
    if (nxt_slow_path(value == NULL)) {
        nxt_unit_req_error(ctx->req,
                           "Python failed to create value string \"%.*s\"",
                           (int) size, str);
        PyErr_Print();

        return NXT_UNIT_ERROR;
    }

    if (nxt_slow_path(PyDict_SetItemString(ctx->environ, name, value) != 0)) {
        nxt_unit_req_error(ctx->req,
                           "Python failed to set the \"%s\" environ value",
                           name);

        Py_DECREF(value);

        return NXT_UNIT_ERROR;
    }

    Py_DECREF(value);

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
            fields_size += PyUnicode_GET_SIZE(string);

        } else {
            return PyErr_Format(PyExc_TypeError,
                                "header #%d name is not a string", (int) i);
        }

        string = PyTuple_GET_ITEM(tuple, 1);
        if (PyBytes_Check(string)) {
            fields_size += PyBytes_GET_SIZE(string);

        } else if (PyUnicode_Check(string)) {
            fields_size += PyUnicode_GET_SIZE(string);

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
    return PyBytes_FromStringAndSize("", 0);
}


static PyObject *
nxt_py_input_readlines(nxt_py_input_t *self, PyObject *args)
{
    return PyList_New(0);
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


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

#define PyString_FromString         PyUnicode_FromString
#define PyString_FromStringAndSize  PyUnicode_FromStringAndSize
#else
#define NXT_PYTHON_BYTES_TYPE       "string"

#define PyBytes_FromString          PyString_FromString
#define PyBytes_FromStringAndSize   PyString_FromStringAndSize
#define PyBytes_Check               PyString_Check
#define PyBytes_GET_SIZE            PyString_GET_SIZE
#define PyBytes_AS_STRING           PyString_AS_STRING
#endif


typedef struct {
    PyObject_HEAD
    //nxt_app_request_t  *request;
} nxt_py_input_t;


typedef struct {
    PyObject_HEAD
    //nxt_app_request_t  *request;
} nxt_py_error_t;

typedef struct nxt_python_run_ctx_s nxt_python_run_ctx_t;

static nxt_int_t nxt_python_init(nxt_task_t *task, nxt_common_app_conf_t *conf);
static nxt_int_t nxt_python_run(nxt_task_t *task,
                      nxt_app_rmsg_t *rmsg, nxt_app_wmsg_t *msg);
static void nxt_python_atexit(nxt_task_t *task);

static PyObject *nxt_python_create_environ(nxt_task_t *task);
static PyObject *nxt_python_get_environ(nxt_task_t *task,
                      nxt_app_rmsg_t *rmsg, nxt_python_run_ctx_t *ctx);

static PyObject *nxt_py_start_resp(PyObject *self, PyObject *args);
static PyObject *nxt_py_write(PyObject *self, PyObject *args);

static void nxt_py_input_dealloc(nxt_py_input_t *self);
static PyObject *nxt_py_input_read(nxt_py_input_t *self, PyObject *args);
static PyObject *nxt_py_input_readline(nxt_py_input_t *self, PyObject *args);
static PyObject *nxt_py_input_readlines(nxt_py_input_t *self, PyObject *args);

struct nxt_python_run_ctx_s {
    nxt_task_t           *task;
    nxt_app_rmsg_t       *rmsg;
    nxt_app_wmsg_t       *wmsg;

    size_t               body_preread_size;
};

nxt_inline nxt_int_t nxt_python_write(nxt_python_run_ctx_t *ctx,
                      const u_char *data, size_t len,
                      nxt_bool_t flush, nxt_bool_t last);

nxt_inline nxt_int_t nxt_python_write_py_str(nxt_python_run_ctx_t *ctx,
                      PyObject *str, nxt_bool_t flush, nxt_bool_t last);


static uint32_t  compat[] = {
    NXT_VERNUM, NXT_DEBUG,
};


NXT_EXPORT nxt_application_module_t  nxt_app_module = {
    sizeof(compat),
    compat,
    nxt_string("python"),
    PY_VERSION,
    nxt_python_init,
    nxt_python_run,
    nxt_python_atexit,
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
    char                   *nxt_py_module;
    size_t                 len;
    PyObject               *obj, *pypath, *module;
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

    obj = NULL;
    module = NULL;

    if (c->path.length > 0) {
        obj = PyString_FromStringAndSize((char *) c->path.start,
                                         c->path.length);

        if (nxt_slow_path(obj == NULL)) {
            nxt_alert(task, "Python failed create string object \"%V\"",
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
        obj = NULL;
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

    if (obj == NULL) {
        goto fail;
    }

    nxt_py_environ_ptyp = obj;

    obj = Py_BuildValue("[s]", "unit");
    if (obj == NULL) {
        nxt_alert(task, "Python failed to create the \"sys.argv\" list");
        goto fail;
    }

    if (PySys_SetObject((char *) "argv", obj) != 0) {
        nxt_alert(task, "Python failed to set the \"sys.argv\" list");
        goto fail;
    }

    Py_DECREF(obj);

    nxt_py_module = nxt_alloca(c->module.length + 1);
    nxt_memcpy(nxt_py_module, c->module.start, c->module.length);
    nxt_py_module[c->module.length] = '\0';

    module = PyImport_ImportModule(nxt_py_module);

    if (nxt_slow_path(module == NULL)) {
        nxt_alert(task, "Python failed to import module \"%s\"", nxt_py_module);
        PyErr_PrintEx(1);
        return NXT_ERROR;
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
        PyErr_PrintEx(1);
        goto fail;
    }

    Py_INCREF(obj);
    Py_DECREF(module);

    nxt_py_application = obj;

    return NXT_OK;

fail:

    Py_XDECREF(obj);
    Py_XDECREF(module);

    if (nxt_py_home != NULL) {
        nxt_free(nxt_py_home);
    }

    return NXT_ERROR;
}


static nxt_int_t
nxt_python_run(nxt_task_t *task, nxt_app_rmsg_t *rmsg, nxt_app_wmsg_t *wmsg)
{
    u_char    *buf;
    size_t    size;
    PyObject  *result, *iterator, *item, *args, *environ;
    nxt_python_run_ctx_t  run_ctx = {task, rmsg, wmsg, 0};

    environ = nxt_python_get_environ(task, rmsg, &run_ctx);

    if (nxt_slow_path(environ == NULL)) {
        return NXT_ERROR;
    }

    args = PyTuple_New(2);

    if (nxt_slow_path(args == NULL)) {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "Python failed to create arguments tuple");
        return NXT_ERROR;
    }

    PyTuple_SET_ITEM(args, 0, environ);

    Py_INCREF(nxt_py_start_resp_obj);
    PyTuple_SET_ITEM(args, 1, nxt_py_start_resp_obj);

    nxt_python_run_ctx = &run_ctx;

    result = PyObject_CallObject(nxt_py_application, args);

    Py_DECREF(args);

    if (nxt_slow_path(result == NULL)) {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "Python failed to call the application");
        PyErr_Print();
        return NXT_ERROR;
    }

    item = NULL;
    iterator = NULL;

    /* Shortcut: avoid iterate over result string symbols. */
    if (PyBytes_Check(result) != 0) {

        size = PyBytes_GET_SIZE(result);
        buf = (u_char *) PyBytes_AS_STRING(result);

        nxt_python_write(&run_ctx, buf, size, 1, 1);

    } else {
        iterator = PyObject_GetIter(result);

        if (nxt_slow_path(iterator == NULL)) {
            nxt_log_error(NXT_LOG_ERR, task->log,
                          "the application returned not an iterable object");

            goto fail;
        }

        while((item = PyIter_Next(iterator))) {

            if (nxt_slow_path(PyBytes_Check(item) == 0)) {
                nxt_log_error(NXT_LOG_ERR, task->log,
                        "the application returned not a bytestring object");

                goto fail;
            }

            size = PyBytes_GET_SIZE(item);
            buf = (u_char *) PyBytes_AS_STRING(item);

            nxt_debug(task, "nxt_app_write(fake): %uz", size);

            nxt_python_write(&run_ctx, buf, size, 1, 0);

            Py_DECREF(item);
        }

        Py_DECREF(iterator);

        nxt_python_write(&run_ctx, NULL, 0, 1, 1);

        if (PyObject_HasAttrString(result, "close")) {
            PyObject_CallMethod(result, (char *) "close", NULL);
        }
    }

    if (nxt_slow_path(PyErr_Occurred() != NULL)) {
        nxt_log_error(NXT_LOG_ERR, task->log, "an application error occurred");
        PyErr_Print();
    }

    Py_DECREF(result);
    nxt_python_run_ctx = NULL;

    return NXT_OK;

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

    return NXT_ERROR;
}


static void
nxt_python_atexit(nxt_task_t *task)
{
    Py_DECREF(nxt_py_application);
    Py_DECREF(nxt_py_start_resp_obj);
    Py_DECREF(nxt_py_write_obj);
    Py_DECREF(nxt_py_environ_ptyp);

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


    obj = PyString_FromString("http");

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

nxt_inline nxt_int_t
nxt_python_add_env(nxt_task_t *task, PyObject *env, const char *name,
    nxt_str_t *v)
{
    PyObject   *value;
    nxt_int_t  rc;

    value = PyString_FromStringAndSize((char *) v->start, v->length);
    if (nxt_slow_path(value == NULL)) {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "Python failed to create value string \"%V\"", v);
        return NXT_ERROR;
    }

    if (nxt_slow_path(PyDict_SetItemString(env, name, value)
        != 0))
    {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "Python failed to set the \"%s\" environ value", name);
        rc = NXT_ERROR;

    } else {
        rc = NXT_OK;
    }

    Py_DECREF(value);

    return rc;
}


nxt_inline nxt_int_t
nxt_python_read_add_env(nxt_task_t *task, nxt_app_rmsg_t *rmsg,
    PyObject *env, const char *name, nxt_str_t *v)
{
    nxt_int_t  rc;

    rc = nxt_app_msg_read_str(task, rmsg, v);
    if (nxt_slow_path(rc != NXT_OK)) {
        return rc;
    }

    if (v->start == NULL) {
        return NXT_OK;
    }

    return nxt_python_add_env(task, env, name, v);
}


static PyObject *
nxt_python_get_environ(nxt_task_t *task, nxt_app_rmsg_t *rmsg,
    nxt_python_run_ctx_t *ctx)
{
    size_t          s;
    u_char          *colon;
    PyObject        *environ;
    nxt_int_t       rc;
    nxt_str_t       n, v, target, path, query;
    nxt_str_t       host, server_name, server_port;

    static nxt_str_t def_host = nxt_string("localhost");
    static nxt_str_t def_port = nxt_string("80");

    environ = PyDict_Copy(nxt_py_environ_ptyp);

    if (nxt_slow_path(environ == NULL)) {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "Python failed to create the \"environ\" dictionary");
        return NULL;
    }

#define RC(S)                                                                 \
    do {                                                                      \
        rc = (S);                                                             \
        if (nxt_slow_path(rc != NXT_OK)) {                                    \
            goto fail;                                                        \
        }                                                                     \
    } while(0)

#define NXT_READ(N)                                                           \
    RC(nxt_python_read_add_env(task, rmsg, environ, N, &v))

    NXT_READ("REQUEST_METHOD");
    NXT_READ("REQUEST_URI");

    target = v;
    RC(nxt_app_msg_read_str(task, rmsg, &path));

    RC(nxt_app_msg_read_size(task, rmsg, &s)); // query length + 1
    if (s > 0) {
        s--;

        query.start = target.start + s;
        query.length = target.length - s;

        RC(nxt_python_add_env(task, environ, "QUERY_STRING", &query));

        if (path.start == NULL) {
            path.start = target.start;
            path.length = s - 1;
        }
    }

    if (path.start == NULL) {
        path = target;
    }

    RC(nxt_python_add_env(task, environ, "PATH_INFO", &path));

    NXT_READ("SERVER_PROTOCOL");

    NXT_READ("REMOTE_ADDR");
    NXT_READ("SERVER_ADDR");

    RC(nxt_app_msg_read_str(task, rmsg, &host));

    if (host.length == 0) {
        host = def_host;
    }

    server_name = host;
    colon = nxt_memchr(host.start, ':', host.length);

    if (colon != NULL) {
        server_name.length = colon - host.start;

        server_port.start = colon + 1;
        server_port.length = host.length - server_name.length - 1;

    } else {
        server_port = def_port;
    }

    RC(nxt_python_add_env(task, environ, "SERVER_NAME", &server_name));
    RC(nxt_python_add_env(task, environ, "SERVER_PORT", &server_port));

    NXT_READ("CONTENT_TYPE");
    NXT_READ("CONTENT_LENGTH");

    while (nxt_app_msg_read_str(task, rmsg, &n) == NXT_OK) {
        if (nxt_slow_path(n.length == 0)) {
            break;
        }

        rc = nxt_app_msg_read_str(task, rmsg, &v);
        if (nxt_slow_path(rc != NXT_OK)) {
            break;
        }

        RC(nxt_python_add_env(task, environ, (char *) n.start, &v));
    }

    RC(nxt_app_msg_read_size(task, rmsg, &ctx->body_preread_size));

#undef NXT_READ
#undef RC

    return environ;

fail:

    Py_DECREF(environ);

    return NULL;
}


static PyObject *
nxt_py_start_resp(PyObject *self, PyObject *args)
{
    PyObject    *headers, *tuple, *string;
    nxt_int_t   rc;
    nxt_uint_t  i, n;
    nxt_python_run_ctx_t  *ctx;

    static const u_char status[] = "Status: ";

    static const u_char cr_lf[] = "\r\n";
    static const u_char sc_sp[] = ": ";

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

    nxt_python_write(ctx, status, nxt_length(status), 0, 0);

    rc = nxt_python_write_py_str(ctx, string, 0, 0);
    if (nxt_slow_path(rc != NXT_OK)) {
        return PyErr_Format(PyExc_TypeError,
                            "failed to write first argument (not a string?)");
    }

    nxt_python_write(ctx, cr_lf, nxt_length(cr_lf), 0, 0);

    headers = PyTuple_GET_ITEM(args, 1);

    if (!PyList_Check(headers)) {
        return PyErr_Format(PyExc_TypeError,
                         "the second argument is not a response headers list");
    }

    for (i = 0; i < (nxt_uint_t) PyList_GET_SIZE(headers); i++) {
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

        rc = nxt_python_write_py_str(ctx, string, 0, 0);
        if (nxt_slow_path(rc != NXT_OK)) {
            return PyErr_Format(PyExc_TypeError,
                                "failed to write response header name"
                                 " (not a string?)");
        }

        nxt_python_write(ctx, sc_sp, nxt_length(sc_sp), 0, 0);

        string = PyTuple_GET_ITEM(tuple, 1);

        rc = nxt_python_write_py_str(ctx, string, 0, 0);
        if (nxt_slow_path(rc != NXT_OK)) {
            return PyErr_Format(PyExc_TypeError,
                                "failed to write response header value"
                                 " (not a string?)");
        }

        nxt_python_write(ctx, cr_lf, nxt_length(cr_lf), 0, 0);
    }

    /* flush headers */
    nxt_python_write(ctx, cr_lf, nxt_length(cr_lf), 1, 0);

    Py_INCREF(nxt_py_write_obj);
    return nxt_py_write_obj;
}


static PyObject *
nxt_py_write(PyObject *self, PyObject *str)
{
    nxt_int_t  rc;

    if (nxt_fast_path(!PyBytes_Check(str))) {
        return PyErr_Format(PyExc_TypeError, "the argument is not a %s",
                            NXT_PYTHON_BYTES_TYPE);
    }

    rc = nxt_app_msg_write_raw(nxt_python_run_ctx->task,
                               nxt_python_run_ctx->wmsg,
                               (const u_char *) PyBytes_AS_STRING(str),
                               PyBytes_GET_SIZE(str));

    if (nxt_slow_path(rc != NXT_OK)) {
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
    u_char      *buf;
    size_t      copy_size;
    PyObject    *body, *obj;
    Py_ssize_t  size;
    nxt_uint_t  n;
    nxt_python_run_ctx_t  *ctx;

    ctx = nxt_python_run_ctx;

    if (nxt_slow_path(ctx == NULL)) {
        return PyErr_Format(PyExc_RuntimeError,
                            "wsgi.input.read() is called "
                            "outside of WSGI request processing");
    }

    size = ctx->body_preread_size;

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

            return PyErr_Format(PyExc_ValueError,
                                "the read body size cannot be zero or less");
        }

        if (size == 0 || size > (Py_ssize_t) ctx->body_preread_size) {
            size = ctx->body_preread_size;
        }
    }

    body = PyBytes_FromStringAndSize(NULL, size);

    if (nxt_slow_path(body == NULL)) {
        return NULL;
    }

    buf = (u_char *) PyBytes_AS_STRING(body);

    copy_size = nxt_min((size_t) size, ctx->body_preread_size);
    copy_size = nxt_app_msg_read_raw(ctx->task, ctx->rmsg, buf, copy_size);

    ctx->body_preread_size -= copy_size;

    return body;
}


static PyObject *
nxt_py_input_readline(nxt_py_input_t *self, PyObject *args)
{
    return PyBytes_FromString("");
}


static PyObject *
nxt_py_input_readlines(nxt_py_input_t *self, PyObject *args)
{
    return PyList_New(0);
}


nxt_inline nxt_int_t
nxt_python_write(nxt_python_run_ctx_t *ctx, const u_char *data, size_t len,
    nxt_bool_t flush, nxt_bool_t last)
{
    nxt_int_t  rc;

    rc = nxt_app_msg_write_raw(ctx->task, ctx->wmsg, data, len);

    if (flush || last) {
        rc = nxt_app_msg_flush(ctx->task, ctx->wmsg, last);
    }

    return rc;
}


nxt_inline nxt_int_t
nxt_python_write_py_str(nxt_python_run_ctx_t *ctx, PyObject *str,
    nxt_bool_t flush, nxt_bool_t last)
{
    PyObject   *bytes;
    nxt_int_t  rc;

    rc = NXT_OK;

    if (PyBytes_Check(str)) {
        rc = nxt_python_write(ctx, (u_char *) PyBytes_AS_STRING(str),
                              PyBytes_GET_SIZE(str), flush, last);

    } else {
        if (!PyUnicode_Check(str)) {
            return NXT_ERROR;
        }

        bytes = PyUnicode_AsLatin1String(str);
        if (nxt_slow_path(bytes == NULL)) {
            return NXT_ERROR;
        }

        rc = nxt_python_write(ctx, (u_char *) PyBytes_AS_STRING(bytes),
                              PyBytes_GET_SIZE(bytes), flush, last);

        Py_DECREF(bytes);
    }

    return rc;
}

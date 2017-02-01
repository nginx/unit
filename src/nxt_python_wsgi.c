
/*
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */


#include <Python.h>

#include <compile.h>
#include <node.h>

#ifdef _DARWIN_C_SOURCE
#undef _DARWIN_C_SOURCE
#endif

#include <nxt_main.h>
#include <nxt_cycle.h>
#include <nxt_application.h>


typedef struct {
    PyObject_HEAD
    //nxt_app_request_t  *request;
} nxt_py_input_t;


typedef struct {
    PyObject_HEAD
    //nxt_app_request_t  *request;
} nxt_py_error_t;


static nxt_int_t nxt_python_init(nxt_thread_t *thr);
static nxt_int_t nxt_python_run(nxt_app_request_t *r);

static PyObject *nxt_python_create_environ(nxt_thread_t *thr);
static PyObject *nxt_python_get_environ(nxt_app_request_t *r);

static PyObject *nxt_py_start_resp(PyObject *self, PyObject *args);

static void nxt_py_input_dealloc(nxt_py_input_t *self);
static PyObject *nxt_py_input_read(nxt_py_input_t *self, PyObject *args);
static PyObject *nxt_py_input_readline(nxt_py_input_t *self, PyObject *args);
static PyObject *nxt_py_input_readlines(nxt_py_input_t *self, PyObject *args);


extern nxt_int_t nxt_python_wsgi_init(nxt_thread_t *thr, nxt_cycle_t *cycle);


nxt_application_module_t  nxt_python_module = {
    nxt_python_init,
    NULL,
    NULL,
    nxt_python_run,
};


static PyMethodDef nxt_py_start_resp_method[] = {
    {"nginext_start_response", nxt_py_start_resp, METH_VARARGS, ""}
};


static PyMethodDef nxt_py_input_methods[] = {
    { "read",      (PyCFunction) nxt_py_input_read,      METH_VARARGS, 0 },
    { "readline",  (PyCFunction) nxt_py_input_readline,  METH_VARARGS, 0 },
    { "readlines", (PyCFunction) nxt_py_input_readlines, METH_VARARGS, 0 },
    { NULL, NULL, 0, 0 }
};


static PyTypeObject nxt_py_input_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "nginext._input",                   /* tp_name              */
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
    "nginext input object.",            /* tp_doc               */
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
};


static char               *nxt_py_module;

static PyObject           *nxt_py_application;
static PyObject           *nxt_py_start_resp_obj;
static PyObject           *nxt_py_environ_ptyp;

static nxt_app_request_t  *nxt_app_request;


nxt_int_t
nxt_python_wsgi_init(nxt_thread_t *thr, nxt_cycle_t *cycle)
{
    char    **argv;
    u_char  *p, *dir;

    PyObject  *obj, *pypath;

    argv = nxt_process_argv;

    while (*argv != NULL) {
        p = (u_char *) *argv++;

        if (nxt_strcmp(p, "--py-module") == 0) {
            if (*argv == NULL) {
                nxt_log_emerg(thr->log,
                              "no argument for option \"--py-module\"");
                return NXT_ERROR;
            }

            nxt_py_module = *argv++;

            nxt_log_error(NXT_LOG_INFO, thr->log, "python module: \"%s\"",
                          nxt_py_module);

            break;
        }
    }

    if (nxt_py_module == NULL) {
        return NXT_OK;
    }

    Py_InitializeEx(0);

    obj = NULL;
    argv = nxt_process_argv;

    while (*argv != NULL) {
        p = (u_char *) *argv++;

        if (nxt_strcmp(p, "--py-path") == 0) {
            if (*argv == NULL) {
                nxt_log_emerg(thr->log, "no argument for option \"--py-path\"");
                goto fail;
            }

            dir = (u_char *) *argv++;

            nxt_log_error(NXT_LOG_INFO, thr->log, "python path \"%s\"", dir);

            obj = PyString_FromString((char *) dir);

            if (nxt_slow_path(obj == NULL)) {
                nxt_log_alert(thr->log,
                              "Python failed create string object \"%s\"", dir);
                goto fail;
            }

            pypath = PySys_GetObject((char *) "path");

            if (nxt_slow_path(pypath == NULL)) {
                nxt_log_alert(thr->log,
                              "Python failed to get \"sys.path\" list");
                goto fail;
            }

            if (nxt_slow_path(PyList_Insert(pypath, 0, obj) != 0)) {
                nxt_log_alert(thr->log,
                      "Python failed to insert \"%s\" into \"sys.path\"", dir);
                goto fail;
            }

            Py_DECREF(obj);
            obj = NULL;

            continue;
        }
    }

    obj = PyCFunction_New(nxt_py_start_resp_method, NULL);

    if (nxt_slow_path(obj == NULL)) {
        nxt_log_alert(thr->log,
                "Python failed to initialize the \"start_response\" function");
        goto fail;
    }

    nxt_py_start_resp_obj = obj;

    obj = nxt_python_create_environ(thr);

    if (obj == NULL) {
        goto fail;
    }

    nxt_py_environ_ptyp = obj;


    obj = Py_BuildValue("[s]", "nginext");
    if (obj == NULL) {
        nxt_log_alert(thr->log,
                      "Python failed to create the \"sys.argv\" list");
        goto fail;
    }

    if (PySys_SetObject((char *) "argv", obj) != 0) {
        nxt_log_alert(thr->log, "Python failed to set the \"sys.argv\" list");
        goto fail;
    }

    Py_DECREF(obj);

    return NXT_OK;

fail:

    Py_XDECREF(obj);
    Py_XDECREF(nxt_py_start_resp_obj);

    Py_Finalize();

    return NXT_ERROR;
}


static nxt_int_t
nxt_python_init(nxt_thread_t *thr)
{
    PyObject  *module, *obj;

#if 0
    FILE          *fp;
    PyObject      *co;
    struct _node  *node;

    chdir((char *) dir);
    fp = fopen((char *) script, "r");

    if (fp == NULL) {
        nxt_log_debug(thr->log, "fopen failed");
        return NXT_ERROR;
    }


    Py_SetProgramName((char *) "python mysite/wsgi.py");
    Py_InitializeEx(0);

    node = PyParser_SimpleParseFile(fp, (char *) script, Py_file_input);

    fclose(fp);

    if (node == NULL) {
        nxt_log_debug(thr->log, "BAD node");
        return NXT_ERROR;
    }

    co = (PyObject *) PyNode_Compile(node, (char *) script);

    PyNode_Free(node);

    if (co == NULL) {
        nxt_log_debug(thr->log, "BAD co");
        return NXT_ERROR;
    }

    pModule = PyImport_ExecCodeModuleEx((char *) "_wsgi_nginext", co, (char *) script);

    Py_XDECREF(co);
#endif

    PyOS_AfterFork();

    module = PyImport_ImportModule(nxt_py_module);

    if (nxt_slow_path(module == NULL)) {
        nxt_log_emerg(thr->log, "Python failed to import module \"%s\"",
                      nxt_py_module);
        return NXT_ERROR;
    }

    obj = PyDict_GetItemString(PyModule_GetDict(module), "application");

    if (nxt_slow_path(obj == NULL)) {
        nxt_log_emerg(thr->log, "Python failed to get \"application\" "
                                "from module \"%s\"", nxt_py_module);
        goto fail;
    }

    if (nxt_slow_path(PyCallable_Check(obj) == 0)) {
        nxt_log_emerg(thr->log, "\"application\" in module \"%s\" "
                                "is not a callable object", nxt_py_module);
        goto fail;
    }

    Py_INCREF(obj);
    Py_DECREF(module);

    nxt_py_application = obj;

    return NXT_OK;

fail:

    Py_DECREF(module);

    return NXT_ERROR;
}


static nxt_int_t
nxt_python_run(nxt_app_request_t *r)
{
    u_char    *buf;
    size_t    size;
    PyObject  *result, *iterator, *item, *args, *environ;

    nxt_app_request = r;

    environ = nxt_python_get_environ(r);

    if (nxt_slow_path(environ == NULL)) {
        return NXT_ERROR;
    }

    args = PyTuple_New(2);

    if (nxt_slow_path(args == NULL)) {
        nxt_log_error(NXT_LOG_ERR, r->log,
                      "Python failed to create arguments tuple");
        return NXT_ERROR;
    }

    PyTuple_SET_ITEM(args, 0, environ);

    Py_INCREF(nxt_py_start_resp_obj);
    PyTuple_SET_ITEM(args, 1, nxt_py_start_resp_obj);

    result = PyObject_CallObject(nxt_py_application, args);

    Py_DECREF(args);

    if (nxt_slow_path(result == NULL)) {
        nxt_log_error(NXT_LOG_ERR, r->log,
                      "Python failed to call the application");
        PyErr_Print();
        return NXT_ERROR;
    }

    iterator = PyObject_GetIter(result);

    Py_DECREF(result);

    if (nxt_slow_path(iterator == NULL)) {
        nxt_log_error(NXT_LOG_ERR, r->log,
                      "the application returned not an iterable object");
        return NXT_ERROR;
    }

    while((item = PyIter_Next(iterator))) {

        if (nxt_slow_path(PyString_Check(item) == 0)) {
            nxt_log_error(NXT_LOG_ERR, r->log,
                          "the application returned not a string object");

            Py_DECREF(item);
            Py_DECREF(iterator);

            return NXT_ERROR;
        }

        size = PyString_GET_SIZE(item);
        buf = (u_char *) PyString_AS_STRING(item);

        nxt_app_write(r, buf, size);

        Py_DECREF(item);
    }

    Py_DECREF(iterator);

    if (nxt_slow_path(PyErr_Occurred() != NULL)) {
        nxt_log_error(NXT_LOG_ERR, r->log, "an application error occurred");
        PyErr_Print();
        return NXT_ERROR;
    }

    return NXT_OK;
}


static PyObject *
nxt_python_create_environ(nxt_thread_t *thr)
{
    PyObject  *obj, *stderr, *environ;

    environ = PyDict_New();

    if (nxt_slow_path(environ == NULL)) {
        nxt_log_alert(thr->log,
                      "Python failed to create the \"environ\" dictionary");
        return NULL;
    }

    obj = Py_BuildValue("(ii)", 1, 0);

    if (nxt_slow_path(obj == NULL)) {
        nxt_log_alert(thr->log,
                  "Python failed to build the \"wsgi.version\" environ value");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "wsgi.version", obj) != 0))
    {
        nxt_log_alert(thr->log,
                    "Python failed to set the \"wsgi.version\" environ value");
        goto fail;
    }

    Py_DECREF(obj);
    obj = NULL;


    if (nxt_slow_path(PyDict_SetItemString(environ, "wsgi.multithread",
                                           Py_False)
        != 0))
    {
        nxt_log_alert(thr->log,
                "Python failed to set the \"wsgi.multithread\" environ value");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "wsgi.multiprocess",
                                           Py_True)
        != 0))
    {
        nxt_log_alert(thr->log,
               "Python failed to set the \"wsgi.multiprocess\" environ value");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "wsgi.run_once",
                                           Py_False)
        != 0))
    {
        nxt_log_alert(thr->log,
                   "Python failed to set the \"wsgi.run_once\" environ value");
        goto fail;
    }


    obj = PyString_FromString("http");

    if (nxt_slow_path(obj == NULL)) {
        nxt_log_alert(thr->log,
              "Python failed to create the \"wsgi.url_scheme\" environ value");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "wsgi.url_scheme", obj)
        != 0))
    {
        nxt_log_alert(thr->log,
                 "Python failed to set the \"wsgi.url_scheme\" environ value");
        goto fail;
    }

    Py_DECREF(obj);
    obj = NULL;


    if (nxt_slow_path(PyType_Ready(&nxt_py_input_type) != 0)) {
        nxt_log_alert(thr->log,
                 "Python failed to initialize the \"wsgi.input\" type object");
        goto fail;
    }

    obj = (PyObject *) PyObject_New(nxt_py_input_t, &nxt_py_input_type);

    if (nxt_slow_path(obj == NULL)) {
        nxt_log_alert(thr->log,
                      "Python failed to create the \"wsgi.input\" object");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "wsgi.input", obj) != 0)) {
        nxt_log_alert(thr->log,
                      "Python failed to set the \"wsgi.input\" environ value");
        goto fail;
    }

    Py_DECREF(obj);
    obj = NULL;


    stderr = PySys_GetObject((char *) "stderr");

    if (nxt_slow_path(stderr == NULL)) {
        nxt_log_alert(thr->log, "Python failed to get \"sys.stderr\" object");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "wsgi.error", stderr) != 0))
    {
        nxt_log_alert(thr->log,
                      "Python failed to set the \"wsgi.error\" environ value");
        goto fail;
    }


    obj = PyString_FromString("localhost");

    if (nxt_slow_path(obj == NULL)) {
        nxt_log_alert(thr->log,
                  "Python failed to create the \"SERVER_NAME\" environ value");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "SERVER_NAME", obj) != 0)) {
        nxt_log_alert(thr->log,
                      "Python failed to set the \"SERVER_NAME\" environ value");
        goto fail;
    }

    Py_DECREF(obj);


    obj = PyString_FromString("80");

    if (nxt_slow_path(obj == NULL)) {
        nxt_log_alert(thr->log,
                  "Python failed to create the \"SERVER_PORT\" environ value");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "SERVER_PORT", obj) != 0)) {
        nxt_log_alert(thr->log,
                      "Python failed to set the \"SERVER_PORT\" environ value");
        goto fail;
    }

    Py_DECREF(obj);

    return environ;

fail:

    Py_XDECREF(obj);
    Py_DECREF(environ);

    return NULL;
}


static PyObject *
nxt_python_get_environ(nxt_app_request_t *r)
{
    u_char                  *p, ch, *query;
    nxt_str_t               *str;
    nxt_uint_t              i, n;
    nxt_app_header_field_t  *fld;

    PyObject                *environ, *value;

    static const u_char prefix[5] = "HTTP_";

    static u_char key[256];

    environ = PyDict_Copy(nxt_py_environ_ptyp);

    if (nxt_slow_path(environ == NULL)) {
        nxt_log_error(NXT_LOG_ERR, r->log,
                      "Python failed to create the \"environ\" dictionary");
        return NULL;
    }

    value = PyString_FromStringAndSize((char *) r->header.version.data,
                                       r->header.version.len);

    if (nxt_slow_path(value == NULL)) {
        nxt_log_error(NXT_LOG_ERR, r->log,
              "Python failed to create the \"SERVER_PROTOCOL\" environ value");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "SERVER_PROTOCOL", value)
        != 0))
    {
        nxt_log_error(NXT_LOG_ERR, r->log,
                 "Python failed to set the \"SERVER_PROTOCOL\" environ value");
        goto fail;
    }

    Py_DECREF(value);

    value = PyString_FromStringAndSize((char *) r->header.method.data,
                                       r->header.method.len);

    if (nxt_slow_path(value == NULL)) {
        nxt_log_error(NXT_LOG_ERR, r->log,
               "Python failed to create the \"REQUEST_METHOD\" environ value");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "REQUEST_METHOD", value)
        != 0))
    {
        nxt_log_error(NXT_LOG_ERR, r->log,
                  "Python failed to set the \"REQUEST_METHOD\" environ value");
        goto fail;
    }

    Py_DECREF(value);

    value = PyString_FromStringAndSize((char *) r->header.path.data,
                                       r->header.path.len);

    if (nxt_slow_path(value == NULL)) {
        nxt_log_error(NXT_LOG_ERR, r->log,
                  "Python failed to create the \"REQUEST_URI\" environ value");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "REQUEST_URI", value)
        != 0))
    {
        nxt_log_error(NXT_LOG_ERR, r->log,
                      "Python failed to set the \"REQUEST_URI\" environ value");
        goto fail;
    }

    Py_DECREF(value);

    query = nxt_memchr(r->header.path.data, '?', r->header.path.len);

    if (query != NULL) {
        value = PyString_FromStringAndSize((char *) r->header.path.data,
                                           query - r->header.path.data);

        query++;

    } else {
        value = PyString_FromStringAndSize((char *) r->header.path.data,
                                           r->header.path.len);
    }

    if (nxt_slow_path(value == NULL)) {
        nxt_log_error(NXT_LOG_ERR, r->log,
                    "Python failed to create the \"PATH_INFO\" environ value");
        goto fail;
    }

    if (nxt_slow_path(PyDict_SetItemString(environ, "PATH_INFO", value) != 0)) {
        nxt_log_error(NXT_LOG_ERR, r->log,
                      "Python failed to set the \"PATH_INFO\" environ value");
        goto fail;
    }

    Py_DECREF(value);

    if (query != NULL) {
        value = PyString_FromStringAndSize((char *) query,
                                           r->header.path.data
                                           + r->header.path.len - query);

        if (nxt_slow_path(value == NULL)) {
            nxt_log_error(NXT_LOG_ERR, r->log,
                 "Python failed to create the \"QUERY_STRING\" environ value");
            goto fail;
        }

        if (nxt_slow_path(PyDict_SetItemString(environ, "QUERY_STRING", value)
            != 0))
        {
            nxt_log_error(NXT_LOG_ERR, r->log,
                    "Python failed to set the \"QUERY_STRING\" environ value");
            goto fail;
        }

        Py_DECREF(value);
    }

    if (r->header.content_length != NULL) {
        str = r->header.content_length;

        value = PyString_FromStringAndSize((char *) str->data, str->len);

        if (nxt_slow_path(value == NULL)) {
            nxt_log_error(NXT_LOG_ERR, r->log,
               "Python failed to create the \"CONTENT_LENGTH\" environ value");
            goto fail;
        }

        if (nxt_slow_path(PyDict_SetItemString(environ, "CONTENT_LENGTH", value)
            != 0))
        {
            nxt_log_error(NXT_LOG_ERR, r->log,
                  "Python failed to set the \"CONTENT_LENGTH\" environ value");
            goto fail;
        }

        Py_DECREF(value);
    }

    if (r->header.content_type != NULL) {
        str = r->header.content_type;

        value = PyString_FromStringAndSize((char *) str->data, str->len);

        if (nxt_slow_path(value == NULL)) {
            nxt_log_error(NXT_LOG_ERR, r->log,
               "Python failed to create the \"CONTENT_TYPE\" environ value");
            goto fail;
        }

        if (nxt_slow_path(PyDict_SetItemString(environ, "CONTENT_TYPE", value)
            != 0))
        {
            nxt_log_error(NXT_LOG_ERR, r->log,
                  "Python failed to set the \"CONTENT_TYPE\" environ value");
            goto fail;
        }

        Py_DECREF(value);
    }

    nxt_memcpy(key, prefix, sizeof(prefix));

    for (i = 0; i < r->header.fields_num; i++) {
        fld = &r->header.fields[i];
        p = key + sizeof(prefix);

        for (n = 0; n < fld->name.len; n++, p++) {

            ch = fld->name.data[n];

            if (ch >= 'a' && ch <= 'z') {
                *p = ch & ~0x20;
                continue;
            }

            if (ch == '-') {
                *p = '_';
                continue;
            }

            *p = ch;
        }

        *p = '\0';

        value = PyString_FromStringAndSize((char *) fld->value.data,
                                           fld->value.len);

        if (nxt_slow_path(PyDict_SetItemString(environ, (char *) key, value)
            != 0))
        {
            nxt_log_error(NXT_LOG_ERR, r->log,
                          "Python failed to set the \"%s\" environ value", key);
            goto fail;
        }

        Py_DECREF(value);
    }

    return environ;

fail:

    Py_XDECREF(value);
    Py_DECREF(environ);

    return NULL;
}


static PyObject *
nxt_py_start_resp(PyObject *self, PyObject *args)
{
    u_char      *p, buf[4096];
    PyObject    *headers, *tuple, *string;
    nxt_str_t   str;
    nxt_uint_t  i, n;

    static const u_char resp[] = "HTTP/1.1 ";

    static const u_char default_headers[]
        = "Server: nginext/0.1\r\n"
          "Connection: close\r\n";

    n = PyTuple_GET_SIZE(args);

    if (n < 2 || n > 3) {
        return PyErr_Format(PyExc_TypeError, "invalid number of arguments");
    }

    string = PyTuple_GET_ITEM(args, 0);

    if (!PyString_Check(string)) {
        return PyErr_Format(PyExc_TypeError,
                            "the first argument is not a string");
    }

    str.len = PyString_GET_SIZE(string);
    str.data = (u_char *) PyString_AS_STRING(string);

    p = nxt_cpymem(buf, resp, sizeof(resp) - 1);
    p = nxt_cpymem(p, str.data, str.len);

    *p++ = '\r'; *p++ = '\n';

    p = nxt_cpymem(p, default_headers, sizeof(default_headers) - 1);

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

        if (!PyString_Check(string)) {
            return PyErr_Format(PyExc_TypeError,
                                "all response headers names must be strings");
        }

        str.len = PyString_GET_SIZE(string);
        str.data = (u_char *) PyString_AS_STRING(string);

        p = nxt_cpymem(p, str.data, str.len);

        *p++ = ':'; *p++ = ' ';

        string = PyTuple_GET_ITEM(tuple, 1);

        if (!PyString_Check(string)) {
            return PyErr_Format(PyExc_TypeError,
                                "all response headers values must be strings");
        }

        str.len = PyString_GET_SIZE(string);
        str.data = (u_char *) PyString_AS_STRING(string);

        p = nxt_cpymem(p, str.data, str.len);

        *p++ = '\r'; *p++ = '\n';
    }

    *p++ = '\r'; *p++ = '\n';

    nxt_app_write(nxt_app_request, buf, p - buf);

    return args;
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
    PyObject    *body, *obj;
    Py_ssize_t  size;
    nxt_uint_t  n;

    nxt_app_request_t *r = nxt_app_request;

    size = r->body_rest;

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

        if (size == 0 || size > r->body_rest) {
            size = r->body_rest;
        }
    }

    body = PyString_FromStringAndSize(NULL, size);

    if (nxt_slow_path(body == NULL)) {
        return NULL;
    }

    buf = (u_char *) PyString_AS_STRING(body);

    if (nxt_app_http_read_body(r, buf, size) != NXT_OK) {
        return PyErr_Format(PyExc_IOError, "failed to read body");
    }

    return body;
}


static PyObject *
nxt_py_input_readline(nxt_py_input_t *self, PyObject *args)
{
    return PyString_FromString("");
}


static PyObject *
nxt_py_input_readlines(nxt_py_input_t *self, PyObject *args)
{
    return PyList_New(0);
}

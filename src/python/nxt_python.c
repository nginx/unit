
/*
 * Copyright (C) NGINX, Inc.
 */


#include <Python.h>

#include <nxt_main.h>
#include <nxt_router.h>
#include <nxt_unit.h>

#include <python/nxt_python.h>

#include NXT_PYTHON_MOUNTS_H


typedef struct {
    pthread_t       thread;
    nxt_unit_ctx_t  *ctx;
    void            *ctx_data;
} nxt_py_thread_info_t;


static nxt_int_t nxt_python_start(nxt_task_t *task,
    nxt_process_data_t *data);
static nxt_int_t nxt_python_set_path(nxt_task_t *task, nxt_conf_value_t *value);
static int nxt_python_init_threads(nxt_python_app_conf_t *c);
static int nxt_python_ready_handler(nxt_unit_ctx_t *ctx);
static void *nxt_python_thread_func(void *main_ctx);
static void nxt_python_join_threads(nxt_unit_ctx_t *ctx,
    nxt_python_app_conf_t *c);
static void nxt_python_atexit(void);

static uint32_t  compat[] = {
    NXT_VERNUM, NXT_DEBUG,
};


NXT_EXPORT nxt_app_module_t  nxt_app_module = {
    sizeof(compat),
    compat,
    nxt_string("python"),
    PY_VERSION,
    nxt_python_mounts,
    nxt_nitems(nxt_python_mounts),
    NULL,
    nxt_python_start,
};

static PyObject           *nxt_py_stderr_flush;
PyObject                  *nxt_py_application;

#if PY_MAJOR_VERSION == 3
static wchar_t            *nxt_py_home;
#else
static char               *nxt_py_home;
#endif

static pthread_attr_t        *nxt_py_thread_attr;
static nxt_py_thread_info_t  *nxt_py_threads;
static nxt_python_proto_t    nxt_py_proto;


static nxt_int_t
nxt_python_start(nxt_task_t *task, nxt_process_data_t *data)
{
    int                    rc;
    char                   *nxt_py_module;
    size_t                 len;
    PyObject               *obj, *module;
    nxt_str_t              proto;
    const char             *callable;
    nxt_unit_ctx_t         *unit_ctx;
    nxt_unit_init_t        python_init;
    nxt_common_app_conf_t  *app_conf;
    nxt_python_app_conf_t  *c;
#if PY_MAJOR_VERSION == 3
    char                   *path;
    size_t                 size;
    nxt_int_t              pep405;

    static const char pyvenv[] = "/pyvenv.cfg";
    static const char bin_python[] = "/bin/python";
#endif

    static const nxt_str_t  wsgi = nxt_string("wsgi");
    static const nxt_str_t  asgi = nxt_string("asgi");

    app_conf = data->app;
    c = &app_conf->u.python;

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

#if PY_VERSION_HEX < NXT_PYTHON_VER(3, 7)
    if (c->threads > 1) {
        PyEval_InitThreads();
    }
#endif

    module = NULL;
    obj = NULL;

    python_init.ctx_data = NULL;

    obj = PySys_GetObject((char *) "stderr");
    if (nxt_slow_path(obj == NULL)) {
        nxt_alert(task, "Python failed to get \"sys.stderr\" object");
        goto fail;
    }

    nxt_py_stderr_flush = PyObject_GetAttrString(obj, "flush");

    /* obj is a Borrowed reference. */
    obj = NULL;

    if (nxt_slow_path(nxt_py_stderr_flush == NULL)) {
        nxt_alert(task, "Python failed to get \"flush\" attribute of "
                        "\"sys.stderr\" object");
        goto fail;
    }

    if (nxt_slow_path(nxt_python_set_path(task, c->path) != NXT_OK)) {
        goto fail;
    }

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
        nxt_python_print_exception();
        goto fail;
    }

    callable = (c->callable != NULL) ? c->callable : "application";

    obj = PyDict_GetItemString(PyModule_GetDict(module), callable);
    if (nxt_slow_path(obj == NULL)) {
        nxt_alert(task, "Python failed to get \"%s\" "
                  "from module \"%s\"", callable, nxt_py_module);
        goto fail;
    }

    if (nxt_slow_path(PyCallable_Check(obj) == 0)) {
        nxt_alert(task, "\"%s\" in module \"%s\" "
                  "is not a callable object", callable, nxt_py_module);
        goto fail;
    }

    nxt_py_application = obj;
    obj = NULL;

    Py_INCREF(nxt_py_application);

    Py_CLEAR(module);

    nxt_unit_default_init(task, &python_init);

    python_init.data = c;
    python_init.shm_limit = data->app->shm_limit;
    python_init.callbacks.ready_handler = nxt_python_ready_handler;

    proto = c->protocol;

    if (proto.length == 0) {
        proto = nxt_python_asgi_check(nxt_py_application) ? asgi : wsgi;
    }

    if (nxt_strstr_eq(&proto, &asgi)) {
        rc = nxt_python_asgi_init(&python_init, &nxt_py_proto);

    } else {
        rc = nxt_python_wsgi_init(&python_init, &nxt_py_proto);
    }

    if (nxt_slow_path(rc == NXT_UNIT_ERROR)) {
        goto fail;
    }

    rc = nxt_py_proto.ctx_data_alloc(&python_init.ctx_data);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    rc = nxt_python_init_threads(c);
    if (nxt_slow_path(rc == NXT_UNIT_ERROR)) {
        goto fail;
    }

    if (nxt_py_proto.startup != NULL) {
        if (nxt_py_proto.startup(python_init.ctx_data) != NXT_UNIT_OK) {
            goto fail;
        }
    }

    unit_ctx = nxt_unit_init(&python_init);
    if (nxt_slow_path(unit_ctx == NULL)) {
        goto fail;
    }

    rc = nxt_py_proto.run(unit_ctx);

    nxt_python_join_threads(unit_ctx, c);

    nxt_unit_done(unit_ctx);

    nxt_py_proto.ctx_data_free(python_init.ctx_data);

    nxt_python_atexit();

    exit(rc);

    return NXT_OK;

fail:

    nxt_python_join_threads(NULL, c);

    if (python_init.ctx_data != NULL) {
        nxt_py_proto.ctx_data_free(python_init.ctx_data);
    }

    Py_XDECREF(obj);
    Py_XDECREF(module);

    nxt_python_atexit();

    return NXT_ERROR;
}


static nxt_int_t
nxt_python_set_path(nxt_task_t *task, nxt_conf_value_t *value)
{
    int               ret;
    PyObject          *path, *sys;
    nxt_str_t         str;
    nxt_uint_t        n;
    nxt_conf_value_t  *array;

    if (value == NULL) {
        return NXT_OK;
    }

    sys = PySys_GetObject((char *) "path");
    if (nxt_slow_path(sys == NULL)) {
        nxt_alert(task, "Python failed to get \"sys.path\" list");
        return NXT_ERROR;
    }

    /* sys is a Borrowed reference. */

    if (nxt_conf_type(value) == NXT_CONF_STRING) {
        n = 0;
        goto value_is_string;
    }

    /* NXT_CONF_ARRAY */
    array = value;

    n = nxt_conf_array_elements_count(array);

    while (n != 0) {
        n--;

        /*
         * Insertion in front of existing paths starting from the last element
         * to preserve original order while giving priority to the values
         * specified in the "path" option.
         */

        value = nxt_conf_get_array_element(array, n);

    value_is_string:

        nxt_conf_get_string(value, &str);

        path = PyString_FromStringAndSize((char *) str.start, str.length);
        if (nxt_slow_path(path == NULL)) {
            nxt_alert(task, "Python failed to create string object \"%V\"",
                      &str);
            return NXT_ERROR;
        }

        ret = PyList_Insert(sys, 0, path);

        Py_DECREF(path);

        if (nxt_slow_path(ret != 0)) {
            nxt_alert(task, "Python failed to insert \"%V\" into \"sys.path\"",
                      &str);
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


static int
nxt_python_init_threads(nxt_python_app_conf_t *c)
{
    int                    res;
    uint32_t               i;
    nxt_py_thread_info_t   *ti;
    static pthread_attr_t  attr;

    if (c->threads <= 1) {
        return NXT_UNIT_OK;
    }

    if (c->thread_stack_size > 0) {
        res = pthread_attr_init(&attr);
        if (nxt_slow_path(res != 0)) {
            nxt_unit_alert(NULL, "thread attr init failed: %s (%d)",
                           strerror(res), res);

            return NXT_UNIT_ERROR;
        }

        res = pthread_attr_setstacksize(&attr, c->thread_stack_size);
        if (nxt_slow_path(res != 0)) {
            nxt_unit_alert(NULL, "thread attr set stack size failed: %s (%d)",
                           strerror(res), res);

            return NXT_UNIT_ERROR;
        }

        nxt_py_thread_attr = &attr;
    }

    nxt_py_threads = nxt_unit_malloc(NULL, sizeof(nxt_py_thread_info_t)
                                           * (c->threads - 1));
    if (nxt_slow_path(nxt_py_threads == NULL)) {
        nxt_unit_alert(NULL, "Failed to allocate thread info array");

        return NXT_UNIT_ERROR;
    }

    memset(nxt_py_threads, 0, sizeof(nxt_py_thread_info_t) * (c->threads - 1));

    for (i = 0; i < c->threads - 1; i++) {
        ti = &nxt_py_threads[i];

        res = nxt_py_proto.ctx_data_alloc(&ti->ctx_data);
        if (nxt_slow_path(res != NXT_UNIT_OK)) {
            return NXT_UNIT_ERROR;
        }
    }

    return NXT_UNIT_OK;
}


static int
nxt_python_ready_handler(nxt_unit_ctx_t *ctx)
{
    int                    res;
    uint32_t               i;
    nxt_py_thread_info_t   *ti;
    nxt_python_app_conf_t  *c;

    if (nxt_py_proto.ready != NULL) {
        res = nxt_py_proto.ready(ctx);
        if (nxt_slow_path(res != NXT_UNIT_OK)) {
            return NXT_UNIT_ERROR;
        }
    }

    /* Worker thread context. */
    if (!nxt_unit_is_main_ctx(ctx)) {
        return NXT_UNIT_OK;
    }

    c = ctx->unit->data;

    if (c->threads <= 1) {
        return NXT_UNIT_OK;
    }

    for (i = 0; i < c->threads - 1; i++) {
        ti = &nxt_py_threads[i];

        ti->ctx = ctx;

        res = pthread_create(&ti->thread, nxt_py_thread_attr,
                             nxt_python_thread_func, ti);

        if (nxt_fast_path(res == 0)) {
            nxt_unit_debug(ctx, "thread #%d created", (int) (i + 1));

        } else {
            nxt_unit_alert(ctx, "thread #%d create failed: %s (%d)",
                           (int) (i + 1), strerror(res), res);
        }
    }

    return NXT_UNIT_OK;
}


static void *
nxt_python_thread_func(void *data)
{
    nxt_unit_ctx_t        *ctx;
    PyGILState_STATE      gstate;
    nxt_py_thread_info_t  *ti;

    ti = data;

    nxt_unit_debug(ti->ctx, "worker thread #%d start",
                   (int) (ti - nxt_py_threads + 1));

    gstate = PyGILState_Ensure();

    if (nxt_py_proto.startup != NULL) {
        if (nxt_py_proto.startup(ti->ctx_data) != NXT_UNIT_OK) {
            goto fail;
        }
    }

    ctx = nxt_unit_ctx_alloc(ti->ctx, ti->ctx_data);
    if (nxt_slow_path(ctx == NULL)) {
        goto fail;
    }

    (void) nxt_py_proto.run(ctx);

    nxt_unit_done(ctx);

fail:

    PyGILState_Release(gstate);

    nxt_unit_debug(NULL, "worker thread #%d end",
                   (int) (ti - nxt_py_threads + 1));

    return NULL;
}


static void
nxt_python_join_threads(nxt_unit_ctx_t *ctx, nxt_python_app_conf_t *c)
{
    int                   res;
    uint32_t              i;
    PyThreadState         *thread_state;
    nxt_py_thread_info_t  *ti;

    if (nxt_py_threads == NULL) {
        return;
    }

    thread_state = PyEval_SaveThread();

    for (i = 0; i < c->threads - 1; i++) {
        ti = &nxt_py_threads[i];

        if ((uintptr_t) ti->thread == 0) {
            continue;
        }

        res = pthread_join(ti->thread, NULL);

        if (nxt_fast_path(res == 0)) {
            nxt_unit_debug(ctx, "thread #%d joined", (int) (i + 1));

        } else {
            nxt_unit_alert(ctx, "thread #%d join failed: %s (%d)",
                           (int) (i + 1), strerror(res), res);
        }
    }

    PyEval_RestoreThread(thread_state);

    for (i = 0; i < c->threads - 1; i++) {
        ti = &nxt_py_threads[i];

        if (ti->ctx_data != NULL) {
            nxt_py_proto.ctx_data_free(ti->ctx_data);
        }
    }

    nxt_unit_free(NULL, nxt_py_threads);
}


int
nxt_python_init_strings(nxt_python_string_t *pstr)
{
    PyObject  *obj;

    while (pstr->string.start != NULL) {
        obj = PyString_FromStringAndSize((char *) pstr->string.start,
                                         pstr->string.length);
        if (nxt_slow_path(obj == NULL)) {
            return NXT_UNIT_ERROR;
        }

        PyUnicode_InternInPlace(&obj);

        *pstr->object_p = obj;

        pstr++;
    }

    return NXT_UNIT_OK;
}


void
nxt_python_done_strings(nxt_python_string_t *pstr)
{
    PyObject  *obj;

    while (pstr->string.start != NULL) {
        obj = *pstr->object_p;

        Py_XDECREF(obj);
        *pstr->object_p = NULL;

        pstr++;
    }
}


static void
nxt_python_atexit(void)
{
    if (nxt_py_proto.done != NULL) {
        nxt_py_proto.done();
    }

    Py_XDECREF(nxt_py_stderr_flush);
    Py_XDECREF(nxt_py_application);

    Py_Finalize();

    if (nxt_py_home != NULL) {
        nxt_free(nxt_py_home);
    }
}


void
nxt_python_print_exception(void)
{
    PyErr_Print();

#if PY_MAJOR_VERSION == 3
    /* The backtrace may be buffered in sys.stderr file object. */
    {
        PyObject  *result;

        result = PyObject_CallFunction(nxt_py_stderr_flush, NULL);
        if (nxt_slow_path(result == NULL)) {
            PyErr_Clear();
            return;
        }

        Py_DECREF(result);
    }
#endif
}


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


#if PY_MAJOR_VERSION == 3
static nxt_int_t nxt_python3_init_config(nxt_int_t pep405);
#endif

static nxt_int_t nxt_python_start(nxt_task_t *task,
    nxt_process_data_t *data);
static nxt_int_t nxt_python_set_target(nxt_task_t *task,
    nxt_python_target_t *target, nxt_conf_value_t *conf);
nxt_inline nxt_int_t nxt_python_set_prefix(nxt_task_t *task,
    nxt_python_target_t *target, nxt_conf_value_t *value);
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
nxt_python_targets_t      *nxt_py_targets;

#if PY_MAJOR_VERSION == 3
static wchar_t            *nxt_py_home;
#else
static char               *nxt_py_home;
#endif

static pthread_attr_t        *nxt_py_thread_attr;
static nxt_py_thread_info_t  *nxt_py_threads;
static nxt_python_proto_t    nxt_py_proto;


#if PY_VERSION_HEX >= NXT_PYTHON_VER(3, 8)

static nxt_int_t
nxt_python3_init_config(nxt_int_t pep405)
{
    PyConfig     config;
    PyStatus     status;
    nxt_int_t    ret;
    PyPreConfig  preconfig;

    ret = NXT_ERROR;

    PyPreConfig_InitIsolatedConfig(&preconfig);
    /*
     * Determine whether to use UTF-8 mode or not, UTF-8
     * will be enabled if LC_CTYPE is C, POSIX or some
     * specific UTF-8 locale.
     */
    preconfig.utf8_mode = -1;

    status = Py_PreInitialize(&preconfig);
    if (PyStatus_Exception(status)) {
        return ret;
    }

    PyConfig_InitIsolatedConfig(&config);

    if (pep405) {
        status = PyConfig_SetString(&config, &config.program_name,
                                    nxt_py_home);
        if (PyStatus_Exception(status)) {
            goto out_config_clear;
        }

    } else {
        status = PyConfig_SetString(&config, &config.home, nxt_py_home);
        if (PyStatus_Exception(status)) {
            goto out_config_clear;
        }
    }

    status = Py_InitializeFromConfig(&config);
    if (PyStatus_Exception(status)) {
        goto out_config_clear;
    }

    ret = NXT_OK;

out_config_clear:

    PyConfig_Clear(&config);

    return ret;
}

#elif PY_MAJOR_VERSION == 3

static nxt_int_t
nxt_python3_init_config(nxt_int_t pep405)
{
    if (pep405) {
        Py_SetProgramName(nxt_py_home);

    } else {
        Py_SetPythonHome(nxt_py_home);
    }

    return NXT_OK;
}

#endif


static nxt_int_t
nxt_python_start(nxt_task_t *task, nxt_process_data_t *data)
{
    int                    rc;
    size_t                 len, size;
    uint32_t               next;
    PyObject               *obj;
    nxt_str_t              proto, probe_proto, name;
    nxt_int_t              ret, n, i;
    nxt_unit_ctx_t         *unit_ctx;
    nxt_unit_init_t        python_init;
    nxt_conf_value_t       *cv;
    nxt_python_targets_t   *targets;
    nxt_common_app_conf_t  *app_conf;
    nxt_python_app_conf_t  *c;
#if PY_MAJOR_VERSION == 3
    char                   *path;
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

        } else {
            mbstowcs(nxt_py_home, c->home, len + 1);
        }

        ret = nxt_python3_init_config(pep405);
        if (nxt_slow_path(ret == NXT_ERROR)) {
            nxt_alert(task, "Failed to initialise config");
            return NXT_ERROR;
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

    n = (c->targets != NULL ? nxt_conf_object_members_count(c->targets) : 1);

    size = sizeof(nxt_python_targets_t) + n * sizeof(nxt_python_target_t);

    targets = nxt_unit_malloc(NULL, size);
    if (nxt_slow_path(targets == NULL)) {
        nxt_alert(task, "Could not allocate targets");
        goto fail;
    }

    memset(targets, 0, size);

    targets->count = n;
    nxt_py_targets = targets;

    if (c->targets != NULL) {
        next = 0;

        for (i = 0; /* void */; i++) {
            cv = nxt_conf_next_object_member(c->targets, &name, &next);
            if (cv == NULL) {
                break;
            }

            ret = nxt_python_set_target(task, &targets->target[i], cv);
            if (nxt_slow_path(ret != NXT_OK)) {
                goto fail;
            }
        }

    } else {
        ret = nxt_python_set_target(task, &targets->target[0], app_conf->self);
        if (nxt_slow_path(ret != NXT_OK)) {
            goto fail;
        }
    }

    nxt_unit_default_init(task, &python_init, data->app);

    python_init.data = c;
    python_init.callbacks.ready_handler = nxt_python_ready_handler;

    proto = c->protocol;

    if (proto.length == 0) {
        proto = nxt_python_asgi_check(targets->target[0].application)
                ? asgi : wsgi;

        for (i = 1; i < targets->count; i++) {
            probe_proto = nxt_python_asgi_check(targets->target[i].application)
                          ? asgi : wsgi;
            if (probe_proto.start != proto.start) {
                nxt_alert(task, "A mix of ASGI & WSGI targets is forbidden, "
                                "specify protocol in config if incorrect");
                goto fail;
            }
        }
    }

    if (nxt_strstr_eq(&proto, &asgi)) {
        rc = nxt_python_asgi_init(&python_init, &nxt_py_proto);

    } else {
        rc = nxt_python_wsgi_init(&python_init, &nxt_py_proto);
    }

    if (nxt_slow_path(rc == NXT_UNIT_ERROR)) {
        goto fail;
    }

    rc = nxt_py_proto.ctx_data_alloc(&python_init.ctx_data, 1);
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

    nxt_python_atexit();

    return NXT_ERROR;
}


static nxt_int_t
nxt_python_set_target(nxt_task_t *task, nxt_python_target_t *target,
    nxt_conf_value_t *conf)
{
    char              *callable, *module_name;
    PyObject          *module, *obj;
    nxt_str_t         str;
    nxt_conf_value_t  *value;

    static nxt_str_t  module_str = nxt_string("module");
    static nxt_str_t  callable_str = nxt_string("callable");
    static nxt_str_t  prefix_str = nxt_string("prefix");

    module = obj = NULL;

    value = nxt_conf_get_object_member(conf, &module_str, NULL);
    if (nxt_slow_path(value == NULL)) {
        goto fail;
    }

    nxt_conf_get_string(value, &str);

    module_name = nxt_alloca(str.length + 1);
    nxt_memcpy(module_name, str.start, str.length);
    module_name[str.length] = '\0';

    module = PyImport_ImportModule(module_name);
    if (nxt_slow_path(module == NULL)) {
        nxt_alert(task, "Python failed to import module \"%s\"", module_name);
        nxt_python_print_exception();
        goto fail;
    }

    value = nxt_conf_get_object_member(conf, &callable_str, NULL);
    if (value == NULL) {
        callable = nxt_alloca(12);
        nxt_memcpy(callable, "application", 12);

    } else {
        nxt_conf_get_string(value, &str);

        callable = nxt_alloca(str.length + 1);
        nxt_memcpy(callable, str.start, str.length);
        callable[str.length] = '\0';
    }

    obj = PyDict_GetItemString(PyModule_GetDict(module), callable);
    if (nxt_slow_path(obj == NULL)) {
        nxt_alert(task, "Python failed to get \"%s\" from module \"%s\"",
                  callable, module_name);
        goto fail;
    }

    if (nxt_slow_path(PyCallable_Check(obj) == 0)) {
        nxt_alert(task, "\"%s\" in module \"%s\" is not a callable object",
                  callable, module_name);
        goto fail;
    }

    value = nxt_conf_get_object_member(conf, &prefix_str, NULL);
    if (nxt_slow_path(nxt_python_set_prefix(task, target, value) != NXT_OK)) {
        goto fail;
    }

    target->application = obj;
    obj = NULL;

    Py_INCREF(target->application);
    Py_CLEAR(module);

    return NXT_OK;

fail:

    Py_XDECREF(obj);
    Py_XDECREF(module);

    return NXT_ERROR;
}


nxt_inline nxt_int_t
nxt_python_set_prefix(nxt_task_t *task, nxt_python_target_t *target,
    nxt_conf_value_t *value)
{
    u_char            *prefix;
    nxt_str_t         str;

    if (value == NULL) {
        return NXT_OK;
    }

    nxt_conf_get_string(value, &str);

    if (str.length == 0) {
        return NXT_OK;
    }

    if (str.start[str.length - 1] == '/') {
        str.length--;
    }
    target->prefix.length = str.length;
    prefix = nxt_malloc(str.length);
    if (nxt_slow_path(prefix == NULL)) {
        nxt_alert(task, "Failed to allocate target prefix string");
        return NXT_ERROR;
    }

    target->py_prefix = PyString_FromStringAndSize((char *)str.start,
                                                    str.length);
    if (nxt_slow_path(target->py_prefix == NULL)) {
        nxt_free(prefix);
        nxt_alert(task, "Python failed to allocate target prefix "
                        "string");
        return NXT_ERROR;
    }
    nxt_memcpy(prefix, str.start, str.length);
    target->prefix.start = prefix;

    return NXT_OK;
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

    array = value;
    n = nxt_conf_array_elements_count_or_1(array);

    while (n != 0) {
        n--;

        /*
         * Insertion in front of existing paths starting from the last element
         * to preserve original order while giving priority to the values
         * specified in the "path" option.
         */

        value = nxt_conf_get_array_element_or_itself(array, n);

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

        res = nxt_py_proto.ctx_data_alloc(&ti->ctx_data, 0);
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
    nxt_int_t            i;
    nxt_python_target_t  *target;

    if (nxt_py_proto.done != NULL) {
        nxt_py_proto.done();
    }

    Py_XDECREF(nxt_py_stderr_flush);

    if (nxt_py_targets != NULL) {
        for (i = 0; i < nxt_py_targets->count; i++) {
            target = &nxt_py_targets->target[i];

            Py_XDECREF(target->application);
            Py_XDECREF(target->py_prefix);

            nxt_free(target->prefix.start);
        }

        nxt_unit_free(NULL, nxt_py_targets);
    }

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

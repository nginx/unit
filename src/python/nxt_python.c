
/*
 * Copyright (C) NGINX, Inc.
 */


#include <Python.h>

#include <nxt_main.h>
#include <nxt_router.h>
#include <nxt_unit.h>

#include <python/nxt_python.h>

#include NXT_PYTHON_MOUNTS_H


static nxt_int_t nxt_python_start(nxt_task_t *task,
    nxt_process_data_t *data);
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


static nxt_int_t
nxt_python_start(nxt_task_t *task, nxt_process_data_t *data)
{
    int                    rc, asgi;
    char                   *nxt_py_module;
    size_t                 len;
    PyObject               *obj, *pypath, *module;
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

    module = NULL;
    obj = NULL;

    obj = PySys_GetObject((char *) "stderr");
    if (nxt_slow_path(obj == NULL)) {
        nxt_alert(task, "Python failed to get \"sys.stderr\" object");
        goto fail;
    }

    nxt_py_stderr_flush = PyObject_GetAttrString(obj, "flush");
    if (nxt_slow_path(nxt_py_stderr_flush == NULL)) {
        nxt_alert(task, "Python failed to get \"flush\" attribute of "
                        "\"sys.stderr\" object");
        goto fail;
    }

    /* obj is a Borrowed reference. */

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

    python_init.shm_limit = data->app->shm_limit;

    asgi = nxt_python_asgi_check(nxt_py_application);

    if (asgi) {
        rc = nxt_python_asgi_init(task, &python_init);

    } else {
        rc = nxt_python_wsgi_init(task, &python_init);
    }

    if (nxt_slow_path(rc == NXT_ERROR)) {
        goto fail;
    }

    unit_ctx = nxt_unit_init(&python_init);
    if (nxt_slow_path(unit_ctx == NULL)) {
        goto fail;
    }

    if (asgi) {
        rc = nxt_python_asgi_run(unit_ctx);

    } else {
        rc = nxt_python_wsgi_run(unit_ctx);
    }

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


nxt_int_t
nxt_python_init_strings(nxt_python_string_t *pstr)
{
    PyObject  *obj;

    while (pstr->string.start != NULL) {
        obj = PyString_FromStringAndSize((char *) pstr->string.start,
                                         pstr->string.length);
        if (nxt_slow_path(obj == NULL)) {
            return NXT_ERROR;
        }

        PyUnicode_InternInPlace(&obj);

        *pstr->object_p = obj;

        pstr++;
    }

    return NXT_OK;
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
    nxt_python_wsgi_done();
    nxt_python_asgi_done();

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

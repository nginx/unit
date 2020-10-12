
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PYTHON_H_INCLUDED_
#define _NXT_PYTHON_H_INCLUDED_


#include <Python.h>
#include <nxt_main.h>
#include <nxt_unit.h>


#if PY_MAJOR_VERSION == 3
#define NXT_PYTHON_BYTES_TYPE       "bytestring"

#define PyString_FromStringAndSize(str, size)                                 \
            PyUnicode_DecodeLatin1((str), (size), "strict")
#define PyString_AS_STRING          PyUnicode_DATA

#else
#define NXT_PYTHON_BYTES_TYPE       "string"

#define PyBytes_FromStringAndSize   PyString_FromStringAndSize
#define PyBytes_Check               PyString_Check
#define PyBytes_GET_SIZE            PyString_GET_SIZE
#define PyBytes_AS_STRING           PyString_AS_STRING
#define PyUnicode_InternInPlace     PyString_InternInPlace
#define PyUnicode_AsUTF8            PyString_AS_STRING
#define PyUnicode_GET_LENGTH        PyUnicode_GET_SIZE
#endif

#if PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION >= 5
#define NXT_HAVE_ASGI  1
#endif

extern PyObject  *nxt_py_application;

typedef struct {
    nxt_str_t  string;
    PyObject   **object_p;
} nxt_python_string_t;


nxt_int_t nxt_python_init_strings(nxt_python_string_t *pstr);
void nxt_python_done_strings(nxt_python_string_t *pstr);

void nxt_python_print_exception(void);

nxt_int_t nxt_python_wsgi_init(nxt_task_t *task, nxt_unit_init_t *init);
int nxt_python_wsgi_run(nxt_unit_ctx_t *ctx);
void nxt_python_wsgi_done(void);

int nxt_python_asgi_check(PyObject *obj);
nxt_int_t nxt_python_asgi_init(nxt_task_t *task, nxt_unit_init_t *init);
nxt_int_t nxt_python_asgi_run(nxt_unit_ctx_t *ctx);
void nxt_python_asgi_done(void);


#endif  /* _NXT_PYTHON_H_INCLUDED_ */

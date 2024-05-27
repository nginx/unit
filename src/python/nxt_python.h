
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PYTHON_H_INCLUDED_
#define _NXT_PYTHON_H_INCLUDED_


#include <Python.h>
#include <nxt_main.h>
#include <nxt_unit.h>

#define NXT_PYTHON_VER(maj, min)    ((maj << 24) | (min << 16))


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

#if PY_VERSION_HEX >= NXT_PYTHON_VER(3, 5)
#define NXT_HAVE_ASGI  1
#endif


typedef struct {
    PyObject    *application;
    PyObject    *py_prefix;
    nxt_str_t   prefix;
    nxt_bool_t  asgi_legacy;
} nxt_python_target_t;


typedef struct {
    nxt_int_t            count;
    nxt_python_target_t  target[];
} nxt_python_targets_t;


extern nxt_python_targets_t  *nxt_py_targets;


typedef struct {
    nxt_str_t  string;
    PyObject   **object_p;
} nxt_python_string_t;


typedef struct {
    int   (*ctx_data_alloc)(void **pdata, int main);
    void  (*ctx_data_free)(void *data);
    int   (*startup)(void *data);
    int   (*run)(nxt_unit_ctx_t *ctx);
    void  (*done)(void);
} nxt_python_proto_t;


int nxt_python_init_strings(nxt_python_string_t *pstr);
void nxt_python_done_strings(nxt_python_string_t *pstr);

void nxt_python_print_exception(void);

int nxt_python_wsgi_init(nxt_unit_init_t *init, nxt_python_proto_t *proto);

int nxt_python_asgi_check(PyObject *obj);
int nxt_python_asgi_init(nxt_unit_init_t *init, nxt_python_proto_t *proto);


#endif  /* _NXT_PYTHON_H_INCLUDED_ */

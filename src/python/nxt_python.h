
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PYTHON_H_INCLUDED_
#define _NXT_PYTHON_H_INCLUDED_


#include <Python.h>
#include <nxt_unit.h>


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


#endif  /* _NXT_PYTHON_H_INCLUDED_ */

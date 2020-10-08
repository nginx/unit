
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PYTHON_ASGI_H_INCLUDED_
#define _NXT_PYTHON_ASGI_H_INCLUDED_


typedef PyObject * (*nxt_py_asgi_enum_header_cb)(void *ctx, int i,
    PyObject *name, PyObject *val);

typedef struct {
    uint32_t       fields_count;
    uint32_t       fields_size;
} nxt_py_asgi_calc_size_ctx_t;

typedef struct {
    nxt_unit_request_info_t  *req;
    uint64_t                 content_length;
} nxt_py_asgi_add_field_ctx_t;

PyObject *nxt_py_asgi_enum_headers(PyObject *headers,
    nxt_py_asgi_enum_header_cb cb, void *data);

PyObject *nxt_py_asgi_calc_size(void *data, int i, PyObject *n, PyObject *v);
PyObject *nxt_py_asgi_add_field(void *data, int i, PyObject *n, PyObject *v);

PyObject *nxt_py_asgi_set_result_soon(nxt_unit_request_info_t *req,
    PyObject *future, PyObject *result);
PyObject *nxt_py_asgi_new_msg(nxt_unit_request_info_t *req, PyObject *type);
PyObject *nxt_py_asgi_new_scope(nxt_unit_request_info_t *req, PyObject *type,
    PyObject *spec_version);

void nxt_py_asgi_dealloc(PyObject *self);
PyObject *nxt_py_asgi_await(PyObject *self);
PyObject *nxt_py_asgi_iter(PyObject *self);
PyObject *nxt_py_asgi_next(PyObject *self);

nxt_int_t nxt_py_asgi_http_init(nxt_task_t *task);
PyObject *nxt_py_asgi_http_create(nxt_unit_request_info_t *req);
void nxt_py_asgi_http_data_handler(nxt_unit_request_info_t *req);
int nxt_py_asgi_http_drain(nxt_queue_link_t *lnk);

nxt_int_t nxt_py_asgi_websocket_init(nxt_task_t *task);
PyObject *nxt_py_asgi_websocket_create(nxt_unit_request_info_t *req);
void nxt_py_asgi_websocket_handler(nxt_unit_websocket_frame_t *ws);
void nxt_py_asgi_websocket_close_handler(nxt_unit_request_info_t *req);

nxt_int_t nxt_py_asgi_lifespan_startup(nxt_task_t *task);
nxt_int_t nxt_py_asgi_lifespan_shutdown(void);

extern PyObject  *nxt_py_loop_run_until_complete;
extern PyObject  *nxt_py_loop_create_future;
extern PyObject  *nxt_py_loop_create_task;

extern nxt_queue_t  nxt_py_asgi_drain_queue;


#endif  /* _NXT_PYTHON_ASGI_H_INCLUDED_ */

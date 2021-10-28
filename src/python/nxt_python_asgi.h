
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PYTHON_ASGI_H_INCLUDED_
#define _NXT_PYTHON_ASGI_H_INCLUDED_


typedef PyObject * (*nxt_py_asgi_enum_header_cb)(void *ctx, int i,
    PyObject *name, PyObject *val);

void nxt_py_asgi_drain_wait(nxt_unit_request_info_t *req,
    nxt_queue_link_t *link);

typedef struct {
    uint32_t       fields_count;
    uint32_t       fields_size;
} nxt_py_asgi_calc_size_ctx_t;

typedef struct {
    nxt_unit_request_info_t  *req;
    uint64_t                 content_length;
} nxt_py_asgi_add_field_ctx_t;

typedef struct {
    nxt_queue_t      drain_queue;
    PyObject         *loop_run_until_complete;
    PyObject         *loop_create_future;
    PyObject         *loop_create_task;
    PyObject         *loop_call_soon;
    PyObject         *loop_add_reader;
    PyObject         *loop_remove_reader;
    PyObject         *quit_future;
    PyObject         *quit_future_set_result;
    PyObject         **target_lifespans;
} nxt_py_asgi_ctx_data_t;

PyObject *nxt_py_asgi_enum_headers(PyObject *headers,
    nxt_py_asgi_enum_header_cb cb, void *data);

PyObject *nxt_py_asgi_calc_size(void *data, int i, PyObject *n, PyObject *v);
PyObject *nxt_py_asgi_add_field(void *data, int i, PyObject *n, PyObject *v);

PyObject *nxt_py_asgi_set_result_soon(nxt_unit_request_info_t *req,
    nxt_py_asgi_ctx_data_t *ctx_data, PyObject *future, PyObject *result);
PyObject *nxt_py_asgi_new_msg(nxt_unit_request_info_t *req, PyObject *type);
PyObject *nxt_py_asgi_new_scope(nxt_unit_request_info_t *req, PyObject *type,
    PyObject *spec_version);

void nxt_py_asgi_dealloc(PyObject *self);
PyObject *nxt_py_asgi_await(PyObject *self);
PyObject *nxt_py_asgi_iter(PyObject *self);
PyObject *nxt_py_asgi_next(PyObject *self);

int nxt_py_asgi_http_init(void);
PyObject *nxt_py_asgi_http_create(nxt_unit_request_info_t *req);
void nxt_py_asgi_http_data_handler(nxt_unit_request_info_t *req);
int nxt_py_asgi_http_drain(nxt_queue_link_t *lnk);
void nxt_py_asgi_http_close_handler(nxt_unit_request_info_t *req);

int nxt_py_asgi_websocket_init(void);
PyObject *nxt_py_asgi_websocket_create(nxt_unit_request_info_t *req);
void nxt_py_asgi_websocket_handler(nxt_unit_websocket_frame_t *ws);
void nxt_py_asgi_websocket_close_handler(nxt_unit_request_info_t *req);

int nxt_py_asgi_lifespan_startup(nxt_py_asgi_ctx_data_t *ctx_data);
int nxt_py_asgi_lifespan_shutdown(nxt_unit_ctx_t *ctx);


#endif  /* _NXT_PYTHON_ASGI_H_INCLUDED_ */

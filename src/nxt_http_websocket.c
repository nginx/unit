
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_router.h>
#include <nxt_http.h>
#include <nxt_router_request.h>
#include <nxt_port_memory_int.h>
#include <nxt_websocket.h>
#include <nxt_websocket_header.h>


static void nxt_http_websocket_client(nxt_task_t *task, void *obj, void *data);
static void nxt_http_websocket_error_handler(nxt_task_t *task, void *obj,
    void *data);


const nxt_http_request_state_t  nxt_http_websocket
    nxt_aligned(64) =
{
    .ready_handler = nxt_http_websocket_client,
    .error_handler = nxt_http_websocket_error_handler,
};


static void
nxt_http_websocket_client(nxt_task_t *task, void *obj, void *data)
{
    size_t                  frame_size, used_size, copy_size, buf_free_size;
    size_t                  chunk_copy_size;
    nxt_buf_t               *out, *buf, **out_tail, *b, *next;
    nxt_int_t               res;
    nxt_http_request_t      *r;
    nxt_request_rpc_data_t  *req_rpc_data;
    nxt_websocket_header_t  *wsh;

    r = obj;
    req_rpc_data = r->req_rpc_data;

    if (nxt_slow_path(req_rpc_data == NULL)) {
        nxt_debug(task, "websocket client frame for destroyed request");

        return;
    }

    nxt_debug(task, "http websocket client frame");

    wsh = (nxt_websocket_header_t *) r->ws_frame->mem.pos;

    frame_size = nxt_websocket_frame_header_size(wsh)
                  + nxt_websocket_frame_payload_len(wsh);

    buf = NULL;
    buf_free_size = 0;
    out = NULL;
    out_tail = &out;

    b = r->ws_frame;

    while (b != NULL && frame_size > 0) {
        used_size = nxt_buf_mem_used_size(&b->mem);
        copy_size = nxt_min(used_size, frame_size);

        while (copy_size > 0) {
            if (buf == NULL || buf_free_size == 0) {
                buf_free_size = nxt_min(frame_size, PORT_MMAP_DATA_SIZE);

                buf = nxt_port_mmap_get_buf(task, &req_rpc_data->app->outgoing,
                                            buf_free_size);

                *out_tail = buf;
                out_tail = &buf->next;
            }

            chunk_copy_size = nxt_min(buf_free_size, copy_size);

            buf->mem.free = nxt_cpymem(buf->mem.free, b->mem.pos,
                                       chunk_copy_size);

            copy_size -= chunk_copy_size;
            b->mem.pos += chunk_copy_size;
            buf_free_size -= chunk_copy_size;
        }

        frame_size -= copy_size;
        next = b->next;
        b->next = NULL;

        if (nxt_buf_mem_used_size(&b->mem) == 0) {
            nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                               b->completion_handler, task, b, b->parent);

            r->ws_frame = next;
        }

        b = next;
    }

    res = nxt_port_socket_write(task, req_rpc_data->app_port,
                                NXT_PORT_MSG_WEBSOCKET, -1,
                                req_rpc_data->stream,
                                task->thread->engine->port->id, out);
    if (nxt_slow_path(res != NXT_OK)) {
        // TODO: handle
    }

    b = r->ws_frame;

    if (b != NULL) {
        used_size = nxt_buf_mem_used_size(&b->mem);

        if (used_size > 0) {
            nxt_memmove(b->mem.start, b->mem.pos, used_size);

            b->mem.pos = b->mem.start;
            b->mem.free = b->mem.start + used_size;
        }
    }

    nxt_http_request_ws_frame_start(task, r, r->ws_frame);
}


static void
nxt_http_websocket_error_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_request_t      *r;
    nxt_request_rpc_data_t  *req_rpc_data;

    nxt_debug(task, "http websocket error handler");

    r = obj;
    req_rpc_data = r->req_rpc_data;

    if (req_rpc_data == NULL) {
        nxt_debug(task, "  req_rpc_data is NULL");
        goto close_handler;
    }

    if (req_rpc_data->app_port == NULL) {
        nxt_debug(task, "  app_port is NULL");
        goto close_handler;
    }

    (void) nxt_port_socket_write(task, req_rpc_data->app_port,
                                 NXT_PORT_MSG_WEBSOCKET_LAST,
                                 -1, req_rpc_data->stream,
                                 task->thread->engine->port->id, NULL);

close_handler:

    nxt_http_request_close_handler(task, obj, data);
}

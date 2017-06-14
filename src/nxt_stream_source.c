
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void nxt_stream_source_connected(nxt_task_t *task, void *obj,
    void *data);
static void nxt_stream_source_write_ready(nxt_task_t *task, void *obj,
    void *data);
static void nxt_stream_source_read_ready(nxt_task_t *task, void *obj,
    void *data);
static nxt_buf_t *nxt_stream_source_process_buffers(nxt_stream_source_t *stream,
    nxt_event_conn_t *c);
static void nxt_stream_source_buf_completion(nxt_task_t *task, void *obj,
    void *data);
static void nxt_stream_source_read_done(nxt_task_t *task, void *obj,
    void *data);
static void nxt_stream_source_refused(nxt_task_t *task, void *obj, void *data);
static void nxt_stream_source_closed(nxt_task_t *task, void *obj, void *data);
static void nxt_stream_source_error(nxt_task_t *task, void *obj, void *data);
static void nxt_stream_source_close(nxt_task_t *task,
    nxt_stream_source_t *stream);


static const nxt_event_conn_state_t  nxt_stream_source_connect_state;
static const nxt_event_conn_state_t  nxt_stream_source_request_write_state;
static const nxt_event_conn_state_t  nxt_stream_source_response_ready_state;
static const nxt_event_conn_state_t  nxt_stream_source_response_read_state;


void
nxt_stream_source_connect(nxt_task_t *task, nxt_stream_source_t *stream)
{
    nxt_thread_t          *thr;
    nxt_event_conn_t      *c;
    nxt_upstream_source_t  *us;

    thr = nxt_thread();

    us = stream->upstream;

    if (nxt_slow_path(!nxt_buf_pool_obtainable(&us->buffers))) {
        nxt_log(task, NXT_LOG_ERR,
                "%d buffers %uDK each are not enough to read upstream response",
                us->buffers.max, us->buffers.size / 1024);
        goto fail;
    }

    c = nxt_event_conn_create(us->buffers.mem_pool, thr->log);
    if (nxt_slow_path(c == NULL)) {
        goto fail;
    }

    stream->conn = c;
    c->socket.data = stream;

    nxt_conn_work_queue_set(c, us->work_queue);

    c->remote = us->peer->sockaddr;
    c->write_state = &nxt_stream_source_connect_state;

    nxt_event_conn_connect(task, c);
    return;

fail:

    stream->error_handler(task, stream);
}


static const nxt_event_conn_state_t  nxt_stream_source_connect_state
    nxt_aligned(64) =
{
    NXT_EVENT_NO_BUF_PROCESS,
    NXT_EVENT_TIMER_AUTORESET,

    nxt_stream_source_connected,
    nxt_stream_source_refused,
    nxt_stream_source_error,

    NULL, /* timeout */
    NULL, /* timeout value */
    0, /* connect_timeout */
};


static void
nxt_stream_source_connected(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_t     *c;
    nxt_stream_source_t  *stream;

    c = obj;
    stream = data;

    nxt_debug(task, "stream source connected fd:%d", c->socket.fd);

    c->read_state = &nxt_stream_source_response_ready_state;
    c->write = stream->out;
    c->write_state = &nxt_stream_source_request_write_state;

    if (task->thread->engine->batch != 0) {
        nxt_event_conn_write(task, c);

    } else {
        stream->read_queued = 1;
        nxt_thread_work_queue_add(task->thread,
                                  &task->thread->engine->read_work_queue,
                                  c->io->read, task, c, stream);

        c->io->write(task, c, stream);
    }
}


static const nxt_event_conn_state_t  nxt_stream_source_request_write_state
    nxt_aligned(64) =
{
    NXT_EVENT_NO_BUF_PROCESS,
    NXT_EVENT_TIMER_AUTORESET,

    nxt_stream_source_write_ready,
    NULL,
    nxt_stream_source_error,

    NULL, /* timeout */
    NULL, /* timeout value */
    0, /* connect_timeout */
};


static const nxt_event_conn_state_t nxt_stream_source_response_ready_state
    nxt_aligned(64) =
{
    NXT_EVENT_NO_BUF_PROCESS,
    NXT_EVENT_TIMER_AUTORESET,

    nxt_stream_source_read_ready,
    nxt_stream_source_closed,
    nxt_stream_source_error,

    NULL, /* timeout */
    NULL, /* timeout value */
    0, /* connect_timeout */
};


static void
nxt_stream_source_write_ready(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_t  *c;

    c = obj;

    nxt_debug(task, "stream source write ready fd:%d", c->socket.fd);

    nxt_conn_read(task, c);
}


static void
nxt_stream_source_read_ready(nxt_task_t *task, void *obj, void *data)
{
    nxt_int_t            ret;
    nxt_buf_t            *b;
    nxt_buf_pool_t       *buffers;
    nxt_event_conn_t     *c;
    nxt_stream_source_t  *stream;

    c = obj;
    stream = data;
    stream->read_queued = 0;

    nxt_debug(task, "stream source read ready fd:%d", c->socket.fd);

    if (c->read == NULL) {

        buffers = &stream->upstream->buffers;

        ret = nxt_buf_pool_mem_alloc(buffers, 0);

        if (nxt_slow_path(ret != NXT_OK)) {

            if (nxt_slow_path(ret == NXT_ERROR)) {
                goto fail;
            }

            /* ret == NXT_AGAIN */

            nxt_debug(task, "stream source flush");

            b = nxt_buf_sync_alloc(buffers->mem_pool, NXT_BUF_SYNC_NOBUF);

            if (nxt_slow_path(b == NULL)) {
                goto fail;
            }

            nxt_event_fd_block_read(task->thread->engine, &c->socket);

            nxt_source_filter(task->thread, c->write_work_queue, task,
                              stream->next, b);
            return;
        }

        c->read = buffers->current;
        buffers->current = NULL;
    }

    c->read_state = &nxt_stream_source_response_read_state;

    nxt_conn_read(task, c);
    return;

fail:

    nxt_stream_source_close(task, stream);
}


static const nxt_event_conn_state_t nxt_stream_source_response_read_state
    nxt_aligned(64) =
{
    NXT_EVENT_NO_BUF_PROCESS,
    NXT_EVENT_TIMER_AUTORESET,

    nxt_stream_source_read_done,
    nxt_stream_source_closed,
    nxt_stream_source_error,

    NULL, /* timeout */
    NULL, /* timeout value */
    0, /* connect_timeout */
};


static void
nxt_stream_source_read_done(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t            *b;
    nxt_bool_t           batch;
    nxt_event_conn_t     *c;
    nxt_stream_source_t  *stream;

    c = obj;
    stream = data;

    nxt_debug(task, "stream source read done fd:%d", c->socket.fd);

    if (c->read != NULL) {
        b = nxt_stream_source_process_buffers(stream, c);

        if (nxt_slow_path(b == NULL)) {
            nxt_stream_source_close(task, stream);
            return;
        }

        batch = (task->thread->engine->batch != 0);

        if (batch) {
            nxt_thread_work_queue_add(task->thread,
                                      stream->upstream->work_queue,
                                      nxt_source_filter_handler,
                                      task, stream->next, b);
        }

        if (!stream->read_queued) {
            stream->read_queued = 1;
            nxt_thread_work_queue_add(task->thread,
                                      stream->upstream->work_queue,
                                      nxt_stream_source_read_ready,
                                      task, c, stream);
        }

        if (!batch) {
            stream->next->filter(task, stream->next->context, b);
        }
    }
}


static nxt_buf_t *
nxt_stream_source_process_buffers(nxt_stream_source_t *stream,
    nxt_event_conn_t *c)
{
    size_t     size, nbytes;
    nxt_buf_t  *b, *in, *head, **prev;

    nbytes = c->nbytes;
    prev = &head;

    do {
        b = nxt_buf_mem_alloc(stream->upstream->buffers.mem_pool, 0, 0);

        if (nxt_slow_path(b == NULL)) {
            return NULL;
        }

        *prev = b;

        b->data = stream;
        b->completion_handler = nxt_stream_source_buf_completion;

        in = c->read;
        in->retain++;
        b->parent = in;

        b->mem.pos = in->mem.free;
        b->mem.start = in->mem.free;

        size = nxt_buf_mem_free_size(&in->mem);

        if (nbytes < size) {
            in->mem.free += nbytes;

            b->mem.free = in->mem.free;
            b->mem.end = in->mem.free;

            break;
        }

        in->mem.free = in->mem.end;

        b->mem.free = in->mem.free;
        b->mem.end = in->mem.free;
        nbytes -= size;

        prev = &b->next;
        c->read = in->next;
        in->next = NULL;

    } while (c->read != NULL);

    return head;
}


static void
nxt_stream_source_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    size_t               size;
    nxt_buf_t            *b, *parent;
    nxt_stream_source_t  *stream;

    b = obj;
    parent = data;

#if 0
    nxt_debug(thr->log,
                  "stream source buf completion: %p parent:%p retain:%uD",
                  b, parent, parent->retain);
#endif

    stream = b->data;

    /* A parent is a buffer where stream reads data. */

    parent->mem.pos = b->mem.pos;
    parent->retain--;

    if (parent->retain == 0 && !stream->conn->socket.closed) {
        size = nxt_buf_mem_size(&parent->mem);

        parent->mem.pos = parent->mem.start;
        parent->mem.free = parent->mem.start;

        /*
         * A buffer's original size can be changed by filters
         * so reuse the buffer only if it is still large enough.
         */
        if (size >= 256 || size >= stream->upstream->buffers.size) {

            if (stream->conn->read != parent) {
                nxt_buf_chain_add(&stream->conn->read, parent);
            }

            if (!stream->read_queued) {
                stream->read_queued = 1;
                nxt_thread_work_queue_add(task->thread,
                                          stream->upstream->work_queue,
                                          nxt_stream_source_read_ready,
                                          task, stream->conn,
                                          stream->conn->socket.data);
            }
        }
    }

    nxt_buf_free(stream->upstream->buffers.mem_pool, b);
}


static void
nxt_stream_source_refused(nxt_task_t *task, void *obj, void *data)
{
    nxt_stream_source_t  *stream;

    stream = data;

#if (NXT_DEBUG)
    {
        nxt_event_conn_t  *c;

        c = obj;

        nxt_debug(task, "stream source refused fd:%d", c->socket.fd);
    }
#endif

    nxt_stream_source_close(task, stream);
}


static void
nxt_stream_source_closed(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t            *b;
    nxt_event_conn_t     *c;
    nxt_stream_source_t  *stream;

    c = obj;
    stream = data;

    nxt_debug(task, "stream source closed fd:%d", c->socket.fd);

    nxt_conn_close(task, c);

    b = nxt_buf_sync_alloc(stream->upstream->buffers.mem_pool,
                           NXT_BUF_SYNC_LAST);

    if (nxt_slow_path(b == NULL)) {
        stream->error_handler(task, stream);
        return;
    }

    nxt_source_filter(task->thread, c->write_work_queue, task, stream->next, b);
}


static void
nxt_stream_source_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_stream_source_t  *stream;

    stream = data;

#if (NXT_DEBUG)
    {
        nxt_event_fd_t  *ev;

        ev = obj;

        nxt_debug(task, "stream source error fd:%d", ev->fd);
    }
#endif

    nxt_stream_source_close(task, stream);
}


static void
nxt_stream_source_close(nxt_task_t *task, nxt_stream_source_t *stream)
{
    nxt_conn_close(task, stream->conn);

    stream->error_handler(task, stream);
}


void
nxt_source_filter_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_source_hook_t  *next;

    next = obj;

    next->filter(task, next->context, data);
}

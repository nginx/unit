
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void nxt_conn_shutdown_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_conn_close_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_conn_close_timer_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_conn_close_error_ignore(nxt_task_t *task, void *obj,
    void *data);


void
nxt_conn_close(nxt_event_engine_t *engine, nxt_conn_t *c)
{
    int                 ret;
    nxt_work_queue_t    *wq;
    nxt_work_handler_t  handler;

    static const struct linger  linger_off = {
        .l_onoff = 1,
        .l_linger = 0,
    };

    nxt_debug(c->socket.task, "conn close fd:%d, to:%d",
              c->socket.fd, c->socket.timedout);

    /*
     * Disable all pending write operations because on success they
     * will incorrectly call a ready handler set for nxt_conn_close().
     */
    c->write = NULL;

    if (c->socket.timedout) {
        /*
         * Resetting of timed out connection on close
         * releases kernel memory associated with socket.
         * This also causes sending TCP/IP RST to a peer.
         */
        ret = setsockopt(c->socket.fd, SOL_SOCKET, SO_LINGER, &linger_off,
                         sizeof(struct linger));

        if (nxt_slow_path(ret != 0)) {
            nxt_alert(c->socket.task, "setsockopt(%d, SO_LINGER) failed %E",
                      c->socket.fd, nxt_socket_errno);
        }
    }

    /*
     * Event errors should be ignored here to avoid repeated nxt_conn_close()
     * calls.  nxt_conn_close_handler() or nxt_conn_close_timer_handler()
     * will eventually close socket.
     */
    c->socket.error_handler = nxt_conn_close_error_ignore;

    if (c->socket.error == 0 && !c->socket.closed && !c->socket.shutdown) {
        wq = &engine->shutdown_work_queue;
        handler = nxt_conn_shutdown_handler;

    } else {
        wq = &engine->close_work_queue;
        handler = nxt_conn_close_handler;
    }

    nxt_work_queue_add(wq, handler, c->socket.task, c, engine);
}


static void
nxt_conn_shutdown_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t          *c;
    nxt_event_engine_t  *engine;

    c = obj;
    engine = data;

    nxt_debug(task, "conn shutdown handler fd:%d", c->socket.fd);

    c->socket.shutdown = 1;

    nxt_socket_shutdown(task, c->socket.fd, SHUT_RDWR);

    nxt_work_queue_add(&engine->close_work_queue, nxt_conn_close_handler,
                       task, c, engine);
}


static void
nxt_conn_close_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_uint_t          events_pending, timers_pending;
    nxt_conn_t          *c;
    nxt_event_engine_t  *engine;

    c = obj;
    engine = data;

    nxt_debug(task, "conn close handler fd:%d", c->socket.fd);

    /*
     * Socket should be closed only after all pending socket event operations
     * will be processed by the kernel.  This could be achieved with zero-timer
     * handler.  Pending timer operations associated with the socket are
     * processed before going to the kernel.
     */

    timers_pending = nxt_timer_delete(engine, &c->read_timer);
    timers_pending += nxt_timer_delete(engine, &c->write_timer);

    events_pending = nxt_fd_event_close(engine, &c->socket);

    if (events_pending == 0) {
        nxt_socket_close(task, c->socket.fd);
        c->socket.fd = -1;

        if (c->idle) {
            engine->closed_conns_cnt++;
        }

        if (timers_pending == 0) {
            nxt_work_queue_add(&engine->fast_work_queue,
                               c->write_state->ready_handler,
                               task, c, c->socket.data);
            return;
        }
    }

    c->write_timer.handler = nxt_conn_close_timer_handler;
    c->write_timer.work_queue = &engine->fast_work_queue;

    nxt_timer_add(engine, &c->write_timer, 0);
}


static void
nxt_conn_close_timer_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t          *c;
    nxt_timer_t         *timer;
    nxt_event_engine_t  *engine;

    timer = obj;

    c = nxt_write_timer_conn(timer);

    nxt_debug(task, "conn close timer handler fd:%d", c->socket.fd);

    engine = task->thread->engine;

    if (c->socket.fd != -1) {
        nxt_socket_close(task, c->socket.fd);
        c->socket.fd = -1;

        if (c->idle) {
            engine->closed_conns_cnt++;
        }
    }

    nxt_work_queue_add(&engine->fast_work_queue, c->write_state->ready_handler,
                       task, c, c->socket.data);
}


static void
nxt_conn_close_error_ignore(nxt_task_t *task, void *obj, void *data)
{
    nxt_debug(task, "conn close error ignore");
}

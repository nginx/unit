
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static nxt_err_t nxt_conn_connect_test_error(nxt_task_t *task, nxt_conn_t *c);


void
nxt_conn_sys_socket(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t          *c;
    nxt_work_handler_t  handler;

    c = obj;

    if (nxt_conn_socket(task, c) == NXT_OK) {
        c->socket.write_work_queue = c->write_work_queue;
        handler = c->io->connect;

    } else {
        handler = c->write_state->error_handler;
    }

    nxt_work_queue_add(&task->thread->engine->connect_work_queue,
                       handler, task, c, data);
}


void
nxt_conn_io_connect(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t              *c;
    nxt_work_handler_t      handler;
    nxt_event_engine_t      *engine;
    const nxt_conn_state_t  *state;

    c = obj;

    state = c->write_state;

    switch (nxt_socket_connect(task, c->socket.fd, c->remote)) {

    case NXT_OK:
        c->socket.write_ready = 1;
        handler = state->ready_handler;
        break;

    case NXT_AGAIN:
        c->socket.write_handler = nxt_conn_connect_test;
        c->socket.error_handler = nxt_conn_connect_error;

        engine = task->thread->engine;

        nxt_conn_timer(engine, c, state, &c->write_timer);

        nxt_fd_event_enable_write(engine, &c->socket);
        return;

    case NXT_DECLINED:
        handler = state->close_handler;
        break;

    default: /* NXT_ERROR */
        handler = state->error_handler;
        break;
    }

    nxt_work_queue_add(c->write_work_queue, handler, task, c, data);
}


nxt_int_t
nxt_conn_socket(nxt_task_t *task, nxt_conn_t *c)
{
    nxt_uint_t    family;
    nxt_socket_t  s;

    nxt_debug(task, "event conn socket");

    family = c->remote->u.sockaddr.sa_family;

    s = nxt_socket_create(task, family, c->remote->type, 0, NXT_NONBLOCK);

    if (nxt_slow_path(s == -1)) {
        return NXT_ERROR;
    }

    c->sendfile = 1;

#if (NXT_HAVE_UNIX_DOMAIN && NXT_SOLARIS)

    if (family == AF_UNIX) {
        /* Solaris AF_UNIX does not support sendfilev(). */
        c->sendfile = 0;
    }

#endif

    c->socket.fd = s;

    c->socket.task = task;
    c->read_timer.task = task;
    c->write_timer.task = task;

    if (c->local != NULL) {
        if (nxt_slow_path(nxt_socket_bind(task, s, c->local) != NXT_OK)) {
            nxt_socket_close(task, s);
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


void
nxt_conn_connect_test(nxt_task_t *task, void *obj, void *data)
{
    nxt_err_t   err;
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "event connect test fd:%d", c->socket.fd);

    nxt_fd_event_block_write(task->thread->engine, &c->socket);

    if (c->write_state->timer_autoreset) {
        nxt_timer_disable(task->thread->engine, &c->write_timer);
    }

    err = nxt_conn_connect_test_error(task, c);

    if (err == 0) {
        nxt_work_queue_add(c->write_work_queue, c->write_state->ready_handler,
                           task, c, data);
    } else {
        nxt_conn_connect_error(task, c, data);
    }
}


void
nxt_conn_connect_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_err_t               err;
    nxt_conn_t              *c;
    nxt_work_handler_t      handler;
    const nxt_conn_state_t  *state;

    c = obj;
    err = c->socket.error;

    if (err == 0) {
        err = nxt_conn_connect_test_error(task, c);
    }

    state = c->write_state;

    switch (err) {

    case NXT_ECONNREFUSED:
#if (NXT_LINUX)
    case NXT_EAGAIN:
        /*
         * Linux returns EAGAIN instead of ECONNREFUSED
         * for UNIX sockets if a listen queue is full.
         */
#endif
        handler = state->close_handler;
        break;

    default:
        handler = state->error_handler;
        break;
    }

    nxt_work_queue_add(c->write_work_queue, handler, task, c, data);
}


static nxt_err_t
nxt_conn_connect_test_error(nxt_task_t *task, nxt_conn_t *c)
{
    nxt_err_t  err;

    err = nxt_socket_error(c->socket.fd);

    if (err != 0) {
        c->socket.error = err;

        nxt_log(task, nxt_socket_error_level(err), "connect(%d, %*s) failed %E",
                c->socket.fd, (size_t) c->remote->length,
                nxt_sockaddr_start(c->remote), err);
    }

    return err;
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


void
nxt_conn_wait(nxt_conn_t *c)
{
    nxt_event_engine_t      *engine;
    const nxt_conn_state_t  *state;

    nxt_debug(c->socket.task, "conn wait fd:%d rdy:%d",
              c->socket.fd, c->socket.read_ready);

    engine = c->socket.task->thread->engine;
    state = c->read_state;

    if (c->socket.read_ready) {
        nxt_work_queue_add(&engine->fast_work_queue, state->ready_handler,
                           c->socket.task, c, c->socket.data);
        return;
    }

    c->socket.read_handler = state->ready_handler;
    c->socket.error_handler = state->error_handler;

    nxt_conn_timer(engine, c, state, &c->read_timer);

    nxt_fd_event_enable_read(engine, &c->socket);
}


void
nxt_conn_io_read(nxt_task_t *task, void *obj, void *data)
{
    ssize_t                 n;
    nxt_conn_t              *c;
    nxt_work_queue_t        *wq;
    nxt_event_engine_t      *engine;
    nxt_work_handler_t      handler;
    const nxt_conn_state_t  *state;

    c = obj;

    nxt_debug(task, "conn read fd:%d rdy:%d cl:%d",
              c->socket.fd, c->socket.read_ready, c->socket.closed);

    engine = task->thread->engine;

    state = c->read_state;

    if (c->socket.read_ready) {

        if (state->io_read_handler == NULL) {
            n = c->io->recvbuf(c, c->read);

        } else {
            n = state->io_read_handler(c);
        }

        if (n > 0) {
            c->nbytes = n;

            nxt_recvbuf_update(c->read, n);

            nxt_fd_event_block_read(engine, &c->socket);

            if (state->timer_autoreset) {
                nxt_timer_disable(engine, &c->read_timer);
            }

            wq = c->read_work_queue;
            handler = state->ready_handler;

            nxt_work_queue_add(wq, handler, task, c, data);

            return;
        }

        if (n != NXT_AGAIN) {
            nxt_fd_event_block_read(engine, &c->socket);
            nxt_timer_disable(engine, &c->read_timer);

            wq = &engine->fast_work_queue;

            handler = (n == 0) ? state->close_handler : state->error_handler;

            nxt_work_queue_add(wq, handler, task, c, data);

            return;
        }
    }

    /*
     * Here c->io->read() is assigned instead of direct nxt_conn_io_read()
     * because the function can be called by nxt_kqueue_conn_io_read().
     */
    c->socket.read_handler = c->io->read;
    c->socket.error_handler = state->error_handler;

    if (c->read_timer.state == NXT_TIMER_DISABLED
        || nxt_fd_event_is_disabled(c->socket.read))
    {
        /* Timer may be set or reset. */
        nxt_conn_timer(engine, c, state, &c->read_timer);

        if (nxt_fd_event_is_disabled(c->socket.read)) {
            nxt_fd_event_enable_read(engine, &c->socket);
        }
    }

    return;
}


ssize_t
nxt_conn_io_recvbuf(nxt_conn_t *c, nxt_buf_t *b)
{
    ssize_t                 n;
    nxt_err_t               err;
    nxt_uint_t              niov;
    struct iovec            iov[NXT_IOBUF_MAX];
    nxt_recvbuf_coalesce_t  rb;

    rb.buf = b;
    rb.iobuf = iov;
    rb.nmax = NXT_IOBUF_MAX;
    rb.size = 0;

    niov = nxt_recvbuf_mem_coalesce(&rb);

    if (niov == 1) {
        /* Disposal of surplus kernel iovec copy-in operation. */
        return nxt_conn_io_recv(c, iov->iov_base, iov->iov_len, 0);
    }

    for ( ;; ) {
        n = readv(c->socket.fd, iov, niov);

        err = (n == -1) ? nxt_socket_errno : 0;

        nxt_debug(c->socket.task, "readv(%d, %ui): %z", c->socket.fd, niov, n);

        if (n > 0) {
            if ((size_t) n < rb.size) {
                c->socket.read_ready = 0;
            }

            return n;
        }

        if (n == 0) {
            c->socket.closed = 1;
            c->socket.read_ready = 0;
            return n;
        }

        /* n == -1 */

        switch (err) {

        case NXT_EAGAIN:
            nxt_debug(c->socket.task, "readv() %E", err);
            c->socket.read_ready = 0;
            return NXT_AGAIN;

        case NXT_EINTR:
            nxt_debug(c->socket.task, "readv() %E", err);
            continue;

        default:
            c->socket.error = err;
            nxt_log(c->socket.task, nxt_socket_error_level(err),
                    "readv(%d, %ui) failed %E", c->socket.fd, niov, err);

            return NXT_ERROR;
        }
    }
}


ssize_t
nxt_conn_io_recv(nxt_conn_t *c, void *buf, size_t size, nxt_uint_t flags)
{
    ssize_t    n;
    nxt_err_t  err;

    for ( ;; ) {
        n = recv(c->socket.fd, buf, size, flags);

        err = (n == -1) ? nxt_socket_errno : 0;

        nxt_debug(c->socket.task, "recv(%d, %p, %uz, 0x%ui): %z",
                  c->socket.fd, buf, size, flags, n);

        if (n > 0) {
            if ((size_t) n < size) {
                c->socket.read_ready = 0;
            }

            return n;
        }

        if (n == 0) {
            c->socket.closed = 1;
            c->socket.read_ready = 0;

            return n;
        }

        /* n == -1 */

        switch (err) {

        case NXT_EAGAIN:
            nxt_debug(c->socket.task, "recv() %E", err);
            c->socket.read_ready = 0;

            return NXT_AGAIN;

        case NXT_EINTR:
            nxt_debug(c->socket.task, "recv() %E", err);
            continue;

        default:
            c->socket.error = err;
            nxt_log(c->socket.task, nxt_socket_error_level(err),
                    "recv(%d, %p, %uz, %ui) failed %E",
                    c->socket.fd, buf, size, flags, err);

            return NXT_ERROR;
        }
    }
}

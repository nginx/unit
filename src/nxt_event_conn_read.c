
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


void
nxt_event_conn_read(nxt_thread_t *thr, nxt_event_conn_t *c)
{
    nxt_work_queue_t    *wq;
    nxt_work_handler_t  handler;

    handler = c->io->read;

    if (thr->engine->batch != 0) {

        wq = &thr->engine->read_work_queue;
        c->socket.read_work_queue = wq;

        nxt_thread_work_queue_add(thr, wq, handler, c, c->socket.data,
                                  c->socket.log);
        return;
    }

    handler(thr, c, c->socket.data);
}


void
nxt_event_conn_io_read(nxt_thread_t *thr, void *obj, void *data)
{
    ssize_t                       n;
    nxt_buf_t                     *b;
    nxt_bool_t                    batch;
    nxt_event_conn_t              *c;
    nxt_work_handler_t            handler;
    const nxt_event_conn_state_t  *state;

    c = obj;

    nxt_log_debug(thr->log, "event conn read fd:%d rdy:%d cl:%d",
                  c->socket.fd, c->socket.read_ready, c->socket.closed);

    batch = (thr->engine->batch != 0);
    state = c->read_state;

    if (c->socket.read_ready) {

        b = c->read;

        if (b == NULL) {
            /* Just test descriptor readiness. */
            goto ready;
        }

        if (c->peek == 0)  {
            n = c->io->recvbuf(c, b);

        } else {
            n = c->io->recv(c, b->mem.free, c->peek, MSG_PEEK);
        }

        if (n > 0) {
            c->nbytes = n;

            if (state->process_buffers) {
                nxt_recvbuf_update(b, n);

            } else {
                /*
                 * A ready_handler must not be queued, instead buffers
                 * must be processed by the ready_handler at once after
                 * recv() operation, otherwise two sequentially queued
                 * recv() operations will read in the same buffers.
                 */
                batch = 0;
            }

            goto ready;
        }

        if (n != NXT_AGAIN) {
            nxt_event_fd_block_read(thr->engine, &c->socket);
            nxt_event_timer_disable(&c->read_timer);

            if (n == 0) {
                handler = state->close_handler;
                goto done;
            }

            /* n == NXT_ERROR */
            handler = state->error_handler;
            goto done;
        }
    }

    /*
     * Here c->io->read() is assigned instead of direct
     * nxt_event_conn_io_read() because the function can
     * be called by nxt_kqueue_event_conn_io_read().
     */
    c->socket.read_handler = c->io->read;
    c->socket.error_handler = state->error_handler;

    if (c->read_timer.state == NXT_EVENT_TIMER_DISABLED
        || nxt_event_fd_is_disabled(c->socket.read))
    {
        /* Timer may be set or reset. */
        nxt_event_conn_timer(thr->engine, c, state, &c->read_timer);

        if (nxt_event_fd_is_disabled(c->socket.read)) {
            nxt_event_fd_enable_read(thr->engine, &c->socket);
        }
    }

    return;

ready:

    nxt_event_fd_block_read(thr->engine, &c->socket);

    if (state->autoreset_timer) {
        nxt_event_timer_disable(&c->read_timer);
    }

    handler = state->ready_handler;

done:

    if (batch) {
        nxt_thread_work_queue_add(thr, c->read_work_queue, handler,
                                  c, data, thr->log);
    } else {
        handler(thr, c, data);
    }
}


ssize_t
nxt_event_conn_io_recvbuf(nxt_event_conn_t *c, nxt_buf_t *b)
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
        return nxt_event_conn_io_recv(c, iov->iov_base, iov->iov_len, 0);
    }

    for ( ;; ) {
        n = readv(c->socket.fd, iov, niov);

        err = (n == -1) ? nxt_socket_errno : 0;

        nxt_log_debug(c->socket.log, "readv(%d, %ui): %z",
                      c->socket.fd, niov, n);

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
            nxt_log_debug(c->socket.log, "readv() %E", err);
            c->socket.read_ready = 0;
            return NXT_AGAIN;

        case NXT_EINTR:
            nxt_log_debug(c->socket.log, "readv() %E", err);
            continue;

        default:
            c->socket.error = err;
            nxt_log_error(nxt_socket_error_level(err, c->socket.log_error),
                          c->socket.log, "readv(%d, %ui) failed %E",
                          c->socket.fd, niov, err);
            return NXT_ERROR;
        }
    }
}


ssize_t
nxt_event_conn_io_recv(nxt_event_conn_t *c, void *buf, size_t size,
    nxt_uint_t flags)
{
    ssize_t    n;
    nxt_err_t  err;

    for ( ;; ) {
        n = recv(c->socket.fd, buf, size, flags);

        err = (n == -1) ? nxt_socket_errno : 0;

        nxt_log_debug(c->socket.log, "recv(%d, %p, %uz, 0x%ui): %z",
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
            nxt_log_debug(c->socket.log, "recv() %E", err);
            c->socket.read_ready = 0;
            return NXT_AGAIN;

        case NXT_EINTR:
            nxt_log_debug(c->socket.log, "recv() %E", err);
            continue;

        default:
            c->socket.error = err;
            nxt_log_error(nxt_socket_error_level(err, c->socket.log_error),
                          c->socket.log, "recv(%d, %p, %uz, %ui) failed %E",
                          c->socket.fd, buf, size, flags, err);
            return NXT_ERROR;
        }
    }
}

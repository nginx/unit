
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void nxt_event_conn_shutdown_socket(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_event_conn_close_socket(nxt_thread_t *thr, void *obj,
    void *data);


nxt_event_conn_io_t  nxt_unix_event_conn_io = {
    nxt_event_conn_io_connect,
    nxt_event_conn_io_accept,

    nxt_event_conn_io_read,
    nxt_event_conn_io_recvbuf,
    nxt_event_conn_io_recv,

    nxt_event_conn_io_write,
    nxt_event_conn_io_write_chunk,

#if (NXT_HAVE_LINUX_SENDFILE)
    nxt_linux_event_conn_io_sendfile,
#elif (NXT_HAVE_FREEBSD_SENDFILE)
    nxt_freebsd_event_conn_io_sendfile,
#elif (NXT_HAVE_MACOSX_SENDFILE)
    nxt_macosx_event_conn_io_sendfile,
#elif (NXT_HAVE_SOLARIS_SENDFILEV)
    nxt_solaris_event_conn_io_sendfilev,
#elif (NXT_HAVE_AIX_SEND_FILE)
    nxt_aix_event_conn_io_send_file,
#elif (NXT_HAVE_HPUX_SENDFILE)
    nxt_hpux_event_conn_io_sendfile,
#else
    nxt_event_conn_io_sendbuf,
#endif

    nxt_event_conn_io_writev,
    nxt_event_conn_io_send,

    nxt_event_conn_io_shutdown,
};


nxt_event_conn_t *
nxt_event_conn_create(nxt_mem_pool_t *mp, nxt_log_t *log)
{
    nxt_thread_t         *thr;
    nxt_event_conn_t     *c;
    static nxt_atomic_t  ident = 1;

    c = nxt_mem_zalloc(mp, sizeof(nxt_event_conn_t));
    if (nxt_slow_path(c == NULL)) {
        return NULL;
    }

    c->mem_pool = mp;

    c->socket.fd = -1;

    c->socket.log = &c->log;
    c->log = *log;

    /* The while loop skips possible uint32_t overflow. */

    while (c->log.ident == 0) {
        c->log.ident = (uint32_t) nxt_atomic_fetch_add(&ident, 1);
    }

    thr = nxt_thread();
    thr->engine->connections++;

    c->io = thr->engine->event->io;
    c->max_chunk = NXT_INT32_T_MAX;
    c->sendfile = NXT_CONN_SENDFILE_UNSET;

    c->socket.read_work_queue = &thr->work_queue.main;
    c->socket.write_work_queue = &thr->work_queue.main;

    nxt_event_conn_timer_init(&c->read_timer, c, c->socket.read_work_queue);
    nxt_event_conn_timer_init(&c->write_timer, c, c->socket.write_work_queue);

    nxt_log_debug(&c->log, "event connections: %uD", thr->engine->connections);

    return c;
}


void
nxt_event_conn_io_shutdown(nxt_thread_t *thr, void *obj, void *data)
{
    int               ret;
    socklen_t         len;
    struct linger     linger;
    nxt_event_conn_t  *c;

    c = obj;

    nxt_log_debug(thr->log, "event conn shutdown");

    if (c->socket.timedout) {
        /*
         * A reset of timed out connection on close
         * to release kernel memory associated with socket.
         * This also causes sending TCP/IP RST to a peer.
         */
        linger.l_onoff = 1;
        linger.l_linger = 0;
        len = sizeof(struct linger);

        ret = setsockopt(c->socket.fd, SOL_SOCKET, SO_LINGER, &linger, len);

        if (nxt_slow_path(ret != 0)) {
            nxt_log_error(NXT_LOG_CRIT, thr->log,
                          "setsockopt(%d, SO_LINGER) failed %E",
                          c->socket.fd, nxt_socket_errno);
        }
    }

    c->write_state->close_handler(thr, c, data);
}


void
nxt_event_conn_close(nxt_thread_t *thr, nxt_event_conn_t *c)
{
    nxt_work_queue_t    *wq;
    nxt_work_handler_t  handler;

    nxt_log_debug(thr->log, "event conn close fd:%d", c->socket.fd);

    nxt_thread_work_queue_drop(thr, c);
    nxt_thread_work_queue_drop(thr, &c->read_timer);
    nxt_thread_work_queue_drop(thr, &c->write_timer);

    nxt_event_timer_delete(thr->engine, &c->read_timer);
    nxt_event_timer_delete(thr->engine, &c->write_timer);

    nxt_event_fd_close(thr->engine, &c->socket);
    thr->engine->connections--;

    nxt_log_debug(thr->log, "event connections: %uD", thr->engine->connections);

    if (thr->engine->batch != 0) {

        if (c->socket.closed || c->socket.error != 0) {
            wq = &thr->engine->close_work_queue;
            handler = nxt_event_conn_close_socket;

        } else {
            wq = &thr->engine->shutdown_work_queue;
            handler = nxt_event_conn_shutdown_socket;
        }

        nxt_thread_work_queue_add(thr, wq, handler,
                                  (void *) (uintptr_t) c->socket.fd, NULL,
                                  &nxt_main_log);

    } else {
        nxt_socket_close(c->socket.fd);
    }

    c->socket.fd = -1;
}


static void
nxt_event_conn_shutdown_socket(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_socket_t  s;

    s = (nxt_socket_t) (uintptr_t) obj;

    nxt_socket_shutdown(s, SHUT_RDWR);

    nxt_thread_work_queue_add(thr, &thr->engine->close_work_queue,
                              nxt_event_conn_close_socket,
                              (void *) (uintptr_t) s, NULL, &nxt_main_log);
}


static void
nxt_event_conn_close_socket(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_socket_t  s;

    s = (nxt_socket_t) (uintptr_t) obj;

    nxt_socket_close(s);
}


void
nxt_event_conn_timer(nxt_event_engine_t *engine, nxt_event_conn_t *c,
    const nxt_event_conn_state_t *state, nxt_event_timer_t *tev)
{
    nxt_msec_t  timer;

    if (state->timer_value != NULL) {
        timer = state->timer_value(c, state->timer_data);

        if (timer != 0) {
            tev->handler = state->timer_handler;
            nxt_event_timer_add(engine, tev, timer);
        }
    }
}


void
nxt_event_conn_work_queue_set(nxt_event_conn_t *c, nxt_work_queue_t *wq)
{
#if 0
    nxt_thread_t      *thr;
    nxt_work_queue_t  *owq;

    thr = nxt_thread();
    owq = c->socket.work_queue;

    nxt_thread_work_queue_move(thr, owq, wq, c);
    nxt_thread_work_queue_move(thr, owq, wq, &c->read_timer);
    nxt_thread_work_queue_move(thr, owq, wq, &c->write_timer);
#endif

    c->read_work_queue = wq;
    c->write_work_queue = wq;
    c->read_timer.work_queue = wq;
    c->write_timer.work_queue = wq;
}

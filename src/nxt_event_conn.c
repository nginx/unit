
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void nxt_event_conn_shutdown_socket(nxt_task_t *task, void *obj,
    void *data);
static void nxt_event_conn_close_socket(nxt_task_t *task, void *obj,
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
    nxt_thread_t      *thr;
    nxt_event_conn_t  *c;

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
        c->log.ident = nxt_task_next_ident();
    }

    thr = nxt_thread();
    thr->engine->connections++;

    c->task.thread = thr;
    c->task.log = &c->log;
    c->task.ident = c->log.ident;
    c->socket.task = &c->task;
    c->read_timer.task = &c->task;
    c->write_timer.task = &c->task;

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
nxt_event_conn_io_shutdown(nxt_task_t *task, void *obj, void *data)
{
    int               ret;
    socklen_t         len;
    struct linger     linger;
    nxt_event_conn_t  *c;

    c = obj;

    nxt_debug(task, "event conn shutdown");

    if (c->socket.timedout) {
        /*
         * Resetting of timed out connection on close
         * releases kernel memory associated with socket.
         * This also causes sending TCP/IP RST to a peer.
         */
        linger.l_onoff = 1;
        linger.l_linger = 0;
        len = sizeof(struct linger);

        ret = setsockopt(c->socket.fd, SOL_SOCKET, SO_LINGER, &linger, len);

        if (nxt_slow_path(ret != 0)) {
            nxt_log(task, NXT_LOG_CRIT, "setsockopt(%d, SO_LINGER) failed %E",
                    c->socket.fd, nxt_socket_errno);
        }
    }

    c->write_state->close_handler(task, c, data);
}


void
nxt_event_conn_close(nxt_task_t *task, nxt_event_conn_t *c)
{
    nxt_thread_t        *thr;
    nxt_work_queue_t    *wq;
    nxt_event_engine_t  *engine;
    nxt_work_handler_t  handler;

    nxt_debug(task, "event conn close fd:%d", c->socket.fd);

    thr = task->thread;

    nxt_thread_work_queue_drop(thr, c);
    nxt_thread_work_queue_drop(thr, &c->read_timer);
    nxt_thread_work_queue_drop(thr, &c->write_timer);

    engine = thr->engine;

    nxt_event_timer_delete(engine, &c->read_timer);
    nxt_event_timer_delete(engine, &c->write_timer);

    nxt_event_fd_close(engine, &c->socket);
    engine->connections--;

    nxt_debug(task, "event connections: %uD", engine->connections);

    if (engine->batch != 0) {

        if (c->socket.closed || c->socket.error != 0) {
            wq = &engine->close_work_queue;
            handler = nxt_event_conn_close_socket;

        } else {
            wq = &engine->shutdown_work_queue;
            handler = nxt_event_conn_shutdown_socket;
        }

        nxt_thread_work_queue_add(thr, wq, handler, task,
                                  (void *) (uintptr_t) c->socket.fd, NULL);

    } else {
        nxt_socket_close(c->socket.fd);
    }

    c->socket.fd = -1;
}


static void
nxt_event_conn_shutdown_socket(nxt_task_t *task, void *obj, void *data)
{
    nxt_socket_t  s;

    s = (nxt_socket_t) (uintptr_t) obj;

    nxt_socket_shutdown(s, SHUT_RDWR);

    nxt_thread_work_queue_add(task->thread,
                              &task->thread->engine->close_work_queue,
                              nxt_event_conn_close_socket, task,
                              (void *) (uintptr_t) s, NULL);
}


static void
nxt_event_conn_close_socket(nxt_task_t *task, void *obj, void *data)
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

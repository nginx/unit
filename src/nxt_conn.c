
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


nxt_conn_io_t  nxt_unix_conn_io = {
    nxt_conn_io_connect,
    nxt_conn_io_accept,

    nxt_conn_io_read,
    nxt_conn_io_recvbuf,
    nxt_conn_io_recv,

    nxt_conn_io_write,
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

    nxt_conn_io_shutdown,
};


nxt_conn_t *
nxt_conn_create(nxt_mp_t *mp, nxt_task_t *task)
{
    nxt_conn_t    *c;
    nxt_thread_t  *thr;

    c = nxt_mp_zget(mp, sizeof(nxt_conn_t));
    if (nxt_slow_path(c == NULL)) {
        return NULL;
    }

    c->mem_pool = mp;

    c->socket.fd = -1;

    c->socket.log = &c->log;
    c->log = *task->log;

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

    c->io = thr->engine->event.io;
    c->max_chunk = NXT_INT32_T_MAX;
    c->sendfile = NXT_CONN_SENDFILE_UNSET;

    c->socket.read_work_queue = &thr->engine->fast_work_queue;
    c->socket.write_work_queue = &thr->engine->fast_work_queue;

    nxt_conn_timer_init(&c->read_timer, c, c->socket.read_work_queue);
    nxt_conn_timer_init(&c->write_timer, c, c->socket.write_work_queue);

    nxt_queue_init(&c->requests);

    nxt_log_debug(&c->log, "connections: %uD", thr->engine->connections);

    return c;
}


void
nxt_conn_io_shutdown(nxt_task_t *task, void *obj, void *data)
{
    int            ret;
    socklen_t      len;
    nxt_conn_t     *c;
    struct linger  linger;

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
nxt_conn_timer(nxt_event_engine_t *engine, nxt_conn_t *c,
    const nxt_conn_state_t *state, nxt_timer_t *timer)
{
    nxt_msec_t  value;

    if (state->timer_value != NULL) {
        value = state->timer_value(c, state->timer_data);

        if (value != 0) {
            timer->handler = state->timer_handler;
            nxt_timer_add(engine, timer, value);
        }
    }
}


void
nxt_conn_work_queue_set(nxt_conn_t *c, nxt_work_queue_t *wq)
{
    c->read_work_queue = wq;
    c->write_work_queue = wq;
    c->read_timer.work_queue = wq;
    c->write_timer.work_queue = wq;
}


nxt_req_conn_link_t *
nxt_conn_request_add(nxt_conn_t *c, nxt_req_id_t req_id)
{
    nxt_req_conn_link_t  *rc;

    rc = nxt_mp_zalloc(c->mem_pool, sizeof(nxt_req_conn_link_t));
    if (nxt_slow_path(rc == NULL)) {
        nxt_thread_log_error(NXT_LOG_WARN, "failed to allocate req %08uxD "
                             "to conn", req_id);
        return NULL;
    }

    rc->req_id = req_id;
    rc->conn = c;

    nxt_queue_insert_tail(&c->requests, &rc->link);

    return rc;
}


void
nxt_conn_request_remove(nxt_conn_t *c, nxt_req_conn_link_t *rc)
{
    nxt_queue_remove(&rc->link);

    nxt_mp_free(c->mem_pool, rc);
}



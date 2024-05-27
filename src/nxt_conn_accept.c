
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * A listen socket handler calls an event facility specific io_accept()
 * method.  The method accept()s a new connection and then calls
 * nxt_event_conn_accept() to handle the new connection and to prepare
 * for a next connection to avoid just dropping next accept()ed socket
 * if no more connections allowed.  If there are no available connections
 * an idle connection would be closed.  If there are no idle connections
 * then new connections will not be accept()ed for 1 second.
 */


static nxt_conn_t *nxt_conn_accept_alloc(nxt_task_t *task,
    nxt_listen_event_t *lev);
static void nxt_conn_listen_handler(nxt_task_t *task, void *obj,
    void *data);
static nxt_conn_t *nxt_conn_accept_next(nxt_task_t *task,
    nxt_listen_event_t *lev);
static void nxt_conn_accept_close_idle(nxt_task_t *task,
    nxt_listen_event_t *lev);
static void nxt_conn_accept_close_idle_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_conn_listen_event_error(nxt_task_t *task, void *obj,
    void *data);
static void nxt_conn_listen_timer_handler(nxt_task_t *task, void *obj,
    void *data);


nxt_listen_event_t *
nxt_listen_event(nxt_task_t *task, nxt_listen_socket_t *ls)
{
    nxt_listen_event_t  *lev;
    nxt_event_engine_t  *engine;

    lev = nxt_zalloc(sizeof(nxt_listen_event_t));

    if (nxt_fast_path(lev != NULL)) {
        lev->socket.fd = ls->socket;

        engine = task->thread->engine;
        lev->batch = engine->batch;
        lev->count = 1;

        lev->socket.read_work_queue = &engine->accept_work_queue;
        lev->socket.read_handler = nxt_conn_listen_handler;
        lev->socket.error_handler = nxt_conn_listen_event_error;
        lev->socket.log = &nxt_main_log;

        lev->accept = engine->event.io->accept;

        lev->listen = ls;
        lev->work_queue = &engine->read_work_queue;

        lev->timer.work_queue = &engine->fast_work_queue;
        lev->timer.handler = nxt_conn_listen_timer_handler;
        lev->timer.log = &nxt_main_log;

        lev->task.thread = task->thread;
        lev->task.log = &nxt_main_log;
        lev->task.ident = nxt_task_next_ident();
        lev->socket.task = &lev->task;
        lev->timer.task = &lev->task;

        if (nxt_conn_accept_alloc(task, lev) != NULL) {
            nxt_fd_event_enable_accept(engine, &lev->socket);

            nxt_queue_insert_tail(&engine->listen_connections, &lev->link);
        }

        return lev;
    }

    return NULL;
}


static nxt_conn_t *
nxt_conn_accept_alloc(nxt_task_t *task, nxt_listen_event_t *lev)
{
    nxt_mp_t            *mp;
    nxt_conn_t          *c;
    nxt_event_engine_t  *engine;

    engine = task->thread->engine;

    if (engine->connections < engine->max_connections) {

        mp = nxt_mp_create(1024, 128, 256, 32);

        if (nxt_fast_path(mp != NULL)) {
            c = nxt_conn_create(mp, lev->socket.task);
            if (nxt_slow_path(c == NULL)) {
                nxt_mp_destroy(mp);

                return NULL;
            }

            c->socket.read_work_queue = lev->socket.read_work_queue;
            c->socket.write_ready = 1;

            c->remote = nxt_sockaddr_cache_alloc(engine, lev->listen);
            if (nxt_fast_path(c->remote != NULL)) {
                lev->next = c;
                return c;
            }

            nxt_conn_free(task, c);
        }
    }

    return NULL;
}


static void
nxt_conn_listen_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_listen_event_t  *lev;

    lev = obj;
    lev->ready = lev->batch;

    lev->accept(task, lev, data);
}


void
nxt_conn_io_accept(nxt_task_t *task, void *obj, void *data)
{
    socklen_t           socklen;
    nxt_conn_t          *c;
    nxt_socket_t        s;
    struct sockaddr     *sa;
    nxt_listen_event_t  *lev;

    lev = obj;
    c = lev->next;

    lev->ready--;
    lev->socket.read_ready = (lev->ready != 0);

    sa = &c->remote->u.sockaddr;
    socklen = c->remote->socklen;
    /*
     * The returned socklen is ignored here, because sockaddr_in and
     * sockaddr_in6 socklens are not changed.  As to unspecified sockaddr_un
     * it is 3 byte length and already prepared, because old BSDs return zero
     * socklen and do not update the sockaddr_un at all; Linux returns 2 byte
     * socklen and updates only the sa_family part; other systems copy 3 bytes
     * and truncate surplus zero part.  Only bound sockaddr_un will be really
     * truncated here.
     */
    s = accept(lev->socket.fd, sa, &socklen);

    if (s == -1) {
        nxt_conn_accept_error(task, lev, "accept", nxt_socket_errno);
        return;
    }

    c->socket.fd = s;

#if (NXT_LINUX)
    /*
     * Linux does not inherit non-blocking mode
     * from listen socket for accept()ed socket.
     */
    if (nxt_slow_path(nxt_socket_nonblocking(task, s) != NXT_OK)) {
        nxt_socket_close(task, s);
    }

#endif

    nxt_debug(task, "accept(%d): %d", lev->socket.fd, s);

    nxt_conn_accept(task, lev, c);
}


void
nxt_conn_accept(nxt_task_t *task, nxt_listen_event_t *lev, nxt_conn_t *c)
{
    nxt_conn_t          *next;
    nxt_event_engine_t  *engine;

    nxt_sockaddr_text(c->remote);

    nxt_debug(task, "client: %*s",
              (size_t) c->remote->address_length,
              nxt_sockaddr_address(c->remote));

    engine = task->thread->engine;

    engine->accepted_conns_cnt++;

    nxt_conn_idle(engine, c);

    c->listen = lev;
    lev->count++;
    lev->next = NULL;
    c->socket.data = NULL;

    c->read_work_queue = lev->work_queue;
    c->write_work_queue = lev->work_queue;

    if (lev->listen->read_after_accept) {

        //c->socket.read_ready = 1;
//        lev->listen->handler(task, c, lev);
        nxt_work_queue_add(c->read_work_queue, lev->listen->handler,
                           &c->task, c, lev);

    } else {
        nxt_work_queue_add(c->write_work_queue, lev->listen->handler,
                           &c->task, c, lev);
    }

    next = nxt_conn_accept_next(task, lev);

    if (next != NULL && lev->socket.read_ready) {
        nxt_work_queue_add(lev->socket.read_work_queue,
                           lev->accept, task, lev, next);
    }
}


static nxt_conn_t *
nxt_conn_accept_next(nxt_task_t *task, nxt_listen_event_t *lev)
{
    nxt_conn_t  *c;

    c = lev->next;

    if (c == NULL) {
        c = nxt_conn_accept_alloc(task, lev);

        if (nxt_slow_path(c == NULL)) {
            nxt_conn_accept_close_idle(task, lev);
        }
    }

    return c;
}


static void
nxt_conn_accept_close_idle(nxt_task_t *task, nxt_listen_event_t *lev)
{
    nxt_event_engine_t  *engine;

    engine = task->thread->engine;

    nxt_work_queue_add(&engine->close_work_queue,
                       nxt_conn_accept_close_idle_handler, task, NULL, NULL);

    nxt_timer_add(engine, &lev->timer, 100);

    nxt_fd_event_disable_read(engine, &lev->socket);

    nxt_alert(task, "new connections are not accepted within 100ms");
}


static void
nxt_conn_accept_close_idle_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_uint_t          times;
    nxt_conn_t          *c;
    nxt_queue_t         *idle;
    nxt_queue_link_t    *link, *next;
    nxt_event_engine_t  *engine;

    static nxt_log_moderation_t  nxt_idle_close_log_moderation = {
        NXT_LOG_INFO, 2, "idle connections closed", NXT_LOG_MODERATION
    };

    times = 10;
    engine = task->thread->engine;
    idle = &engine->idle_connections;

    for (link = nxt_queue_last(idle);
         link != nxt_queue_head(idle);
         link = next)
    {
        next = nxt_queue_next(link);

        c = nxt_queue_link_data(link, nxt_conn_t, link);

        nxt_debug(c->socket.task, "idle connection: %d rdy:%d",
                  c->socket.fd, c->socket.read_ready);

        if (!c->socket.read_ready) {
            nxt_log_moderate(&nxt_idle_close_log_moderation, NXT_LOG_INFO,
                             task->log, "no available connections, "
                             "close idle connection");

            c->read_state->close_handler(c->socket.task, c, c->socket.data);

            times--;

            if (times == 0) {
                break;
            }
        }
    }
}


void
nxt_conn_accept_error(nxt_task_t *task, nxt_listen_event_t *lev,
    const char *accept_syscall, nxt_err_t err)
{
    static nxt_log_moderation_t  nxt_accept_log_moderation = {
        NXT_LOG_INFO, 2, "accept() failed", NXT_LOG_MODERATION
    };

    lev->socket.read_ready = 0;

    switch (err) {

    case NXT_EAGAIN:
        nxt_debug(task, "%s(%d) %E", accept_syscall, lev->socket.fd, err);
        return;

    case ECONNABORTED:
        nxt_log_moderate(&nxt_accept_log_moderation, NXT_LOG_WARN,
                         task->log, "%s(%d) failed %E",
                         accept_syscall, lev->socket.fd, err);
        return;

    case EMFILE:
    case ENFILE:
    case ENOBUFS:
    case ENOMEM:
        nxt_alert(task, "%s(%d) failed %E",
                  accept_syscall, lev->socket.fd, err);

        nxt_conn_accept_close_idle(task, lev);
        return;

    default:
        nxt_alert(task, "%s(%d) failed %E",
                  accept_syscall, lev->socket.fd, err);
        return;
    }
}


static void
nxt_conn_listen_timer_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t          *c;
    nxt_timer_t         *timer;
    nxt_listen_event_t  *lev;

    timer = obj;

    lev = nxt_timer_data(timer, nxt_listen_event_t, timer);

    c = nxt_conn_accept_next(task, lev);
    if (c == NULL) {
        return;
    }

    nxt_fd_event_enable_accept(task->thread->engine, &lev->socket);

    lev->accept(task, lev, c);
}


static void
nxt_conn_listen_event_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_fd_event_t  *ev;

    ev = obj;

    nxt_alert(task, "accept(%d) event error", ev->fd);
}

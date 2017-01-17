
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


static nxt_event_conn_t *nxt_event_conn_accept_alloc(nxt_thread_t *thr,
    nxt_event_conn_listen_t *cls);
static void nxt_event_conn_listen_handler(nxt_thread_t *thr, void *obj,
    void *data);
static nxt_event_conn_t *nxt_event_conn_accept_next(nxt_thread_t *thr,
    nxt_event_conn_listen_t *cls);
static nxt_int_t nxt_event_conn_accept_close_idle(nxt_thread_t *thr,
    nxt_event_conn_listen_t *cls);
static void nxt_event_conn_listen_event_error(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_event_conn_listen_timer_handler(nxt_thread_t *thr, void *obj,
    void *data);


nxt_int_t
nxt_event_conn_listen(nxt_thread_t *thr, nxt_listen_socket_t *ls)
{
    nxt_event_conn_listen_t  *cls;

    cls = nxt_zalloc(sizeof(nxt_event_conn_listen_t));

    if (nxt_fast_path(cls != NULL)) {
        cls->socket.fd = ls->socket;

        cls->batch = thr->engine->batch;

        if (cls->batch != 0) {
            cls->socket.read_work_queue = &thr->engine->accept_work_queue;

        } else {
            cls->socket.read_work_queue = &thr->work_queue.main;
            cls->batch = 1;
        }

        cls->socket.read_handler = nxt_event_conn_listen_handler;
        cls->socket.error_handler = nxt_event_conn_listen_event_error;
        cls->socket.log = &nxt_main_log;

        cls->accept = thr->engine->event->io->accept;

        cls->listen = ls;

        cls->timer.work_queue = &thr->work_queue.main;
        cls->timer.handler = nxt_event_conn_listen_timer_handler;
        cls->timer.log = &nxt_main_log;

        nxt_event_timer_ident(&cls->timer, cls->socket.fd);

        if (nxt_event_conn_accept_alloc(thr, cls) != NULL) {
            nxt_event_fd_enable_accept(thr->engine, &cls->socket);

            nxt_queue_insert_head(&thr->engine->listen_connections, &cls->link);
        }

        return NXT_OK;
    }

    return NXT_ERROR;
}


static nxt_event_conn_t *
nxt_event_conn_accept_alloc(nxt_thread_t *thr, nxt_event_conn_listen_t *cls)
{
    nxt_sockaddr_t       *sa, *remote;
    nxt_mem_pool_t       *mp;
    nxt_event_conn_t     *c;
    nxt_listen_socket_t  *ls;

    if (thr->engine->connections < thr->engine->max_connections) {

        mp = nxt_mem_pool_create(cls->listen->mem_pool_size);

        if (nxt_fast_path(mp != NULL)) {
            /* This allocation cannot fail. */
            c = nxt_event_conn_create(mp, cls->socket.log);

            cls->socket.data = c;
            c->socket.read_work_queue = cls->socket.read_work_queue;
            c->socket.write_ready = 1;

            ls = cls->listen;
            c->listen = ls;

            /* This allocation cannot fail. */
            remote = nxt_sockaddr_alloc(mp, ls->socklen);
            c->remote = remote;

            sa = ls->sockaddr;
            remote->type = sa->type;
            /*
             * Set address family for unspecified Unix domain,
             * because these sockaddr's are not be passed to accept().
             */
            remote->u.sockaddr.sa_family = sa->u.sockaddr.sa_family;

            return c;
        }
    }

    return NULL;
}


static void
nxt_event_conn_listen_handler(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_event_conn_listen_t  *cls;

    cls = obj;
    cls->ready = cls->batch;

    cls->accept(thr, cls, data);
}


void
nxt_event_conn_io_accept(nxt_thread_t *thr, void *obj, void *data)
{
    socklen_t                len;
    nxt_socket_t             s;
    struct sockaddr          *sa;
    nxt_event_conn_t         *c;
    nxt_event_conn_listen_t  *cls;

    cls = obj;
    c = data;

    cls->ready--;
    cls->socket.read_ready = (cls->ready != 0);

    len = nxt_socklen(c->remote);

    if (len >= sizeof(struct sockaddr)) {
        sa = &c->remote->u.sockaddr;

    } else {
        sa = NULL;
        len = 0;
    }

    s = accept(cls->socket.fd, sa, &len);

    if (s == -1) {
        nxt_event_conn_accept_error(thr, cls, "accept", nxt_socket_errno);
        return;
    }

    c->socket.fd = s;

#if (NXT_LINUX)
    /*
     * Linux does not inherit non-blocking mode
     * from listen socket for accept()ed socket.
     */
    if (nxt_slow_path(nxt_socket_nonblocking(s) != NXT_OK)) {
        nxt_socket_close(s);
    }

#endif

    nxt_log_debug(thr->log, "accept(%d): %d", cls->socket.fd, s);

    nxt_event_conn_accept(thr, cls, c);
}


void
nxt_event_conn_accept(nxt_thread_t *thr, nxt_event_conn_listen_t *cls,
    nxt_event_conn_t *c)
{
    nxt_event_conn_t  *next;

    nxt_event_timer_ident(&c->read_timer, c->socket.fd);
    nxt_event_timer_ident(&c->write_timer, c->socket.fd);

    /* This allocation cannot fail. */
    (void) nxt_sockaddr_text(c->mem_pool, c->remote, 0);

    nxt_log_debug(c->socket.log, "client: %*s",
                  c->remote->text_len, c->remote->text);

    nxt_queue_insert_head(&thr->engine->idle_connections, &c->link);

    c->read_work_queue = c->listen->work_queue;
    c->write_work_queue = c->listen->work_queue;

    if (c->listen->read_after_accept) {

        //c->socket.read_ready = 1;
        thr->log = c->socket.log;
        c->listen->handler(thr, c, NULL);
        thr->log = cls->socket.log;

    } else {
        nxt_thread_work_queue_add(thr, c->write_work_queue,
                                  c->listen->handler, c, NULL, c->socket.log);
    }

    next = nxt_event_conn_accept_next(thr, cls);

    if (next != NULL && cls->socket.read_ready) {
        nxt_thread_work_queue_add(thr, cls->socket.read_work_queue,
                                  cls->accept, cls, next, cls->socket.log);
    }
}


static nxt_event_conn_t *
nxt_event_conn_accept_next(nxt_thread_t *thr, nxt_event_conn_listen_t *cls)
{
    nxt_event_conn_t  *c;

    cls->socket.data = NULL;

    do {
        c = nxt_event_conn_accept_alloc(thr, cls);

        if (nxt_fast_path(c != NULL)) {
            return c;
        }

    } while (nxt_event_conn_accept_close_idle(thr, cls) == NXT_OK);

    nxt_log_alert(cls->socket.log, "no available connections, "
                  "new connections are not accepted within 1s");

    return NULL;
}


static nxt_int_t
nxt_event_conn_accept_close_idle(nxt_thread_t *thr,
    nxt_event_conn_listen_t *cls)
{
    nxt_queue_t       *idle;
    nxt_queue_link_t  *link;
    nxt_event_conn_t  *c;

    static nxt_log_moderation_t  nxt_idle_close_log_moderation = {
        NXT_LOG_INFO, 2, "idle connections closed", NXT_LOG_MODERATION
    };

    idle = &thr->engine->idle_connections;

    for (link = nxt_queue_last(idle);
         link != nxt_queue_head(idle);
         link = nxt_queue_next(link))
    {
        c = nxt_queue_link_data(link, nxt_event_conn_t, link);

        if (!c->socket.read_ready) {
            nxt_log_moderate(&nxt_idle_close_log_moderation, NXT_LOG_INFO,
                             thr->log, "no available connections, "
                             "close idle connection");
            nxt_queue_remove(link);
            nxt_event_conn_close(thr, c);

            return NXT_OK;
        }
    }

    nxt_event_timer_add(thr->engine, &cls->timer, 1000);
    nxt_event_fd_disable_read(thr->engine, &cls->socket);

    return NXT_DECLINED;
}


void
nxt_event_conn_accept_error(nxt_thread_t *thr, nxt_event_conn_listen_t *cls,
    const char *accept_syscall, nxt_err_t err)
{
    static nxt_log_moderation_t  nxt_accept_log_moderation = {
        NXT_LOG_INFO, 2, "accept() failed", NXT_LOG_MODERATION
    };

    cls->socket.read_ready = 0;

    switch (err) {

    case NXT_EAGAIN:
        nxt_log_debug(thr->log, "%s(%d) %E",
                      accept_syscall, cls->socket.fd, err);
        return;

    case ECONNABORTED:
        nxt_log_moderate(&nxt_accept_log_moderation, NXT_LOG_INFO,
                         thr->log, "%s(%d) failed %E",
                         accept_syscall, cls->socket.fd, err);
        return;

    case EMFILE:
    case ENFILE:
    case ENOBUFS:
    case ENOMEM:
        if (nxt_event_conn_accept_close_idle(thr, cls) != NXT_OK) {
            nxt_log_alert(thr->log, "%s(%d) failed %E, "
                          "new connections are not accepted within 1s",
                          accept_syscall, cls->socket.fd, err);
        }

        return;

    default:
        nxt_log_alert(thr->log, "%s(%d) failed %E",
                      accept_syscall, cls->socket.fd, err);
        return;
    }
}


static void
nxt_event_conn_listen_timer_handler(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_event_conn_t         *c;
    nxt_event_timer_t        *ev;
    nxt_event_conn_listen_t  *cls;

    ev = obj;

    cls = nxt_event_timer_data(ev, nxt_event_conn_listen_t, timer);
    c = cls->socket.data;

    if (c == NULL) {
        c = nxt_event_conn_accept_next(thr, cls);

        if (c == NULL) {
            return;
        }
    }

    nxt_event_fd_enable_accept(thr->engine, &cls->socket);

    cls->accept(thr, cls, c);
}


static void
nxt_event_conn_listen_event_error(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_event_fd_t  *ev;

    ev = obj;

    nxt_log_alert(thr->log, "accept(%d) event error", ev->fd);
}

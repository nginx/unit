
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static nxt_event_set_t *nxt_select_create(nxt_event_signals_t *signals,
    nxt_uint_t mchanges, nxt_uint_t mevents);
static void nxt_select_free(nxt_event_set_t *event_set);
static void nxt_select_enable(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_select_disable(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_select_enable_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_select_enable_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_select_error_handler(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_select_disable_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_select_disable_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_select_block_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_select_block_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_select_oneshot_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_select_oneshot_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_select_poll(nxt_thread_t *thr, nxt_event_set_t *event_set,
    nxt_msec_t timeout);


const nxt_event_set_ops_t  nxt_select_event_set = {
    "select",
    nxt_select_create,
    nxt_select_free,
    nxt_select_enable,
    nxt_select_disable,
    nxt_select_disable,
    nxt_select_disable,
    nxt_select_enable_read,
    nxt_select_enable_write,
    nxt_select_disable_read,
    nxt_select_disable_write,
    nxt_select_block_read,
    nxt_select_block_write,
    nxt_select_oneshot_read,
    nxt_select_oneshot_write,
    nxt_select_enable_read,
    NULL,
    NULL,
    NULL,
    NULL,
    nxt_select_poll,

    &nxt_unix_event_conn_io,

    NXT_NO_FILE_EVENTS,
    NXT_NO_SIGNAL_EVENTS,
};


static nxt_event_set_t *
nxt_select_create(nxt_event_signals_t *signals, nxt_uint_t mchanges,
    nxt_uint_t mevents)
{
    nxt_event_set_t         *event_set;
    nxt_select_event_set_t  *ss;

    event_set = nxt_zalloc(sizeof(nxt_select_event_set_t));
    if (event_set == NULL) {
        return NULL;
    }

    ss = &event_set->select;

    ss->nfds = -1;
    ss->update_nfds = 0;

    ss->events = nxt_zalloc(FD_SETSIZE * sizeof(nxt_event_fd_t *));
    if (ss->events != NULL) {
        return event_set;
    }

    nxt_select_free(event_set);

    return NULL;
}


static void
nxt_select_free(nxt_event_set_t *event_set)
{
    nxt_select_event_set_t  *ss;

    nxt_main_log_debug("select free");

    ss = &event_set->select;

    nxt_free(ss->events);
    nxt_free(ss);
}


static void
nxt_select_enable(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_select_enable_read(event_set, ev);
    nxt_select_enable_write(event_set, ev);
}


static void
nxt_select_disable(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        nxt_select_disable_read(event_set, ev);
    }

    if (ev->write != NXT_EVENT_INACTIVE) {
        nxt_select_disable_write(event_set, ev);
    }
}


static void
nxt_select_enable_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_fd_t                fd;
    nxt_thread_t            *thr;
    nxt_select_event_set_t  *ss;

    fd = ev->fd;

    nxt_log_debug(ev->log, "select enable read: fd:%d", fd);

    ss = &event_set->select;

    if (fd < 0 || fd >= (nxt_fd_t) FD_SETSIZE) {
        thr = nxt_thread();
        nxt_thread_work_queue_add(thr, &thr->work_queue.main,
                                  nxt_select_error_handler,
                                  ev, ev->data, ev->log);
        return;
    }

    ev->read = NXT_EVENT_DEFAULT;

    FD_SET(fd, &ss->main_read_fd_set);
    ss->events[fd] = ev;

    if (ss->nfds < fd) {
        ss->nfds = fd;
        ss->update_nfds = 0;
    }
}


static void
nxt_select_enable_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_fd_t                fd;
    nxt_thread_t            *thr;
    nxt_select_event_set_t  *ss;

    fd = ev->fd;

    nxt_log_debug(ev->log, "select enable write: fd:%d", fd);

    ss = &event_set->select;

    if (fd < 0 || fd >= (nxt_fd_t) FD_SETSIZE) {
        thr = nxt_thread();
        nxt_thread_work_queue_add(thr, &thr->work_queue.main,
                                  nxt_select_error_handler,
                                  ev, ev->data, ev->log);
        return;
    }

    ev->write = NXT_EVENT_DEFAULT;

    FD_SET(fd, &ss->main_write_fd_set);
    ss->events[fd] = ev;

    if (ss->nfds < fd) {
        ss->nfds = fd;
        ss->update_nfds = 0;
    }
}


static void
nxt_select_error_handler(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_event_fd_t  *ev;

    ev = obj;

    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;

    ev->error_handler(thr, ev, data);
}


static void
nxt_select_disable_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_fd_t                fd;
    nxt_select_event_set_t  *ss;

    fd = ev->fd;

    nxt_log_debug(ev->log, "select disable read: fd:%d", fd);

    if (fd < 0 || fd >= (nxt_fd_t) FD_SETSIZE) {
        return;
    }

    ss = &event_set->select;
    FD_CLR(fd, &ss->main_read_fd_set);

    ev->read = NXT_EVENT_INACTIVE;

    if (ev->write == NXT_EVENT_INACTIVE) {
        ss->events[fd] = NULL;
        ss->update_nfds = 1;
    }
}


static void
nxt_select_disable_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_fd_t                fd;
    nxt_select_event_set_t  *ss;

    fd = ev->fd;

    nxt_log_debug(ev->log, "select disable write: fd:%d", fd);

    if (fd < 0 || fd >= (nxt_fd_t) FD_SETSIZE) {
        return;
    }

    ss = &event_set->select;
    FD_CLR(fd, &ss->main_write_fd_set);

    ev->write = NXT_EVENT_INACTIVE;

    if (ev->read == NXT_EVENT_INACTIVE) {
        ss->events[fd] = NULL;
        ss->update_nfds = 1;
    }
}


static void
nxt_select_block_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        nxt_select_disable_read(event_set, ev);
    }
}


static void
nxt_select_block_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->write != NXT_EVENT_INACTIVE) {
        nxt_select_disable_write(event_set, ev);
    }
}


static void
nxt_select_oneshot_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_select_enable_read(event_set, ev);

    ev->read = NXT_EVENT_ONESHOT;
}


static void
nxt_select_oneshot_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_select_enable_write(event_set, ev);

    ev->write = NXT_EVENT_ONESHOT;
}


static void
nxt_select_poll(nxt_thread_t *thr, nxt_event_set_t *event_set,
    nxt_msec_t timeout)
{
    int                     nevents, nfds, found;
    nxt_err_t               err;
    nxt_int_t               i;
    nxt_uint_t              fd, level;
    nxt_event_fd_t          *ev;
    struct timeval          tv, *tp;
    nxt_select_event_set_t  *ss;

    if (timeout == NXT_INFINITE_MSEC) {
        tp = NULL;

    } else {
        tv.tv_sec = (long) (timeout / 1000);
        tv.tv_usec = (long) ((timeout % 1000) * 1000);
        tp = &tv;
    }

    ss = &event_set->select;

    if (ss->update_nfds) {
        for (i = ss->nfds; i >= 0; i--) {
            if (ss->events[i] != NULL) {
                ss->nfds = i;
                ss->update_nfds = 0;
                break;
            }
        }
    }

    ss->work_read_fd_set = ss->main_read_fd_set;
    ss->work_write_fd_set = ss->main_write_fd_set;

    nfds = ss->nfds + 1;

    nxt_log_debug(thr->log, "select() nfds:%d timeout:%M", nfds, timeout);

    nevents = select(nfds, &ss->work_read_fd_set, &ss->work_write_fd_set,
                     NULL, tp);

    err = (nevents == -1) ? nxt_errno : 0;

    nxt_thread_time_update(thr);

    nxt_log_debug(thr->log, "select(): %d", nevents);

    if (nevents == -1) {
        level = (err == NXT_EINTR) ? NXT_LOG_INFO : NXT_LOG_ALERT;
        nxt_log_error(level, thr->log, "select() failed %E", err);
        return;
    }

    for (fd = 0; fd < (nxt_uint_t) nfds && nevents != 0; fd++) {

        found = 0;

        if (FD_ISSET(fd, &ss->work_read_fd_set)) {
            ev = ss->events[fd];

            nxt_log_debug(ev->log, "select() fd:%ui read rd:%d wr:%d",
                          fd, ev->read, ev->write);

            ev->read_ready = 1;

            if (ev->read == NXT_EVENT_ONESHOT) {
                nxt_select_disable_read(event_set, ev);
            }

            nxt_thread_work_queue_add(thr, ev->read_work_queue,
                                      ev->read_handler, ev, ev->data, ev->log);
            found = 1;
        }

        if (FD_ISSET(fd, &ss->work_write_fd_set)) {
            ev = ss->events[fd];

            nxt_log_debug(ev->log, "select() fd:%ui write rd:%d wr:%d",
                          fd, ev->read, ev->write);

            ev->write_ready = 1;

            if (ev->write == NXT_EVENT_ONESHOT) {
                nxt_select_disable_write(event_set, ev);
            }

            nxt_thread_work_queue_add(thr, ev->write_work_queue,
                                      ev->write_handler, ev, ev->data, ev->log);
            found = 1;
        }

        nevents -= found;
    }
}

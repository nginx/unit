
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static nxt_int_t nxt_select_create(nxt_event_engine_t *engine,
    nxt_uint_t mchanges, nxt_uint_t mevents);
static void nxt_select_free(nxt_event_engine_t *engine);
static void nxt_select_enable(nxt_event_engine_t *engine, nxt_fd_event_t *ev);
static void nxt_select_disable(nxt_event_engine_t *engine, nxt_fd_event_t *ev);
static nxt_bool_t nxt_select_close(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_select_enable_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_select_enable_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_select_error_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_select_disable_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_select_disable_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_select_block_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_select_block_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_select_oneshot_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_select_oneshot_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_select_poll(nxt_event_engine_t *engine, nxt_msec_t timeout);


const nxt_event_interface_t  nxt_select_engine = {
    "select",
    nxt_select_create,
    nxt_select_free,
    nxt_select_enable,
    nxt_select_disable,
    nxt_select_disable,
    nxt_select_close,
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

    &nxt_unix_conn_io,

    NXT_NO_FILE_EVENTS,
    NXT_NO_SIGNAL_EVENTS,
};


static nxt_int_t
nxt_select_create(nxt_event_engine_t *engine, nxt_uint_t mchanges,
    nxt_uint_t mevents)
{
    engine->u.select.nfds = -1;
    engine->u.select.update_nfds = 0;

    engine->u.select.events = nxt_zalloc(FD_SETSIZE * sizeof(nxt_fd_event_t *));

    if (engine->u.select.events != NULL) {
        return NXT_OK;
    }

    nxt_select_free(engine);

    return NXT_ERROR;
}


static void
nxt_select_free(nxt_event_engine_t *engine)
{
    nxt_debug(&engine->task, "select free");

    nxt_free(engine->u.select.events);

    nxt_memzero(&engine->u.select, sizeof(nxt_select_engine_t));
}


static void
nxt_select_enable(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_select_enable_read(engine, ev);
    nxt_select_enable_write(engine, ev);
}


static void
nxt_select_disable(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        nxt_select_disable_read(engine, ev);
    }

    if (ev->write != NXT_EVENT_INACTIVE) {
        nxt_select_disable_write(engine, ev);
    }
}


static nxt_bool_t
nxt_select_close(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_select_disable(engine, ev);

    return 0;
}


static void
nxt_select_enable_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_fd_t  fd;

    fd = ev->fd;

    nxt_debug(ev->task, "select enable read: fd:%d", fd);

    if (fd < 0 || fd >= (nxt_fd_t) FD_SETSIZE) {
        nxt_work_queue_add(&engine->fast_work_queue, nxt_select_error_handler,
                           ev->task, ev, ev->data);
        return;
    }

    ev->read = NXT_EVENT_ACTIVE;

    FD_SET(fd, &engine->u.select.main_read_fd_set);
    engine->u.select.events[fd] = ev;

    if (engine->u.select.nfds < fd) {
        engine->u.select.nfds = fd;
        engine->u.select.update_nfds = 0;
    }
}


static void
nxt_select_enable_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_fd_t  fd;

    fd = ev->fd;

    nxt_debug(ev->task, "select enable write: fd:%d", fd);

    if (fd < 0 || fd >= (nxt_fd_t) FD_SETSIZE) {
        nxt_work_queue_add(&engine->fast_work_queue, nxt_select_error_handler,
                           ev->task, ev, ev->data);
        return;
    }

    ev->write = NXT_EVENT_ACTIVE;

    FD_SET(fd, &engine->u.select.main_write_fd_set);
    engine->u.select.events[fd] = ev;

    if (engine->u.select.nfds < fd) {
        engine->u.select.nfds = fd;
        engine->u.select.update_nfds = 0;
    }
}


static void
nxt_select_error_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_fd_event_t  *ev;

    ev = obj;

    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;

    ev->error_handler(task, ev, data);
}


static void
nxt_select_disable_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_fd_t  fd;

    fd = ev->fd;

    nxt_debug(ev->task, "select disable read: fd:%d", fd);

    if (fd < 0 || fd >= (nxt_fd_t) FD_SETSIZE) {
        return;
    }

    FD_CLR(fd, &engine->u.select.main_read_fd_set);

    ev->read = NXT_EVENT_INACTIVE;

    if (ev->write == NXT_EVENT_INACTIVE) {
        engine->u.select.events[fd] = NULL;
        engine->u.select.update_nfds = 1;
    }
}


static void
nxt_select_disable_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_fd_t  fd;

    fd = ev->fd;

    nxt_debug(ev->task, "select disable write: fd:%d", fd);

    if (fd < 0 || fd >= (nxt_fd_t) FD_SETSIZE) {
        return;
    }

    FD_CLR(fd, &engine->u.select.main_write_fd_set);

    ev->write = NXT_EVENT_INACTIVE;

    if (ev->read == NXT_EVENT_INACTIVE) {
        engine->u.select.events[fd] = NULL;
        engine->u.select.update_nfds = 1;
    }
}


static void
nxt_select_block_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        nxt_select_disable_read(engine, ev);
    }
}


static void
nxt_select_block_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->write != NXT_EVENT_INACTIVE) {
        nxt_select_disable_write(engine, ev);
    }
}


static void
nxt_select_oneshot_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_select_enable_read(engine, ev);

    ev->read = NXT_EVENT_ONESHOT;
}


static void
nxt_select_oneshot_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_select_enable_write(engine, ev);

    ev->write = NXT_EVENT_ONESHOT;
}


static void
nxt_select_poll(nxt_event_engine_t *engine, nxt_msec_t timeout)
{
    int             nevents, nfds, found;
    nxt_err_t       err;
    nxt_int_t       i;
    nxt_uint_t      fd, level;
    nxt_fd_event_t  *ev;
    struct timeval  tv, *tp;

    if (timeout == NXT_INFINITE_MSEC) {
        tp = NULL;

    } else {
        tv.tv_sec = (long) (timeout / 1000);
        tv.tv_usec = (long) ((timeout % 1000) * 1000);
        tp = &tv;
    }

    if (engine->u.select.update_nfds) {
        for (i = engine->u.select.nfds; i >= 0; i--) {
            if (engine->u.select.events[i] != NULL) {
                engine->u.select.nfds = i;
                engine->u.select.update_nfds = 0;
                break;
            }
        }
    }

    engine->u.select.work_read_fd_set = engine->u.select.main_read_fd_set;
    engine->u.select.work_write_fd_set = engine->u.select.main_write_fd_set;

    nfds = engine->u.select.nfds + 1;

    nxt_debug(&engine->task, "select() nfds:%d timeout:%M", nfds, timeout);

    nevents = select(nfds, &engine->u.select.work_read_fd_set,
                     &engine->u.select.work_write_fd_set, NULL, tp);

    err = (nevents == -1) ? nxt_errno : 0;

    nxt_thread_time_update(engine->task.thread);

    nxt_debug(&engine->task, "select(): %d", nevents);

    if (nevents == -1) {
        level = (err == NXT_EINTR) ? NXT_LOG_INFO : NXT_LOG_ALERT;
        nxt_log(&engine->task, level, "select() failed %E", err);
        return;
    }

    for (fd = 0; fd < (nxt_uint_t) nfds && nevents != 0; fd++) {

        found = 0;

        if (FD_ISSET(fd, &engine->u.select.work_read_fd_set)) {
            ev = engine->u.select.events[fd];

            nxt_debug(ev->task, "select() fd:%ui read rd:%d wr:%d",
                      fd, ev->read, ev->write);

            ev->read_ready = 1;

            if (ev->read == NXT_EVENT_ONESHOT) {
                nxt_select_disable_read(engine, ev);
            }

            nxt_work_queue_add(ev->read_work_queue, ev->read_handler,
                               ev->task, ev, ev->data);
            found = 1;
        }

        if (FD_ISSET(fd, &engine->u.select.work_write_fd_set)) {
            ev = engine->u.select.events[fd];

            nxt_debug(ev->task, "select() fd:%ui write rd:%d wr:%d",
                      fd, ev->read, ev->write);

            ev->write_ready = 1;

            if (ev->write == NXT_EVENT_ONESHOT) {
                nxt_select_disable_write(engine, ev);
            }

            nxt_work_queue_add(ev->write_work_queue, ev->write_handler,
                               ev->task, ev, ev->data);
            found = 1;
        }

        nevents -= found;
    }
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * The event ports have been introduced in Solaris 10.
 * The PORT_SOURCE_MQ and PORT_SOURCE_FILE sources have
 * been added in OpenSolaris.
 */


static nxt_int_t nxt_eventport_create(nxt_event_engine_t *engine,
    nxt_uint_t mchanges, nxt_uint_t mevents);
static void nxt_eventport_free(nxt_event_engine_t *engine);
static void nxt_eventport_enable(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_eventport_disable(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static nxt_bool_t nxt_eventport_close(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_eventport_enable_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_eventport_enable_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_eventport_enable_event(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev, nxt_uint_t events);
static void nxt_eventport_disable_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_eventport_disable_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_eventport_disable_event(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static nxt_int_t nxt_eventport_commit_changes(nxt_event_engine_t *engine);
static void nxt_eventport_error_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_eventport_block_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_eventport_block_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_eventport_oneshot_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_eventport_oneshot_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_eventport_enable_accept(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static nxt_int_t nxt_eventport_enable_post(nxt_event_engine_t *engine,
    nxt_work_handler_t handler);
static void nxt_eventport_signal(nxt_event_engine_t *engine, nxt_uint_t signo);
static void nxt_eventport_poll(nxt_event_engine_t *engine,
    nxt_msec_t timeout);


const nxt_event_interface_t  nxt_eventport_engine = {
    "eventport",
    nxt_eventport_create,
    nxt_eventport_free,
    nxt_eventport_enable,
    nxt_eventport_disable,
    nxt_eventport_disable,
    nxt_eventport_close,
    nxt_eventport_enable_read,
    nxt_eventport_enable_write,
    nxt_eventport_disable_read,
    nxt_eventport_disable_write,
    nxt_eventport_block_read,
    nxt_eventport_block_write,
    nxt_eventport_oneshot_read,
    nxt_eventport_oneshot_write,
    nxt_eventport_enable_accept,
    NULL,
    NULL,
    nxt_eventport_enable_post,
    nxt_eventport_signal,
    nxt_eventport_poll,

    &nxt_unix_conn_io,

    NXT_NO_FILE_EVENTS,
    NXT_NO_SIGNAL_EVENTS,
};


static nxt_int_t
nxt_eventport_create(nxt_event_engine_t *engine, nxt_uint_t mchanges,
    nxt_uint_t mevents)
{
    nxt_eventport_change_t  *changes;

    engine->u.eventport.fd = -1;
    engine->u.eventport.mchanges = mchanges;
    engine->u.eventport.mevents = mevents;

    changes = nxt_malloc(sizeof(nxt_eventport_change_t) * mchanges);
    if (changes == NULL) {
        goto fail;
    }

    engine->u.eventport.changes = changes;

    engine->u.eventport.events = nxt_malloc(sizeof(port_event_t) * mevents);
    if (engine->u.eventport.events == NULL) {
        goto fail;
    }

    engine->u.eventport.fd = port_create();
    if (engine->u.eventport.fd == -1) {
        nxt_alert(&engine->task, "port_create() failed %E", nxt_errno);
        goto fail;
    }

    nxt_debug(&engine->task, "port_create(): %d", engine->u.eventport.fd);

    if (engine->signals != NULL) {
        engine->u.eventport.signal_handler = engine->signals->handler;
    }

    return NXT_OK;

fail:

    nxt_eventport_free(engine);

    return NXT_ERROR;
}


static void
nxt_eventport_free(nxt_event_engine_t *engine)
{
    int  port;

    port = engine->u.eventport.fd;

    nxt_debug(&engine->task, "eventport %d free", port);

    if (port != -1 && close(port) != 0) {
        nxt_alert(&engine->task, "eventport close(%d) failed %E",
                  port, nxt_errno);
    }

    nxt_free(engine->u.eventport.events);

    nxt_memzero(&engine->u.eventport, sizeof(nxt_eventport_engine_t));
}


static void
nxt_eventport_enable(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    ev->read = NXT_EVENT_ACTIVE;
    ev->write = NXT_EVENT_ACTIVE;

    nxt_eventport_enable_event(engine, ev, POLLIN | POLLOUT);
}


static void
nxt_eventport_disable(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE || ev->write != NXT_EVENT_INACTIVE) {

        ev->read = NXT_EVENT_INACTIVE;
        ev->write = NXT_EVENT_INACTIVE;

        nxt_eventport_disable_event(engine, ev);
    }
}


/*
 * port_dissociate(3):
 *
 *   The association is removed if the owner of the association closes the port.
 */

static nxt_bool_t
nxt_eventport_close(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;

    return ev->changing;
}


static void
nxt_eventport_enable_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_uint_t  events;

    if (ev->read != NXT_EVENT_BLOCKED) {
        events = (ev->write == NXT_EVENT_INACTIVE) ? POLLIN
                                                   : (POLLIN | POLLOUT);
        nxt_eventport_enable_event(engine, ev, events);
    }

    ev->read = NXT_EVENT_ACTIVE;
}


static void
nxt_eventport_enable_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_uint_t  events;

    if (ev->write != NXT_EVENT_BLOCKED) {
        events = (ev->read == NXT_EVENT_INACTIVE) ? POLLOUT
                                                  : (POLLIN | POLLOUT);
        nxt_eventport_enable_event(engine, ev, events);
    }

    ev->write = NXT_EVENT_ACTIVE;
}


/*
 * eventport changes are batched to improve instruction and data
 * cache locality of several port_associate() and port_dissociate()
 * calls followed by port_getn() call.
 */

static void
nxt_eventport_enable_event(nxt_event_engine_t *engine, nxt_fd_event_t *ev,
    nxt_uint_t events)
{
    nxt_eventport_change_t  *change;

    nxt_debug(ev->task, "port %d set event: fd:%d ev:%04XD u:%p",
              engine->u.eventport.fd, ev->fd, events, ev);

    if (engine->u.eventport.nchanges >= engine->u.eventport.mchanges) {
        (void) nxt_eventport_commit_changes(engine);
    }

    ev->changing = 1;

    change = &engine->u.eventport.changes[engine->u.eventport.nchanges++];
    change->events = events;
    change->event = ev;
}


static void
nxt_eventport_disable_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    ev->read = NXT_EVENT_INACTIVE;

    if (ev->write == NXT_EVENT_INACTIVE) {
        nxt_eventport_disable_event(engine, ev);

    } else {
        nxt_eventport_enable_event(engine, ev, POLLOUT);
    }
}


static void
nxt_eventport_disable_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    ev->write = NXT_EVENT_INACTIVE;

    if (ev->read == NXT_EVENT_INACTIVE) {
        nxt_eventport_disable_event(engine, ev);

    } else {
        nxt_eventport_enable_event(engine, ev, POLLIN);
    }
}


static void
nxt_eventport_disable_event(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_eventport_change_t  *change;

    nxt_debug(ev->task, "port %d disable event : fd:%d",
              engine->u.eventport.fd, ev->fd);

    if (engine->u.eventport.nchanges >= engine->u.eventport.mchanges) {
        (void) nxt_eventport_commit_changes(engine);
    }

    ev->changing = 1;

    change = &engine->u.eventport.changes[engine->u.eventport.nchanges++];
    change->events = 0;
    change->event = ev;
}


static nxt_int_t
nxt_eventport_commit_changes(nxt_event_engine_t *engine)
{
    int                     ret, port;
    nxt_int_t               retval;
    nxt_fd_event_t          *ev;
    nxt_eventport_change_t  *change, *end;

    port = engine->u.eventport.fd;

    nxt_debug(&engine->task, "eventport %d changes:%ui",
              port, engine->u.eventport.nchanges);

    retval = NXT_OK;
    change = engine->u.eventport.changes;
    end = change + engine->u.eventport.nchanges;

    do {
        ev = change->event;
        ev->changing = 0;

        if (change->events != 0) {
            nxt_debug(ev->task, "port_associate(%d): fd:%d ev:%04XD u:%p",
                      port, ev->fd, change->events, ev);

            ret = port_associate(port, PORT_SOURCE_FD,
                                 ev->fd, change->events, ev);

            if (nxt_fast_path(ret == 0)) {
                goto next;
            }

            nxt_alert(ev->task, "port_associate(%d, %d, %d, %04XD) failed %E",
                      port, PORT_SOURCE_FD, ev->fd, change->events, nxt_errno);

        } else {
            nxt_debug(ev->task, "port_dissociate(%d): fd:%d", port, ev->fd);

            ret = port_dissociate(port, PORT_SOURCE_FD, ev->fd);

            if (nxt_fast_path(ret == 0)) {
                goto next;
            }

            nxt_alert(ev->task, "port_dissociate(%d, %d, %d) failed %E",
                      port, PORT_SOURCE_FD, ev->fd, nxt_errno);
        }

        nxt_work_queue_add(&engine->fast_work_queue,
                           nxt_eventport_error_handler,
                           ev->task, ev, ev->data);

        retval = NXT_ERROR;

    next:

        change++;

    } while (change < end);

    engine->u.eventport.nchanges = 0;

    return retval;
}


static void
nxt_eventport_error_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_fd_event_t  *ev;

    ev = obj;

    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;

    ev->error_handler(task, ev, data);
}


static void
nxt_eventport_block_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_eventport_block_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->write != NXT_EVENT_INACTIVE) {
        ev->write = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_eventport_oneshot_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read == NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_ACTIVE;

        nxt_eventport_enable_event(engine, ev, POLLIN);
    }
}


static void
nxt_eventport_oneshot_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->write == NXT_EVENT_INACTIVE) {
        ev->write = NXT_EVENT_ACTIVE;

        nxt_eventport_enable_event(engine, ev, POLLOUT);
    }
}


static void
nxt_eventport_enable_accept(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    ev->read = NXT_EVENT_LEVEL;

    nxt_eventport_enable_event(engine, ev, POLLIN);
}


static nxt_int_t
nxt_eventport_enable_post(nxt_event_engine_t *engine,
    nxt_work_handler_t handler)
{
    engine->u.eventport.post_handler = handler;

    return NXT_OK;
}


static void
nxt_eventport_signal(nxt_event_engine_t *engine, nxt_uint_t signo)
{
    int  port;

    port = engine->u.eventport.fd;

    nxt_debug(&engine->task, "port_send(%d, %ui)", port, signo);

    if (port_send(port, signo, NULL) != 0) {
        nxt_alert(&engine->task, "port_send(%d) failed %E", port, nxt_errno);
    }
}


static void
nxt_eventport_poll(nxt_event_engine_t *engine, nxt_msec_t timeout)
{
    int                 n, events, signo;
    uint_t              nevents;
    nxt_err_t           err;
    nxt_uint_t          i, level;
    timespec_t          ts, *tp;
    port_event_t        *event;
    nxt_fd_event_t      *ev;
    nxt_work_handler_t  handler;

    if (engine->u.eventport.nchanges != 0) {
        if (nxt_eventport_commit_changes(engine) != NXT_OK) {
            /* Error handlers have been enqueued on failure. */
            timeout = 0;
        }
    }

    if (timeout == NXT_INFINITE_MSEC) {
        tp = NULL;

    } else {
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000000;
        tp = &ts;
    }

    nxt_debug(&engine->task, "port_getn(%d) timeout: %M",
              engine->u.eventport.fd, timeout);

    /*
     * A trap for possible error when Solaris does not update nevents
     * if ETIME or EINTR is returned.  This issue will be logged as
     * "unexpected port_getn() event".
     *
     * The details are in OpenSolaris mailing list thread "port_getn()
     * and timeouts - is this a bug or an undocumented feature?"
     */
    event = &engine->u.eventport.events[0];
    event->portev_events = -1; /* invalid port events */
    event->portev_source = -1; /* invalid port source */
    event->portev_object = -1;
    event->portev_user = (void *) -1;

    nevents = 1;
    n = port_getn(engine->u.eventport.fd, engine->u.eventport.events,
                  engine->u.eventport.mevents, &nevents, tp);

    /*
     * 32-bit port_getn() on Solaris 10 x86 returns large negative
     * values instead of 0 when returning immediately.
     */
    err = (n < 0) ? nxt_errno : 0;

    nxt_thread_time_update(engine->task.thread);

    if (n == -1) {
        if (err == NXT_ETIME || err == NXT_EINTR) {
            if (nevents != 0) {
                nxt_alert(&engine->task, "port_getn(%d) failed %E, events:%ud",
                          engine->u.eventport.fd, err, nevents);
            }
        }

        if (err != NXT_ETIME) {
            level = (err == NXT_EINTR) ? NXT_LOG_INFO : NXT_LOG_ALERT;

            nxt_log(&engine->task, level, "port_getn(%d) failed %E",
                    engine->u.eventport.fd, err);

            if (err != NXT_EINTR) {
                return;
            }
        }
    }

    nxt_debug(&engine->task, "port_getn(%d) events: %d",
              engine->u.eventport.fd, nevents);

    for (i = 0; i < nevents; i++) {
        event = &engine->u.eventport.events[i];

        switch (event->portev_source) {

        case PORT_SOURCE_FD:
            ev = event->portev_user;
            events = event->portev_events;

            nxt_debug(ev->task, "eventport: fd:%d ev:%04Xd u:%p rd:%d wr:%d",
                      event->portev_object, events, ev, ev->read, ev->write);

            if (nxt_slow_path(events & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                nxt_alert(ev->task, "port_getn(%d) error fd:%d events:%04Xud",
                          engine->u.eventport.fd, ev->fd, events);

                nxt_work_queue_add(&engine->fast_work_queue,
                                   nxt_eventport_error_handler,
                                   ev->task, ev, ev->data);
                continue;
            }

            if (events & POLLIN) {
                ev->read_ready = 1;

                if (ev->read != NXT_EVENT_BLOCKED) {
                    nxt_work_queue_add(ev->read_work_queue, ev->read_handler,
                                       ev->task, ev, ev->data);

                }

                if (ev->read != NXT_EVENT_LEVEL) {
                    ev->read = NXT_EVENT_INACTIVE;
                }
            }

            if (events & POLLOUT) {
                ev->write_ready = 1;

                if (ev->write != NXT_EVENT_BLOCKED) {
                    nxt_work_queue_add(ev->write_work_queue, ev->write_handler,
                                       ev->task, ev, ev->data);
                }

                ev->write = NXT_EVENT_INACTIVE;
            }

            /*
             * Reactivate counterpart direction, because the
             * eventport is oneshot notification facility.
             */
            events = (ev->read == NXT_EVENT_INACTIVE) ? 0 : POLLIN;
            events |= (ev->write == NXT_EVENT_INACTIVE) ? 0 : POLLOUT;

            if (events != 0) {
                nxt_eventport_enable_event(engine, ev, events);
            }

            break;

        case PORT_SOURCE_USER:
            nxt_debug(&engine->task, "eventport: user ev:%d u:%p",
                      event->portev_events, event->portev_user);

            signo = event->portev_events;

            handler = (signo == 0) ? engine->u.eventport.post_handler
                                   : engine->u.eventport.signal_handler;

            nxt_work_queue_add(&engine->fast_work_queue, handler,
                               &engine->task, (void *) (uintptr_t) signo, NULL);

            break;

        default:
            nxt_alert(&engine->task,
                      "unexpected port_getn(%d) event: "
                      "ev:%d src:%d obj:%p u:%p",
                      engine->u.eventport.fd, event->portev_events,
                      event->portev_source, event->portev_object,
                      event->portev_user);
        }
    }
}

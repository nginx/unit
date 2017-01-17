
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


static nxt_event_set_t *nxt_eventport_create(nxt_event_signals_t *signals,
    nxt_uint_t mchanges, nxt_uint_t mevents);
static void nxt_eventport_free(nxt_event_set_t *event_set);
static void nxt_eventport_enable(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_eventport_disable(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_eventport_close(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_eventport_drop_changes(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_eventport_enable_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_eventport_enable_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_eventport_enable_event(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev, nxt_uint_t events);
static void nxt_eventport_disable_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_eventport_disable_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_eventport_disable_event(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static nxt_int_t nxt_eventport_commit_changes(nxt_thread_t *thr,
    nxt_eventport_event_set_t *es);
static void nxt_eventport_error_handler(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_eventport_block_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_eventport_block_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_eventport_oneshot_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_eventport_oneshot_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_eventport_enable_accept(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static nxt_int_t nxt_eventport_enable_post(nxt_event_set_t *event_set,
    nxt_work_handler_t handler);
static void nxt_eventport_signal(nxt_event_set_t *event_set, nxt_uint_t signo);
static void nxt_eventport_poll(nxt_thread_t *thr, nxt_event_set_t *event_set,
    nxt_msec_t timeout);


const nxt_event_set_ops_t  nxt_eventport_event_set = {
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

    &nxt_unix_event_conn_io,

    NXT_NO_FILE_EVENTS,
    NXT_NO_SIGNAL_EVENTS,
};


static nxt_event_set_t *
nxt_eventport_create(nxt_event_signals_t *signals, nxt_uint_t mchanges,
    nxt_uint_t mevents)
{
    nxt_event_set_t            *event_set;
    nxt_eventport_event_set_t  *es;

    event_set = nxt_zalloc(sizeof(nxt_eventport_event_set_t));
    if (event_set == NULL) {
        return NULL;
    }

    es = &event_set->eventport;

    es->port = -1;
    es->mchanges = mchanges;
    es->mevents = mevents;

    es->changes = nxt_malloc(sizeof(nxt_eventport_change_t) * mchanges);
    if (es->changes == NULL) {
        goto fail;
    }

    es->events = nxt_malloc(sizeof(port_event_t) * mevents);
    if (es->events == NULL) {
        goto fail;
    }

    es->port = port_create();
    if (es->port == -1) {
        nxt_main_log_emerg("port_create() failed %E", nxt_errno);
        goto fail;
    }

    nxt_main_log_debug("port_create(): %d", es->port);

    if (signals != NULL) {
        es->signal_handler = signals->handler;
    }

    return event_set;

fail:

    nxt_eventport_free(event_set);

    return NULL;
}


static void
nxt_eventport_free(nxt_event_set_t *event_set)
{
    nxt_eventport_event_set_t  *es;

    es = &event_set->eventport;

    nxt_main_log_debug("eventport %d free", es->port);

    if (es->port != -1) {
        if (close(es->port) != 0) {
            nxt_main_log_emerg("eventport close(%d) failed %E",
                               es->port, nxt_errno);
        }
    }

    nxt_free(es->events);
    nxt_free(es);
}


static void
nxt_eventport_enable(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->read = NXT_EVENT_DEFAULT;
    ev->write = NXT_EVENT_DEFAULT;

    nxt_eventport_enable_event(event_set, ev, POLLIN | POLLOUT);
}


static void
nxt_eventport_disable(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE || ev->write != NXT_EVENT_INACTIVE) {

        ev->read = NXT_EVENT_INACTIVE;
        ev->write = NXT_EVENT_INACTIVE;

        nxt_eventport_disable_event(event_set, ev);
    }
}


static void
nxt_eventport_close(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;

    nxt_eventport_drop_changes(event_set, ev);
}


static void
nxt_eventport_drop_changes(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_eventport_change_t     *dst, *src, *end;
    nxt_eventport_event_set_t  *es;

    es = &event_set->eventport;

    dst = es->changes;
    end = dst + es->nchanges;

    for (src = dst; src < end; src++) {

        if (src->event == ev) {
            continue;
        }

        if (dst != src) {
            *dst = *src;
        }

        dst++;
    }

    es->nchanges -= end - dst;
}


static void
nxt_eventport_enable_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_uint_t  events;

    if (ev->read != NXT_EVENT_BLOCKED) {
        events = (ev->write == NXT_EVENT_INACTIVE) ? POLLIN:
                                                     (POLLIN | POLLOUT);
        nxt_eventport_enable_event(event_set, ev, events);
    }

    ev->read = NXT_EVENT_DEFAULT;
}


static void
nxt_eventport_enable_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_uint_t  events;

    if (ev->write != NXT_EVENT_BLOCKED) {
        events = (ev->read == NXT_EVENT_INACTIVE) ? POLLOUT:
                                                    (POLLIN | POLLOUT);
        nxt_eventport_enable_event(event_set, ev, events);
    }

    ev->write = NXT_EVENT_DEFAULT;
}


/*
 * eventport changes are batched to improve instruction and data
 * cache locality of several port_associate() and port_dissociate()
 * calls followed by port_getn() call.
 */

static void
nxt_eventport_enable_event(nxt_event_set_t *event_set, nxt_event_fd_t *ev,
    nxt_uint_t events)
{
    nxt_eventport_change_t     *ch;
    nxt_eventport_event_set_t  *es;

    es = &event_set->eventport;

    nxt_log_debug(ev->log, "port %d set event: fd:%d ev:%04XD u:%p",
                  es->port, ev->fd, events, ev);

    if (es->nchanges >= es->mchanges) {
        (void) nxt_eventport_commit_changes(nxt_thread(), es);
    }

    ch = &es->changes[es->nchanges++];
    ch->fd = ev->fd;
    ch->events = events;
    ch->event = ev;
}


static void
nxt_eventport_disable_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->read = NXT_EVENT_INACTIVE;

    if (ev->write == NXT_EVENT_INACTIVE) {
        nxt_eventport_disable_event(event_set, ev);

    } else {
        nxt_eventport_enable_event(event_set, ev, POLLOUT);
    }
}


static void
nxt_eventport_disable_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->write = NXT_EVENT_INACTIVE;

    if (ev->read == NXT_EVENT_INACTIVE) {
        nxt_eventport_disable_event(event_set, ev);

    } else {
        nxt_eventport_enable_event(event_set, ev, POLLIN);
    }
}


static void
nxt_eventport_disable_event(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_eventport_change_t     *ch;
    nxt_eventport_event_set_t  *es;

    es = &event_set->eventport;

    nxt_log_debug(ev->log, "port %d disable event : fd:%d", es->port, ev->fd);

    if (es->nchanges >= es->mchanges) {
        (void) nxt_eventport_commit_changes(nxt_thread(), es);
    }

    ch = &es->changes[es->nchanges++];
    ch->fd = ev->fd;
    ch->events = 0;
    ch->event = ev;
}


static nxt_int_t
nxt_eventport_commit_changes(nxt_thread_t *thr, nxt_eventport_event_set_t *es)
{
    int                     ret;
    nxt_int_t               retval;
    nxt_event_fd_t          *ev;
    nxt_eventport_change_t  *ch, *end;

    nxt_log_debug(thr->log, "eventport %d changes:%ui", es->port, es->nchanges);

    retval = NXT_OK;
    ch = es->changes;
    end = ch + es->nchanges;

    do {
        ev = ch->event;

        if (ch->events != 0) {
            nxt_log_debug(ev->log, "port_associate(%d): fd:%d ev:%04XD u:%p",
                          es->port, ch->fd, ch->events, ev);

            ret = port_associate(es->port, PORT_SOURCE_FD, ch->fd,
                                 ch->events, ev);
            if (ret == 0) {
                goto next;
            }

            nxt_log_alert(ev->log,
                          "port_associate(%d, %d, %d, %04XD) failed %E",
                          es->port, PORT_SOURCE_FD, ch->fd, ch->events,
                          nxt_errno);

        } else {
            nxt_log_debug(ev->log, "port_dissociate(%d): fd:%d",
                          es->port, ch->fd);

            if (port_dissociate(es->port, PORT_SOURCE_FD, ch->fd) == 0) {
                goto next;
            }

            nxt_log_alert(ev->log, "port_dissociate(%d, %d, %d) failed %E",
                          es->port, PORT_SOURCE_FD, ch->fd, nxt_errno);
        }

        nxt_thread_work_queue_add(thr, &thr->work_queue.main,
                                  nxt_eventport_error_handler,
                                  ev, ev->data, ev->log);

        retval = NXT_ERROR;

    next:

        ch++;

    } while (ch < end);

    es->nchanges = 0;

    return retval;
}


static void
nxt_eventport_error_handler(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_event_fd_t  *ev;

    ev = obj;

    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;

    ev->error_handler(thr, ev, data);
}


static void
nxt_eventport_block_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_eventport_block_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->write != NXT_EVENT_INACTIVE) {
        ev->write = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_eventport_oneshot_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read == NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_DEFAULT;

        nxt_eventport_enable_event(event_set, ev, POLLIN);
    }
}


static void
nxt_eventport_oneshot_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->write == NXT_EVENT_INACTIVE) {
        ev->write = NXT_EVENT_DEFAULT;

        nxt_eventport_enable_event(event_set, ev, POLLOUT);
    }
}


static void
nxt_eventport_enable_accept(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->read = NXT_EVENT_LEVEL;

    nxt_eventport_enable_event(event_set, ev, POLLIN);
}


static nxt_int_t
nxt_eventport_enable_post(nxt_event_set_t *event_set,
    nxt_work_handler_t handler)
{
    event_set->eventport.post_handler = handler;

    return NXT_OK;
}


static void
nxt_eventport_signal(nxt_event_set_t *event_set, nxt_uint_t signo)
{
    nxt_eventport_event_set_t  *es;

    es = &event_set->eventport;

    nxt_thread_log_debug("port_send(%d, %ui)", es->port, signo);

    if (port_send(es->port, signo, NULL) != 0) {
        nxt_thread_log_alert("port_send(%d) failed %E", es->port, nxt_errno);
    }
}


static void
nxt_eventport_poll(nxt_thread_t *thr, nxt_event_set_t *event_set,
    nxt_msec_t timeout)
{
    int                        n, events, signo;
    uint_t                     nevents;
    nxt_err_t                  err;
    nxt_uint_t                 i, level;
    timespec_t                 ts, *tp;
    port_event_t               *event;
    nxt_event_fd_t             *ev;
    nxt_work_handler_t         handler;
    nxt_eventport_event_set_t  *es;

    es = &event_set->eventport;

    if (es->nchanges != 0) {
        if (nxt_eventport_commit_changes(thr, es) != NXT_OK) {
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

    nxt_log_debug(thr->log, "port_getn(%d) timeout: %M", es->port, timeout);

    /*
     * A trap for possible error when Solaris does not update nevents
     * if ETIME or EINTR is returned.  This issue will be logged as
     * "unexpected port_getn() event".
     *
     * The details are in OpenSolaris mailing list thread "port_getn()
     * and timeouts - is this a bug or an undocumented feature?"
     */
    event = &es->events[0];
    event->portev_events = -1; /* invalid port events */
    event->portev_source = -1; /* invalid port source */
    event->portev_object = -1;
    event->portev_user = (void *) -1;

    nevents = 1;
    n = port_getn(es->port, es->events, es->mevents, &nevents, tp);

    /*
     * 32-bit port_getn() on Solaris 10 x86 returns large negative
     * values instead of 0 when returning immediately.
     */
    err = (n < 0) ? nxt_errno : 0;

    nxt_thread_time_update(thr);

    if (n == -1) {
        if (err == NXT_ETIME || err == NXT_EINTR) {
            if (nevents != 0) {
                nxt_log_alert(thr->log, "port_getn(%d) failed %E, events:%ud",
                              es->port, err, nevents);
            }
        }

        if (err != NXT_ETIME) {
            level = (err == NXT_EINTR) ? NXT_LOG_INFO : NXT_LOG_ALERT;
            nxt_log_error(level, thr->log, "port_getn(%d) failed %E",
                          es->port, err);

            if (err != NXT_EINTR) {
                return;
            }
        }
    }

    nxt_log_debug(thr->log, "port_getn(%d) events: %d", es->port, nevents);

    for (i = 0; i < nevents; i++) {
        event = &es->events[i];

        switch (event->portev_source) {

        case PORT_SOURCE_FD:
            ev = event->portev_user;
            events = event->portev_events;

            nxt_log_debug(ev->log, "eventport: fd:%d ev:%04Xd u:%p rd:%d wr:%d",
                          event->portev_object, events, ev,
                          ev->read, ev->write);

            if (nxt_slow_path(events & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                nxt_log_alert(ev->log,
                              "port_getn(%d) error fd:%d events:%04Xud",
                              es->port, ev->fd, events);

                nxt_thread_work_queue_add(thr, &thr->work_queue.main,
                                          nxt_eventport_error_handler,
                                          ev, ev->data, ev->log);
                continue;
            }

            if (events & POLLIN) {
                ev->read_ready = 1;

                if (ev->read != NXT_EVENT_BLOCKED) {
                    nxt_thread_work_queue_add(thr, ev->read_work_queue,
                                              ev->read_handler,
                                              ev, ev->data, ev->log);

                }

                if (ev->read != NXT_EVENT_LEVEL) {
                    ev->read = NXT_EVENT_INACTIVE;
                }
            }

            if (events & POLLOUT) {
                ev->write_ready = 1;

                if (ev->write != NXT_EVENT_BLOCKED) {
                    nxt_thread_work_queue_add(thr, ev->write_work_queue,
                                              ev->write_handler,
                                              ev, ev->data, ev->log);
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
                nxt_eventport_enable_event(event_set, ev, events);
            }

            break;

        case PORT_SOURCE_USER:
            nxt_log_debug(thr->log, "eventport: user ev:%d u:%p",
                          event->portev_events, event->portev_user);

            signo = event->portev_events;

            handler = (signo == 0) ? es->post_handler : es->signal_handler;

            nxt_thread_work_queue_add(thr, &thr->work_queue.main, handler,
                                      (void *) (uintptr_t) signo, NULL,
                                      thr->log);

            break;

        default:
            nxt_log_alert(thr->log, "unexpected port_getn(%d) event: "
                          "ev:%d src:%d obj:%p u:%p",
                          es->port, event->portev_events,
                          event->portev_source, event->portev_object,
                          event->portev_user);
        }
    }
}

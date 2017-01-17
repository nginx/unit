
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * "/dev/poll" has been introduced in Solaris 7 (11/99), HP-UX 11.22 (named
 * "eventport pseudo driver" internally, not to be confused with Solaris 10
 * event ports), IRIX 6.5.15, and Tru64 UNIX 5.1A.
 *
 * Although "/dev/poll" descriptor is a file descriptor, nevertheless
 * it cannot be added to another poll set, Solaris poll(7d):
 *
 *   The /dev/poll driver does not yet support polling.  Polling on a
 *   /dev/poll file descriptor will result in POLLERR being returned
 *   in the revents field of pollfd structure.
 */


#define NXT_DEVPOLL_ADD     0
#define NXT_DEVPOLL_UPDATE  1
#define NXT_DEVPOLL_CHANGE  2
#define NXT_DEVPOLL_DELETE  3


static nxt_event_set_t *nxt_devpoll_create(nxt_event_signals_t *signals,
    nxt_uint_t mchanges, nxt_uint_t mevents);
static void nxt_devpoll_free(nxt_event_set_t *event_set);
static void nxt_devpoll_enable(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_devpoll_disable(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
#if (NXT_HPUX)
static void nxt_devpoll_close(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_devpoll_drop_changes(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
#endif
static void nxt_devpoll_enable_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_devpoll_enable_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_devpoll_disable_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_devpoll_disable_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_devpoll_block_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_devpoll_block_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_devpoll_oneshot_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_devpoll_oneshot_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_devpoll_change(nxt_event_set_t *event_set, nxt_event_fd_t *ev,
    nxt_uint_t op, nxt_uint_t events);
static nxt_int_t nxt_devpoll_commit_changes(nxt_thread_t *thr,
    nxt_devpoll_event_set_t *ds);
static void nxt_devpoll_change_error(nxt_thread_t *thr,
    nxt_devpoll_event_set_t *ds, nxt_event_fd_t *ev);
static void nxt_devpoll_remove(nxt_thread_t *thr, nxt_devpoll_event_set_t *ds,
    nxt_fd_t fd);
static nxt_int_t nxt_devpoll_write(nxt_thread_t *thr, int devpoll,
    struct pollfd *pfd, size_t n);
static void nxt_devpoll_set_poll(nxt_thread_t *thr, nxt_event_set_t *event_set,
    nxt_msec_t timeout);


const nxt_event_set_ops_t  nxt_devpoll_event_set = {
    "devpoll",
    nxt_devpoll_create,
    nxt_devpoll_free,
    nxt_devpoll_enable,
    nxt_devpoll_disable,
    nxt_devpoll_disable,
#if (NXT_HPUX)
    nxt_devpoll_close,
#else
    nxt_devpoll_disable,
#endif
    nxt_devpoll_enable_read,
    nxt_devpoll_enable_write,
    nxt_devpoll_disable_read,
    nxt_devpoll_disable_write,
    nxt_devpoll_block_read,
    nxt_devpoll_block_write,
    nxt_devpoll_oneshot_read,
    nxt_devpoll_oneshot_write,
    nxt_devpoll_enable_read,
    NULL,
    NULL,
    NULL,
    NULL,
    nxt_devpoll_set_poll,

    &nxt_unix_event_conn_io,

    NXT_NO_FILE_EVENTS,
    NXT_NO_SIGNAL_EVENTS,
};


static nxt_event_set_t *
nxt_devpoll_create(nxt_event_signals_t *signals, nxt_uint_t mchanges,
    nxt_uint_t mevents)
{
    nxt_event_set_t          *event_set;
    nxt_devpoll_event_set_t  *ds;

    event_set = nxt_zalloc(sizeof(nxt_devpoll_event_set_t));
    if (event_set == NULL) {
        return NULL;
    }

    ds = &event_set->devpoll;

    ds->devpoll = -1;
    ds->mchanges = mchanges;
    ds->mevents = mevents;

    ds->devpoll_changes = nxt_malloc(sizeof(nxt_devpoll_change_t) * mchanges);
    if (ds->devpoll_changes == NULL) {
        goto fail;
    }

    /*
     * NXT_DEVPOLL_CHANGE requires two struct pollfd's:
     * for POLLREMOVE and subsequent POLLIN or POLLOUT.
     */
    ds->changes = nxt_malloc(2 * sizeof(struct pollfd) * mchanges);
    if (ds->changes == NULL) {
        goto fail;
    }

    ds->events = nxt_malloc(sizeof(struct pollfd) * mevents);
    if (ds->events == NULL) {
        goto fail;
    }

    ds->devpoll = open("/dev/poll", O_RDWR);
    if (ds->devpoll == -1) {
        nxt_main_log_emerg("open(/dev/poll) failed %E", nxt_errno);
        goto fail;
    }

    nxt_main_log_debug("open(/dev/poll): %d", ds->devpoll);

    return event_set;

fail:

    nxt_devpoll_free(event_set);

    return NULL;
}


static void
nxt_devpoll_free(nxt_event_set_t *event_set)
{
    nxt_devpoll_event_set_t  *ds;

    ds = &event_set->devpoll;

    nxt_main_log_debug("devpoll %d free", ds->devpoll);

    if (ds->devpoll != -1) {
        if (close(ds->devpoll) != 0) {
            nxt_main_log_emerg("devpoll close(%d) failed %E",
                               ds->devpoll, nxt_errno);
        }
    }

    nxt_free(ds->events);
    nxt_free(ds->changes);
    nxt_free(ds->devpoll_changes);
    nxt_event_set_fd_hash_destroy(&ds->fd_hash);
    nxt_free(ds);
}


static void
nxt_devpoll_enable(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->read = NXT_EVENT_DEFAULT;
    ev->write = NXT_EVENT_DEFAULT;

    nxt_devpoll_change(event_set, ev, NXT_DEVPOLL_ADD, POLLIN | POLLOUT);
}


/*
 * Solaris does not automatically remove a closed file descriptor from
 * a "/dev/poll" set: ioctl(DP_ISPOLLED) for the descriptor returns 1,
 * significative of active descriptor.  POLLREMOVE can remove already
 * closed file descriptor, so the removal can be batched, Solaris poll(7d):
 *
 *   When using the "/dev/poll" driver, you should remove a closed file
 *   descriptor from a monitored poll set.  Failure to do so may result
 *   in a POLLNVAL revents being returned for the closed file descriptor.
 *   When a file descriptor is closed but not removed from the monitored
 *   set, and is reused in subsequent open of a different device, you
 *   will be polling the device associated with the reused file descriptor.
 *   In a multithreaded application, careful coordination among threads
 *   doing close and DP_POLL ioctl is recommended for consistent results.
 *
 * Besides Solaris and HP-UX allow to add invalid descriptors to an
 * "/dev/poll" set, although the descriptors are not marked as polled,
 * that is, ioctl(DP_ISPOLLED) returns 0.
 */

static void
nxt_devpoll_disable(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE || ev->write != NXT_EVENT_INACTIVE) {

        ev->read = NXT_EVENT_INACTIVE;
        ev->write = NXT_EVENT_INACTIVE;

        nxt_devpoll_change(event_set, ev, NXT_DEVPOLL_DELETE, POLLREMOVE);
    }
}


#if (NXT_HPUX)

/*
 * HP-UX poll(7):
 *
 *   When a polled file descriptor is closed, it is automatically
 *   deregistered.
 */

static void
nxt_devpoll_close(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;

    nxt_devpoll_drop_changes(event_set, ev);
}


static void
nxt_devpoll_drop_changes(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_devpoll_change_t     *dst, *src, *end;
    nxt_devpoll_event_set_t  *ds;

    ds = &event_set->devpoll;

    dst = ds->devpoll_changes;
    end = dst + ds->nchanges;

    for (src = dst; src < end; src++) {

        if (src->event == ev) {
            continue;
        }

        if (dst != src) {
            *dst = *src;
        }

        dst++;
    }

    ds->nchanges -= end - dst;
}

#endif


/*
 * Solaris poll(7d):
 *
 *   The fd field specifies the file descriptor being polled.  The events
 *   field indicates the interested poll events on the file descriptor.
 *   If a pollfd array contains multiple pollfd entries with the same fd field,
 *   the "events" field in each pollfd entry is OR'ed.  A special POLLREMOVE
 *   event in the events field of the pollfd structure removes the fd from
 *   the monitored set. The revents field is not used.
 */

static void
nxt_devpoll_enable_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_uint_t  op, events;

    if (ev->read != NXT_EVENT_BLOCKED) {

        events = POLLIN;

        if (ev->write == NXT_EVENT_INACTIVE) {
            op = NXT_DEVPOLL_ADD;

        } else if (ev->write == NXT_EVENT_BLOCKED) {
            ev->write = NXT_EVENT_INACTIVE;
            op = NXT_DEVPOLL_CHANGE;

        } else {
            op = NXT_DEVPOLL_UPDATE;
            events = POLLIN | POLLOUT;
        }

        nxt_devpoll_change(event_set, ev, op, events);
    }

    ev->read = NXT_EVENT_DEFAULT;
}


static void
nxt_devpoll_enable_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_uint_t  op, events;

    if (ev->write != NXT_EVENT_BLOCKED) {

        events = POLLOUT;

        if (ev->read == NXT_EVENT_INACTIVE) {
            op = NXT_DEVPOLL_ADD;

        } else if (ev->read == NXT_EVENT_BLOCKED) {
            ev->read = NXT_EVENT_INACTIVE;
            op = NXT_DEVPOLL_CHANGE;

        } else {
            op = NXT_DEVPOLL_UPDATE;
            events = POLLIN | POLLOUT;
        }

        nxt_devpoll_change(event_set, ev, op, events);
    }

    ev->write = NXT_EVENT_DEFAULT;
}


static void
nxt_devpoll_disable_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_uint_t  op, events;

    ev->read = NXT_EVENT_INACTIVE;

    if (ev->write <= NXT_EVENT_BLOCKED) {
        ev->write = NXT_EVENT_INACTIVE;
        op = NXT_DEVPOLL_DELETE;
        events = POLLREMOVE;

    } else {
        op = NXT_DEVPOLL_CHANGE;
        events = POLLOUT;
    }

    nxt_devpoll_change(event_set, ev, op, events);
}


static void
nxt_devpoll_disable_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_uint_t  op, events;

    ev->write = NXT_EVENT_INACTIVE;

    if (ev->read <= NXT_EVENT_BLOCKED) {
        ev->read = NXT_EVENT_INACTIVE;
        op = NXT_DEVPOLL_DELETE;
        events = POLLREMOVE;

    } else {
        op = NXT_DEVPOLL_CHANGE;
        events = POLLIN;
    }

    nxt_devpoll_change(event_set, ev, op, events);
}


static void
nxt_devpoll_block_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_devpoll_block_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->write != NXT_EVENT_INACTIVE) {
        ev->write = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_devpoll_oneshot_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_devpoll_enable_read(event_set, ev);

    ev->read = NXT_EVENT_ONESHOT;
}


static void
nxt_devpoll_oneshot_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_devpoll_enable_write(event_set, ev);

    ev->write = NXT_EVENT_ONESHOT;
}


static void
nxt_devpoll_change(nxt_event_set_t *event_set, nxt_event_fd_t *ev,
    nxt_uint_t op, nxt_uint_t events)
{
    nxt_devpoll_change_t     *ch;
    nxt_devpoll_event_set_t  *ds;

    ds = &event_set->devpoll;

    nxt_log_debug(ev->log, "devpoll %d change fd:%d op:%ui ev:%04Xi",
                  ds->devpoll, ev->fd, op, events);

    if (ds->nchanges >= ds->mchanges) {
        (void) nxt_devpoll_commit_changes(nxt_thread(), ds);
    }

    ch = &ds->devpoll_changes[ds->nchanges++];
    ch->op = op;
    ch->fd = ev->fd;
    ch->events = events;
    ch->event = ev;
}


static nxt_int_t
nxt_devpoll_commit_changes(nxt_thread_t *thr, nxt_devpoll_event_set_t *ds)
{
    size_t                n;
    nxt_int_t             ret, retval;
    struct pollfd         *pfd;
    nxt_devpoll_change_t  *ch, *end;

    nxt_log_debug(thr->log, "devpoll %d changes:%ui",
                  ds->devpoll, ds->nchanges);

    retval = NXT_OK;
    n = 0;
    ch = ds->devpoll_changes;
    end = ch + ds->nchanges;

    do {
        nxt_log_debug(thr->log, "devpoll fd:%d op:%d ev:%04Xd",
                      ch->fd, ch->op, ch->events);

        if (ch->op == NXT_DEVPOLL_CHANGE) {
            pfd = &ds->changes[n++];
            pfd->fd = ch->fd;
            pfd->events = POLLREMOVE;
            pfd->revents = 0;
        }

        pfd = &ds->changes[n++];
        pfd->fd = ch->fd;
        pfd->events = ch->events;
        pfd->revents = 0;

        ch++;

    } while (ch < end);

    ch = ds->devpoll_changes;
    end = ch + ds->nchanges;

    ret = nxt_devpoll_write(thr, ds->devpoll, ds->changes, n);

    if (nxt_slow_path(ret != NXT_OK)) {
        do {
            nxt_devpoll_change_error(thr, ds, ch->event);
            ch++;
        } while (ch < end);

        ds->nchanges = 0;

        return NXT_ERROR;
    }

    do {
        if (ch->op == NXT_DEVPOLL_ADD) {
            ret = nxt_event_set_fd_hash_add(&ds->fd_hash, ch->fd, ch->event);

            if (nxt_slow_path(ret != NXT_OK)) {
                nxt_devpoll_change_error(thr, ds, ch->event);
                retval = NXT_ERROR;
            }

        } else if (ch->op == NXT_DEVPOLL_DELETE) {
            nxt_event_set_fd_hash_delete(&ds->fd_hash, ch->fd, 0);
        }

        /* Nothing tp do for NXT_DEVPOLL_UPDATE and NXT_DEVPOLL_CHANGE. */

        ch++;

    } while (ch < end);

    ds->nchanges = 0;

    return retval;
}


static void
nxt_devpoll_change_error(nxt_thread_t *thr, nxt_devpoll_event_set_t *ds,
    nxt_event_fd_t *ev)
{
    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;

    nxt_thread_work_queue_add(thr, &thr->work_queue.main,
                              ev->error_handler, ev, ev->data, ev->log);

    nxt_event_set_fd_hash_delete(&ds->fd_hash, ev->fd, 1);

    nxt_devpoll_remove(thr, ds, ev->fd);
}


static void
nxt_devpoll_remove(nxt_thread_t *thr, nxt_devpoll_event_set_t *ds, nxt_fd_t fd)
{
    int            n;
    struct pollfd  pfd;

    pfd.fd = fd;
    pfd.events = 0;
    pfd.revents = 0;

    n = ioctl(ds->devpoll, DP_ISPOLLED, &pfd);

    nxt_log_debug(thr->log, "ioctl(%d, DP_ISPOLLED, %d): %d",
                  ds->devpoll, fd, n);

    if (n == 0) {
        /* The file descriptor is not in the set. */
        return;
    }

    if (n == -1) {
        nxt_log_alert(thr->log, "ioctl(%d, DP_ISPOLLED, %d) failed %E",
                      ds->devpoll, fd, nxt_errno);
        /* Fall through. */
    }

    /* n == 1: the file descriptor is in the set. */

    nxt_log_debug(thr->log, "devpoll %d remove fd:%d", ds->devpoll, fd);

    pfd.fd = fd;
    pfd.events = POLLREMOVE;
    pfd.revents = 0;

    nxt_devpoll_write(thr, ds->devpoll, &pfd, 1);
}


static nxt_int_t
nxt_devpoll_write(nxt_thread_t *thr, int devpoll, struct pollfd *pfd,
    size_t n)
{
    nxt_log_debug(thr->log, "devpoll write(%d) changes:%uz", devpoll, n);

    n *= sizeof(struct pollfd);

    if (nxt_slow_path(write(devpoll, pfd, n) == (ssize_t) n)) {
        return NXT_OK;
    }

    nxt_log_alert(thr->log, "devpoll write(%d) failed %E",
                  devpoll, nxt_errno);

    return NXT_ERROR;
}


static void
nxt_devpoll_set_poll(nxt_thread_t *thr, nxt_event_set_t *event_set,
    nxt_msec_t timeout)
{
    int                      nevents;
    nxt_fd_t                 fd;
    nxt_int_t                i;
    nxt_err_t                err;
    nxt_uint_t               events, level;
    struct dvpoll            dvp;
    struct pollfd            *pfd;
    nxt_event_fd_t           *ev;
    nxt_devpoll_event_set_t  *ds;

    ds = &event_set->devpoll;

    if (ds->nchanges != 0) {
        if (nxt_devpoll_commit_changes(thr, ds) != NXT_OK) {
            /* Error handlers have been enqueued on failure. */
            timeout = 0;
        }
    }

    nxt_log_debug(thr->log, "ioctl(%d, DP_POLL) timeout:%M",
                  ds->devpoll, timeout);

    dvp.dp_fds = ds->events;
    dvp.dp_nfds = ds->mevents;
    dvp.dp_timeout = timeout;

    nevents = ioctl(ds->devpoll, DP_POLL, &dvp);

    err = (nevents == -1) ? nxt_errno : 0;

    nxt_thread_time_update(thr);

    nxt_log_debug(thr->log, "ioctl(%d, DP_POLL): %d", ds->devpoll, nevents);

    if (nevents == -1) {
        level = (err == NXT_EINTR) ? NXT_LOG_INFO : NXT_LOG_ALERT;
        nxt_log_error(level, thr->log, "ioctl(%d, DP_POLL) failed %E",
                      ds->devpoll, err);
        return;
    }

    for (i = 0; i < nevents; i++) {

        pfd = &ds->events[i];
        fd = pfd->fd;
        events = pfd->revents;

        ev = nxt_event_set_fd_hash_get(&ds->fd_hash, fd);

        if (nxt_slow_path(ev == NULL)) {
            nxt_log_alert(thr->log, "ioctl(%d, DP_POLL) returned invalid "
                          "fd:%d ev:%04Xd rev:%04uXi",
                          ds->devpoll, fd, pfd->events, events);

            nxt_devpoll_remove(thr, ds, fd);
            continue;
        }

        nxt_log_debug(ev->log, "devpoll: fd:%d ev:%04uXi rd:%d wr:%d",
                      fd, events, ev->read, ev->write);

        if (nxt_slow_path(events & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            nxt_log_alert(ev->log,
                          "ioctl(%d, DP_POLL) error fd:%d ev:%04Xd rev:%04uXi",
                          ds->devpoll, fd, pfd->events, events);

            nxt_thread_work_queue_add(thr, &thr->work_queue.main,
                                      ev->error_handler, ev, ev->data, ev->log);
            continue;
        }

        if (events & POLLIN) {
            ev->read_ready = 1;

            if (ev->read != NXT_EVENT_BLOCKED) {

                if (ev->read == NXT_EVENT_ONESHOT) {
                    nxt_devpoll_disable_read(event_set, ev);
                }

                nxt_thread_work_queue_add(thr, ev->read_work_queue,
                                          ev->read_handler,
                                          ev, ev->data, ev->log);
            }
        }

        if (events & POLLOUT) {
            ev->write_ready = 1;

            if (ev->write != NXT_EVENT_BLOCKED) {

                if (ev->write == NXT_EVENT_ONESHOT) {
                    nxt_devpoll_disable_write(event_set, ev);
                }

                nxt_thread_work_queue_add(thr, ev->write_work_queue,
                                          ev->write_handler,
                                          ev, ev->data, ev->log);
            }
        }
    }
}

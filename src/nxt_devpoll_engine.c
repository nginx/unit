
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


static nxt_int_t nxt_devpoll_create(nxt_event_engine_t *engine,
    nxt_uint_t mchanges, nxt_uint_t mevents);
static void nxt_devpoll_free(nxt_event_engine_t *engine);
static void nxt_devpoll_enable(nxt_event_engine_t *engine, nxt_fd_event_t *ev);
static void nxt_devpoll_disable(nxt_event_engine_t *engine, nxt_fd_event_t *ev);
static nxt_bool_t nxt_devpoll_close(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_devpoll_enable_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_devpoll_enable_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_devpoll_disable_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_devpoll_disable_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_devpoll_block_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_devpoll_block_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_devpoll_oneshot_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_devpoll_oneshot_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_devpoll_change(nxt_event_engine_t *engine, nxt_fd_event_t *ev,
    nxt_uint_t op, nxt_uint_t events);
static nxt_int_t nxt_devpoll_commit_changes(nxt_event_engine_t *engine);
static void nxt_devpoll_change_error(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_devpoll_remove(nxt_event_engine_t *engine, nxt_fd_t fd);
static nxt_int_t nxt_devpoll_write(nxt_event_engine_t *engine,
    struct pollfd *pfd, size_t n);
static void nxt_devpoll_poll(nxt_event_engine_t *engine,
    nxt_msec_t timeout);


const nxt_event_interface_t  nxt_devpoll_engine = {
    "devpoll",
    nxt_devpoll_create,
    nxt_devpoll_free,
    nxt_devpoll_enable,
    nxt_devpoll_disable,
    nxt_devpoll_disable,
    nxt_devpoll_close,
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
    nxt_devpoll_poll,

    &nxt_unix_conn_io,

    NXT_NO_FILE_EVENTS,
    NXT_NO_SIGNAL_EVENTS,
};


static nxt_int_t
nxt_devpoll_create(nxt_event_engine_t *engine, nxt_uint_t mchanges,
    nxt_uint_t mevents)
{
    void  *changes;

    engine->u.devpoll.fd = -1;
    engine->u.devpoll.mchanges = mchanges;
    engine->u.devpoll.mevents = mevents;

    changes = nxt_malloc(sizeof(nxt_devpoll_change_t) * mchanges);
    if (changes == NULL) {
        goto fail;
    }

    engine->u.devpoll.changes = changes;

    /*
     * NXT_DEVPOLL_CHANGE requires two struct pollfd's:
     * for POLLREMOVE and subsequent POLLIN or POLLOUT.
     */
    changes = nxt_malloc(2 * sizeof(struct pollfd) * mchanges);
    if (changes == NULL) {
        goto fail;
    }

    engine->u.devpoll.write_changes = changes;

    engine->u.devpoll.events = nxt_malloc(sizeof(struct pollfd) * mevents);
    if (engine->u.devpoll.events == NULL) {
        goto fail;
    }

    engine->u.devpoll.fd = open("/dev/poll", O_RDWR);

    if (engine->u.devpoll.fd == -1) {
        nxt_alert(&engine->task, "open(\"/dev/poll\") failed %E", nxt_errno);
        goto fail;
    }

    nxt_debug(&engine->task, "open(\"/dev/poll\"): %d", engine->u.devpoll.fd);

    return NXT_OK;

fail:

    nxt_devpoll_free(engine);

    return NXT_ERROR;
}


static void
nxt_devpoll_free(nxt_event_engine_t *engine)
{
    nxt_fd_t  fd;

    fd = engine->u.devpoll.fd;

    nxt_debug(&engine->task, "devpoll %d free", fd);

    if (fd != -1 && close(fd) != 0) {
        nxt_alert(&engine->task, "devpoll close(%d) failed %E", fd, nxt_errno);
    }

    nxt_free(engine->u.devpoll.events);
    nxt_free(engine->u.devpoll.write_changes);
    nxt_free(engine->u.devpoll.changes);
    nxt_fd_event_hash_destroy(&engine->u.devpoll.fd_hash);

    nxt_memzero(&engine->u.devpoll, sizeof(nxt_devpoll_engine_t));
}


static void
nxt_devpoll_enable(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    ev->read = NXT_EVENT_ACTIVE;
    ev->write = NXT_EVENT_ACTIVE;

    nxt_devpoll_change(engine, ev, NXT_DEVPOLL_ADD, POLLIN | POLLOUT);
}


static void
nxt_devpoll_disable(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE || ev->write != NXT_EVENT_INACTIVE) {

        ev->read = NXT_EVENT_INACTIVE;
        ev->write = NXT_EVENT_INACTIVE;

        nxt_devpoll_change(engine, ev, NXT_DEVPOLL_DELETE, POLLREMOVE);
    }
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
 *
 * HP-UX poll(7):
 *
 *   When a polled file descriptor is closed, it is automatically
 *   deregistered.
 */

static nxt_bool_t
nxt_devpoll_close(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_devpoll_disable(engine, ev);

    return ev->changing;
}


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
nxt_devpoll_enable_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
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

        nxt_devpoll_change(engine, ev, op, events);
    }

    ev->read = NXT_EVENT_ACTIVE;
}


static void
nxt_devpoll_enable_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
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

        nxt_devpoll_change(engine, ev, op, events);
    }

    ev->write = NXT_EVENT_ACTIVE;
}


static void
nxt_devpoll_disable_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
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

    nxt_devpoll_change(engine, ev, op, events);
}


static void
nxt_devpoll_disable_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
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

    nxt_devpoll_change(engine, ev, op, events);
}


static void
nxt_devpoll_block_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_devpoll_block_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->write != NXT_EVENT_INACTIVE) {
        ev->write = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_devpoll_oneshot_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_devpoll_enable_read(engine, ev);

    ev->read = NXT_EVENT_ONESHOT;
}


static void
nxt_devpoll_oneshot_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_devpoll_enable_write(engine, ev);

    ev->write = NXT_EVENT_ONESHOT;
}


static void
nxt_devpoll_change(nxt_event_engine_t *engine, nxt_fd_event_t *ev,
    nxt_uint_t op, nxt_uint_t events)
{
    nxt_devpoll_change_t  *change;

    nxt_debug(ev->task, "devpoll %d change fd:%d op:%ui ev:%04Xi",
              engine->u.devpoll.fd, ev->fd, op, events);

    if (engine->u.devpoll.nchanges >= engine->u.devpoll.mchanges) {
        (void) nxt_devpoll_commit_changes(engine);
    }

    ev->changing = 1;

    change = &engine->u.devpoll.changes[engine->u.devpoll.nchanges++];
    change->op = op;
    change->events = events;
    change->event = ev;
}


static nxt_int_t
nxt_devpoll_commit_changes(nxt_event_engine_t *engine)
{
    size_t                n;
    nxt_int_t             ret, retval;
    struct pollfd         *pfd, *write_changes;
    nxt_fd_event_t        *ev;
    nxt_devpoll_change_t  *change, *end;

    nxt_debug(&engine->task, "devpoll %d changes:%ui",
              engine->u.devpoll.fd, engine->u.devpoll.nchanges);

    retval = NXT_OK;
    n = 0;
    write_changes = engine->u.devpoll.write_changes;
    change = engine->u.devpoll.changes;
    end = change + engine->u.devpoll.nchanges;

    do {
        ev = change->event;

        nxt_debug(&engine->task, "devpoll fd:%d op:%d ev:%04Xd",
                  ev->fd, change->op, change->events);

        if (change->op == NXT_DEVPOLL_CHANGE) {
            pfd = &write_changes[n++];
            pfd->fd = ev->fd;
            pfd->events = POLLREMOVE;
            pfd->revents = 0;
        }

        pfd = &write_changes[n++];
        pfd->fd = ev->fd;
        pfd->events = change->events;
        pfd->revents = 0;

        ev->changing = 0;

        change++;

    } while (change < end);

    change = engine->u.devpoll.changes;
    end = change + engine->u.devpoll.nchanges;

    ret = nxt_devpoll_write(engine, write_changes, n);

    if (nxt_slow_path(ret != NXT_OK)) {

        do {
            nxt_devpoll_change_error(engine, change->event);
            change++;
        } while (change < end);

        engine->u.devpoll.nchanges = 0;

        return NXT_ERROR;
    }

    do {
        ev = change->event;

        if (change->op == NXT_DEVPOLL_ADD) {
            ret = nxt_fd_event_hash_add(&engine->u.devpoll.fd_hash, ev->fd, ev);

            if (nxt_slow_path(ret != NXT_OK)) {
                nxt_devpoll_change_error(engine, ev);
                retval = NXT_ERROR;
            }

        } else if (change->op == NXT_DEVPOLL_DELETE) {
            nxt_fd_event_hash_delete(&engine->task, &engine->u.devpoll.fd_hash,
                                     ev->fd, 0);
        }

        /* Nothing tp do for NXT_DEVPOLL_UPDATE and NXT_DEVPOLL_CHANGE. */

        change++;

    } while (change < end);

    engine->u.devpoll.nchanges = 0;

    return retval;
}


static void
nxt_devpoll_change_error(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;

    nxt_work_queue_add(&engine->fast_work_queue, ev->error_handler,
                       ev->task, ev, ev->data);

    nxt_fd_event_hash_delete(ev->task, &engine->u.devpoll.fd_hash, ev->fd, 1);

    nxt_devpoll_remove(engine, ev->fd);
}


static void
nxt_devpoll_remove(nxt_event_engine_t *engine, nxt_fd_t fd)
{
    int            n;
    struct pollfd  pfd;

    pfd.fd = fd;
    pfd.events = 0;
    pfd.revents = 0;

    n = ioctl(engine->u.devpoll.fd, DP_ISPOLLED, &pfd);

    nxt_debug(&engine->task, "ioctl(%d, DP_ISPOLLED, %d): %d",
              engine->u.devpoll.fd, fd, n);

    if (n == 0) {
        /* The file descriptor is not in the set. */
        return;
    }

    if (n == -1) {
        nxt_alert(&engine->task, "ioctl(%d, DP_ISPOLLED, %d) failed %E",
                  engine->u.devpoll.fd, fd, nxt_errno);
        /* Fall through. */
    }

    /* n == 1: the file descriptor is in the set. */

    nxt_debug(&engine->task, "devpoll %d remove fd:%d",
              engine->u.devpoll.fd, fd);

    pfd.fd = fd;
    pfd.events = POLLREMOVE;
    pfd.revents = 0;

    nxt_devpoll_write(engine, &pfd, 1);
}


static nxt_int_t
nxt_devpoll_write(nxt_event_engine_t *engine, struct pollfd *pfd, size_t n)
{
    int  fd;

    fd = engine->u.devpoll.fd;

    nxt_debug(&engine->task, "devpoll write(%d) changes:%uz", fd, n);

    n *= sizeof(struct pollfd);

    if (nxt_slow_path(write(fd, pfd, n) == (ssize_t) n)) {
        return NXT_OK;
    }

    nxt_alert(&engine->task, "devpoll write(%d) failed %E", fd, nxt_errno);

    return NXT_ERROR;
}


static void
nxt_devpoll_poll(nxt_event_engine_t *engine, nxt_msec_t timeout)
{
    int             nevents;
    nxt_fd_t        fd;
    nxt_int_t       i;
    nxt_err_t       err;
    nxt_uint_t      events, level;
    struct dvpoll   dvp;
    struct pollfd   *pfd;
    nxt_fd_event_t  *ev;

    if (engine->u.devpoll.nchanges != 0) {
        if (nxt_devpoll_commit_changes(engine) != NXT_OK) {
            /* Error handlers have been enqueued on failure. */
            timeout = 0;
        }
    }

    nxt_debug(&engine->task, "ioctl(%d, DP_POLL) timeout:%M",
              engine->u.devpoll.fd, timeout);

    dvp.dp_fds = engine->u.devpoll.events;
    dvp.dp_nfds = engine->u.devpoll.mevents;
    dvp.dp_timeout = timeout;

    nevents = ioctl(engine->u.devpoll.fd, DP_POLL, &dvp);

    err = (nevents == -1) ? nxt_errno : 0;

    nxt_thread_time_update(engine->task.thread);

    nxt_debug(&engine->task, "ioctl(%d, DP_POLL): %d",
              engine->u.devpoll.fd, nevents);

    if (nevents == -1) {
        level = (err == NXT_EINTR) ? NXT_LOG_INFO : NXT_LOG_ALERT;

        nxt_log(&engine->task, level, "ioctl(%d, DP_POLL) failed %E",
                engine->u.devpoll.fd, err);

        return;
    }

    for (i = 0; i < nevents; i++) {

        pfd = &engine->u.devpoll.events[i];
        fd = pfd->fd;
        events = pfd->revents;

        ev = nxt_fd_event_hash_get(&engine->task, &engine->u.devpoll.fd_hash,
                                   fd);

        if (nxt_slow_path(ev == NULL)) {
            nxt_alert(&engine->task,
                      "ioctl(%d, DP_POLL) returned invalid "
                      "fd:%d ev:%04Xd rev:%04uXi",
                      engine->u.devpoll.fd, fd, pfd->events, events);

            nxt_devpoll_remove(engine, fd);
            continue;
        }

        nxt_debug(ev->task, "devpoll: fd:%d ev:%04uXi rd:%d wr:%d",
                  fd, events, ev->read, ev->write);

        if (nxt_slow_path(events & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            nxt_alert(ev->task,
                      "ioctl(%d, DP_POLL) error fd:%d ev:%04Xd rev:%04uXi",
                      engine->u.devpoll.fd, fd, pfd->events, events);

            nxt_work_queue_add(&engine->fast_work_queue, ev->error_handler,
                               ev->task, ev, ev->data);
            continue;
        }

        if (events & POLLIN) {
            ev->read_ready = 1;

            if (ev->read != NXT_EVENT_BLOCKED) {
                nxt_work_queue_add(ev->read_work_queue, ev->read_handler,
                                   ev->task, ev, ev->data);
            }

            if (ev->read == NXT_EVENT_BLOCKED
                || ev->read == NXT_EVENT_ONESHOT)
            {
                nxt_devpoll_disable_read(engine, ev);
            }
        }

        if (events & POLLOUT) {
            ev->write_ready = 1;

            if (ev->write != NXT_EVENT_BLOCKED) {
                nxt_work_queue_add(ev->write_work_queue, ev->write_handler,
                                   ev->task, ev, ev->data);
            }

            if (ev->write == NXT_EVENT_BLOCKED
                || ev->write == NXT_EVENT_ONESHOT)
            {
                nxt_devpoll_disable_write(engine, ev);
            }
        }
    }
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * pollset has been introduced in AIX 5L 5.3.
 *
 * pollset_create() returns a pollset_t descriptor which is not
 * a file descriptor, so it cannot be added to another pollset.
 * The first pollset_create() call returns 0.
 */


#define NXT_POLLSET_ADD     0
#define NXT_POLLSET_UPDATE  1
#define NXT_POLLSET_CHANGE  2
#define NXT_POLLSET_DELETE  3


static nxt_int_t nxt_pollset_create(nxt_event_engine_t *engine,
    nxt_uint_t mchanges, nxt_uint_t mevents);
static void nxt_pollset_free(nxt_event_engine_t *engine);
static void nxt_pollset_enable(nxt_event_engine_t *engine, nxt_fd_event_t *ev);
static void nxt_pollset_disable(nxt_event_engine_t *engine, nxt_fd_event_t *ev);
static nxt_bool_t nxt_pollset_close(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_pollset_enable_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_pollset_enable_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_pollset_disable_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_pollset_disable_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_pollset_block_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_pollset_block_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_pollset_oneshot_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_pollset_oneshot_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_pollset_change(nxt_event_engine_t *engine, nxt_fd_event_t *ev,
    nxt_uint_t op, nxt_uint_t events);
static nxt_int_t nxt_pollset_commit_changes(nxt_event_engine_t *engine);
static void nxt_pollset_change_error(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_pollset_remove(nxt_event_engine_t *engine, nxt_fd_t fd);
static nxt_int_t nxt_pollset_write(nxt_event_engine_t *engine,
    struct poll_ctl *ctl, int n);
static void nxt_pollset_poll(nxt_event_engine_t *engine, nxt_msec_t timeout);


const nxt_event_interface_t  nxt_pollset_engine = {
    "pollset",
    nxt_pollset_create,
    nxt_pollset_free,
    nxt_pollset_enable,
    nxt_pollset_disable,
    nxt_pollset_disable,
    nxt_pollset_close,
    nxt_pollset_enable_read,
    nxt_pollset_enable_write,
    nxt_pollset_disable_read,
    nxt_pollset_disable_write,
    nxt_pollset_block_read,
    nxt_pollset_block_write,
    nxt_pollset_oneshot_read,
    nxt_pollset_oneshot_write,
    nxt_pollset_enable_read,
    NULL,
    NULL,
    NULL,
    NULL,
    nxt_pollset_poll,

    &nxt_unix_conn_io,

    NXT_NO_FILE_EVENTS,
    NXT_NO_SIGNAL_EVENTS,
};


static nxt_int_t
nxt_pollset_create(nxt_event_engine_t *engine, nxt_uint_t mchanges,
    nxt_uint_t mevents)
{
    void  *changes;

    engine->u.pollset.ps = -1;
    engine->u.pollset.mchanges = mchanges;
    engine->u.pollset.mevents = mevents;

    changes = nxt_malloc(sizeof(nxt_pollset_change_t) * mchanges);
    if (changes == NULL) {
        goto fail;
    }

    engine->u.pollset.changes = changes;

    /*
     * NXT_POLLSET_CHANGE requires two struct poll_ctl's
     * for PS_DELETE and subsequent PS_ADD.
     */
    changes = nxt_malloc(2 * sizeof(struct poll_ctl) * mchanges);
    if (changes == NULL) {
        goto fail;
    }

    engine->u.pollset.write_changes = changes;

    engine->u.pollset.events = nxt_malloc(sizeof(struct pollfd) * mevents);
    if (engine->u.pollset.events == NULL) {
        goto fail;
    }

    engine->u.pollset.ps = pollset_create(-1);

    if (engine->u.pollset.ps == -1) {
        nxt_alert(&engine->task, "pollset_create() failed %E", nxt_errno);
        goto fail;
    }

    nxt_debug(&engine->task, "pollset_create(): %d", engine->u.pollset.ps);

    return NXT_OK;

fail:

    nxt_pollset_free(engine);

    return NXT_ERROR;
}


static void
nxt_pollset_free(nxt_event_engine_t *engine)
{
    pollset_t  ps;

    ps = engine->u.pollset.ps;

    nxt_debug(&engine->task, "pollset %d free", ps);

    if (ps != -1 && pollset_destroy(ps) != 0) {
        nxt_alert(&engine->task, "pollset_destroy(%d) failed %E",
                  ps, nxt_errno);
    }

    nxt_free(engine->u.pollset.events);
    nxt_free(engine->u.pollset.write_changes);
    nxt_free(engine->u.pollset.changes);
    nxt_fd_event_hash_destroy(&engine->u.pollset.fd_hash);

    nxt_memzero(&engine->u.pollset, sizeof(nxt_pollset_engine_t));
}


static void
nxt_pollset_enable(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    ev->read = NXT_EVENT_ACTIVE;
    ev->write = NXT_EVENT_ACTIVE;

    nxt_pollset_change(engine, ev, NXT_POLLSET_ADD, POLLIN | POLLOUT);
}


static void
nxt_pollset_disable(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE || ev->write != NXT_EVENT_INACTIVE) {

        ev->read = NXT_EVENT_INACTIVE;
        ev->write = NXT_EVENT_INACTIVE;

        nxt_pollset_change(engine, ev, NXT_POLLSET_DELETE, 0);
    }
}


/*
 * A closed descriptor must be deleted from a pollset, otherwise next
 * pollset_poll() will return POLLNVAL on it.  However, pollset_ctl()
 * allows to delete the already closed file descriptor from the pollset
 * using PS_DELETE, so the removal can be batched, pollset_ctl(2):
 *
 *   After a file descriptor is added to a pollset, the file descriptor will
 *   not be removed until a pollset_ctl call with the cmd of PS_DELETE is
 *   executed.  The file descriptor remains in the pollset even if the file
 *   descriptor is closed.  A pollset_poll operation on a pollset containing
 *   a closed file descriptor returns a POLLNVAL event for that file
 *   descriptor. If the file descriptor is later allocated to a new object,
 *   the new object will be polled on future pollset_poll calls.
 */

static nxt_bool_t
nxt_pollset_close(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_pollset_disable(engine, ev);

    return ev->changing;
}


static void
nxt_pollset_enable_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_uint_t  op, events;

    if (ev->read != NXT_EVENT_BLOCKED) {

        events = POLLIN;

        if (ev->write == NXT_EVENT_INACTIVE) {
            op = NXT_POLLSET_ADD;

        } else if (ev->write == NXT_EVENT_BLOCKED) {
            ev->write = NXT_EVENT_INACTIVE;
            op = NXT_POLLSET_CHANGE;

        } else {
            op = NXT_POLLSET_UPDATE;
            events = POLLIN | POLLOUT;
        }

        nxt_pollset_change(engine, ev, op, events);
    }

    ev->read = NXT_EVENT_ACTIVE;
}


static void
nxt_pollset_enable_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_uint_t  op, events;

    if (ev->write != NXT_EVENT_BLOCKED) {

        events = POLLOUT;

        if (ev->read == NXT_EVENT_INACTIVE) {
            op = NXT_POLLSET_ADD;

        } else if (ev->read == NXT_EVENT_BLOCKED) {
            ev->read = NXT_EVENT_INACTIVE;
            op = NXT_POLLSET_CHANGE;

        } else {
            op = NXT_POLLSET_UPDATE;
            events = POLLIN | POLLOUT;
        }

        nxt_pollset_change(engine, ev, op, events);
    }

    ev->write = NXT_EVENT_ACTIVE;
}


static void
nxt_pollset_disable_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_uint_t  op, events;

    ev->read = NXT_EVENT_INACTIVE;

    if (ev->write <= NXT_EVENT_BLOCKED) {
        ev->write = NXT_EVENT_INACTIVE;
        op = NXT_POLLSET_DELETE;
        events = POLLREMOVE;

    } else {
        op = NXT_POLLSET_CHANGE;
        events = POLLOUT;
    }

    nxt_pollset_change(engine, ev, op, events);
}


static void
nxt_pollset_disable_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_uint_t  op, events;

    ev->write = NXT_EVENT_INACTIVE;

    if (ev->read <= NXT_EVENT_BLOCKED) {
        ev->read = NXT_EVENT_INACTIVE;
        op = NXT_POLLSET_DELETE;
        events = POLLREMOVE;

    } else {
        op = NXT_POLLSET_CHANGE;
        events = POLLIN;
    }

    nxt_pollset_change(engine, ev, op, events);
}


static void
nxt_pollset_block_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_pollset_block_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->write != NXT_EVENT_INACTIVE) {
        ev->write = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_pollset_oneshot_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_pollset_enable_read(engine, ev);

    ev->read = NXT_EVENT_ONESHOT;
}


static void
nxt_pollset_oneshot_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_pollset_enable_write(engine, ev);

    ev->write = NXT_EVENT_ONESHOT;
}


/*
 * PS_ADD adds only a new file descriptor to a pollset.
 * PS_DELETE removes a file descriptor from a pollset.
 *
 * PS_MOD can add a new file descriptor or modify events for a file
 * descriptor which is already in a pollset.  However, modified events
 * are always ORed, so to delete an event for a file descriptor,
 * the file descriptor must be removed using PS_DELETE and then
 * added again without the event.
 */

static void
nxt_pollset_change(nxt_event_engine_t *engine, nxt_fd_event_t *ev,
    nxt_uint_t op, nxt_uint_t events)
{
    nxt_pollset_change_t  *change;

    nxt_debug(ev->task, "pollset %d change fd:%d op:%ui ev:%04Xi",
              engine->u.pollset.ps, ev->fd, op, events);

    if (engine->u.pollset.nchanges >= engine->u.pollset.mchanges) {
        (void) nxt_pollset_commit_changes(engine);
    }

    ev->changing = 1;

    change = &engine->u.pollset.changes[engine->u.pollset.nchanges++];
    change->op = op;
    change->cmd = (op == NXT_POLLSET_DELETE) ? PS_DELETE : PS_MOD;
    change->events = events;
    change->event = ev;
}


static nxt_int_t
nxt_pollset_commit_changes(nxt_event_engine_t *engine)
{
    size_t                n;
    nxt_int_t             ret, retval;
    nxt_fd_event_t        *ev;
    struct poll_ctl       *ctl, *write_changes;
    nxt_pollset_change_t  *change, *end;

    nxt_debug(&engine->task, "pollset %d changes:%ui",
              engine->u.pollset.ps, engine->u.pollset.nchanges);

    retval = NXT_OK;
    n = 0;
    write_changes = engine->u.pollset.write_changes;
    change = engine->u.pollset.changes;
    end = change + engine->u.pollset.nchanges;

    do {
        ev = change->event;
        ev->changing = 0;

        nxt_debug(&engine->task, "pollset fd:%d op:%d ev:%04Xd",
                  ev->fd, change->op, change->events);

        if (change->op == NXT_POLLSET_CHANGE) {
            ctl = &write_changes[n++];
            ctl->cmd = PS_DELETE;
            ctl->events = 0;
            ctl->fd = ev->fd;
        }

        ctl = &write_changes[n++];
        ctl->cmd = change->cmd;
        ctl->events = change->events;
        ctl->fd = ev->fd;

        change++;

    } while (change < end);

    change = engine->u.pollset.changes;
    end = change + engine->u.pollset.nchanges;

    ret = nxt_pollset_write(engine, write_changes, n);

    if (nxt_slow_path(ret != NXT_OK)) {

        do {
            nxt_pollset_change_error(engine, change->event);
            change++;
        } while (change < end);

        engine->u.pollset.nchanges = 0;

        return NXT_ERROR;
    }

    do {
        ev = change->event;

        if (change->op == NXT_POLLSET_ADD) {
            ret = nxt_fd_event_hash_add(&engine->u.pollset.fd_hash, ev->fd, ev);

            if (nxt_slow_path(ret != NXT_OK)) {
                nxt_pollset_change_error(engine, ev);
                retval = NXT_ERROR;
            }

        } else if (change->op == NXT_POLLSET_DELETE) {
            nxt_fd_event_hash_delete(&engine->task, &engine->u.pollset.fd_hash,
                                     ev->fd, 0);
        }

        /* Nothing to do for NXT_POLLSET_UPDATE and NXT_POLLSET_CHANGE. */

        change++;

    } while (change < end);

    engine->u.pollset.nchanges = 0;

    return retval;
}


static void
nxt_pollset_change_error(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;

    nxt_work_queue_add(&engine->fast_work_queue, ev->error_handler,
                       ev->task, ev, ev->data);

    nxt_fd_event_hash_delete(&engine->task, &engine->u.pollset.fd_hash,
                             ev->fd, 1);

    nxt_pollset_remove(engine, ev->fd);
}


static void
nxt_pollset_remove(nxt_event_engine_t *engine, nxt_fd_t fd)
{
    int              n;
    struct pollfd    pfd;
    struct poll_ctl  ctl;

    pfd.fd = fd;
    pfd.events = 0;
    pfd.revents = 0;

    n = pollset_query(engine->u.pollset.ps, &pfd);

    nxt_debug(&engine->task, "pollset_query(%d, %d): %d",
              engine->u.pollset.ps, fd, n);

    if (n == 0) {
        /* The file descriptor is not in the pollset. */
        return;
    }

    if (n == -1) {
        nxt_alert(&engine->task, "pollset_query(%d, %d) failed %E",
                  engine->u.pollset.ps, fd, nxt_errno);
        /* Fall through. */
    }

    /* n == 1: The file descriptor is in the pollset. */

    nxt_debug(&engine->task, "pollset %d remove fd:%d",
              engine->u.pollset.ps, fd);

    ctl.cmd = PS_DELETE;
    ctl.events = 0;
    ctl.fd = fd;

    nxt_pollset_write(engine, &ctl, 1);
}


static nxt_int_t
nxt_pollset_write(nxt_event_engine_t *engine, struct poll_ctl *ctl, int n)
{
    pollset_t  ps;

    ps = engine->u.pollset.ps;

    nxt_debug(&engine->task, "pollset_ctl(%d) changes:%d", ps, n);

    nxt_set_errno(0);

    n = pollset_ctl(ps, ctl, n);

    if (nxt_fast_path(n == 0)) {
        return NXT_OK;
    }

    nxt_alert(&engine->task, "pollset_ctl(%d) failed: %d %E", ps, n, nxt_errno);

    return NXT_ERROR;
}


static void
nxt_pollset_poll(nxt_event_engine_t *engine, nxt_msec_t timeout)
{
    int             nevents;
    nxt_fd_t        fd;
    nxt_int_t       i;
    nxt_err_t       err;
    nxt_uint_t      events, level;
    struct pollfd   *pfd;
    nxt_fd_event_t  *ev;

    if (engine->u.pollset.nchanges != 0) {
        if (nxt_pollset_commit_changes(engine) != NXT_OK) {
            /* Error handlers have been enqueued on failure. */
            timeout = 0;
        }
    }

    nxt_debug(&engine->task, "pollset_poll(%d) timeout:%M",
              engine->u.pollset.ps, timeout);

    nevents = pollset_poll(engine->u.pollset.ps, engine->u.pollset.events,
                           engine->u.pollset.mevents, timeout);

    err = (nevents == -1) ? nxt_errno : 0;

    nxt_thread_time_update(engine->task.thread);

    nxt_debug(&engine->task, "pollset_poll(%d): %d",
              engine->u.pollset.ps, nevents);

    if (nevents == -1) {
        level = (err == NXT_EINTR) ? NXT_LOG_INFO : NXT_LOG_ALERT;

        nxt_log(&engine->task, level, "pollset_poll(%d) failed %E",
                engine->u.pollset.ps, err);

        return;
    }

    for (i = 0; i < nevents; i++) {

        pfd = &engine->u.pollset.events[i];
        fd = pfd->fd;
        events = pfd->revents;

        ev = nxt_fd_event_hash_get(&engine->task, &engine->u.pollset.fd_hash,
                                   fd);

        if (nxt_slow_path(ev == NULL)) {
            nxt_alert(&engine->task,
                      "pollset_poll(%d) returned invalid "
                      "fd:%d ev:%04Xd rev:%04uXi",
                      engine->u.pollset.ps, fd, pfd->events, events);

            nxt_pollset_remove(engine, fd);
            continue;
        }

        nxt_debug(ev->task, "pollset: fd:%d ev:%04uXi", fd, events);

        if (nxt_slow_path(events & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            nxt_alert(ev->task,
                      "pollset_poll(%d) error fd:%d ev:%04Xd rev:%04uXi",
                      engine->u.pollset.ps, fd, pfd->events, events);

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
                nxt_pollset_disable_read(engine, ev);
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
                nxt_pollset_disable_write(engine, ev);
            }
        }
    }
}

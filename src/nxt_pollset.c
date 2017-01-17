
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


static nxt_event_set_t *nxt_pollset_create(nxt_event_signals_t *signals,
    nxt_uint_t mchanges, nxt_uint_t mevents);
static void nxt_pollset_free(nxt_event_set_t *event_set);
static void nxt_pollset_enable(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_pollset_disable(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_pollset_enable_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_pollset_enable_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_pollset_disable_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_pollset_disable_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_pollset_block_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_pollset_block_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_pollset_oneshot_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_pollset_oneshot_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_pollset_change(nxt_event_set_t *event_set, nxt_event_fd_t *ev,
    nxt_uint_t op, nxt_uint_t events);
static nxt_int_t nxt_pollset_commit_changes(nxt_thread_t *thr,
    nxt_pollset_event_set_t *ps);
static void nxt_pollset_change_error(nxt_thread_t *thr,
    nxt_pollset_event_set_t *ps, nxt_event_fd_t *ev);
static void nxt_pollset_remove(nxt_thread_t *thr, nxt_pollset_event_set_t *ps,
    nxt_fd_t fd);
static nxt_int_t nxt_pollset_write(nxt_thread_t *thr, int pollset,
    struct poll_ctl *ctl, int n);
static void nxt_pollset_poll(nxt_thread_t *thr, nxt_event_set_t *event_set,
    nxt_msec_t timeout);


const nxt_event_set_ops_t  nxt_pollset_event_set = {
    "pollset",
    nxt_pollset_create,
    nxt_pollset_free,
    nxt_pollset_enable,
    nxt_pollset_disable,
    nxt_pollset_disable,
    nxt_pollset_disable,
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

    &nxt_unix_event_conn_io,

    NXT_NO_FILE_EVENTS,
    NXT_NO_SIGNAL_EVENTS,
};


static nxt_event_set_t *
nxt_pollset_create(nxt_event_signals_t *signals, nxt_uint_t mchanges,
    nxt_uint_t mevents)
{
    nxt_event_set_t          *event_set;
    nxt_pollset_event_set_t  *ps;

    event_set = nxt_zalloc(sizeof(nxt_pollset_event_set_t));
    if (event_set == NULL) {
        return NULL;
    }

    ps = &event_set->pollset;

    ps->pollset = -1;
    ps->mchanges = mchanges;
    ps->mevents = mevents;

    ps->pollset_changes = nxt_malloc(sizeof(nxt_pollset_change_t) * mchanges);
    if (ps->pollset_changes == NULL) {
        goto fail;
    }

    /*
     * NXT_POLLSET_CHANGE requires two struct poll_ctl's
     * for PS_DELETE and subsequent PS_ADD.
     */
    ps->changes = nxt_malloc(2 * sizeof(struct poll_ctl) * mchanges);
    if (ps->changes == NULL) {
        goto fail;
    }

    ps->events = nxt_malloc(sizeof(struct pollfd) * mevents);
    if (ps->events == NULL) {
        goto fail;
    }

    ps->pollset = pollset_create(-1);
    if (ps->pollset == -1) {
        nxt_main_log_emerg("pollset_create() failed %E", nxt_errno);
        goto fail;
    }

    nxt_main_log_debug("pollset_create(): %d", ps->pollset);

    return event_set;

fail:

    nxt_pollset_free(event_set);

    return NULL;
}


static void
nxt_pollset_free(nxt_event_set_t *event_set)
{
    nxt_pollset_event_set_t  *ps;

    ps = &event_set->pollset;

    nxt_main_log_debug("pollset %d free", ps->pollset);

    if (ps->pollset != -1) {
        if (pollset_destroy(ps->pollset) != 0) {
            nxt_main_log_emerg("pollset_destroy(%d) failed %E",
                               ps->pollset, nxt_errno);
        }
    }

    nxt_free(ps->events);
    nxt_free(ps->changes);
    nxt_free(ps->pollset_changes);
    nxt_event_set_fd_hash_destroy(&ps->fd_hash);
    nxt_free(ps);
}


static void
nxt_pollset_enable(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->read = NXT_EVENT_DEFAULT;
    ev->write = NXT_EVENT_DEFAULT;

    nxt_pollset_change(event_set, ev, NXT_POLLSET_ADD, POLLIN | POLLOUT);
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

static void
nxt_pollset_disable(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE || ev->write != NXT_EVENT_INACTIVE) {

        ev->read = NXT_EVENT_INACTIVE;
        ev->write = NXT_EVENT_INACTIVE;

        nxt_pollset_change(event_set, ev, NXT_POLLSET_DELETE, 0);
    }
}


static void
nxt_pollset_enable_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
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

        nxt_pollset_change(event_set, ev, op, events);
    }

    ev->read = NXT_EVENT_DEFAULT;
}


static void
nxt_pollset_enable_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
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

        nxt_pollset_change(event_set, ev, op, events);
    }

    ev->write = NXT_EVENT_DEFAULT;
}


static void
nxt_pollset_disable_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
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

    nxt_pollset_change(event_set, ev, op, events);
}


static void
nxt_pollset_disable_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
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

    nxt_pollset_change(event_set, ev, op, events);
}


static void
nxt_pollset_block_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_pollset_block_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->write != NXT_EVENT_INACTIVE) {
        ev->write = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_pollset_oneshot_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_pollset_enable_read(event_set, ev);

    ev->read = NXT_EVENT_ONESHOT;
}


static void
nxt_pollset_oneshot_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_pollset_enable_write(event_set, ev);

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
nxt_pollset_change(nxt_event_set_t *event_set, nxt_event_fd_t *ev,
    nxt_uint_t op, nxt_uint_t events)
{
    nxt_pollset_change_t     *ch;
    nxt_pollset_event_set_t  *ps;

    ps = &event_set->pollset;

    nxt_log_debug(ev->log, "pollset %d change fd:%d op:%ui ev:%04Xi",
                  ps->pollset, ev->fd, op, events);

    if (ps->nchanges >= ps->mchanges) {
        (void) nxt_pollset_commit_changes(nxt_thread(), ps);
    }

    ch = &ps->pollset_changes[ps->nchanges++];
    ch->op = op;
    ch->cmd = (op == NXT_POLLSET_DELETE) ? PS_DELETE : PS_MOD;
    ch->fd = ev->fd;
    ch->events = events;
    ch->event = ev;
}


static nxt_int_t
nxt_pollset_commit_changes(nxt_thread_t *thr, nxt_pollset_event_set_t *ps)
{
    size_t                n;
    nxt_int_t             ret, retval;
    struct poll_ctl       *ctl;
    nxt_pollset_change_t  *ch, *end;

    nxt_log_debug(thr->log, "pollset %d changes:%ui",
                  ps->pollset, ps->nchanges);

    retval = NXT_OK;
    n = 0;
    ch = ps->pollset_changes;
    end = ch + ps->nchanges;

    do {
        nxt_log_debug(thr->log, "pollset fd:%d op:%d ev:%04Xd",
                      ch->fd, ch->op, ch->events);

        if (ch->op == NXT_POLLSET_CHANGE) {
            ctl = &ps->changes[n++];
            ctl->cmd = PS_DELETE;
            ctl->events = 0;
            ctl->fd = ch->fd;
        }

        ctl = &ps->changes[n++];
        ctl->cmd = ch->cmd;
        ctl->events = ch->events;
        ctl->fd = ch->fd;

        ch++;

    } while (ch < end);

    ch = ps->pollset_changes;
    end = ch + ps->nchanges;

    ret = nxt_pollset_write(thr, ps->pollset, ps->changes, n);

    if (nxt_slow_path(ret != NXT_OK)) {
        do {
            nxt_pollset_change_error(thr, ps, ch->event);
            ch++;
        } while (ch < end);

        ps->nchanges = 0;

        return NXT_ERROR;
    }

    do {
        if (ch->op == NXT_POLLSET_ADD) {
            ret = nxt_event_set_fd_hash_add(&ps->fd_hash, ch->fd, ch->event);

            if (nxt_slow_path(ret != NXT_OK)) {
                nxt_pollset_change_error(thr, ps, ch->event);
                retval = NXT_ERROR;
            }

        } else if (ch->op == NXT_POLLSET_DELETE) {
            nxt_event_set_fd_hash_delete(&ps->fd_hash, ch->fd, 0);
        }

        /* Nothing to do for NXT_POLLSET_UPDATE and NXT_POLLSET_CHANGE. */

        ch++;

    } while (ch < end);

    ps->nchanges = 0;

    return retval;
}


static void
nxt_pollset_change_error(nxt_thread_t *thr, nxt_pollset_event_set_t *ps,
    nxt_event_fd_t *ev)
{
    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;

    nxt_thread_work_queue_add(thr, &thr->work_queue.main,
                              ev->error_handler, ev, ev->data, ev->log);

    nxt_event_set_fd_hash_delete(&ps->fd_hash, ev->fd, 1);

    nxt_pollset_remove(thr, ps, ev->fd);
}


static void
nxt_pollset_remove(nxt_thread_t *thr, nxt_pollset_event_set_t *ps, nxt_fd_t fd)
{
    int              n;
    struct pollfd    pfd;
    struct poll_ctl  ctl;

    pfd.fd = fd;
    pfd.events = 0;
    pfd.revents = 0;

    n = pollset_query(ps->pollset, &pfd);

    nxt_thread_log_debug("pollset_query(%d, %d): %d", ps->pollset, fd, n);

    if (n == 0) {
        /* The file descriptor is not in the pollset. */
        return;
    }

    if (n == -1) {
        nxt_thread_log_alert("pollset_query(%d, %d) failed %E",
                             ps->pollset, fd, nxt_errno);
        /* Fall through. */
    }

    /* n == 1: The file descriptor is in the pollset. */

    nxt_thread_log_debug("pollset %d remove fd:%d", ps->pollset, fd);

    ctl.cmd = PS_DELETE;
    ctl.events = 0;
    ctl.fd = fd;

    nxt_pollset_write(thr, ps->pollset, &ctl, 1);
}


static nxt_int_t
nxt_pollset_write(nxt_thread_t *thr, int pollset, struct poll_ctl *ctl, int n)
{
    nxt_thread_log_debug("pollset_ctl(%d) changes:%d", pollset, n);

    nxt_set_errno(0);

    n = pollset_ctl(pollset, ctl, n);

    if (nxt_fast_path(n == 0)) {
        return NXT_OK;
    }

    nxt_log_alert(thr->log, "pollset_ctl(%d) failed: %d %E",
                  pollset, n, nxt_errno);

    return NXT_ERROR;
}


static void
nxt_pollset_poll(nxt_thread_t *thr, nxt_event_set_t *event_set,
    nxt_msec_t timeout)
{
    int                      nevents;
    nxt_fd_t                 fd;
    nxt_int_t                i;
    nxt_err_t                err;
    nxt_uint_t               events, level;
    struct pollfd            *pfd;
    nxt_event_fd_t           *ev;
    nxt_pollset_event_set_t  *ps;

    ps = &event_set->pollset;

    if (ps->nchanges != 0) {
        if (nxt_pollset_commit_changes(thr, ps) != NXT_OK) {
            /* Error handlers have been enqueued on failure. */
            timeout = 0;
        }
    }

    nxt_log_debug(thr->log, "pollset_poll(%d) timeout:%M",
                  ps->pollset, timeout);

    nevents = pollset_poll(ps->pollset, ps->events, ps->mevents, timeout);

    err = (nevents == -1) ? nxt_errno : 0;

    nxt_thread_time_update(thr);

    nxt_log_debug(thr->log, "pollset_poll(%d): %d", ps->pollset, nevents);

    if (nevents == -1) {
        level = (err == NXT_EINTR) ? NXT_LOG_INFO : NXT_LOG_ALERT;
        nxt_log_error(level, thr->log, "pollset_poll(%d) failed %E",
                      ps->pollset, err);
        return;
    }

    for (i = 0; i < nevents; i++) {

        pfd = &ps->events[i];
        fd = pfd->fd;
        events = pfd->revents;

        ev = nxt_event_set_fd_hash_get(&ps->fd_hash, fd);

        if (nxt_slow_path(ev == NULL)) {
            nxt_log_alert(thr->log, "pollset_poll(%d) returned invalid "
                          "fd:%d ev:%04Xd rev:%04uXi",
                          ps->pollset, fd, pfd->events, events);

            nxt_pollset_remove(thr, ps, fd);
            continue;
        }

        nxt_log_debug(ev->log, "pollset: fd:%d ev:%04uXi", fd, events);

        if (nxt_slow_path(events & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            nxt_log_alert(ev->log,
                          "pollset_poll(%d) error fd:%d ev:%04Xd rev:%04uXi",
                          ps->pollset, fd, pfd->events, events);

            nxt_thread_work_queue_add(thr, &thr->work_queue.main,
                                      ev->error_handler, ev, ev->data, ev->log);
            continue;
        }

        if (events & POLLIN) {
            ev->read_ready = 1;

            if (ev->read != NXT_EVENT_BLOCKED) {

                if (ev->read == NXT_EVENT_ONESHOT) {
                    nxt_pollset_disable_read(event_set, ev);
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
                    nxt_pollset_disable_write(event_set, ev);
                }

                nxt_thread_work_queue_add(thr, ev->write_work_queue,
                                          ev->write_handler,
                                          ev, ev->data, ev->log);
            }
        }
    }
}

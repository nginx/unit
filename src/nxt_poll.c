
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


#define NXT_POLL_ADD     0
#define NXT_POLL_CHANGE  1
#define NXT_POLL_DELETE  2


typedef struct {
    /*
     * A file descriptor is stored in hash entry to allow
     * nxt_poll_fd_hash_test() to not dereference a pointer to
     * nxt_event_fd_t which may be invalid if the file descriptor has
     * been already closed and the nxt_event_fd_t's memory has been freed.
     */
    nxt_socket_t         fd;

    uint32_t             index;
    void                 *event;
} nxt_poll_hash_entry_t;


static nxt_event_set_t *nxt_poll_create(nxt_event_signals_t *signals,
    nxt_uint_t mchanges, nxt_uint_t mevents);
static void nxt_poll_free(nxt_event_set_t *event_set);
static void nxt_poll_enable(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_poll_disable(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_poll_drop_changes(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_poll_enable_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_poll_enable_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_poll_disable_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_poll_disable_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_poll_block_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_poll_block_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_poll_oneshot_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_poll_oneshot_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_poll_change(nxt_event_set_t *event_set, nxt_event_fd_t *ev,
    nxt_uint_t op, nxt_uint_t events);
static nxt_int_t nxt_poll_commit_changes(nxt_thread_t *thr,
    nxt_poll_event_set_t *ps);
static nxt_int_t nxt_poll_set_add(nxt_thread_t *thr, nxt_poll_event_set_t *ps,
    nxt_poll_change_t *ch);
static nxt_int_t nxt_poll_set_change(nxt_thread_t *thr,
    nxt_poll_event_set_t *ps, nxt_poll_change_t *ch);
static nxt_int_t nxt_poll_set_delete(nxt_thread_t *thr,
    nxt_poll_event_set_t *ps, nxt_poll_change_t *ch);
static void nxt_poll_set_poll(nxt_thread_t *thr, nxt_event_set_t *event_set,
    nxt_msec_t timeout);
static nxt_poll_hash_entry_t *nxt_poll_fd_hash_get(nxt_poll_event_set_t *ps,
    nxt_fd_t fd);
static nxt_int_t nxt_poll_fd_hash_test(nxt_lvlhsh_query_t *lhq, void *data);
static void nxt_poll_fd_hash_destroy(nxt_lvlhsh_t *lh);


const nxt_event_set_ops_t  nxt_poll_event_set = {
    "poll",
    nxt_poll_create,
    nxt_poll_free,
    nxt_poll_enable,
    nxt_poll_disable,
    nxt_poll_disable,
    nxt_poll_disable,
    nxt_poll_enable_read,
    nxt_poll_enable_write,
    nxt_poll_disable_read,
    nxt_poll_disable_write,
    nxt_poll_block_read,
    nxt_poll_block_write,
    nxt_poll_oneshot_read,
    nxt_poll_oneshot_write,
    nxt_poll_enable_read,
    NULL,
    NULL,
    NULL,
    NULL,
    nxt_poll_set_poll,

    &nxt_unix_event_conn_io,

    NXT_NO_FILE_EVENTS,
    NXT_NO_SIGNAL_EVENTS,
};


static const nxt_lvlhsh_proto_t  nxt_poll_fd_hash_proto  nxt_aligned(64) =
{
    NXT_LVLHSH_LARGE_MEMALIGN,
    0,
    nxt_poll_fd_hash_test,
    nxt_lvlhsh_alloc,
    nxt_lvlhsh_free,
};


static nxt_event_set_t *
nxt_poll_create(nxt_event_signals_t *signals, nxt_uint_t mchanges,
    nxt_uint_t mevents)
{
    nxt_event_set_t       *event_set;
    nxt_poll_event_set_t  *ps;

    event_set = nxt_zalloc(sizeof(nxt_poll_event_set_t));
    if (event_set == NULL) {
        return NULL;
    }

    ps = &event_set->poll;

    ps->mchanges = mchanges;

    ps->changes = nxt_malloc(sizeof(nxt_poll_change_t) * mchanges);
    if (ps->changes == NULL) {
        nxt_free(event_set);
        return NULL;
    }

    return event_set;
}


static void
nxt_poll_free(nxt_event_set_t *event_set)
{
    nxt_poll_event_set_t  *ps;

    ps = &event_set->poll;

    nxt_main_log_debug("poll free");

    nxt_free(ps->poll_set);
    nxt_free(ps->changes);
    nxt_poll_fd_hash_destroy(&ps->fd_hash);
    nxt_free(ps);
}


static void
nxt_poll_enable(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->read = NXT_EVENT_DEFAULT;
    ev->write = NXT_EVENT_DEFAULT;

    nxt_poll_change(event_set, ev, NXT_POLL_ADD, POLLIN | POLLOUT);
}


static void
nxt_poll_disable(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;

    nxt_poll_drop_changes(event_set, ev);
    /*
     * A simple non-zero value POLLHUP is a flag to ignore error handling
     * if the event is not present in poll set, because the event may be
     * freed at the time when the NXT_POLL_DELETE change will be processed
     * and correct event error_handler will not be available.
     */
    nxt_poll_change(event_set, ev, NXT_POLL_DELETE, POLLHUP);
}


static void
nxt_poll_drop_changes(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_poll_change_t     *dst, *src, *end;
    nxt_poll_event_set_t  *ps;

    ps = &event_set->poll;

    dst = ps->changes;
    end = dst + ps->nchanges;

    for (src = dst; src < end; src++) {

        if (src->event == ev) {
            continue;
        }

        if (dst != src) {
            *dst = *src;
        }

        dst++;
    }

    ps->nchanges -= end - dst;
}


static void
nxt_poll_enable_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_uint_t  op, events;

    ev->read = NXT_EVENT_DEFAULT;

    if (ev->write == NXT_EVENT_INACTIVE) {
        op = NXT_POLL_ADD;
        events = POLLIN;

    } else {
        op = NXT_POLL_CHANGE;
        events = POLLIN | POLLOUT;
    }

    nxt_poll_change(event_set, ev, op, events);
}


static void
nxt_poll_enable_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_uint_t  op, events;

    ev->write = NXT_EVENT_DEFAULT;

    if (ev->read == NXT_EVENT_INACTIVE) {
        op = NXT_POLL_ADD;
        events = POLLOUT;

    } else {
        op = NXT_POLL_CHANGE;
        events = POLLIN | POLLOUT;
    }

    nxt_poll_change(event_set, ev, op, events);
}


static void
nxt_poll_disable_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_uint_t  op, events;

    ev->read = NXT_EVENT_INACTIVE;

    if (ev->write == NXT_EVENT_INACTIVE) {
        op = NXT_POLL_DELETE;
        events = 0;

    } else {
        op = NXT_POLL_CHANGE;
        events = POLLOUT;
    }

    nxt_poll_change(event_set, ev, op, events);
}


static void
nxt_poll_disable_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_uint_t  op, events;

    ev->write = NXT_EVENT_INACTIVE;

    if (ev->read == NXT_EVENT_INACTIVE) {
        op = NXT_POLL_DELETE;
        events = 0;

    } else {
        op = NXT_POLL_CHANGE;
        events = POLLIN;
    }

    nxt_poll_change(event_set, ev, op, events);
}


static void
nxt_poll_block_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        nxt_poll_disable_read(event_set, ev);
    }
}


static void
nxt_poll_block_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->write != NXT_EVENT_INACTIVE) {
        nxt_poll_disable_write(event_set, ev);
    }
}


static void
nxt_poll_oneshot_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_uint_t  op;

    op = (ev->read == NXT_EVENT_INACTIVE && ev->write == NXT_EVENT_INACTIVE) ?
             NXT_POLL_ADD : NXT_POLL_CHANGE;

    ev->read = NXT_EVENT_ONESHOT;
    ev->write = NXT_EVENT_INACTIVE;

    nxt_poll_change(event_set, ev, op, POLLIN);
}


static void
nxt_poll_oneshot_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_uint_t  op;

    op = (ev->read == NXT_EVENT_INACTIVE && ev->write == NXT_EVENT_INACTIVE) ?
             NXT_POLL_ADD : NXT_POLL_CHANGE;

    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_ONESHOT;

    nxt_poll_change(event_set, ev, op, POLLOUT);
}


/*
 * poll changes are batched to improve instruction and data cache
 * locality of several lvlhsh operations followed by poll() call.
 */

static void
nxt_poll_change(nxt_event_set_t *event_set, nxt_event_fd_t *ev, nxt_uint_t op,
    nxt_uint_t events)
{
    nxt_poll_change_t     *ch;
    nxt_poll_event_set_t  *ps;

    nxt_log_debug(ev->log, "poll change: fd:%d op:%d ev:%XD",
                  ev->fd, op, events);

    ps = &event_set->poll;

    if (ps->nchanges >= ps->mchanges) {
        (void) nxt_poll_commit_changes(nxt_thread(), ps);
    }

    ch = &ps->changes[ps->nchanges++];
    ch->op = op;
    ch->fd = ev->fd;
    ch->events = events;
    ch->event = ev;
}


static nxt_int_t
nxt_poll_commit_changes(nxt_thread_t *thr, nxt_poll_event_set_t *ps)
{
    nxt_int_t          ret;
    nxt_event_fd_t     *ev;
    nxt_poll_change_t  *ch, *end;

    nxt_log_debug(thr->log, "poll changes:%ui", ps->nchanges);

    ret = NXT_OK;
    ch = ps->changes;
    end = ch + ps->nchanges;

    do {
        ev = ch->event;

        switch (ch->op) {

        case NXT_POLL_ADD:
            if (nxt_fast_path(nxt_poll_set_add(thr, ps, ch) == NXT_OK)) {
                goto next;
            }
            break;

        case NXT_POLL_CHANGE:
            if (nxt_fast_path(nxt_poll_set_change(thr, ps, ch) == NXT_OK)) {
                goto next;
            }
            break;

        case NXT_POLL_DELETE:
            if (nxt_fast_path(nxt_poll_set_delete(thr, ps, ch) == NXT_OK)) {
                goto next;
            }
            break;
        }

        nxt_thread_work_queue_add(thr, &thr->work_queue.main,
                                  ev->error_handler, ev, ev->data, ev->log);

        ret = NXT_ERROR;

      next:

        ch++;

    } while (ch < end);

    ps->nchanges = 0;

    return ret;
}


static nxt_int_t
nxt_poll_set_add(nxt_thread_t *thr, nxt_poll_event_set_t *ps,
    nxt_poll_change_t *ch)
{
    nxt_uint_t             max_nfds;
    struct pollfd          *pfd;
    nxt_lvlhsh_query_t     lhq;
    nxt_poll_hash_entry_t  *phe;

    nxt_log_debug(thr->log, "poll add event: fd:%d ev:%04Xi",
                  ch->fd, ch->events);

    if (ps->nfds >= ps->max_nfds) {
        max_nfds = ps->max_nfds + 512; /* 4K */

        pfd = nxt_realloc(ps->poll_set, sizeof(struct pollfd) * max_nfds);
        if (nxt_slow_path(pfd == NULL)) {
            return NXT_ERROR;
        }

        ps->poll_set = pfd;
        ps->max_nfds = max_nfds;
    }

    phe = nxt_malloc(sizeof(nxt_poll_hash_entry_t));
    if (nxt_slow_path(phe == NULL)) {
        return NXT_ERROR;
    }

    phe->fd = ch->fd;
    phe->index = ps->nfds;
    phe->event = ch->event;

    pfd = &ps->poll_set[ps->nfds++];
    pfd->fd = ch->fd;
    pfd->events = ch->events;
    pfd->revents = 0;

    lhq.key_hash = nxt_murmur_hash2(&ch->fd, sizeof(nxt_fd_t));
    lhq.replace = 0;
    lhq.key.len = sizeof(nxt_fd_t);
    lhq.key.data = (u_char *) &ch->fd;
    lhq.value = phe;
    lhq.proto = &nxt_poll_fd_hash_proto;
    lhq.data = ps->poll_set;

    if (nxt_fast_path(nxt_lvlhsh_insert(&ps->fd_hash, &lhq) == NXT_OK)) {
        return NXT_OK;
    }

    nxt_free(phe);

    return NXT_ERROR;
}


static nxt_int_t
nxt_poll_set_change(nxt_thread_t *thr, nxt_poll_event_set_t *ps,
    nxt_poll_change_t *ch)
{
    nxt_poll_hash_entry_t  *phe;

    nxt_log_debug(thr->log, "poll change event: fd:%d ev:%04Xi",
                  ch->fd, ch->events);

    phe = nxt_poll_fd_hash_get(ps, ch->fd);

    if (nxt_fast_path(phe != NULL)) {
        ps->poll_set[phe->index].events = ch->events;
        return NXT_OK;
    }

    return NXT_ERROR;
}


static nxt_int_t
nxt_poll_set_delete(nxt_thread_t *thr, nxt_poll_event_set_t *ps,
    nxt_poll_change_t *ch)
{
    nxt_uint_t             index;
    nxt_lvlhsh_query_t     lhq;
    nxt_poll_hash_entry_t  *phe;

    nxt_log_debug(thr->log, "poll delete event: fd:%d", ch->fd);

    lhq.key_hash = nxt_murmur_hash2(&ch->fd, sizeof(nxt_fd_t));
    lhq.key.len = sizeof(nxt_fd_t);
    lhq.key.data = (u_char *) &ch->fd;
    lhq.proto = &nxt_poll_fd_hash_proto;
    lhq.data = ps->poll_set;

    if (nxt_slow_path(nxt_lvlhsh_delete(&ps->fd_hash, &lhq) != NXT_OK)) {
        /*
         * Ignore NXT_DECLINED error if ch->events
         * has the special value POLLHUP.
         */
        return (ch->events != 0) ? NXT_OK : NXT_ERROR;
    }

    phe = lhq.value;

    index = phe->index;
    ps->nfds--;

    if (index != ps->nfds) {
        ps->poll_set[index] = ps->poll_set[ps->nfds];

        phe = nxt_poll_fd_hash_get(ps, ps->poll_set[ps->nfds].fd);

        phe->index = index;
    }

    nxt_free(lhq.value);

    return NXT_OK;
}


static void
nxt_poll_set_poll(nxt_thread_t *thr, nxt_event_set_t *event_set,
    nxt_msec_t timeout)
{
    int                    nevents;
    nxt_fd_t               fd;
    nxt_err_t              err;
    nxt_bool_t             error;
    nxt_uint_t             i, events, level;
    struct pollfd          *pfd;
    nxt_event_fd_t         *ev;
    nxt_poll_event_set_t   *ps;
    nxt_poll_hash_entry_t  *phe;

    ps = &event_set->poll;

    if (ps->nchanges != 0) {
        if (nxt_poll_commit_changes(nxt_thread(), ps) != NXT_OK) {
            /* Error handlers have been enqueued on failure. */
            timeout = 0;
        }
    }

    nxt_log_debug(thr->log, "poll() events:%ui timeout:%M", ps->nfds, timeout);

    nevents = poll(ps->poll_set, ps->nfds, timeout);

    err = (nevents == -1) ? nxt_errno : 0;

    nxt_thread_time_update(thr);

    nxt_log_debug(thr->log, "poll(): %d", nevents);

    if (nevents == -1) {
        level = (err == NXT_EINTR) ? NXT_LOG_INFO : NXT_LOG_ALERT;
        nxt_log_error(level, thr->log, "poll() failed %E", err);
        return;
    }

    for (i = 0; i < ps->nfds && nevents != 0; i++) {

        pfd = &ps->poll_set[i];
        events = pfd->revents;

        if (events == 0) {
            continue;
        }

        fd = pfd->fd;

        phe = nxt_poll_fd_hash_get(ps, fd);

        if (nxt_slow_path(phe == NULL)) {
            nxt_log_alert(thr->log,
                          "poll() returned invalid fd:%d ev:%04Xd rev:%04uXi",
                          fd, pfd->events, events);

            /* Mark the poll entry to ignore it by the kernel. */
            pfd->fd = -1;
            goto next;
        }

        ev = phe->event;

        nxt_log_debug(ev->log, "poll: fd:%d ev:%04uXi rd:%d %wr:%d",
                      fd, events, ev->read, ev->write);

        if (nxt_slow_path((events & POLLNVAL) != 0)) {
            nxt_log_alert(ev->log, "poll() error fd:%d ev:%04Xd rev:%04uXi",
                          fd, pfd->events, events);

            /* Mark the poll entry to ignore it by the kernel. */
            pfd->fd = -1;

            nxt_thread_work_queue_add(thr, &thr->work_queue.main,
                                      ev->error_handler, ev, ev->data, ev->log);
            goto next;
        }

        /*
         * On a socket's remote end close:
         *
         *   Linux, FreeBSD, and Solaris set POLLIN;
         *   MacOSX sets POLLIN and POLLHUP;
         *   NetBSD sets POLLIN, and poll(2) claims this explicitly:
         *
         *     If the remote end of a socket is closed, poll()
         *     returns a POLLIN event, rather than a POLLHUP.
         *
         * On error:
         *
         *   Linux sets POLLHUP and POLLERR only;
         *   FreeBSD adds POLLHUP to POLLIN or POLLOUT, although poll(2)
         *   claims the opposite:
         *
         *     Note that POLLHUP and POLLOUT should never be
         *     present in the revents bitmask at the same time.
         *
         *   Solaris and NetBSD do not add POLLHUP or POLLERR;
         *   MacOSX sets POLLHUP only.
         *
         * If an implementation sets POLLERR or POLLHUP only without POLLIN
         * or POLLOUT, the "error" variable enqueues only one active handler.
         */

        error = (((events & (POLLERR | POLLHUP)) != 0)
                 && ((events & (POLLIN | POLLOUT)) == 0));

        if ((events & POLLIN) || (error && ev->read_handler != NULL)) {
            error = 0;
            ev->read_ready = 1;

            if (ev->read == NXT_EVENT_ONESHOT) {
                ev->read = NXT_EVENT_INACTIVE;
                nxt_poll_change(event_set, ev, NXT_POLL_DELETE, 0);
            }

            nxt_thread_work_queue_add(thr, ev->read_work_queue,
                                      ev->read_handler, ev, ev->data, ev->log);
        }

        if ((events & POLLOUT) || (error && ev->write_handler != NULL)) {
            ev->write_ready = 1;

            if (ev->write == NXT_EVENT_ONESHOT) {
                ev->write = NXT_EVENT_INACTIVE;
                nxt_poll_change(event_set, ev, NXT_POLL_DELETE, 0);
            }

            nxt_thread_work_queue_add(thr, ev->write_work_queue,
                                      ev->write_handler, ev, ev->data, ev->log);
        }

    next:

        nevents--;
    }
}


static nxt_poll_hash_entry_t *
nxt_poll_fd_hash_get(nxt_poll_event_set_t *ps, nxt_fd_t fd)
{
    nxt_lvlhsh_query_t     lhq;
    nxt_poll_hash_entry_t  *phe;

    lhq.key_hash = nxt_murmur_hash2(&fd, sizeof(nxt_fd_t));
    lhq.key.len = sizeof(nxt_fd_t);
    lhq.key.data = (u_char *) &fd;
    lhq.proto = &nxt_poll_fd_hash_proto;
    lhq.data = ps->poll_set;

    if (nxt_lvlhsh_find(&ps->fd_hash, &lhq) == NXT_OK) {
        phe = lhq.value;
        return phe;
    }

    nxt_thread_log_alert("fd %d not found in hash", fd);

    return NULL;
}


static nxt_int_t
nxt_poll_fd_hash_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    struct pollfd          *poll_set;
    nxt_poll_hash_entry_t  *phe;

    phe = data;

    if (*(nxt_fd_t *) lhq->key.data == phe->fd) {
        poll_set = lhq->data;

        if (nxt_fast_path(phe->fd == poll_set[phe->index].fd)) {
            return NXT_OK;
        }

        nxt_thread_log_alert("fd %d in hash mismatches fd %d in poll set",
                             phe->fd, poll_set[phe->index].fd);
    }

    return NXT_DECLINED;
}


static void
nxt_poll_fd_hash_destroy(nxt_lvlhsh_t *lh)
{
    nxt_lvlhsh_each_t      lhe;
    nxt_lvlhsh_query_t     lhq;
    nxt_poll_hash_entry_t  *phe;

    nxt_memzero(&lhe, sizeof(nxt_lvlhsh_each_t));
    lhe.proto = &nxt_poll_fd_hash_proto;
    lhq.proto = &nxt_poll_fd_hash_proto;

    for ( ;; ) {
        phe = nxt_lvlhsh_each(lh, &lhe);

        if (phe == NULL) {
            return;
        }

        lhq.key_hash = nxt_murmur_hash2(&phe->fd, sizeof(nxt_fd_t));
        lhq.key.len = sizeof(nxt_fd_t);
        lhq.key.data = (u_char *) &phe->fd;

        if (nxt_lvlhsh_delete(lh, &lhq) != NXT_OK) {
            nxt_thread_log_alert("event fd %d not found in hash", phe->fd);
        }

        nxt_free(phe);
    }
}

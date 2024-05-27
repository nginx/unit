
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
     * nxt_fd_event_t which may be invalid if the file descriptor has
     * been already closed and the nxt_fd_event_t's memory has been freed.
     */
    nxt_socket_t         fd;

    uint32_t             index;
    void                 *event;
} nxt_poll_hash_entry_t;


static nxt_int_t nxt_poll_create(nxt_event_engine_t *engine,
    nxt_uint_t mchanges, nxt_uint_t mevents);
static void nxt_poll_free(nxt_event_engine_t *engine);
static void nxt_poll_enable(nxt_event_engine_t *engine, nxt_fd_event_t *ev);
static void nxt_poll_disable(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static nxt_bool_t nxt_poll_close(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_poll_enable_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_poll_enable_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_poll_disable_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_poll_disable_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_poll_block_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev);
static void nxt_poll_block_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_poll_oneshot_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_poll_oneshot_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_poll_change(nxt_event_engine_t *engine, nxt_fd_event_t *ev,
    nxt_uint_t op, nxt_uint_t events);
static nxt_int_t nxt_poll_commit_changes(nxt_event_engine_t *engine);
static nxt_int_t nxt_poll_set_add(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev, int events);
static nxt_int_t nxt_poll_set_change(nxt_event_engine_t *engine,
    nxt_fd_t fd, int events);
static nxt_int_t nxt_poll_set_delete(nxt_event_engine_t *engine, nxt_fd_t fd);
static void nxt_poll(nxt_event_engine_t *engine, nxt_msec_t timeout);
static nxt_poll_hash_entry_t *nxt_poll_fd_hash_get(nxt_event_engine_t *engine,
    nxt_fd_t fd);
static nxt_int_t nxt_poll_fd_hash_test(nxt_lvlhsh_query_t *lhq, void *data);
static void nxt_poll_fd_hash_destroy(nxt_event_engine_t *engine,
    nxt_lvlhsh_t *lh);


const nxt_event_interface_t  nxt_poll_engine = {
    "poll",
    nxt_poll_create,
    nxt_poll_free,
    nxt_poll_enable,
    nxt_poll_disable,
    nxt_poll_disable,
    nxt_poll_close,
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
    nxt_poll,

    &nxt_unix_conn_io,

    NXT_NO_FILE_EVENTS,
    NXT_NO_SIGNAL_EVENTS,
};


static const nxt_lvlhsh_proto_t  nxt_poll_fd_hash_proto  nxt_aligned(64) =
{
    NXT_LVLHSH_LARGE_MEMALIGN,
    nxt_poll_fd_hash_test,
    nxt_lvlhsh_alloc,
    nxt_lvlhsh_free,
};


static nxt_int_t
nxt_poll_create(nxt_event_engine_t *engine, nxt_uint_t mchanges,
    nxt_uint_t mevents)
{
    engine->u.poll.mchanges = mchanges;

    engine->u.poll.changes = nxt_malloc(sizeof(nxt_poll_change_t) * mchanges);

    if (engine->u.poll.changes != NULL) {
        return NXT_OK;
    }

    return NXT_ERROR;
}


static void
nxt_poll_free(nxt_event_engine_t *engine)
{
    nxt_debug(&engine->task, "poll free");

    nxt_free(engine->u.poll.set);
    nxt_free(engine->u.poll.changes);
    nxt_poll_fd_hash_destroy(engine, &engine->u.poll.fd_hash);

    nxt_memzero(&engine->u.poll, sizeof(nxt_poll_engine_t));
}


static void
nxt_poll_enable(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    ev->read = NXT_EVENT_ACTIVE;
    ev->write = NXT_EVENT_ACTIVE;

    nxt_poll_change(engine, ev, NXT_POLL_ADD, POLLIN | POLLOUT);
}


static void
nxt_poll_disable(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE && ev->write != NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_INACTIVE;
        ev->write = NXT_EVENT_INACTIVE;

        nxt_poll_change(engine, ev, NXT_POLL_DELETE, 0);
    }
}


static nxt_bool_t
nxt_poll_close(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_poll_disable(engine, ev);

    return ev->changing;
}


static void
nxt_poll_enable_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_uint_t  op, events;

    ev->read = NXT_EVENT_ACTIVE;

    if (ev->write == NXT_EVENT_INACTIVE) {
        op = NXT_POLL_ADD;
        events = POLLIN;

    } else {
        op = NXT_POLL_CHANGE;
        events = POLLIN | POLLOUT;
    }

    nxt_poll_change(engine, ev, op, events);
}


static void
nxt_poll_enable_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_uint_t  op, events;

    ev->write = NXT_EVENT_ACTIVE;

    if (ev->read == NXT_EVENT_INACTIVE) {
        op = NXT_POLL_ADD;
        events = POLLOUT;

    } else {
        op = NXT_POLL_CHANGE;
        events = POLLIN | POLLOUT;
    }

    nxt_poll_change(engine, ev, op, events);
}


static void
nxt_poll_disable_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
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

    nxt_poll_change(engine, ev, op, events);
}


static void
nxt_poll_disable_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
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

    nxt_poll_change(engine, ev, op, events);
}


static void
nxt_poll_block_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        nxt_poll_disable_read(engine, ev);
    }
}


static void
nxt_poll_block_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->write != NXT_EVENT_INACTIVE) {
        nxt_poll_disable_write(engine, ev);
    }
}


static void
nxt_poll_oneshot_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_uint_t  op;

    op = (ev->read == NXT_EVENT_INACTIVE && ev->write == NXT_EVENT_INACTIVE) ?
             NXT_POLL_ADD : NXT_POLL_CHANGE;

    ev->read = NXT_EVENT_ONESHOT;
    ev->write = NXT_EVENT_INACTIVE;

    nxt_poll_change(engine, ev, op, POLLIN);
}


static void
nxt_poll_oneshot_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_uint_t  op;

    op = (ev->read == NXT_EVENT_INACTIVE && ev->write == NXT_EVENT_INACTIVE) ?
             NXT_POLL_ADD : NXT_POLL_CHANGE;

    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_ONESHOT;

    nxt_poll_change(engine, ev, op, POLLOUT);
}


/*
 * poll changes are batched to improve instruction and data cache
 * locality of several lvlhsh operations followed by poll() call.
 */

static void
nxt_poll_change(nxt_event_engine_t *engine, nxt_fd_event_t *ev, nxt_uint_t op,
    nxt_uint_t events)
{
    nxt_poll_change_t  *change;

    nxt_debug(ev->task, "poll change: fd:%d op:%d ev:%XD", ev->fd, op, events);

    if (engine->u.poll.nchanges >= engine->u.poll.mchanges) {
        (void) nxt_poll_commit_changes(engine);
    }

    ev->changing = 1;

    change = &engine->u.poll.changes[engine->u.poll.nchanges++];
    change->op = op;
    change->events = events;
    change->event = ev;
}


static nxt_int_t
nxt_poll_commit_changes(nxt_event_engine_t *engine)
{
    nxt_int_t          ret, retval;
    nxt_fd_event_t     *ev;
    nxt_poll_change_t  *change, *end;

    nxt_debug(&engine->task, "poll changes:%ui", engine->u.poll.nchanges);

    retval = NXT_OK;
    change = engine->u.poll.changes;
    end = change + engine->u.poll.nchanges;

    do {
        ev = change->event;
        ev->changing = 0;

        switch (change->op) {

        case NXT_POLL_ADD:
            ret = nxt_poll_set_add(engine, ev, change->events);

            if (nxt_fast_path(ret == NXT_OK)) {
                goto next;
            }

            break;

        case NXT_POLL_CHANGE:
            ret = nxt_poll_set_change(engine, ev->fd, change->events);

            if (nxt_fast_path(ret == NXT_OK)) {
                goto next;
            }

            break;

        case NXT_POLL_DELETE:
            ret = nxt_poll_set_delete(engine, ev->fd);

            if (nxt_fast_path(ret == NXT_OK)) {
                goto next;
            }

            break;
        }

        nxt_work_queue_add(&engine->fast_work_queue, ev->error_handler,
                           ev->task, ev, ev->data);

        retval = NXT_ERROR;

    next:

        change++;

    } while (change < end);

    engine->u.poll.nchanges = 0;

    return retval;
}


static nxt_int_t
nxt_poll_set_add(nxt_event_engine_t *engine, nxt_fd_event_t *ev, int events)
{
    nxt_int_t              ret;
    nxt_uint_t             max_nfds;
    struct pollfd          *pfd;
    nxt_lvlhsh_query_t     lhq;
    nxt_poll_hash_entry_t  *phe;

    nxt_debug(&engine->task, "poll add event: fd:%d ev:%04Xi", ev->fd, events);

    if (engine->u.poll.nfds >= engine->u.poll.max_nfds) {
        max_nfds = engine->u.poll.max_nfds + 512; /* 4K */

        pfd = nxt_realloc(engine->u.poll.set, sizeof(struct pollfd) * max_nfds);
        if (nxt_slow_path(pfd == NULL)) {
            return NXT_ERROR;
        }

        engine->u.poll.set = pfd;
        engine->u.poll.max_nfds = max_nfds;
    }

    phe = nxt_malloc(sizeof(nxt_poll_hash_entry_t));
    if (nxt_slow_path(phe == NULL)) {
        return NXT_ERROR;
    }

    phe->fd = ev->fd;
    phe->index = engine->u.poll.nfds;
    phe->event = ev;

    pfd = &engine->u.poll.set[engine->u.poll.nfds++];
    pfd->fd = ev->fd;
    pfd->events = events;
    pfd->revents = 0;

    lhq.key_hash = nxt_murmur_hash2(&ev->fd, sizeof(nxt_fd_t));
    lhq.replace = 0;
    lhq.value = phe;
    lhq.proto = &nxt_poll_fd_hash_proto;
    lhq.data = engine;

    ret = nxt_lvlhsh_insert(&engine->u.poll.fd_hash, &lhq);

    if (nxt_fast_path(ret == NXT_OK)) {
        return NXT_OK;
    }

    nxt_free(phe);

    return NXT_ERROR;
}


static nxt_int_t
nxt_poll_set_change(nxt_event_engine_t *engine, nxt_fd_t fd, int events)
{
    nxt_poll_hash_entry_t  *phe;

    nxt_debug(&engine->task, "poll change event: fd:%d ev:%04Xi",
              fd, events);

    phe = nxt_poll_fd_hash_get(engine, fd);

    if (nxt_fast_path(phe != NULL)) {
        engine->u.poll.set[phe->index].events = events;
        return NXT_OK;
    }

    return NXT_ERROR;
}


static nxt_int_t
nxt_poll_set_delete(nxt_event_engine_t *engine, nxt_fd_t fd)
{
    nxt_int_t              ret;
    nxt_uint_t             index, nfds;
    nxt_lvlhsh_query_t     lhq;
    nxt_poll_hash_entry_t  *phe;

    nxt_debug(&engine->task, "poll delete event: fd:%d", fd);

    lhq.key_hash = nxt_murmur_hash2(&fd, sizeof(nxt_fd_t));
    lhq.proto = &nxt_poll_fd_hash_proto;
    lhq.data = engine;

    ret = nxt_lvlhsh_delete(&engine->u.poll.fd_hash, &lhq);

    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    phe = lhq.value;

    index = phe->index;
    engine->u.poll.nfds--;
    nfds = engine->u.poll.nfds;

    if (index != nfds) {
        engine->u.poll.set[index] = engine->u.poll.set[nfds];

        phe = nxt_poll_fd_hash_get(engine, engine->u.poll.set[nfds].fd);

        phe->index = index;
    }

    nxt_free(lhq.value);

    return NXT_OK;
}


static void
nxt_poll(nxt_event_engine_t *engine, nxt_msec_t timeout)
{
    int                    nevents;
    nxt_fd_t               fd;
    nxt_err_t              err;
    nxt_bool_t             error;
    nxt_uint_t             i, events, level;
    struct pollfd          *pfd;
    nxt_fd_event_t         *ev;
    nxt_poll_hash_entry_t  *phe;

    if (engine->u.poll.nchanges != 0) {
        if (nxt_poll_commit_changes(engine) != NXT_OK) {
            /* Error handlers have been enqueued on failure. */
            timeout = 0;
        }
    }

    nxt_debug(&engine->task, "poll() events:%ui timeout:%M",
              engine->u.poll.nfds, timeout);

    nevents = poll(engine->u.poll.set, engine->u.poll.nfds, timeout);

    err = (nevents == -1) ? nxt_errno : 0;

    nxt_thread_time_update(engine->task.thread);

    nxt_debug(&engine->task, "poll(): %d", nevents);

    if (nevents == -1) {
        level = (err == NXT_EINTR) ? NXT_LOG_INFO : NXT_LOG_ALERT;
        nxt_log(&engine->task, level, "poll() failed %E", err);
        return;
    }

    for (i = 0; i < engine->u.poll.nfds && nevents != 0; i++) {

        pfd = &engine->u.poll.set[i];
        events = pfd->revents;

        if (events == 0) {
            continue;
        }

        fd = pfd->fd;

        phe = nxt_poll_fd_hash_get(engine, fd);

        if (nxt_slow_path(phe == NULL)) {
            nxt_alert(&engine->task,
                      "poll() returned invalid fd:%d ev:%04Xd rev:%04uXi",
                      fd, pfd->events, events);

            /* Mark the poll entry to ignore it by the kernel. */
            pfd->fd = -1;
            goto next;
        }

        ev = phe->event;

        nxt_debug(ev->task, "poll: fd:%d ev:%04uXi rd:%d wr:%d",
                  fd, events, ev->read, ev->write);

        if (nxt_slow_path((events & POLLNVAL) != 0)) {
            nxt_alert(ev->task, "poll() error fd:%d ev:%04Xd rev:%04uXi",
                      fd, pfd->events, events);

            /* Mark the poll entry to ignore it by the kernel. */
            pfd->fd = -1;

            nxt_work_queue_add(&engine->fast_work_queue,
                               ev->error_handler, ev->task, ev, ev->data);
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
                nxt_poll_change(engine, ev, NXT_POLL_DELETE, 0);
            }

            nxt_work_queue_add(ev->read_work_queue, ev->read_handler,
                               ev->task, ev, ev->data);
        }

        if ((events & POLLOUT) || (error && ev->write_handler != NULL)) {
            ev->write_ready = 1;

            if (ev->write == NXT_EVENT_ONESHOT) {
                ev->write = NXT_EVENT_INACTIVE;
                nxt_poll_change(engine, ev, NXT_POLL_DELETE, 0);
            }

            nxt_work_queue_add(ev->write_work_queue, ev->write_handler,
                               ev->task, ev, ev->data);
        }

    next:

        nevents--;
    }
}


static nxt_poll_hash_entry_t *
nxt_poll_fd_hash_get(nxt_event_engine_t *engine, nxt_fd_t fd)
{
    nxt_lvlhsh_query_t     lhq;
    nxt_poll_hash_entry_t  *phe;

    lhq.key_hash = nxt_murmur_hash2(&fd, sizeof(nxt_fd_t));
    lhq.proto = &nxt_poll_fd_hash_proto;
    lhq.data = engine;

    if (nxt_lvlhsh_find(&engine->u.poll.fd_hash, &lhq) == NXT_OK) {
        phe = lhq.value;
        return phe;
    }

    nxt_alert(&engine->task, "fd %d not found in hash", fd);

    return NULL;
}


static nxt_int_t
nxt_poll_fd_hash_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_event_engine_t     *engine;
    nxt_poll_hash_entry_t  *phe;

    phe = data;

    /* nxt_murmur_hash2() is unique for 4 bytes. */

    engine = lhq->data;

    if (nxt_fast_path(phe->fd == engine->u.poll.set[phe->index].fd)) {
        return NXT_OK;
    }

    nxt_alert(&engine->task, "fd %d in hash mismatches fd %d in poll set",
              phe->fd, engine->u.poll.set[phe->index].fd);

    return NXT_DECLINED;
}


static void
nxt_poll_fd_hash_destroy(nxt_event_engine_t *engine, nxt_lvlhsh_t *lh)
{
    nxt_poll_hash_entry_t  *phe;

    for ( ;; ) {
        phe = nxt_lvlhsh_retrieve(lh, &nxt_poll_fd_hash_proto, NULL);

        if (phe == NULL) {
            return;
        }

        nxt_free(phe);
    }
}

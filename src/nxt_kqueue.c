
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * kqueue()      has been introduced in FreeBSD 4.1 and then was ported
 *               to OpenBSD 2.9, MacOSX 10.3 (Panther), and NetBSD 2.0.
 *               DragonFlyBSD inherited it with FreeBSD 4 code base.
 *
 * NOTE_REVOKE   has been introduced in FreeBSD 4.3 and then was ported
 *               to OpenBSD 2.9, MacOSX 10.3 (Panther), and NetBSD 2.0.
 *               DragonFlyBSD inherited it with FreeBSD 4 code base.
 *
 * EVFILT_TIMER  has been introduced in FreeBSD 4.4-STABLE and then was
 *               ported to NetBSD 2.0, MacOSX 10.4 (Tiger), and OpenBSD 4.2.
 *               DragonFlyBSD inherited it with FreeBSD 4 code base.
 *
 * EVFILT_USER and EV_DISPATCH have been introduced in MacOSX 10.6 (Snow
 *               Leopard) as part of the Grand Central Dispatch framework
 *               and then were ported to FreeBSD 8.0-STABLE as part of the
 *               libdispatch support.
 */


/*
 * EV_DISPATCH is better because it just disables an event on delivery
 * whilst EV_ONESHOT deletes the event.  This eliminates in-kernel memory
 * deallocation and probable subsequent allocation with a lock acquiring.
 */
#ifdef EV_DISPATCH
#define NXT_KEVENT_ONESHOT  EV_DISPATCH
#else
#define NXT_KEVENT_ONESHOT  EV_ONESHOT
#endif


#if (NXT_NETBSD)
/* NetBSD defines the kevent.udata field as intptr_t. */

#define nxt_kevent_set_udata(udata)  (intptr_t) (udata)
#define nxt_kevent_get_udata(udata)  (void *) (udata)

#else
#define nxt_kevent_set_udata(udata)  (void *) (udata)
#define nxt_kevent_get_udata(udata)  (udata)
#endif


static nxt_event_set_t *nxt_kqueue_create(nxt_event_signals_t *signals,
    nxt_uint_t mchanges, nxt_uint_t mevents);
static void nxt_kqueue_free(nxt_event_set_t *event_set);
static void nxt_kqueue_enable(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_kqueue_disable(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_kqueue_delete(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_kqueue_close(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_kqueue_drop_changes(nxt_event_set_t *event_set,
    uintptr_t ident);
static void nxt_kqueue_enable_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_kqueue_enable_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_kqueue_disable_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_kqueue_disable_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_kqueue_block_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_kqueue_block_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_kqueue_oneshot_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_kqueue_oneshot_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_kqueue_enable_accept(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_kqueue_enable_file(nxt_event_set_t *event_set,
    nxt_event_file_t *ev);
static void nxt_kqueue_close_file(nxt_event_set_t *event_set,
    nxt_event_file_t *ev);
static void nxt_kqueue_fd_set(nxt_event_set_t *event_set, nxt_event_fd_t *ev,
    nxt_int_t filter, nxt_uint_t flags);
static struct kevent *nxt_kqueue_get_kevent(nxt_kqueue_event_set_t *ks);
static void nxt_kqueue_commit_changes(nxt_kqueue_event_set_t *ks);
static void nxt_kqueue_error(nxt_kqueue_event_set_t *ks);
static void nxt_kqueue_fd_error_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_kqueue_file_error_handler(nxt_task_t *task, void *obj,
    void *data);
static nxt_int_t nxt_kqueue_add_signal(nxt_kqueue_event_set_t *kq,
    const nxt_event_sig_t *sigev);
#if (NXT_HAVE_EVFILT_USER)
static nxt_int_t nxt_kqueue_enable_post(nxt_event_set_t *event_set,
    nxt_work_handler_t handler);
static void nxt_kqueue_signal(nxt_event_set_t *event_set, nxt_uint_t signo);
#endif
static void nxt_kqueue_poll(nxt_task_t *task, nxt_event_set_t *event_set,
    nxt_msec_t timeout);

static void nxt_kqueue_event_conn_io_connect(nxt_task_t *task, void *obj,
    void *data);
static void nxt_kqueue_event_conn_connected(nxt_task_t *task, void *obj,
    void *data);
static void nxt_kqueue_listen_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_kqueue_event_conn_io_accept(nxt_task_t *task, void *obj,
    void *data);
static void nxt_kqueue_event_conn_io_read(nxt_task_t *task, void *obj,
    void *data);
static ssize_t nxt_kqueue_event_conn_io_recvbuf(nxt_event_conn_t *c,
    nxt_buf_t *b);


static nxt_event_conn_io_t  nxt_kqueue_event_conn_io = {
    nxt_kqueue_event_conn_io_connect,
    nxt_kqueue_event_conn_io_accept,

    nxt_kqueue_event_conn_io_read,
    nxt_kqueue_event_conn_io_recvbuf,
    nxt_event_conn_io_recv,

    nxt_event_conn_io_write,
    nxt_event_conn_io_write_chunk,

#if (NXT_HAVE_FREEBSD_SENDFILE)
    nxt_freebsd_event_conn_io_sendfile,
#elif (NXT_HAVE_MACOSX_SENDFILE)
    nxt_macosx_event_conn_io_sendfile,
#else
    nxt_event_conn_io_sendbuf,
#endif

    nxt_event_conn_io_writev,
    nxt_event_conn_io_send,

    nxt_event_conn_io_shutdown,
};


const nxt_event_set_ops_t  nxt_kqueue_event_set = {
    "kqueue",
    nxt_kqueue_create,
    nxt_kqueue_free,
    nxt_kqueue_enable,
    nxt_kqueue_disable,
    nxt_kqueue_delete,
    nxt_kqueue_close,
    nxt_kqueue_enable_read,
    nxt_kqueue_enable_write,
    nxt_kqueue_disable_read,
    nxt_kqueue_disable_write,
    nxt_kqueue_block_read,
    nxt_kqueue_block_write,
    nxt_kqueue_oneshot_read,
    nxt_kqueue_oneshot_write,
    nxt_kqueue_enable_accept,
    nxt_kqueue_enable_file,
    nxt_kqueue_close_file,
#if (NXT_HAVE_EVFILT_USER)
    nxt_kqueue_enable_post,
    nxt_kqueue_signal,
#else
    NULL,
    NULL,
#endif
    nxt_kqueue_poll,

    &nxt_kqueue_event_conn_io,

    NXT_FILE_EVENTS,
    NXT_SIGNAL_EVENTS,
};


static nxt_event_set_t *
nxt_kqueue_create(nxt_event_signals_t *signals, nxt_uint_t mchanges,
    nxt_uint_t mevents)
{
    nxt_event_set_t         *event_set;
    const nxt_event_sig_t   *sigev;
    nxt_kqueue_event_set_t  *ks;

    event_set = nxt_zalloc(sizeof(nxt_kqueue_event_set_t));
    if (event_set == NULL) {
        return NULL;
    }

    ks = &event_set->kqueue;

    ks->kqueue = -1;
    ks->mchanges = mchanges;
    ks->mevents = mevents;
    ks->pid = nxt_pid;

    ks->changes = nxt_malloc(sizeof(struct kevent) * mchanges);
    if (ks->changes == NULL) {
        goto fail;
    }

    ks->events = nxt_malloc(sizeof(struct kevent) * mevents);
    if (ks->events == NULL) {
        goto fail;
    }

    ks->kqueue = kqueue();
    if (ks->kqueue == -1) {
        nxt_main_log_emerg("kqueue() failed %E", nxt_errno);
        goto fail;
    }

    nxt_main_log_debug("kqueue(): %d", ks->kqueue);

    if (signals != NULL) {
        for (sigev = signals->sigev; sigev->signo != 0; sigev++) {
            if (nxt_kqueue_add_signal(ks, sigev) != NXT_OK) {
                goto fail;
            }
        }
    }

    return event_set;

fail:

    nxt_kqueue_free(event_set);

    return NULL;
}


static void
nxt_kqueue_free(nxt_event_set_t *event_set)
{
    nxt_kqueue_event_set_t  *ks;

    ks = &event_set->kqueue;

    nxt_main_log_debug("kqueue %d free", ks->kqueue);

    if (ks->kqueue != -1 && ks->pid == nxt_pid) {
        /* kqueue is not inherited by fork() */

        if (close(ks->kqueue) != 0) {
            nxt_main_log_emerg("kqueue close(%d) failed %E",
                               ks->kqueue, nxt_errno);
        }
    }

    nxt_free(ks->events);
    nxt_free(ks->changes);
    nxt_free(ks);
}


static void
nxt_kqueue_enable(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_kqueue_enable_read(event_set, ev);
    nxt_kqueue_enable_write(event_set, ev);
}


/*
 * EV_DISABLE is better because it eliminates in-kernel memory
 * deallocation and probable subsequent allocation with a lock acquiring.
 */

static void
nxt_kqueue_disable(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_INACTIVE;
        nxt_kqueue_fd_set(event_set, ev, EVFILT_READ, EV_DISABLE);
    }

    if (ev->write != NXT_EVENT_INACTIVE) {
        ev->write = NXT_EVENT_INACTIVE;
        nxt_kqueue_fd_set(event_set, ev, EVFILT_WRITE, EV_DISABLE);
    }
}


static void
nxt_kqueue_delete(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_INACTIVE;
        nxt_kqueue_fd_set(event_set, ev, EVFILT_READ, EV_DELETE);
    }

    if (ev->write != NXT_EVENT_INACTIVE) {
        ev->write = NXT_EVENT_INACTIVE;
        nxt_kqueue_fd_set(event_set, ev, EVFILT_WRITE, EV_DELETE);
    }
}


/*
 * kqueue(2):
 *
 *   Calling close() on a file descriptor will remove any kevents that
 *   reference the descriptor.
 */

static void
nxt_kqueue_close(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;

    nxt_kqueue_drop_changes(event_set, ev->fd);
}


static void
nxt_kqueue_drop_changes(nxt_event_set_t *event_set, uintptr_t ident)
{
    struct kevent           *dst, *src, *end;
    nxt_kqueue_event_set_t  *ks;

    ks = &event_set->kqueue;

    dst = ks->changes;
    end = dst + ks->nchanges;

    for (src = dst; src < end; src++) {

        if (src->ident == ident) {

            switch (src->filter) {

            case EVFILT_READ:
            case EVFILT_WRITE:
            case EVFILT_VNODE:
                 continue;
            }
        }

        if (dst != src) {
            *dst = *src;
        }

        dst++;
    }

    ks->nchanges -= end - dst;
}


/*
 * The kqueue event set uses only three states: inactive, blocked, and
 * default.  An active oneshot event is marked as it is in the default
 * state.  The event will eventually be converted to the default EV_CLEAR
 * mode after it will become inactive after delivery.
 */

static void
nxt_kqueue_enable_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read == NXT_EVENT_INACTIVE) {
        nxt_kqueue_fd_set(event_set, ev, EVFILT_READ,
                          EV_ADD | EV_ENABLE | EV_CLEAR);
    }

    ev->read = NXT_EVENT_DEFAULT;
}


static void
nxt_kqueue_enable_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->write == NXT_EVENT_INACTIVE) {
        nxt_kqueue_fd_set(event_set, ev, EVFILT_WRITE,
                          EV_ADD | EV_ENABLE | EV_CLEAR);
    }

    ev->write = NXT_EVENT_DEFAULT;
}


static void
nxt_kqueue_disable_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->read = NXT_EVENT_INACTIVE;

    nxt_kqueue_fd_set(event_set, ev, EVFILT_READ, EV_DISABLE);
}


static void
nxt_kqueue_disable_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->write = NXT_EVENT_INACTIVE;

    nxt_kqueue_fd_set(event_set, ev, EVFILT_WRITE, EV_DISABLE);
}


static void
nxt_kqueue_block_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_kqueue_block_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->write != NXT_EVENT_INACTIVE) {
        ev->write = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_kqueue_oneshot_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->write = NXT_EVENT_DEFAULT;

    nxt_kqueue_fd_set(event_set, ev, EVFILT_WRITE,
                      EV_ADD | EV_ENABLE | NXT_KEVENT_ONESHOT);
}


static void
nxt_kqueue_oneshot_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->write = NXT_EVENT_DEFAULT;

    nxt_kqueue_fd_set(event_set, ev, EVFILT_WRITE,
                      EV_ADD | EV_ENABLE | NXT_KEVENT_ONESHOT);
}


static void
nxt_kqueue_enable_accept(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->read = NXT_EVENT_DEFAULT;
    ev->read_handler = nxt_kqueue_listen_handler;

    nxt_kqueue_fd_set(event_set, ev, EVFILT_READ, EV_ADD | EV_ENABLE);
}


static void
nxt_kqueue_enable_file(nxt_event_set_t *event_set, nxt_event_file_t *ev)
{
    struct kevent           *kev;
    nxt_kqueue_event_set_t  *ks;

    ks = &event_set->kqueue;

    kev = nxt_kqueue_get_kevent(ks);

    kev->ident = ev->file->fd;
    kev->filter = EVFILT_VNODE;
    kev->flags = EV_ADD | EV_ENABLE | EV_ONESHOT;
    kev->fflags = NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND
                  | NOTE_ATTRIB | NOTE_RENAME | NOTE_REVOKE;
    kev->data = 0;
    kev->udata = nxt_kevent_set_udata(ev);

    nxt_thread_log_debug("kevent(%d) set: id:%d ft:%i fl:%04Xd, ff:%04XuD",
                         ks->kqueue, ev->file->fd, EVFILT_VNODE,
                         kev->flags, kev->fflags);
}


static void
nxt_kqueue_close_file(nxt_event_set_t *event_set, nxt_event_file_t *ev)
{
    nxt_kqueue_drop_changes(event_set, ev->file->fd);
}


static void
nxt_kqueue_fd_set(nxt_event_set_t *event_set, nxt_event_fd_t *ev,
    nxt_int_t filter, nxt_uint_t flags)
{
    struct kevent           *kev;
    nxt_kqueue_event_set_t  *ks;

    ks = &event_set->kqueue;

    nxt_log_debug(ev->log, "kevent(%d) set event: id:%d ft:%i fl:%04Xui",
                  ks->kqueue, ev->fd, filter, flags);

    kev = nxt_kqueue_get_kevent(ks);

    kev->ident = ev->fd;
    kev->filter = filter;
    kev->flags = flags;
    kev->fflags = 0;
    kev->data = 0;
    kev->udata = nxt_kevent_set_udata(ev);
}


static struct kevent *
nxt_kqueue_get_kevent(nxt_kqueue_event_set_t *ks)
{
    if (nxt_slow_path(ks->nchanges >= ks->mchanges)) {
        nxt_kqueue_commit_changes(ks);
    }

    return &ks->changes[ks->nchanges++];
}


static void
nxt_kqueue_commit_changes(nxt_kqueue_event_set_t *ks)
{
    nxt_thread_log_debug("kevent(%d) changes:%d", ks->kqueue, ks->nchanges);

    if (kevent(ks->kqueue, ks->changes, ks->nchanges, NULL, 0, NULL) != 0) {
        nxt_thread_log_alert("kevent(%d) failed %E", ks->kqueue, nxt_errno);

        nxt_kqueue_error(ks);
    }

    ks->nchanges = 0;
}


static void
nxt_kqueue_error(nxt_kqueue_event_set_t *ks)
{
    struct kevent     *kev, *end;
    nxt_thread_t      *thr;
    nxt_event_fd_t    *ev;
    nxt_event_file_t  *fev;

    thr = nxt_thread();
    end = &ks->changes[ks->nchanges];

    for (kev = ks->changes; kev < end; kev++) {

        switch (kev->filter) {

        case EVFILT_READ:
        case EVFILT_WRITE:
            ev = nxt_kevent_get_udata(kev->udata);
            nxt_thread_work_queue_add(thr, &thr->work_queue.main,
                                      nxt_kqueue_fd_error_handler,
                                      ev->task, ev, ev->data);
            break;

        case EVFILT_VNODE:
            fev = nxt_kevent_get_udata(kev->udata);
            nxt_thread_work_queue_add(thr, &thr->work_queue.main,
                                      nxt_kqueue_file_error_handler,
                                      fev->task, fev, fev->data);
            break;
        }
    }
}


static void
nxt_kqueue_fd_error_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_fd_t  *ev;

    ev = obj;

    if (ev->kq_eof && ev->kq_errno != 0) {
        ev->error = ev->kq_errno;
        nxt_log(task, nxt_socket_error_level(ev->kq_errno, ev->log_error),
                "kevent() reported error on descriptor %d %E",
                ev->fd, ev->kq_errno);
    }

    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;
    ev->error = ev->kq_errno;

    ev->error_handler(task, ev, data);
}


static void
nxt_kqueue_file_error_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_file_t  *ev;

    ev = obj;

    ev->handler(task, ev, data);
}


static nxt_int_t
nxt_kqueue_add_signal(nxt_kqueue_event_set_t *ks, const nxt_event_sig_t *sigev)
{
    int               signo;
    struct kevent     kev;
    struct sigaction  sa;

    signo = sigev->signo;

    nxt_memzero(&sa, sizeof(struct sigaction));
    sigemptyset(&sa.sa_mask);

    /*
     * SIGCHLD must not be set to SIG_IGN, since kqueue cannot catch
     * this signal.  It should be set to SIG_DFL instead.  And although
     * SIGCHLD default action is also ignoring, nevertheless SIG_DFL
     * allows kqueue to catch the signal.
     */
    sa.sa_handler = (signo == SIGCHLD) ? SIG_DFL : SIG_IGN;

    if (sigaction(signo, &sa, NULL) != 0) {
        nxt_main_log_alert("sigaction(%d) failed %E", signo, nxt_errno);
        return NXT_ERROR;
    }

    nxt_main_log_debug("kevent(%d) signo:%d (%s)",
                       ks->kqueue, signo, sigev->name);

    kev.ident = signo;
    kev.filter = EVFILT_SIGNAL;
    kev.flags = EV_ADD;
    kev.fflags = 0;
    kev.data = 0;
    kev.udata = nxt_kevent_set_udata(sigev);

    if (kevent(ks->kqueue, &kev, 1, NULL, 0, NULL) == 0) {
        return NXT_OK;
    }

    nxt_main_log_alert("kevent(%d) failed %E", ks->kqueue, nxt_errno);
    return NXT_ERROR;
}


#if (NXT_HAVE_EVFILT_USER)

static nxt_int_t
nxt_kqueue_enable_post(nxt_event_set_t *event_set, nxt_work_handler_t handler)
{
    struct kevent           kev;
    nxt_kqueue_event_set_t  *ks;

    /* EVFILT_USER must be added to a kqueue before it can be triggered. */

    kev.ident = 0;
    kev.filter = EVFILT_USER;
    kev.flags = EV_ADD | EV_CLEAR;
    kev.fflags = 0;
    kev.data = 0;
    kev.udata = NULL;

    ks = &event_set->kqueue;
    ks->post_handler = handler;

    if (kevent(ks->kqueue, &kev, 1, NULL, 0, NULL) == 0) {
        return NXT_OK;
    }

    nxt_main_log_alert("kevent(%d) failed %E", ks->kqueue, nxt_errno);
    return NXT_ERROR;
}


static void
nxt_kqueue_signal(nxt_event_set_t *event_set, nxt_uint_t signo)
{
    struct kevent           kev;
    nxt_kqueue_event_set_t  *ks;

    /*
     * kqueue has a builtin signal processing support, so the function
     * is used only to post events and the signo argument is ignored.
     */

    kev.ident = 0;
    kev.filter = EVFILT_USER;
    kev.flags = 0;
    kev.fflags = NOTE_TRIGGER;
    kev.data = 0;
    kev.udata = NULL;

    ks = &event_set->kqueue;

    if (kevent(ks->kqueue, &kev, 1, NULL, 0, NULL) != 0) {
        nxt_thread_log_alert("kevent(%d) failed %E", ks->kqueue, nxt_errno);
    }
}

#endif


static void
nxt_kqueue_poll(nxt_task_t *task, nxt_event_set_t *event_set,
    nxt_msec_t timeout)
{
    int                     nevents;
    void                    *obj, *data;
    nxt_int_t               i;
    nxt_err_t               err;
    nxt_uint_t              level;
    nxt_bool_t              error, eof;
    nxt_task_t              *event_task;
    struct kevent           *kev;
    nxt_event_fd_t          *ev;
    nxt_event_sig_t         *sigev;
    struct timespec         ts, *tp;
    nxt_event_file_t        *fev;
    nxt_work_queue_t        *wq;
    nxt_work_handler_t      handler;
    nxt_kqueue_event_set_t  *ks;

    if (timeout == NXT_INFINITE_MSEC) {
        tp = NULL;

    } else {
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000000;
        tp = &ts;
    }

    ks = &event_set->kqueue;

    nxt_debug(task, "kevent(%d) changes:%d timeout:%M",
              ks->kqueue, ks->nchanges, timeout);

    nevents = kevent(ks->kqueue, ks->changes, ks->nchanges,
                     ks->events, ks->mevents, tp);

    err = (nevents == -1) ? nxt_errno : 0;

    nxt_thread_time_update(task->thread);

    nxt_debug(task, "kevent(%d): %d", ks->kqueue, nevents);

    if (nevents == -1) {
        level = (err == NXT_EINTR) ? NXT_LOG_INFO : NXT_LOG_ALERT;
        nxt_log(task, level, "kevent(%d) failed %E", ks->kqueue, err);

        nxt_kqueue_error(ks);
        return;
    }

    ks->nchanges = 0;

    for (i = 0; i < nevents; i++) {

        kev = &ks->events[i];

        nxt_debug(task,
                  (kev->ident > 0x8000000 && kev->ident != (uintptr_t) -1) ?
                      "kevent: id:%p ft:%d fl:%04Xd ff:%d d:%d ud:%p":
                      "kevent: id:%d ft:%d fl:%04Xd ff:%d d:%d ud:%p",
                  kev->ident, kev->filter, kev->flags, kev->fflags,
                  kev->data, kev->udata);

        error = (kev->flags & EV_ERROR);

        if (nxt_slow_path(error)) {
            nxt_log(task, NXT_LOG_CRIT,
                    "kevent(%d) error %E on ident:%d filter:%d",
                    ks->kqueue, kev->data, kev->ident, kev->filter);
        }

        event_task = task;
        wq = &task->thread->work_queue.main;
        handler = nxt_kqueue_fd_error_handler;
        obj = nxt_kevent_get_udata(kev->udata);

        switch (kev->filter) {

        case EVFILT_READ:
            ev = obj;
            ev->read_ready = 1;
            ev->kq_available = (int32_t) kev->data;
            err = kev->fflags;
            eof = (kev->flags & EV_EOF) != 0;
            ev->kq_errno = err;
            ev->kq_eof = eof;

            if (ev->read == NXT_EVENT_BLOCKED) {
                nxt_debug(ev->task, "blocked read event fd:%d", ev->fd);
                continue;
            }

            if ((kev->flags & NXT_KEVENT_ONESHOT) != 0) {
                ev->read = NXT_EVENT_INACTIVE;
            }

            if (nxt_slow_path(ev->kq_available == 0 && eof && err != 0)) {
                error = 1;
            }

            if (nxt_fast_path(!error)) {
                handler = ev->read_handler;
                wq = ev->read_work_queue;
            }

            event_task = ev->task;
            data = ev->data;

            break;

        case EVFILT_WRITE:
            ev = obj;
            ev->write_ready = 1;
            err = kev->fflags;
            eof = (kev->flags & EV_EOF) != 0;
            ev->kq_errno = err;
            ev->kq_eof = eof;

            if (ev->write == NXT_EVENT_BLOCKED) {
                nxt_debug(ev->task, "blocked write event fd:%d", ev->fd);
                continue;
            }

            if ((kev->flags & NXT_KEVENT_ONESHOT) != 0) {
                ev->write = NXT_EVENT_INACTIVE;
            }

            if (nxt_slow_path(eof && err != 0)) {
                error = 1;
            }

            if (nxt_fast_path(!error)) {
                handler = ev->write_handler;
                wq = ev->write_work_queue;
            }

            event_task = ev->task;
            data = ev->data;

            break;

        case EVFILT_VNODE:
            fev = obj;
            handler = fev->handler;
            event_task = fev->task;
            data = fev->data;
            break;

        case EVFILT_SIGNAL:
            sigev = obj;
            obj = (void *) kev->ident;
            handler = sigev->handler;
            data = (void *) sigev->name;
            break;

#if (NXT_HAVE_EVFILT_USER)

        case EVFILT_USER:
            handler = ks->post_handler;
            data = NULL;
            break;

#endif

        default:

#if (NXT_DEBUG)
            nxt_log(task, NXT_LOG_CRIT,
                    "unexpected kevent(%d) filter %d on ident %d",
                    ks->kqueue, kev->filter, kev->ident);
#endif

            continue;
        }

        nxt_thread_work_queue_add(task->thread, wq, handler,
                                  event_task, obj, data);
    }
}


/*
 * nxt_kqueue_event_conn_io_connect() eliminates the
 * getsockopt() syscall to test pending connect() error.
 */

static void
nxt_kqueue_event_conn_io_connect(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_t              *c;
    nxt_work_handler_t            handler;
    const nxt_event_conn_state_t  *state;

    c = obj;

    state = c->write_state;

    switch (nxt_socket_connect(c->socket.fd, c->remote) ){

    case NXT_OK:
        c->socket.write_ready = 1;
        handler = state->ready_handler;
        break;

    case NXT_AGAIN:
        c->socket.write_handler = nxt_kqueue_event_conn_connected;
        c->socket.error_handler = nxt_event_conn_connect_error;

        nxt_event_conn_timer(task->thread->engine, c, state, &c->write_timer);

        nxt_kqueue_enable_write(task->thread->engine->event_set, &c->socket);
        return;

    case NXT_DECLINED:
        handler = state->close_handler;
        break;

    default: /* NXT_ERROR */
        handler = state->error_handler;
        break;
    }

    nxt_event_conn_io_handle(task->thread, c->write_work_queue, handler, task,
                             c, data);
}


static void
nxt_kqueue_event_conn_connected(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_t  *c;

    c = obj;

    nxt_debug(task, "kqueue event conn connected fd:%d", c->socket.fd);

    c->socket.write = NXT_EVENT_BLOCKED;

    if (c->write_state->autoreset_timer) {
        nxt_event_timer_disable(&c->write_timer);
    }

    nxt_thread_work_queue_add(task->thread, c->write_work_queue,
                              c->write_state->ready_handler, task, c, data);
}


static void
nxt_kqueue_listen_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_listen_t  *cls;

    cls = obj;

    nxt_debug(task, "kevent fd:%d avail:%D",
              cls->socket.fd, cls->socket.kq_available);

    cls->ready = nxt_min(cls->batch, (uint32_t) cls->socket.kq_available);

    nxt_kqueue_event_conn_io_accept(task, cls, data);
}


static void
nxt_kqueue_event_conn_io_accept(nxt_task_t *task, void *obj, void *data)
{
    socklen_t                len;
    nxt_socket_t             s;
    struct sockaddr          *sa;
    nxt_event_conn_t         *c;
    nxt_event_conn_listen_t  *cls;

    cls = obj;
    c = data;

    cls->ready--;
    cls->socket.read_ready = (cls->ready != 0);

    cls->socket.kq_available--;
    cls->socket.read_ready = (cls->socket.kq_available != 0);

    len = nxt_socklen(c->remote);

    if (len >= sizeof(struct sockaddr)) {
        sa = &c->remote->u.sockaddr;

    } else {
        sa = NULL;
        len = 0;
    }

    s = accept(cls->socket.fd, sa, &len);

    if (s != -1) {
        c->socket.fd = s;

        nxt_debug(task, "accept(%d): %d", cls->socket.fd, s);

        nxt_event_conn_accept(task, cls, c);
        return;
    }

    nxt_event_conn_accept_error(task, cls, "accept", nxt_errno);
}


/*
 * nxt_kqueue_event_conn_io_read() is just a wrapper to eliminate the
 * readv() or recv() syscall if a remote side just closed connection.
 */

static void
nxt_kqueue_event_conn_io_read(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_t  *c;

    c = obj;

    nxt_debug(task, "kqueue event conn read fd:%d", c->socket.fd);

    if (c->socket.kq_available == 0 && c->socket.kq_eof) {
        nxt_debug(task, "kevent fd:%d eof", c->socket.fd);

        c->socket.closed = 1;
        nxt_thread_work_queue_add(task->thread, c->read_work_queue,
                                  c->read_state->close_handler, task, c, data);
        return;
    }

    nxt_event_conn_io_read(task, c, data);
}


/*
 * nxt_kqueue_event_conn_io_recvbuf() is just wrapper around standard
 * nxt_event_conn_io_recvbuf() to eliminate the readv() or recv() syscalls
 * if there is no pending data or a remote side closed connection.
 */

static ssize_t
nxt_kqueue_event_conn_io_recvbuf(nxt_event_conn_t *c, nxt_buf_t *b)
{
    ssize_t  n;

    if (c->socket.kq_available == 0 && c->socket.kq_eof) {
        c->socket.closed = 1;
        return 0;
    }

    n = nxt_event_conn_io_recvbuf(c, b);

    if (n > 0) {
        c->socket.kq_available -= n;

        if (c->socket.kq_available < 0) {
            c->socket.kq_available = 0;
        }

        nxt_log_debug(c->socket.log, "kevent fd:%d avail:%D eof:%d",
                      c->socket.fd, c->socket.kq_available, c->socket.kq_eof);

        c->socket.read_ready = (c->socket.kq_available != 0
                                || c->socket.kq_eof);
    }

    return n;
}

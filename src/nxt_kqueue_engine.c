
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


static nxt_int_t nxt_kqueue_create(nxt_event_engine_t *engine,
    nxt_uint_t mchanges, nxt_uint_t mevents);
static void nxt_kqueue_free(nxt_event_engine_t *engine);
static void nxt_kqueue_enable(nxt_event_engine_t *engine, nxt_fd_event_t *ev);
static void nxt_kqueue_disable(nxt_event_engine_t *engine, nxt_fd_event_t *ev);
static void nxt_kqueue_delete(nxt_event_engine_t *engine, nxt_fd_event_t *ev);
static nxt_bool_t nxt_kqueue_close(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_kqueue_enable_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_kqueue_enable_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_kqueue_disable_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_kqueue_disable_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_kqueue_block_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_kqueue_block_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_kqueue_oneshot_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_kqueue_oneshot_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_kqueue_enable_accept(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_kqueue_enable_file(nxt_event_engine_t *engine,
    nxt_file_event_t *ev);
static void nxt_kqueue_close_file(nxt_event_engine_t *engine,
    nxt_file_event_t *ev);
static void nxt_kqueue_fd_set(nxt_event_engine_t *engine, nxt_fd_event_t *ev,
    nxt_int_t filter, nxt_uint_t flags);
static struct kevent *nxt_kqueue_get_kevent(nxt_event_engine_t *engine);
static void nxt_kqueue_error(nxt_event_engine_t *engine);
static void nxt_kqueue_fd_error_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_kqueue_file_error_handler(nxt_task_t *task, void *obj,
    void *data);
static nxt_int_t nxt_kqueue_add_signal(nxt_event_engine_t *engine,
    const nxt_sig_event_t *sigev);
#if (NXT_HAVE_EVFILT_USER)
static nxt_int_t nxt_kqueue_enable_post(nxt_event_engine_t *engine,
    nxt_work_handler_t handler);
static void nxt_kqueue_signal(nxt_event_engine_t *engine, nxt_uint_t signo);
#endif
static void nxt_kqueue_poll(nxt_event_engine_t *engine, nxt_msec_t timeout);

static void nxt_kqueue_conn_io_connect(nxt_task_t *task, void *obj,
    void *data);
static void nxt_kqueue_conn_connected(nxt_task_t *task, void *obj,
    void *data);
static void nxt_kqueue_listen_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_kqueue_conn_io_accept(nxt_task_t *task, void *obj,
    void *data);
static void nxt_kqueue_conn_io_read(nxt_task_t *task, void *obj,
    void *data);
static ssize_t nxt_kqueue_conn_io_recvbuf(nxt_conn_t *c, nxt_buf_t *b);


static nxt_conn_io_t  nxt_kqueue_conn_io = {
    .connect = nxt_kqueue_conn_io_connect,
    .accept = nxt_kqueue_conn_io_accept,

    .read = nxt_kqueue_conn_io_read,
    .recvbuf = nxt_kqueue_conn_io_recvbuf,
    .recv = nxt_conn_io_recv,

    .write = nxt_conn_io_write,
    .sendbuf = nxt_conn_io_sendbuf,

#if (NXT_HAVE_FREEBSD_SENDFILE)
    .old_sendbuf = nxt_freebsd_event_conn_io_sendfile,
#elif (NXT_HAVE_MACOSX_SENDFILE)
    .old_sendbuf = nxt_macosx_event_conn_io_sendfile,
#else
    .old_sendbuf = nxt_event_conn_io_sendbuf,
#endif

    .writev = nxt_event_conn_io_writev,
    .send = nxt_event_conn_io_send,
};


const nxt_event_interface_t  nxt_kqueue_engine = {
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

    &nxt_kqueue_conn_io,

    NXT_FILE_EVENTS,
    NXT_SIGNAL_EVENTS,
};


static nxt_int_t
nxt_kqueue_create(nxt_event_engine_t *engine, nxt_uint_t mchanges,
    nxt_uint_t mevents)
{
    const nxt_sig_event_t  *sigev;

    engine->u.kqueue.fd = -1;
    engine->u.kqueue.mchanges = mchanges;
    engine->u.kqueue.mevents = mevents;
    engine->u.kqueue.pid = nxt_pid;

    engine->u.kqueue.changes = nxt_malloc(sizeof(struct kevent) * mchanges);
    if (engine->u.kqueue.changes == NULL) {
        goto fail;
    }

    engine->u.kqueue.events = nxt_malloc(sizeof(struct kevent) * mevents);
    if (engine->u.kqueue.events == NULL) {
        goto fail;
    }

    engine->u.kqueue.fd = kqueue();
    if (engine->u.kqueue.fd == -1) {
        nxt_alert(&engine->task, "kqueue() failed %E", nxt_errno);
        goto fail;
    }

    nxt_debug(&engine->task, "kqueue(): %d", engine->u.kqueue.fd);

    if (engine->signals != NULL) {
        for (sigev = engine->signals->sigev; sigev->signo != 0; sigev++) {
            if (nxt_kqueue_add_signal(engine, sigev) != NXT_OK) {
                goto fail;
            }
        }
    }

    return NXT_OK;

fail:

    nxt_kqueue_free(engine);

    return NXT_ERROR;
}


static void
nxt_kqueue_free(nxt_event_engine_t *engine)
{
    nxt_fd_t  fd;

    fd = engine->u.kqueue.fd;

    nxt_debug(&engine->task, "kqueue %d free", fd);

    if (fd != -1 && engine->u.kqueue.pid == nxt_pid) {
        /* kqueue is not inherited by fork() */

        if (close(fd) != 0) {
            nxt_alert(&engine->task, "kqueue close(%d) failed %E",
                      fd, nxt_errno);
        }
    }

    nxt_free(engine->u.kqueue.events);
    nxt_free(engine->u.kqueue.changes);

    nxt_memzero(&engine->u.kqueue, sizeof(nxt_kqueue_engine_t));
}


static void
nxt_kqueue_enable(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_kqueue_enable_read(engine, ev);
    nxt_kqueue_enable_write(engine, ev);
}


/*
 * EV_DISABLE is better because it eliminates in-kernel memory
 * deallocation and probable subsequent allocation with a lock acquiring.
 */

static void
nxt_kqueue_disable(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_INACTIVE;
        nxt_kqueue_fd_set(engine, ev, EVFILT_READ, EV_DISABLE);
    }

    if (ev->write != NXT_EVENT_INACTIVE) {
        ev->write = NXT_EVENT_INACTIVE;
        nxt_kqueue_fd_set(engine, ev, EVFILT_WRITE, EV_DISABLE);
    }
}


static void
nxt_kqueue_delete(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_INACTIVE;
        nxt_kqueue_fd_set(engine, ev, EVFILT_READ, EV_DELETE);
    }

    if (ev->write != NXT_EVENT_INACTIVE) {
        ev->write = NXT_EVENT_INACTIVE;
        nxt_kqueue_fd_set(engine, ev, EVFILT_WRITE, EV_DELETE);
    }
}


/*
 * kqueue(2):
 *
 *   Calling close() on a file descriptor will remove any kevents that
 *   reference the descriptor.
 *
 * So nxt_kqueue_close() returns true only if there are pending events.
 */

static nxt_bool_t
nxt_kqueue_close(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    struct kevent  *kev, *end;

    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;

    end = &engine->u.kqueue.changes[engine->u.kqueue.nchanges];

    for (kev = engine->u.kqueue.changes; kev < end; kev++) {
        if (kev->ident == (uintptr_t) ev->fd) {
            return 1;
        }
    }

    return 0;
}


/*
 * The kqueue event engine uses only three states: inactive, blocked, and
 * active.  An active oneshot event is marked as it is in the default
 * state.  The event will be converted eventually to the default EV_CLEAR
 * mode after it will become inactive after delivery.
 */

static void
nxt_kqueue_enable_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read == NXT_EVENT_INACTIVE) {
        nxt_kqueue_fd_set(engine, ev, EVFILT_READ,
                          EV_ADD | EV_ENABLE | EV_CLEAR);
    }

    ev->read = NXT_EVENT_ACTIVE;
}


static void
nxt_kqueue_enable_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->write == NXT_EVENT_INACTIVE) {
        nxt_kqueue_fd_set(engine, ev, EVFILT_WRITE,
                          EV_ADD | EV_ENABLE | EV_CLEAR);
    }

    ev->write = NXT_EVENT_ACTIVE;
}


static void
nxt_kqueue_disable_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    ev->read = NXT_EVENT_INACTIVE;

    nxt_kqueue_fd_set(engine, ev, EVFILT_READ, EV_DISABLE);
}


static void
nxt_kqueue_disable_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    ev->write = NXT_EVENT_INACTIVE;

    nxt_kqueue_fd_set(engine, ev, EVFILT_WRITE, EV_DISABLE);
}


static void
nxt_kqueue_block_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_kqueue_block_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->write != NXT_EVENT_INACTIVE) {
        ev->write = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_kqueue_oneshot_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    ev->write = NXT_EVENT_ACTIVE;

    nxt_kqueue_fd_set(engine, ev, EVFILT_WRITE,
                      EV_ADD | EV_ENABLE | NXT_KEVENT_ONESHOT);
}


static void
nxt_kqueue_oneshot_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    ev->write = NXT_EVENT_ACTIVE;

    nxt_kqueue_fd_set(engine, ev, EVFILT_WRITE,
                      EV_ADD | EV_ENABLE | NXT_KEVENT_ONESHOT);
}


static void
nxt_kqueue_enable_accept(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    ev->read = NXT_EVENT_ACTIVE;
    ev->read_handler = nxt_kqueue_listen_handler;

    nxt_kqueue_fd_set(engine, ev, EVFILT_READ, EV_ADD | EV_ENABLE);
}


static void
nxt_kqueue_enable_file(nxt_event_engine_t *engine, nxt_file_event_t *ev)
{
    struct kevent  *kev;

    const nxt_int_t   flags = EV_ADD | EV_ENABLE | EV_ONESHOT;
    const nxt_uint_t  fflags = NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND
                               | NOTE_ATTRIB | NOTE_RENAME | NOTE_REVOKE;

    nxt_debug(&engine->task, "kevent(%d) set: id:%d ft:%i fl:%04Xd, ff:%04XuD",
              engine->u.kqueue.fd, ev->file->fd, EVFILT_VNODE, flags, fflags);

    kev = nxt_kqueue_get_kevent(engine);

    kev->ident = ev->file->fd;
    kev->filter = EVFILT_VNODE;
    kev->flags = flags;
    kev->fflags = fflags;
    kev->data = 0;
    kev->udata = nxt_kevent_set_udata(ev);
}


static void
nxt_kqueue_close_file(nxt_event_engine_t *engine, nxt_file_event_t *ev)
{
    /* TODO: pending event. */
}


static void
nxt_kqueue_fd_set(nxt_event_engine_t *engine, nxt_fd_event_t *ev,
    nxt_int_t filter, nxt_uint_t flags)
{
    struct kevent  *kev;

    nxt_debug(ev->task, "kevent(%d) set event: id:%d ft:%i fl:%04Xui",
              engine->u.kqueue.fd, ev->fd, filter, flags);

    kev = nxt_kqueue_get_kevent(engine);

    kev->ident = ev->fd;
    kev->filter = filter;
    kev->flags = flags;
    kev->fflags = 0;
    kev->data = 0;
    kev->udata = nxt_kevent_set_udata(ev);
}


static struct kevent *
nxt_kqueue_get_kevent(nxt_event_engine_t *engine)
{
    int  ret, nchanges;

    nchanges = engine->u.kqueue.nchanges;

    if (nxt_slow_path(nchanges >= engine->u.kqueue.mchanges)) {

        nxt_debug(&engine->task, "kevent(%d) changes:%d",
                  engine->u.kqueue.fd, nchanges);

        ret = kevent(engine->u.kqueue.fd, engine->u.kqueue.changes, nchanges,
                     NULL, 0, NULL);

        if (nxt_slow_path(ret != 0)) {
            nxt_alert(&engine->task, "kevent(%d) failed %E",
                      engine->u.kqueue.fd, nxt_errno);

            nxt_kqueue_error(engine);
        }

        engine->u.kqueue.nchanges = 0;
    }

    return &engine->u.kqueue.changes[engine->u.kqueue.nchanges++];
}


static void
nxt_kqueue_error(nxt_event_engine_t *engine)
{
    struct kevent     *kev, *end;
    nxt_fd_event_t    *ev;
    nxt_file_event_t  *fev;
    nxt_work_queue_t  *wq;

    wq = &engine->fast_work_queue;
    end = &engine->u.kqueue.changes[engine->u.kqueue.nchanges];

    for (kev = engine->u.kqueue.changes; kev < end; kev++) {

        switch (kev->filter) {

        case EVFILT_READ:
        case EVFILT_WRITE:
            ev = nxt_kevent_get_udata(kev->udata);
            nxt_work_queue_add(wq, nxt_kqueue_fd_error_handler,
                               ev->task, ev, ev->data);
            break;

        case EVFILT_VNODE:
            fev = nxt_kevent_get_udata(kev->udata);
            nxt_work_queue_add(wq, nxt_kqueue_file_error_handler,
                               fev->task, fev, fev->data);
            break;
        }
    }
}


static void
nxt_kqueue_fd_error_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_fd_event_t  *ev;

    ev = obj;

    nxt_debug(task, "kqueue fd error handler fd:%d", ev->fd);

    if (ev->kq_eof && ev->kq_errno != 0) {
        ev->error = ev->kq_errno;
        nxt_log(task, nxt_socket_error_level(ev->kq_errno),
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
    nxt_file_event_t  *ev;

    ev = obj;

    nxt_debug(task, "kqueue file error handler fd:%d", ev->file->fd);

    ev->handler(task, ev, data);
}


static nxt_int_t
nxt_kqueue_add_signal(nxt_event_engine_t *engine, const nxt_sig_event_t *sigev)
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
        nxt_alert(&engine->task, "sigaction(%d) failed %E", signo, nxt_errno);

        return NXT_ERROR;
    }

    nxt_debug(&engine->task, "kevent(%d) signo:%d (%s)",
              engine->u.kqueue.fd, signo, sigev->name);

    kev.ident = signo;
    kev.filter = EVFILT_SIGNAL;
    kev.flags = EV_ADD;
    kev.fflags = 0;
    kev.data = 0;
    kev.udata = nxt_kevent_set_udata(sigev);

    if (kevent(engine->u.kqueue.fd, &kev, 1, NULL, 0, NULL) == 0) {
        return NXT_OK;
    }

    nxt_alert(&engine->task, "kevent(%d) failed %E", kqueue, nxt_errno);

    return NXT_ERROR;
}


#if (NXT_HAVE_EVFILT_USER)

static nxt_int_t
nxt_kqueue_enable_post(nxt_event_engine_t *engine, nxt_work_handler_t handler)
{
    struct kevent  kev;

    /* EVFILT_USER must be added to a kqueue before it can be triggered. */

    kev.ident = 0;
    kev.filter = EVFILT_USER;
    kev.flags = EV_ADD | EV_CLEAR;
    kev.fflags = 0;
    kev.data = 0;
    kev.udata = NULL;

    engine->u.kqueue.post_handler = handler;

    if (kevent(engine->u.kqueue.fd, &kev, 1, NULL, 0, NULL) == 0) {
        return NXT_OK;
    }

    nxt_alert(&engine->task, "kevent(%d) failed %E",
              engine->u.kqueue.fd, nxt_errno);

    return NXT_ERROR;
}


static void
nxt_kqueue_signal(nxt_event_engine_t *engine, nxt_uint_t signo)
{
    struct kevent  kev;

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

    if (kevent(engine->u.kqueue.fd, &kev, 1, NULL, 0, NULL) != 0) {
        nxt_alert(&engine->task, "kevent(%d) failed %E",
                  engine->u.kqueue.fd, nxt_errno);
    }
}

#endif


static void
nxt_kqueue_poll(nxt_event_engine_t *engine, nxt_msec_t timeout)
{
    int                 nevents;
    void                *obj, *data;
    nxt_int_t           i;
    nxt_err_t           err;
    nxt_uint_t          level;
    nxt_bool_t          error, eof;
    nxt_task_t          *task;
    struct kevent       *kev;
    nxt_fd_event_t      *ev;
    nxt_sig_event_t     *sigev;
    struct timespec     ts, *tp;
    nxt_file_event_t    *fev;
    nxt_work_queue_t    *wq;
    nxt_work_handler_t  handler;

    if (timeout == NXT_INFINITE_MSEC) {
        tp = NULL;

    } else {
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000000;
        tp = &ts;
    }

    nxt_debug(&engine->task, "kevent(%d) changes:%d timeout:%M",
              engine->u.kqueue.fd, engine->u.kqueue.nchanges, timeout);

    nevents = kevent(engine->u.kqueue.fd,
                     engine->u.kqueue.changes, engine->u.kqueue.nchanges,
                     engine->u.kqueue.events, engine->u.kqueue.mevents, tp);

    err = (nevents == -1) ? nxt_errno : 0;

    nxt_thread_time_update(engine->task.thread);

    nxt_debug(&engine->task, "kevent(%d): %d", engine->u.kqueue.fd, nevents);

    if (nevents == -1) {
        level = (err == NXT_EINTR) ? NXT_LOG_INFO : NXT_LOG_ALERT;

        nxt_log(&engine->task, level, "kevent(%d) failed %E",
                engine->u.kqueue.fd, err);

        nxt_kqueue_error(engine);
        return;
    }

    engine->u.kqueue.nchanges = 0;

    for (i = 0; i < nevents; i++) {

        kev = &engine->u.kqueue.events[i];

        nxt_debug(&engine->task,
                  (kev->ident > 0x8000000 && kev->ident != (uintptr_t) -1) ?
                      "kevent: id:%p ft:%d fl:%04Xd ff:%d d:%d ud:%p":
                      "kevent: id:%d ft:%d fl:%04Xd ff:%d d:%d ud:%p",
                  kev->ident, kev->filter, kev->flags, kev->fflags,
                  kev->data, kev->udata);

        error = (kev->flags & EV_ERROR);

        if (nxt_slow_path(error)) {
            nxt_alert(&engine->task,
                      "kevent(%d) error %E on ident:%d filter:%d",
                      engine->u.kqueue.fd, kev->data, kev->ident, kev->filter);
        }

        task = &engine->task;
        wq = &engine->fast_work_queue;
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

            if (ev->read <= NXT_EVENT_BLOCKED) {
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

            task = ev->task;
            data = ev->data;

            break;

        case EVFILT_WRITE:
            ev = obj;
            ev->write_ready = 1;
            err = kev->fflags;
            eof = (kev->flags & EV_EOF) != 0;
            ev->kq_errno = err;
            ev->kq_eof = eof;

            if (ev->write <= NXT_EVENT_BLOCKED) {
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

            task = ev->task;
            data = ev->data;

            break;

        case EVFILT_VNODE:
            fev = obj;
            handler = fev->handler;
            task = fev->task;
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
            handler = engine->u.kqueue.post_handler;
            data = NULL;
            break;

#endif

        default:

#if (NXT_DEBUG)
            nxt_alert(&engine->task,
                      "unexpected kevent(%d) filter %d on ident %d",
                      engine->u.kqueue.fd, kev->filter, kev->ident);
#endif

            continue;
        }

        nxt_work_queue_add(wq, handler, task, obj, data);
    }
}


/*
 * nxt_kqueue_event_conn_io_connect() eliminates the
 * getsockopt() syscall to test pending connect() error.
 */

static void
nxt_kqueue_conn_io_connect(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t                    *c;
    nxt_event_engine_t            *engine;
    nxt_work_handler_t            handler;
    const nxt_event_conn_state_t  *state;

    c = obj;

    state = c->write_state;

    switch (nxt_socket_connect(task, c->socket.fd, c->remote)) {

    case NXT_OK:
        c->socket.write_ready = 1;
        handler = state->ready_handler;
        break;

    case NXT_AGAIN:
        c->socket.write_handler = nxt_kqueue_conn_connected;
        c->socket.error_handler = nxt_conn_connect_error;

        engine = task->thread->engine;
        nxt_conn_timer(engine, c, state, &c->write_timer);

        nxt_kqueue_enable_write(engine, &c->socket);
        return;

    case NXT_DECLINED:
        handler = state->close_handler;
        break;

    default: /* NXT_ERROR */
        handler = state->error_handler;
        break;
    }

    nxt_work_queue_add(c->write_work_queue, handler, task, c, data);
}


static void
nxt_kqueue_conn_connected(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "kqueue conn connected fd:%d", c->socket.fd);

    c->socket.write = NXT_EVENT_BLOCKED;

    if (c->write_state->timer_autoreset) {
        nxt_timer_disable(task->thread->engine, &c->write_timer);
    }

    nxt_work_queue_add(c->write_work_queue, c->write_state->ready_handler,
                       task, c, data);
}


static void
nxt_kqueue_listen_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_listen_event_t  *lev;

    lev = obj;

    nxt_debug(task, "kevent fd:%d avail:%D",
              lev->socket.fd, lev->socket.kq_available);

    lev->ready = nxt_min(lev->batch, (uint32_t) lev->socket.kq_available);

    nxt_kqueue_conn_io_accept(task, lev, data);
}


static void
nxt_kqueue_conn_io_accept(nxt_task_t *task, void *obj, void *data)
{
    socklen_t           socklen;
    nxt_conn_t          *c;
    nxt_socket_t        s;
    struct sockaddr     *sa;
    nxt_listen_event_t  *lev;

    lev = obj;
    c = lev->next;

    lev->ready--;
    lev->socket.read_ready = (lev->ready != 0);

    lev->socket.kq_available--;
    lev->socket.read_ready = (lev->socket.kq_available != 0);

    sa = &c->remote->u.sockaddr;
    socklen = c->remote->socklen;
    /*
     * The returned socklen is ignored here,
     * see comment in nxt_conn_io_accept().
     */
    s = accept(lev->socket.fd, sa, &socklen);

    if (s != -1) {
        c->socket.fd = s;

        nxt_debug(task, "accept(%d): %d", lev->socket.fd, s);

        nxt_conn_accept(task, lev, c);
        return;
    }

    nxt_conn_accept_error(task, lev, "accept", nxt_errno);
}


/*
 * nxt_kqueue_conn_io_read() is just a wrapper to eliminate the
 * readv() or recv() syscall if a remote side just closed connection.
 */

static void
nxt_kqueue_conn_io_read(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "kqueue conn read fd:%d", c->socket.fd);

    if (c->socket.kq_available == 0 && c->socket.kq_eof) {
        nxt_debug(task, "kevent fd:%d eof", c->socket.fd);

        c->socket.closed = 1;
        nxt_work_queue_add(c->read_work_queue, c->read_state->close_handler,
                           task, c, data);
        return;
    }

    nxt_conn_io_read(task, c, data);
}


/*
 * nxt_kqueue_conn_io_recvbuf() is just wrapper around standard
 * nxt_conn_io_recvbuf() to eliminate the readv() or recv() syscalls
 * if there is no pending data or a remote side closed connection.
 */

static ssize_t
nxt_kqueue_conn_io_recvbuf(nxt_conn_t *c, nxt_buf_t *b)
{
    ssize_t  n;

    if (c->socket.kq_available == 0 && c->socket.kq_eof) {
        c->socket.closed = 1;
        return 0;
    }

    n = nxt_conn_io_recvbuf(c, b);

    if (n > 0) {
        c->socket.kq_available -= n;

        if (c->socket.kq_available < 0) {
            c->socket.kq_available = 0;
        }

        nxt_debug(c->socket.task, "kevent fd:%d avail:%D eof:%d",
                  c->socket.fd, c->socket.kq_available, c->socket.kq_eof);

        c->socket.read_ready = (c->socket.kq_available != 0
                                || c->socket.kq_eof);
    }

    return n;
}

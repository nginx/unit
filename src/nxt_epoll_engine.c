
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * The first epoll version has been introduced in Linux 2.5.44.  The
 * interface was changed several times since then and the final version
 * of epoll_create(), epoll_ctl(), epoll_wait(), and EPOLLET mode has
 * been introduced in Linux 2.6.0 and is supported since glibc 2.3.2.
 *
 * EPOLLET mode did not work reliable in early implementaions and in
 * Linux 2.4 backport.
 *
 * EPOLLONESHOT             Linux 2.6.2,  glibc 2.3.
 * EPOLLRDHUP               Linux 2.6.17, glibc 2.8.
 * epoll_pwait()            Linux 2.6.19, glibc 2.6.
 * signalfd()               Linux 2.6.22, glibc 2.7.
 * eventfd()                Linux 2.6.22, glibc 2.7.
 * timerfd_create()         Linux 2.6.25, glibc 2.8.
 * epoll_create1()          Linux 2.6.27, glibc 2.9.
 * signalfd4()              Linux 2.6.27, glibc 2.9.
 * eventfd2()               Linux 2.6.27, glibc 2.9.
 * accept4()                Linux 2.6.28, glibc 2.10.
 * eventfd2(EFD_SEMAPHORE)  Linux 2.6.30, glibc 2.10.
 * EPOLLEXCLUSIVE           Linux 4.5, glibc 2.24.
 */


#if (NXT_HAVE_EPOLL_EDGE)
static nxt_int_t nxt_epoll_edge_create(nxt_event_engine_t *engine,
    nxt_uint_t mchanges, nxt_uint_t mevents);
#endif
static nxt_int_t nxt_epoll_level_create(nxt_event_engine_t *engine,
    nxt_uint_t mchanges, nxt_uint_t mevents);
static nxt_int_t nxt_epoll_create(nxt_event_engine_t *engine,
    nxt_uint_t mchanges, nxt_uint_t mevents, nxt_conn_io_t *io, uint32_t mode);
static void nxt_epoll_test_accept4(nxt_event_engine_t *engine,
    nxt_conn_io_t *io);
static void nxt_epoll_free(nxt_event_engine_t *engine);
static void nxt_epoll_enable(nxt_event_engine_t *engine, nxt_fd_event_t *ev);
static void nxt_epoll_disable(nxt_event_engine_t *engine, nxt_fd_event_t *ev);
static void nxt_epoll_delete(nxt_event_engine_t *engine, nxt_fd_event_t *ev);
static nxt_bool_t nxt_epoll_close(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_epoll_enable_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_epoll_enable_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_epoll_disable_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_epoll_disable_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_epoll_block_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_epoll_block_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_epoll_oneshot_read(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_epoll_oneshot_write(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_epoll_enable_accept(nxt_event_engine_t *engine,
    nxt_fd_event_t *ev);
static void nxt_epoll_change(nxt_event_engine_t *engine, nxt_fd_event_t *ev,
    int op, uint32_t events);
static void nxt_epoll_commit_changes(nxt_event_engine_t *engine);
static void nxt_epoll_error_handler(nxt_task_t *task, void *obj, void *data);
#if (NXT_HAVE_SIGNALFD)
static nxt_int_t nxt_epoll_add_signal(nxt_event_engine_t *engine);
static void nxt_epoll_signalfd_handler(nxt_task_t *task, void *obj, void *data);
#endif
#if (NXT_HAVE_EVENTFD)
static nxt_int_t nxt_epoll_enable_post(nxt_event_engine_t *engine,
    nxt_work_handler_t handler);
static void nxt_epoll_eventfd_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_epoll_signal(nxt_event_engine_t *engine, nxt_uint_t signo);
#endif
static void nxt_epoll_poll(nxt_event_engine_t *engine, nxt_msec_t timeout);

#if (NXT_HAVE_ACCEPT4)
static void nxt_epoll_conn_io_accept4(nxt_task_t *task, void *obj,
    void *data);
#endif


#if (NXT_HAVE_EPOLL_EDGE)

static void nxt_epoll_edge_conn_io_connect(nxt_task_t *task, void *obj,
    void *data);
static void nxt_epoll_edge_conn_connected(nxt_task_t *task, void *obj,
    void *data);
static ssize_t nxt_epoll_edge_conn_io_recvbuf(nxt_conn_t *c, nxt_buf_t *b);


static nxt_conn_io_t  nxt_epoll_edge_conn_io = {
    .connect = nxt_epoll_edge_conn_io_connect,
    .accept = nxt_conn_io_accept,

    .read = nxt_conn_io_read,
    .recvbuf = nxt_epoll_edge_conn_io_recvbuf,
    .recv = nxt_conn_io_recv,

    .write = nxt_conn_io_write,
    .sendbuf = nxt_conn_io_sendbuf,

#if (NXT_HAVE_LINUX_SENDFILE)
    .old_sendbuf = nxt_linux_event_conn_io_sendfile,
#else
    .old_sendbuf = nxt_event_conn_io_sendbuf,
#endif

    .writev = nxt_event_conn_io_writev,
    .send = nxt_event_conn_io_send,
};


const nxt_event_interface_t  nxt_epoll_edge_engine = {
    "epoll_edge",
    nxt_epoll_edge_create,
    nxt_epoll_free,
    nxt_epoll_enable,
    nxt_epoll_disable,
    nxt_epoll_delete,
    nxt_epoll_close,
    nxt_epoll_enable_read,
    nxt_epoll_enable_write,
    nxt_epoll_disable_read,
    nxt_epoll_disable_write,
    nxt_epoll_block_read,
    nxt_epoll_block_write,
    nxt_epoll_oneshot_read,
    nxt_epoll_oneshot_write,
    nxt_epoll_enable_accept,
    NULL,
    NULL,
#if (NXT_HAVE_EVENTFD)
    nxt_epoll_enable_post,
    nxt_epoll_signal,
#else
    NULL,
    NULL,
#endif
    nxt_epoll_poll,

    &nxt_epoll_edge_conn_io,

#if (NXT_HAVE_INOTIFY)
    NXT_FILE_EVENTS,
#else
    NXT_NO_FILE_EVENTS,
#endif

#if (NXT_HAVE_SIGNALFD)
    NXT_SIGNAL_EVENTS,
#else
    NXT_NO_SIGNAL_EVENTS,
#endif
};

#endif


const nxt_event_interface_t  nxt_epoll_level_engine = {
    "epoll_level",
    nxt_epoll_level_create,
    nxt_epoll_free,
    nxt_epoll_enable,
    nxt_epoll_disable,
    nxt_epoll_delete,
    nxt_epoll_close,
    nxt_epoll_enable_read,
    nxt_epoll_enable_write,
    nxt_epoll_disable_read,
    nxt_epoll_disable_write,
    nxt_epoll_block_read,
    nxt_epoll_block_write,
    nxt_epoll_oneshot_read,
    nxt_epoll_oneshot_write,
    nxt_epoll_enable_accept,
    NULL,
    NULL,
#if (NXT_HAVE_EVENTFD)
    nxt_epoll_enable_post,
    nxt_epoll_signal,
#else
    NULL,
    NULL,
#endif
    nxt_epoll_poll,

    &nxt_unix_conn_io,

#if (NXT_HAVE_INOTIFY)
    NXT_FILE_EVENTS,
#else
    NXT_NO_FILE_EVENTS,
#endif

#if (NXT_HAVE_SIGNALFD)
    NXT_SIGNAL_EVENTS,
#else
    NXT_NO_SIGNAL_EVENTS,
#endif
};


#if (NXT_HAVE_EPOLL_EDGE)

static nxt_int_t
nxt_epoll_edge_create(nxt_event_engine_t *engine, nxt_uint_t mchanges,
    nxt_uint_t mevents)
{
    return nxt_epoll_create(engine, mchanges, mevents, &nxt_epoll_edge_conn_io,
                            EPOLLET | EPOLLRDHUP);
}

#endif


static nxt_int_t
nxt_epoll_level_create(nxt_event_engine_t *engine, nxt_uint_t mchanges,
    nxt_uint_t mevents)
{
    return nxt_epoll_create(engine, mchanges, mevents,
                            &nxt_unix_conn_io, 0);
}


static nxt_int_t
nxt_epoll_create(nxt_event_engine_t *engine, nxt_uint_t mchanges,
    nxt_uint_t mevents, nxt_conn_io_t *io, uint32_t mode)
{
    engine->u.epoll.fd = -1;
    engine->u.epoll.mode = mode;
    engine->u.epoll.mchanges = mchanges;
    engine->u.epoll.mevents = mevents;
#if (NXT_HAVE_SIGNALFD)
    engine->u.epoll.signalfd.fd = -1;
#endif

    engine->u.epoll.changes = nxt_malloc(sizeof(nxt_epoll_change_t) * mchanges);
    if (engine->u.epoll.changes == NULL) {
        goto fail;
    }

    engine->u.epoll.events = nxt_malloc(sizeof(struct epoll_event) * mevents);
    if (engine->u.epoll.events == NULL) {
        goto fail;
    }

    engine->u.epoll.fd = epoll_create(1);
    if (engine->u.epoll.fd == -1) {
        nxt_alert(&engine->task, "epoll_create() failed %E", nxt_errno);
        goto fail;
    }

    nxt_debug(&engine->task, "epoll_create(): %d", engine->u.epoll.fd);

    if (engine->signals != NULL) {

#if (NXT_HAVE_SIGNALFD)

        if (nxt_epoll_add_signal(engine) != NXT_OK) {
            goto fail;
        }

#endif

        nxt_epoll_test_accept4(engine, io);
    }

    return NXT_OK;

fail:

    nxt_epoll_free(engine);

    return NXT_ERROR;
}


static void
nxt_epoll_test_accept4(nxt_event_engine_t *engine, nxt_conn_io_t *io)
{
    static nxt_work_handler_t  handler;

    if (handler == NULL) {

        handler = io->accept;

#if (NXT_HAVE_ACCEPT4)

        (void) accept4(-1, NULL, NULL, SOCK_NONBLOCK);

        if (nxt_errno != NXT_ENOSYS) {
            handler = nxt_epoll_conn_io_accept4;

        } else {
            nxt_log(&engine->task, NXT_LOG_INFO, "accept4() failed %E",
                    NXT_ENOSYS);
        }

#endif
    }

    io->accept = handler;
}


static void
nxt_epoll_free(nxt_event_engine_t *engine)
{
    int  fd;

    nxt_debug(&engine->task, "epoll %d free", engine->u.epoll.fd);

#if (NXT_HAVE_SIGNALFD)

    fd = engine->u.epoll.signalfd.fd;

    if (fd != -1 && close(fd) != 0) {
        nxt_alert(&engine->task, "signalfd close(%d) failed %E", fd, nxt_errno);
    }

#endif

#if (NXT_HAVE_EVENTFD)

    fd = engine->u.epoll.eventfd.fd;

    if (fd != -1 && close(fd) != 0) {
        nxt_alert(&engine->task, "eventfd close(%d) failed %E", fd, nxt_errno);
    }

#endif

    fd = engine->u.epoll.fd;

    if (fd != -1 && close(fd) != 0) {
        nxt_alert(&engine->task, "epoll close(%d) failed %E", fd, nxt_errno);
    }

    nxt_free(engine->u.epoll.events);
    nxt_free(engine->u.epoll.changes);

    nxt_memzero(&engine->u.epoll, sizeof(nxt_epoll_engine_t));
}


static void
nxt_epoll_enable(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    ev->read = NXT_EVENT_ACTIVE;
    ev->write = NXT_EVENT_ACTIVE;

    nxt_epoll_change(engine, ev, EPOLL_CTL_ADD,
                     EPOLLIN | EPOLLOUT | engine->u.epoll.mode);
}


static void
nxt_epoll_disable(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read > NXT_EVENT_DISABLED || ev->write > NXT_EVENT_DISABLED) {

        ev->read = NXT_EVENT_INACTIVE;
        ev->write = NXT_EVENT_INACTIVE;

        nxt_epoll_change(engine, ev, EPOLL_CTL_DEL, 0);
    }
}


static void
nxt_epoll_delete(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE || ev->write != NXT_EVENT_INACTIVE) {

        ev->read = NXT_EVENT_INACTIVE;
        ev->write = NXT_EVENT_INACTIVE;

        nxt_epoll_change(engine, ev, EPOLL_CTL_DEL, 0);
    }
}


/*
 * Although calling close() on a file descriptor will remove any epoll
 * events that reference the descriptor, in this case the close() acquires
 * the kernel global "epmutex" while epoll_ctl(EPOLL_CTL_DEL) does not
 * acquire the "epmutex" since Linux 3.13 if the file descriptor presents
 * only in one epoll set.  Thus removing events explicitly before closing
 * eliminates possible lock contention.
 */

static nxt_bool_t
nxt_epoll_close(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    nxt_epoll_delete(engine, ev);

    return ev->changing;
}


static void
nxt_epoll_enable_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    int       op;
    uint32_t  events;

    if (ev->read != NXT_EVENT_BLOCKED) {

        op = EPOLL_CTL_MOD;
        events = EPOLLIN | engine->u.epoll.mode;

        if (ev->read == NXT_EVENT_INACTIVE && ev->write == NXT_EVENT_INACTIVE) {
            op = EPOLL_CTL_ADD;

        } else if (ev->write >= NXT_EVENT_BLOCKED) {
            events |= EPOLLOUT;
        }

        nxt_epoll_change(engine, ev, op, events);
    }

    ev->read = NXT_EVENT_ACTIVE;
}


static void
nxt_epoll_enable_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    int       op;
    uint32_t  events;

    if (ev->write != NXT_EVENT_BLOCKED) {

        op = EPOLL_CTL_MOD;
        events = EPOLLOUT | engine->u.epoll.mode;

        if (ev->read == NXT_EVENT_INACTIVE && ev->write == NXT_EVENT_INACTIVE) {
            op = EPOLL_CTL_ADD;

        } else if (ev->read >= NXT_EVENT_BLOCKED) {
            events |= EPOLLIN;
        }

        nxt_epoll_change(engine, ev, op, events);
    }

    ev->write = NXT_EVENT_ACTIVE;
}


static void
nxt_epoll_disable_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    int       op;
    uint32_t  events;

    ev->read = NXT_EVENT_INACTIVE;

    if (ev->write <= NXT_EVENT_DISABLED) {
        ev->write = NXT_EVENT_INACTIVE;
        op = EPOLL_CTL_DEL;
        events = 0;

    } else {
        op = EPOLL_CTL_MOD;
        events = EPOLLOUT | engine->u.epoll.mode;
    }

    nxt_epoll_change(engine, ev, op, events);
}


static void
nxt_epoll_disable_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    int       op;
    uint32_t  events;

    ev->write = NXT_EVENT_INACTIVE;

    if (ev->read <= NXT_EVENT_DISABLED) {
        ev->read = NXT_EVENT_INACTIVE;
        op = EPOLL_CTL_DEL;
        events = 0;

    } else {
        op = EPOLL_CTL_MOD;
        events = EPOLLIN | engine->u.epoll.mode;
    }

    nxt_epoll_change(engine, ev, op, events);
}


static void
nxt_epoll_block_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_epoll_block_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    if (ev->write != NXT_EVENT_INACTIVE) {
        ev->write = NXT_EVENT_BLOCKED;
    }
}


/*
 * NXT_EVENT_DISABLED state is used to track whether EPOLLONESHOT
 * event should be added or modified, epoll_ctl(2):
 *
 * EPOLLONESHOT (since Linux 2.6.2)
 *     Sets the one-shot behavior for the associated file descriptor.
 *     This means that after an event is pulled out with epoll_wait(2)
 *     the associated file descriptor is internally disabled and no
 *     other events will be reported by the epoll interface.  The user
 *     must call epoll_ctl() with EPOLL_CTL_MOD to rearm the file
 *     descriptor with a new event mask.
 */

static void
nxt_epoll_oneshot_read(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    int  op;

    op = (ev->read == NXT_EVENT_INACTIVE && ev->write == NXT_EVENT_INACTIVE) ?
             EPOLL_CTL_ADD : EPOLL_CTL_MOD;

    ev->read = NXT_EVENT_ONESHOT;
    ev->write = NXT_EVENT_INACTIVE;

    nxt_epoll_change(engine, ev, op, EPOLLIN | EPOLLONESHOT);
}


static void
nxt_epoll_oneshot_write(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    int  op;

    op = (ev->read == NXT_EVENT_INACTIVE && ev->write == NXT_EVENT_INACTIVE) ?
             EPOLL_CTL_ADD : EPOLL_CTL_MOD;

    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_ONESHOT;

    nxt_epoll_change(engine, ev, op, EPOLLOUT | EPOLLONESHOT);
}


static void
nxt_epoll_enable_accept(nxt_event_engine_t *engine, nxt_fd_event_t *ev)
{
    uint32_t  events;

    ev->read = NXT_EVENT_ACTIVE;

    events = EPOLLIN;

#ifdef EPOLLEXCLUSIVE
    events |= EPOLLEXCLUSIVE;
#endif

    nxt_epoll_change(engine, ev, EPOLL_CTL_ADD, events);
}


/*
 * epoll changes are batched to improve instruction and data cache
 * locality of several epoll_ctl() calls followed by epoll_wait() call.
 */

static void
nxt_epoll_change(nxt_event_engine_t *engine, nxt_fd_event_t *ev, int op,
    uint32_t events)
{
    nxt_epoll_change_t  *change;

    nxt_debug(ev->task, "epoll %d set event: fd:%d op:%d ev:%XD",
              engine->u.epoll.fd, ev->fd, op, events);

    if (engine->u.epoll.nchanges >= engine->u.epoll.mchanges) {
        nxt_epoll_commit_changes(engine);
    }

    ev->changing = 1;

    change = &engine->u.epoll.changes[engine->u.epoll.nchanges++];
    change->op = op;
    change->event.events = events;
    change->event.data.ptr = ev;
}


static void
nxt_epoll_commit_changes(nxt_event_engine_t *engine)
{
    int                 ret;
    nxt_fd_event_t      *ev;
    nxt_epoll_change_t  *change, *end;

    nxt_debug(&engine->task, "epoll %d changes:%ui",
              engine->u.epoll.fd, engine->u.epoll.nchanges);

    change = engine->u.epoll.changes;
    end = change + engine->u.epoll.nchanges;

    do {
        ev = change->event.data.ptr;
        ev->changing = 0;

        nxt_debug(ev->task, "epoll_ctl(%d): fd:%d op:%d ev:%XD",
                  engine->u.epoll.fd, ev->fd, change->op,
                  change->event.events);

        ret = epoll_ctl(engine->u.epoll.fd, change->op, ev->fd, &change->event);

        if (nxt_slow_path(ret != 0)) {
            nxt_alert(ev->task, "epoll_ctl(%d, %d, %d) failed %E",
                      engine->u.epoll.fd, change->op, ev->fd, nxt_errno);

            nxt_work_queue_add(&engine->fast_work_queue,
                               nxt_epoll_error_handler, ev->task, ev, ev->data);

            engine->u.epoll.error = 1;
        }

        change++;

    } while (change < end);

    engine->u.epoll.nchanges = 0;
}


static void
nxt_epoll_error_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_fd_event_t  *ev;

    ev = obj;

    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;

    ev->error_handler(ev->task, ev, data);
}


#if (NXT_HAVE_SIGNALFD)

static nxt_int_t
nxt_epoll_add_signal(nxt_event_engine_t *engine)
{
    int                 fd;
    struct epoll_event  ee;

    if (sigprocmask(SIG_BLOCK, &engine->signals->sigmask, NULL) != 0) {
        nxt_alert(&engine->task, "sigprocmask(SIG_BLOCK) failed %E", nxt_errno);
        return NXT_ERROR;
    }

    /*
     * Glibc signalfd() wrapper always has the flags argument.  Glibc 2.7
     * and 2.8 signalfd() wrappers call the original signalfd() syscall
     * without the flags argument.  Glibc 2.9+ signalfd() wrapper at first
     * tries to call signalfd4() syscall and if it fails then calls the
     * original signalfd() syscall.  For this reason the non-blocking mode
     * is set separately.
     */

    fd = signalfd(-1, &engine->signals->sigmask, 0);

    if (fd == -1) {
        nxt_alert(&engine->task, "signalfd(%d) failed %E",
                  engine->u.epoll.signalfd.fd, nxt_errno);
        return NXT_ERROR;
    }

    engine->u.epoll.signalfd.fd = fd;

    if (nxt_fd_nonblocking(&engine->task, fd) != NXT_OK) {
        return NXT_ERROR;
    }

    nxt_debug(&engine->task, "signalfd(): %d", fd);

    engine->u.epoll.signalfd.data = engine->signals->handler;
    engine->u.epoll.signalfd.read_work_queue = &engine->fast_work_queue;
    engine->u.epoll.signalfd.read_handler = nxt_epoll_signalfd_handler;
    engine->u.epoll.signalfd.log = engine->task.log;
    engine->u.epoll.signalfd.task = &engine->task;

    ee.events = EPOLLIN;
    ee.data.ptr = &engine->u.epoll.signalfd;

    if (epoll_ctl(engine->u.epoll.fd, EPOLL_CTL_ADD, fd, &ee) != 0) {
        nxt_alert(&engine->task, "epoll_ctl(%d, %d, %d) failed %E",
                  engine->u.epoll.fd, EPOLL_CTL_ADD, fd, nxt_errno);

        return NXT_ERROR;
    }

    return NXT_OK;
}


static void
nxt_epoll_signalfd_handler(nxt_task_t *task, void *obj, void *data)
{
    int                      n;
    nxt_fd_event_t           *ev;
    nxt_work_handler_t       handler;
    struct signalfd_siginfo  sfd;

    ev = obj;
    handler = data;

    nxt_debug(task, "signalfd handler");

    n = read(ev->fd, &sfd, sizeof(struct signalfd_siginfo));

    nxt_debug(task, "read signalfd(%d): %d", ev->fd, n);

    if (n != sizeof(struct signalfd_siginfo)) {
        nxt_alert(task, "read signalfd(%d) failed %E", ev->fd, nxt_errno);
        return;
    }

    nxt_debug(task, "signalfd(%d) signo:%d", ev->fd, sfd.ssi_signo);

    handler(task, (void *) (uintptr_t) sfd.ssi_signo, NULL);
}

#endif


#if (NXT_HAVE_EVENTFD)

static nxt_int_t
nxt_epoll_enable_post(nxt_event_engine_t *engine, nxt_work_handler_t handler)
{
    int                 ret;
    struct epoll_event  ee;

    engine->u.epoll.post_handler = handler;

    /*
     * Glibc eventfd() wrapper always has the flags argument.  Glibc 2.7
     * and 2.8 eventfd() wrappers call the original eventfd() syscall
     * without the flags argument.  Glibc 2.9+ eventfd() wrapper at first
     * tries to call eventfd2() syscall and if it fails then calls the
     * original eventfd() syscall.  For this reason the non-blocking mode
     * is set separately.
     */

    engine->u.epoll.eventfd.fd = eventfd(0, 0);

    if (engine->u.epoll.eventfd.fd == -1) {
        nxt_alert(&engine->task, "eventfd() failed %E", nxt_errno);
        return NXT_ERROR;
    }

    ret = nxt_fd_nonblocking(&engine->task, engine->u.epoll.eventfd.fd);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    nxt_debug(&engine->task, "eventfd(): %d", engine->u.epoll.eventfd.fd);

    engine->u.epoll.eventfd.read_work_queue = &engine->fast_work_queue;
    engine->u.epoll.eventfd.read_handler = nxt_epoll_eventfd_handler;
    engine->u.epoll.eventfd.data = engine;
    engine->u.epoll.eventfd.log = engine->task.log;
    engine->u.epoll.eventfd.task = &engine->task;

    ee.events = EPOLLIN | EPOLLET;
    ee.data.ptr = &engine->u.epoll.eventfd;

    ret = epoll_ctl(engine->u.epoll.fd, EPOLL_CTL_ADD,
                    engine->u.epoll.eventfd.fd, &ee);

    if (nxt_fast_path(ret == 0)) {
        return NXT_OK;
    }

    nxt_alert(&engine->task, "epoll_ctl(%d, %d, %d) failed %E",
              engine->u.epoll.fd, EPOLL_CTL_ADD, engine->u.epoll.eventfd.fd,
              nxt_errno);

    return NXT_ERROR;
}


static void
nxt_epoll_eventfd_handler(nxt_task_t *task, void *obj, void *data)
{
    int                 n;
    uint64_t            events;
    nxt_event_engine_t  *engine;

    engine = data;

    nxt_debug(task, "eventfd handler, times:%ui", engine->u.epoll.neventfd);

    /*
     * The maximum value after write() to a eventfd() descriptor will
     * block or return EAGAIN is 0xFFFFFFFFFFFFFFFE, so the descriptor
     * can be read once per many notifications, for example, once per
     * 2^32-2 noticifcations.  Since the eventfd() file descriptor is
     * always registered in EPOLLET mode, epoll returns event about
     * only the latest write() to the descriptor.
     */

    if (engine->u.epoll.neventfd++ >= 0xFFFFFFFE) {
        engine->u.epoll.neventfd = 0;

        n = read(engine->u.epoll.eventfd.fd, &events, sizeof(uint64_t));

        nxt_debug(task, "read(%d): %d events:%uL",
                  engine->u.epoll.eventfd.fd, n, events);

        if (n != sizeof(uint64_t)) {
            nxt_alert(task, "read eventfd(%d) failed %E",
                      engine->u.epoll.eventfd.fd, nxt_errno);
        }
    }

    engine->u.epoll.post_handler(task, NULL, NULL);
}


static void
nxt_epoll_signal(nxt_event_engine_t *engine, nxt_uint_t signo)
{
    size_t    ret;
    uint64_t  event;

    /*
     * eventfd() presents along with signalfd(), so the function
     * is used only to post events and the signo argument is ignored.
     */

    event = 1;

    ret = write(engine->u.epoll.eventfd.fd, &event, sizeof(uint64_t));

    if (nxt_slow_path(ret != sizeof(uint64_t))) {
        nxt_alert(&engine->task, "write(%d) to eventfd failed %E",
                  engine->u.epoll.eventfd.fd, nxt_errno);
    }
}

#endif


static void
nxt_epoll_poll(nxt_event_engine_t *engine, nxt_msec_t timeout)
{
    int                 nevents;
    uint32_t            events;
    nxt_int_t           i;
    nxt_err_t           err;
    nxt_bool_t          error;
    nxt_uint_t          level;
    nxt_fd_event_t      *ev;
    struct epoll_event  *event;

    if (engine->u.epoll.nchanges != 0) {
        nxt_epoll_commit_changes(engine);
    }

    if (engine->u.epoll.error) {
        engine->u.epoll.error = 0;
        /* Error handlers have been enqueued on failure. */
        timeout = 0;
    }

    nxt_debug(&engine->task, "epoll_wait(%d) timeout:%M",
              engine->u.epoll.fd, timeout);

    nevents = epoll_wait(engine->u.epoll.fd, engine->u.epoll.events,
                         engine->u.epoll.mevents, timeout);

    err = (nevents == -1) ? nxt_errno : 0;

    nxt_thread_time_update(engine->task.thread);

    nxt_debug(&engine->task, "epoll_wait(%d): %d", engine->u.epoll.fd, nevents);

    if (nevents == -1) {
        level = (err == NXT_EINTR) ? NXT_LOG_INFO : NXT_LOG_ALERT;

        nxt_log(&engine->task, level, "epoll_wait(%d) failed %E",
                engine->u.epoll.fd, err);

        return;
    }

    for (i = 0; i < nevents; i++) {

        event = &engine->u.epoll.events[i];
        events = event->events;
        ev = event->data.ptr;

        nxt_debug(ev->task, "epoll: fd:%d ev:%04XD d:%p rd:%d wr:%d",
                  ev->fd, events, ev, ev->read, ev->write);

        /*
         * On error epoll may set EPOLLERR and EPOLLHUP only without EPOLLIN
         * or EPOLLOUT, so the "error" variable enqueues only error handler.
         */
        error = ((events & (EPOLLERR | EPOLLHUP)) != 0);
        ev->epoll_error = error;

#if (NXT_HAVE_EPOLL_EDGE)

        ev->epoll_eof = ((events & EPOLLRDHUP) != 0);

#endif

        if ((events & EPOLLIN) != 0) {
            ev->read_ready = 1;

            if (ev->read != NXT_EVENT_BLOCKED) {

                if (ev->read == NXT_EVENT_ONESHOT) {
                    ev->read = NXT_EVENT_DISABLED;
                }

                nxt_work_queue_add(ev->read_work_queue, ev->read_handler,
                                   ev->task, ev, ev->data);

            } else if (engine->u.epoll.mode == 0) {
                /* Level-triggered mode. */
                nxt_epoll_disable_read(engine, ev);
            }

            error = 0;
        }

        if ((events & EPOLLOUT) != 0) {
            ev->write_ready = 1;

            if (ev->write != NXT_EVENT_BLOCKED) {

                if (ev->write == NXT_EVENT_ONESHOT) {
                    ev->write = NXT_EVENT_DISABLED;
                }

                nxt_work_queue_add(ev->write_work_queue, ev->write_handler,
                                   ev->task, ev, ev->data);

            } else if (engine->u.epoll.mode == 0) {
                /* Level-triggered mode. */
                nxt_epoll_disable_write(engine, ev);
            }

            error = 0;
        }

        if (!error) {
            continue;
        }

        ev->read_ready = 1;
        ev->write_ready = 1;

        if (ev->read == NXT_EVENT_BLOCKED && ev->write == NXT_EVENT_BLOCKED) {

            if (engine->u.epoll.mode == 0) {
                /* Level-triggered mode. */
                nxt_epoll_disable(engine, ev);
            }

            continue;
        }

        nxt_work_queue_add(&engine->fast_work_queue, nxt_epoll_error_handler,
                           ev->task, ev, ev->data);
    }
}


#if (NXT_HAVE_ACCEPT4)

static void
nxt_epoll_conn_io_accept4(nxt_task_t *task, void *obj, void *data)
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

    sa = &c->remote->u.sockaddr;
    socklen = c->remote->socklen;
    /*
     * The returned socklen is ignored here,
     * see comment in nxt_conn_io_accept().
     */
    s = accept4(lev->socket.fd, sa, &socklen, SOCK_NONBLOCK);

    if (s != -1) {
        c->socket.fd = s;

        nxt_debug(task, "accept4(%d): %d", lev->socket.fd, s);

        nxt_conn_accept(task, lev, c);
        return;
    }

    nxt_conn_accept_error(task, lev, "accept4", nxt_errno);
}

#endif


#if (NXT_HAVE_EPOLL_EDGE)

/*
 * nxt_epoll_edge_event_conn_io_connect() eliminates the getsockopt()
 * syscall to test pending connect() error.  Although this special
 * interface can work in both edge-triggered and level-triggered
 * modes it is enabled only for the former mode because this mode is
 * available in all modern Linux distributions.  For the latter mode
 * it is required to create additional nxt_epoll_level_event_conn_io
 * with single non-generic connect() interface.
 */

static void
nxt_epoll_edge_conn_io_connect(nxt_task_t *task, void *obj, void *data)
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
        c->socket.write_handler = nxt_epoll_edge_conn_connected;
        c->socket.error_handler = nxt_conn_connect_error;

        engine = task->thread->engine;
        nxt_conn_timer(engine, c, state, &c->write_timer);

        nxt_epoll_enable(engine, &c->socket);
        c->socket.read = NXT_EVENT_BLOCKED;
        return;

#if 0
    case NXT_AGAIN:
        nxt_conn_timer(engine, c, state, &c->write_timer);

        /* Fall through. */

    case NXT_OK:
        /*
         * Mark both read and write directions as ready and try to perform
         * I/O operations before receiving readiness notifications.
         * On unconnected socket Linux send() and recv() return EAGAIN
         * instead of ENOTCONN.
         */
        c->socket.read_ready = 1;
        c->socket.write_ready = 1;
        /*
         * Enabling both read and write notifications on a getting
         * connected socket eliminates one epoll_ctl() syscall.
         */
        c->socket.write_handler = nxt_epoll_edge_event_conn_connected;
        c->socket.error_handler = state->error_handler;

        nxt_epoll_enable(engine, &c->socket);
        c->socket.read = NXT_EVENT_BLOCKED;

        handler = state->ready_handler;
        break;
#endif

    case NXT_ERROR:
        handler = state->error_handler;
        break;

    default:  /* NXT_DECLINED: connection refused. */
        handler = state->close_handler;
        break;
    }

    nxt_work_queue_add(c->write_work_queue, handler, task, c, data);
}


static void
nxt_epoll_edge_conn_connected(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "epoll event conn connected fd:%d", c->socket.fd);

    if (!c->socket.epoll_error) {
        c->socket.write = NXT_EVENT_BLOCKED;

        if (c->write_state->timer_autoreset) {
            nxt_timer_disable(task->thread->engine, &c->write_timer);
        }

        nxt_work_queue_add(c->write_work_queue, c->write_state->ready_handler,
                           task, c, data);
        return;
    }

    nxt_conn_connect_test(task, c, data);
}


/*
 * nxt_epoll_edge_conn_io_recvbuf() is just wrapper around
 * standard nxt_conn_io_recvbuf() to enforce to read a pending EOF
 * in edge-triggered mode.
 */

static ssize_t
nxt_epoll_edge_conn_io_recvbuf(nxt_conn_t *c, nxt_buf_t *b)
{
    ssize_t  n;

    n = nxt_conn_io_recvbuf(c, b);

    if (n > 0 && c->socket.epoll_eof) {
        c->socket.read_ready = 1;
    }

    return n;
}

#endif

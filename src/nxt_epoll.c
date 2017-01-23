
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
 */


#if (NXT_HAVE_EPOLL_EDGE)
static nxt_event_set_t *nxt_epoll_edge_create(nxt_event_signals_t *signals,
    nxt_uint_t mchanges, nxt_uint_t mevents);
#endif
static nxt_event_set_t *nxt_epoll_level_create(nxt_event_signals_t *signals,
    nxt_uint_t mchanges, nxt_uint_t mevents);
static nxt_event_set_t *nxt_epoll_create(nxt_event_signals_t *signals,
    nxt_uint_t mchanges, nxt_uint_t mevents, nxt_event_conn_io_t *io,
    uint32_t mode);
static void nxt_epoll_test_accept4(nxt_event_conn_io_t *io);
static void nxt_epoll_free(nxt_event_set_t *event_set);
static void nxt_epoll_enable(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_epoll_disable(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_epoll_delete(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_epoll_close(nxt_event_set_t *event_set, nxt_event_fd_t *ev);
static void nxt_epoll_enable_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_epoll_enable_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_epoll_disable_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_epoll_disable_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_epoll_block_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_epoll_block_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_epoll_oneshot_read(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_epoll_oneshot_write(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_epoll_enable_accept(nxt_event_set_t *event_set,
    nxt_event_fd_t *ev);
static void nxt_epoll_change(nxt_event_set_t *event_set, nxt_event_fd_t *ev,
    int op, uint32_t events);
static nxt_int_t nxt_epoll_commit_changes(nxt_task_t *task,
    nxt_epoll_event_set_t *es);
static void nxt_epoll_error_handler(nxt_task_t *task, void *obj,
    void *data);
#if (NXT_HAVE_SIGNALFD)
static nxt_int_t nxt_epoll_add_signal(nxt_epoll_event_set_t *es,
    nxt_event_signals_t *signals);
static void nxt_epoll_signalfd_handler(nxt_task_t *task, void *obj,
    void *data);
#endif
#if (NXT_HAVE_EVENTFD)
static nxt_int_t nxt_epoll_enable_post(nxt_event_set_t *event_set,
    nxt_work_handler_t handler);
static void nxt_epoll_eventfd_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_epoll_signal(nxt_event_set_t *event_set, nxt_uint_t signo);
#endif
static void nxt_epoll_poll(nxt_task_t *task, nxt_event_set_t *event_set,
    nxt_msec_t timeout);

#if (NXT_HAVE_ACCEPT4)
static void nxt_epoll_event_conn_io_accept4(nxt_task_t *task, void *obj,
    void *data);
#endif


#if (NXT_HAVE_EPOLL_EDGE)

static void nxt_epoll_edge_event_conn_io_connect(nxt_task_t *task, void *obj,
    void *data);
static void nxt_epoll_edge_event_conn_connected(nxt_task_t *task, void *obj,
    void *data);
static ssize_t nxt_epoll_edge_event_conn_io_recvbuf(nxt_event_conn_t *c,
    nxt_buf_t *b);


static nxt_event_conn_io_t  nxt_epoll_edge_event_conn_io = {
    nxt_epoll_edge_event_conn_io_connect,
    nxt_event_conn_io_accept,

    nxt_event_conn_io_read,
    nxt_epoll_edge_event_conn_io_recvbuf,
    nxt_event_conn_io_recv,

    nxt_event_conn_io_write,
    nxt_event_conn_io_write_chunk,

#if (NXT_HAVE_LINUX_SENDFILE)
    nxt_linux_event_conn_io_sendfile,
#else
    nxt_event_conn_io_sendbuf,
#endif

    nxt_event_conn_io_writev,
    nxt_event_conn_io_send,

    nxt_event_conn_io_shutdown,
};


const nxt_event_set_ops_t  nxt_epoll_edge_event_set = {
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

    &nxt_epoll_edge_event_conn_io,

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


const nxt_event_set_ops_t  nxt_epoll_level_event_set = {
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

    &nxt_unix_event_conn_io,

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

static nxt_event_set_t *
nxt_epoll_edge_create(nxt_event_signals_t *signals, nxt_uint_t mchanges,
    nxt_uint_t mevents)
{
    return nxt_epoll_create(signals, mchanges, mevents,
                            &nxt_epoll_edge_event_conn_io,
                            EPOLLET | EPOLLRDHUP);
}

#endif


static nxt_event_set_t *
nxt_epoll_level_create(nxt_event_signals_t *signals, nxt_uint_t mchanges,
    nxt_uint_t mevents)
{
    return nxt_epoll_create(signals, mchanges, mevents,
                            &nxt_unix_event_conn_io, 0);
}


static nxt_event_set_t *
nxt_epoll_create(nxt_event_signals_t *signals, nxt_uint_t mchanges,
    nxt_uint_t mevents, nxt_event_conn_io_t *io, uint32_t mode)
{
    nxt_event_set_t        *event_set;
    nxt_epoll_event_set_t  *es;

    event_set = nxt_zalloc(sizeof(nxt_epoll_event_set_t));
    if (event_set == NULL) {
        return NULL;
    }

    es = &event_set->epoll;

    es->epoll = -1;
    es->mode = mode;
    es->mchanges = mchanges;
    es->mevents = mevents;
#if (NXT_HAVE_SIGNALFD)
    es->signalfd.fd = -1;
#endif

    es->changes = nxt_malloc(sizeof(nxt_epoll_change_t) * mchanges);
    if (es->changes == NULL) {
        goto fail;
    }

    es->events = nxt_malloc(sizeof(struct epoll_event) * mevents);
    if (es->events == NULL) {
        goto fail;
    }

    es->epoll = epoll_create(1);
    if (es->epoll == -1) {
        nxt_main_log_emerg("epoll_create() failed %E", nxt_errno);
        goto fail;
    }

    nxt_main_log_debug("epoll_create(): %d", es->epoll);

#if (NXT_HAVE_SIGNALFD)

    if (signals != NULL) {
        if (nxt_epoll_add_signal(es, signals) != NXT_OK) {
            goto fail;
        }
    }

#endif

    nxt_epoll_test_accept4(io);

    return event_set;

fail:

    nxt_epoll_free(event_set);

    return NULL;
}


static void
nxt_epoll_test_accept4(nxt_event_conn_io_t *io)
{
    static nxt_work_handler_t  handler;

    if (handler == NULL) {

        handler = io->accept;

#if (NXT_HAVE_ACCEPT4)

        (void) accept4(-1, NULL, NULL, SOCK_NONBLOCK);

        if (nxt_errno != NXT_ENOSYS) {
            handler = nxt_epoll_event_conn_io_accept4;

        } else {
            nxt_main_log_error(NXT_LOG_NOTICE, "accept4() failed %E",
                               NXT_ENOSYS);
        }

#endif
    }

    io->accept = handler;
}


static void
nxt_epoll_free(nxt_event_set_t *event_set)
{
    nxt_epoll_event_set_t  *es;

    es = &event_set->epoll;

    nxt_main_log_debug("epoll %d free", es->epoll);

#if (NXT_HAVE_SIGNALFD)

    if (es->signalfd.fd != -1) {
        if (close(es->signalfd.fd) != 0) {
            nxt_main_log_emerg("signalfd close(%d) failed %E",
                               es->signalfd.fd, nxt_errno);
        }
    }

#endif

#if (NXT_HAVE_EVENTFD)

    if (es->eventfd.fd != -1) {
        if (close(es->eventfd.fd) != 0) {
            nxt_main_log_emerg("eventfd close(%d) failed %E",
                               es->eventfd.fd, nxt_errno);
        }
    }

#endif

    if (es->epoll != -1) {
        if (close(es->epoll) != 0) {
            nxt_main_log_emerg("epoll close(%d) failed %E",
                               es->epoll, nxt_errno);
        }
    }

    nxt_free(es->events);
    nxt_free(es);
}


static void
nxt_epoll_enable(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->read = NXT_EVENT_DEFAULT;
    ev->write = NXT_EVENT_DEFAULT;

    nxt_epoll_change(event_set, ev, EPOLL_CTL_ADD,
                     EPOLLIN | EPOLLOUT | event_set->epoll.mode);
}


static void
nxt_epoll_disable(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read > NXT_EVENT_DISABLED || ev->write > NXT_EVENT_DISABLED) {

        ev->read = NXT_EVENT_INACTIVE;
        ev->write = NXT_EVENT_INACTIVE;

        nxt_epoll_change(event_set, ev, EPOLL_CTL_DEL, 0);
    }
}


static void
nxt_epoll_delete(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE || ev->write != NXT_EVENT_INACTIVE) {

        ev->read = NXT_EVENT_INACTIVE;
        ev->write = NXT_EVENT_INACTIVE;

        nxt_epoll_change(event_set, ev, EPOLL_CTL_DEL, 0);
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

static void
nxt_epoll_close(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    nxt_epoll_event_set_t  *es;

    nxt_epoll_delete(event_set, ev);

    es = &event_set->epoll;

    if (es->nchanges != 0) {
        (void) nxt_epoll_commit_changes(ev->task, &event_set->epoll);
    }
}


static void
nxt_epoll_enable_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    int       op;
    uint32_t  events;

    if (ev->read != NXT_EVENT_BLOCKED) {

        op = EPOLL_CTL_MOD;
        events = EPOLLIN | event_set->epoll.mode;

        if (ev->read == NXT_EVENT_INACTIVE && ev->write == NXT_EVENT_INACTIVE) {
            op = EPOLL_CTL_ADD;

        } else if (ev->write >= NXT_EVENT_BLOCKED) {
            events |= EPOLLOUT;
        }

        nxt_epoll_change(event_set, ev, op, events);
    }

    ev->read = NXT_EVENT_DEFAULT;
}


static void
nxt_epoll_enable_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    int       op;
    uint32_t  events;

    if (ev->write != NXT_EVENT_BLOCKED) {

        op = EPOLL_CTL_MOD;
        events = EPOLLOUT | event_set->epoll.mode;

        if (ev->read == NXT_EVENT_INACTIVE && ev->write == NXT_EVENT_INACTIVE) {
            op = EPOLL_CTL_ADD;

        } else if (ev->read >= NXT_EVENT_BLOCKED) {
            events |= EPOLLIN;
        }

        nxt_epoll_change(event_set, ev, op, events);
    }

    ev->write = NXT_EVENT_DEFAULT;
}


static void
nxt_epoll_disable_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
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
        events = EPOLLOUT | event_set->epoll.mode;
    }

    nxt_epoll_change(event_set, ev, op, events);
}


static void
nxt_epoll_disable_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    int       op;
    uint32_t  events;

    ev->write = NXT_EVENT_INACTIVE;

    if (ev->read <= NXT_EVENT_DISABLED) {
        ev->write = NXT_EVENT_INACTIVE;
        op = EPOLL_CTL_DEL;
        events = 0;

    } else {
        op = EPOLL_CTL_MOD;
        events = EPOLLIN | event_set->epoll.mode;
    }

    nxt_epoll_change(event_set, ev, op, events);
}


static void
nxt_epoll_block_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    if (ev->read != NXT_EVENT_INACTIVE) {
        ev->read = NXT_EVENT_BLOCKED;
    }
}


static void
nxt_epoll_block_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
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
nxt_epoll_oneshot_read(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    int  op;

    op = (ev->read == NXT_EVENT_INACTIVE && ev->write == NXT_EVENT_INACTIVE) ?
             EPOLL_CTL_ADD : EPOLL_CTL_MOD;

    ev->read = NXT_EVENT_ONESHOT;
    ev->write = NXT_EVENT_INACTIVE;

    nxt_epoll_change(event_set, ev, op, EPOLLIN | EPOLLONESHOT);
}


static void
nxt_epoll_oneshot_write(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    int  op;

    op = (ev->read == NXT_EVENT_INACTIVE && ev->write == NXT_EVENT_INACTIVE) ?
             EPOLL_CTL_ADD : EPOLL_CTL_MOD;

    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_ONESHOT;

    nxt_epoll_change(event_set, ev, op, EPOLLOUT | EPOLLONESHOT);
}


static void
nxt_epoll_enable_accept(nxt_event_set_t *event_set, nxt_event_fd_t *ev)
{
    ev->read = NXT_EVENT_DEFAULT;

    nxt_epoll_change(event_set, ev, EPOLL_CTL_ADD, EPOLLIN);
}


/*
 * epoll changes are batched to improve instruction and data cache
 * locality of several epoll_ctl() calls followed by epoll_wait() call.
 */

static void
nxt_epoll_change(nxt_event_set_t *event_set, nxt_event_fd_t *ev, int op,
    uint32_t events)
{
    nxt_epoll_change_t     *ch;
    nxt_epoll_event_set_t  *es;

    es = &event_set->epoll;

    nxt_log_debug(ev->log, "epoll %d set event: fd:%d op:%d ev:%XD",
                  es->epoll, ev->fd, op, events);

    if (es->nchanges >= es->mchanges) {
        (void) nxt_epoll_commit_changes(ev->task, es);
    }

    ch = &es->changes[es->nchanges++];
    ch->op = op;
    ch->fd = ev->fd;
    ch->event.events = events;
    ch->event.data.ptr = ev;
}


static nxt_int_t
nxt_epoll_commit_changes(nxt_task_t *task, nxt_epoll_event_set_t *es)
{
    nxt_int_t           ret;
    nxt_event_fd_t      *ev;
    nxt_epoll_change_t  *ch, *end;

    nxt_debug(task, "epoll %d changes:%ui", es->epoll, es->nchanges);

    ret = NXT_OK;
    ch = es->changes;
    end = ch + es->nchanges;

    do {
        ev = ch->event.data.ptr;

        nxt_debug(ev->task, "epoll_ctl(%d): fd:%d op:%d ev:%XD",
                  es->epoll, ch->fd, ch->op, ch->event.events);

        if (epoll_ctl(es->epoll, ch->op, ch->fd, &ch->event) != 0) {
            nxt_log(ev->task, NXT_LOG_CRIT, "epoll_ctl(%d, %d, %d) failed %E",
                    es->epoll, ch->op, ch->fd, nxt_errno);

            nxt_thread_work_queue_add(task->thread,
                                      &task->thread->work_queue.main,
                                      nxt_epoll_error_handler,
                                      ev->task, ev, ev->data);

            ret = NXT_ERROR;
        }

        ch++;

    } while (ch < end);

    es->nchanges = 0;

    return ret;
}


static void
nxt_epoll_error_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_fd_t  *ev;

    ev = obj;

    ev->read = NXT_EVENT_INACTIVE;
    ev->write = NXT_EVENT_INACTIVE;

    ev->error_handler(ev->task, ev, data);
}


#if (NXT_HAVE_SIGNALFD)

static nxt_int_t
nxt_epoll_add_signal(nxt_epoll_event_set_t *es, nxt_event_signals_t *signals)
{
    int                 fd;
    nxt_thread_t        *thr;
    struct epoll_event  ee;

    if (sigprocmask(SIG_BLOCK, &signals->sigmask, NULL) != 0) {
        nxt_main_log_alert("sigprocmask(SIG_BLOCK) failed %E", nxt_errno);
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

    fd = signalfd(-1, &signals->sigmask, 0);

    if (fd == -1) {
        nxt_main_log_emerg("signalfd(%d) failed %E",
                           es->signalfd.fd, nxt_errno);
        return NXT_ERROR;
    }

    es->signalfd.fd = fd;

    if (nxt_fd_nonblocking(fd) != NXT_OK) {
        return NXT_ERROR;
    }

    nxt_main_log_debug("signalfd(): %d", fd);

    es->signalfd.data = signals->handler;
    es->signalfd.read_work_queue = nxt_thread_main_work_queue();
    es->signalfd.read_handler = nxt_epoll_signalfd_handler;
    es->signalfd.log = &nxt_main_log;

    thr = nxt_thread();
    es->signalfd.task = &thr->engine->task;

    ee.events = EPOLLIN;
    ee.data.ptr = &es->signalfd;

    if (epoll_ctl(es->epoll, EPOLL_CTL_ADD, fd, &ee) != 0) {
        nxt_main_log_alert("epoll_ctl(%d, %d, %d) failed %E",
                           es->epoll, EPOLL_CTL_ADD, fd, nxt_errno);

        return NXT_ERROR;
    }

    return NXT_OK;
}


static void
nxt_epoll_signalfd_handler(nxt_task_t *task, void *obj, void *data)
{
    int                      n;
    nxt_event_fd_t           *ev;
    nxt_work_handler_t       handler;
    struct signalfd_siginfo  sfd;

    ev = obj;
    handler = data;

    nxt_debug(task, "signalfd handler");

    n = read(ev->fd, &sfd, sizeof(struct signalfd_siginfo));

    nxt_debug(task, "read signalfd(%d): %d", ev->fd, n);

    if (n != sizeof(struct signalfd_siginfo)) {
        nxt_log(task, NXT_LOG_CRIT, "read signalfd(%d) failed %E",
                ev->fd, nxt_errno);
    }

    nxt_debug(task, "signalfd(%d) signo:%d", ev->fd, sfd.ssi_signo);

    handler(task, (void *) (uintptr_t) sfd.ssi_signo, NULL);
}

#endif


#if (NXT_HAVE_EVENTFD)

static nxt_int_t
nxt_epoll_enable_post(nxt_event_set_t *event_set, nxt_work_handler_t handler)
{
    nxt_thread_t           *thr;
    struct epoll_event     ee;
    nxt_epoll_event_set_t  *es;

    es = &event_set->epoll;
    es->post_handler = handler;

    /*
     * Glibc eventfd() wrapper always has the flags argument.  Glibc 2.7
     * and 2.8 eventfd() wrappers call the original eventfd() syscall
     * without the flags argument.  Glibc 2.9+ eventfd() wrapper at first
     * tries to call eventfd2() syscall and if it fails then calls the
     * original eventfd() syscall.  For this reason the non-blocking mode
     * is set separately.
     */

    es->eventfd.fd = eventfd(0, 0);

    if (es->eventfd.fd == -1) {
        nxt_main_log_emerg("eventfd() failed %E", nxt_errno);
        return NXT_ERROR;
    }

    if (nxt_fd_nonblocking(es->eventfd.fd) != NXT_OK) {
        return NXT_ERROR;
    }

    nxt_main_log_debug("eventfd(): %d", es->eventfd.fd);

    es->eventfd.read_work_queue = nxt_thread_main_work_queue();
    es->eventfd.read_handler = nxt_epoll_eventfd_handler;
    es->eventfd.data = es;
    es->eventfd.log = &nxt_main_log;

    thr = nxt_thread();
    es->eventfd.task = &thr->engine->task;

    ee.events = EPOLLIN | EPOLLET;
    ee.data.ptr = &es->eventfd;

    if (epoll_ctl(es->epoll, EPOLL_CTL_ADD, es->eventfd.fd, &ee) == 0) {
        return NXT_OK;
    }

    nxt_main_log_alert("epoll_ctl(%d, %d, %d) failed %E",
                       es->epoll, EPOLL_CTL_ADD, es->eventfd.fd, nxt_errno);

    return NXT_ERROR;
}


static void
nxt_epoll_eventfd_handler(nxt_task_t *task, void *obj, void *data)
{
    int                    n;
    uint64_t               events;
    nxt_epoll_event_set_t  *es;

    es = data;

    nxt_debug(task, "eventfd handler, times:%ui", es->neventfd);

    /*
     * The maximum value after write() to a eventfd() descriptor will
     * block or return EAGAIN is 0xfffffffffffffffe, so the descriptor
     * can be read once per many notifications, for example, once per
     * 2^32-2 noticifcations.  Since the eventfd() file descriptor is
     * always registered in EPOLLET mode, epoll returns event about
     * only the latest write() to the descriptor.
     */

    if (es->neventfd++ >= 0xfffffffe) {
        es->neventfd = 0;

        n = read(es->eventfd.fd, &events, sizeof(uint64_t));

        nxt_debug(task, "read(%d): %d events:%uL", es->eventfd.fd, n, events);

        if (n != sizeof(uint64_t)) {
            nxt_log(task, NXT_LOG_CRIT, "read eventfd(%d) failed %E",
                    es->eventfd.fd, nxt_errno);
        }
    }

    es->post_handler(task, NULL, NULL);
}


static void
nxt_epoll_signal(nxt_event_set_t *event_set, nxt_uint_t signo)
{
    uint64_t               event;
    nxt_epoll_event_set_t  *es;

    es = &event_set->epoll;

    /*
     * eventfd() presents along with signalfd(), so the function
     * is used only to post events and the signo argument is ignored.
     */

    event = 1;

    if (write(es->eventfd.fd, &event, sizeof(uint64_t)) != sizeof(uint64_t)) {
        nxt_thread_log_alert("write(%d) to eventfd failed %E",
                             es->eventfd.fd, nxt_errno);
    }
}

#endif


static void
nxt_epoll_poll(nxt_task_t *task, nxt_event_set_t *event_set,
    nxt_msec_t timeout)
{
    int                    nevents;
    uint32_t               events;
    nxt_int_t              i;
    nxt_err_t              err;
    nxt_bool_t             error;
    nxt_uint_t             level;
    nxt_event_fd_t         *ev;
    struct epoll_event     *event;
    nxt_epoll_event_set_t  *es;

    es = &event_set->epoll;

    if (es->nchanges != 0) {
        if (nxt_epoll_commit_changes(task, es) != NXT_OK) {
            /* Error handlers have been enqueued on failure. */
            timeout = 0;
        }
    }

    nxt_debug(task, "epoll_wait(%d) timeout:%M", es->epoll, timeout);

    nevents = epoll_wait(es->epoll, es->events, es->mevents, timeout);

    err = (nevents == -1) ? nxt_errno : 0;

    nxt_thread_time_update(task->thread);

    nxt_debug(task, "epoll_wait(%d): %d", es->epoll, nevents);

    if (nevents == -1) {
        level = (err == NXT_EINTR) ? NXT_LOG_INFO : NXT_LOG_ALERT;
        nxt_log(task, level, "epoll_wait(%d) failed %E", es->epoll, err);
        return;
    }

    for (i = 0; i < nevents; i++) {

        event = &es->events[i];
        events = event->events;
        ev = event->data.ptr;

        nxt_debug(ev->task, "epoll: fd:%d ev:%04XD d:%p rd:%d wr:%d",
                  ev->fd, events, ev, ev->read, ev->write);

        /*
         * On error epoll may set EPOLLERR and EPOLLHUP only without EPOLLIN or
         * EPOLLOUT, so the "error" variable enqueues only one active handler.
         */
        error = ((events & (EPOLLERR | EPOLLHUP)) != 0);
        ev->epoll_error = error;

#if (NXT_HAVE_EPOLL_EDGE)

        ev->epoll_eof = ((events & EPOLLRDHUP) != 0);

#endif

        if ((events & EPOLLIN) || error) {
            ev->read_ready = 1;

            if (ev->read != NXT_EVENT_BLOCKED) {

                if (ev->read == NXT_EVENT_ONESHOT) {
                    ev->read = NXT_EVENT_DISABLED;
                }

                error = 0;

                nxt_thread_work_queue_add(task->thread, ev->read_work_queue,
                                          ev->read_handler,
                                          ev->task, ev, ev->data);

            } else if (event_set->epoll.mode == 0) {
                /* Level-triggered mode. */
                nxt_epoll_disable_read(event_set, ev);
            }
        }

        if ((events & EPOLLOUT) || error) {
            ev->write_ready = 1;

            if (ev->write != NXT_EVENT_BLOCKED) {

                if (ev->write == NXT_EVENT_ONESHOT) {
                    ev->write = NXT_EVENT_DISABLED;
                }

                error = 0;

                nxt_thread_work_queue_add(task->thread, ev->write_work_queue,
                                          ev->write_handler,
                                          ev->task, ev, ev->data);

            } else if (event_set->epoll.mode == 0) {
                /* Level-triggered mode. */
                nxt_epoll_disable_write(event_set, ev);
            }
        }

        if (error) {
            ev->read_ready = 1;
            ev->write_ready = 1;
        }
    }
}


#if (NXT_HAVE_ACCEPT4)

static void
nxt_epoll_event_conn_io_accept4(nxt_task_t *task, void *obj, void *data)
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

    len = nxt_socklen(c->remote);

    if (len >= sizeof(struct sockaddr)) {
        sa = &c->remote->u.sockaddr;

    } else {
        sa = NULL;
        len = 0;
    }

    s = accept4(cls->socket.fd, sa, &len, SOCK_NONBLOCK);

    if (s != -1) {
        c->socket.fd = s;

        nxt_debug(task, "accept4(%d): %d", cls->socket.fd, s);

        nxt_event_conn_accept(task, cls, c);
        return;
    }

    nxt_event_conn_accept_error(task, cls, "accept4", nxt_errno);
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
nxt_epoll_edge_event_conn_io_connect(nxt_task_t *task, void *obj, void *data)
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
        c->socket.write_handler = nxt_epoll_edge_event_conn_connected;
        c->socket.error_handler = nxt_event_conn_connect_error;

        nxt_event_conn_timer(task->thread->engine, c, state, &c->write_timer);

        nxt_epoll_enable(task->thread->engine->event_set, &c->socket);
        c->socket.read = NXT_EVENT_BLOCKED;
        return;

#if 0
    case NXT_AGAIN:
        nxt_event_conn_timer(thr->engine, c, state, &c->write_timer);

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

        nxt_epoll_enable(thr->engine->event_set, &c->socket);
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

    nxt_event_conn_io_handle(task->thread, c->write_work_queue, handler,
                             task, c, data);
}


static void
nxt_epoll_edge_event_conn_connected(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_t  *c;

    c = obj;

    nxt_debug(task, "epoll event conn connected fd:%d", c->socket.fd);

    if (!c->socket.epoll_error) {
        c->socket.write = NXT_EVENT_BLOCKED;

        if (c->write_state->autoreset_timer) {
            nxt_event_timer_disable(&c->write_timer);
        }

        nxt_event_conn_io_handle(task->thread, c->write_work_queue,
                                 c->write_state->ready_handler, task, c, data);
        return;
    }

    nxt_event_conn_connect_test(task, c, data);
}


/*
 * nxt_epoll_edge_event_conn_io_recvbuf() is just wrapper around
 * standard nxt_event_conn_io_recvbuf() to enforce to read a pending EOF
 * in edge-triggered mode.
 */

static ssize_t
nxt_epoll_edge_event_conn_io_recvbuf(nxt_event_conn_t *c, nxt_buf_t *b)
{
    ssize_t  n;

    n = nxt_event_conn_io_recvbuf(c, b);

    if (n > 0 && c->socket.epoll_eof) {
        c->socket.read_ready = 1;
    }

    return n;
}

#endif

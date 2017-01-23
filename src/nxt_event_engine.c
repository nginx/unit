
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static nxt_int_t nxt_event_engine_post_init(nxt_event_engine_t *engine);
static nxt_int_t nxt_event_engine_signal_pipe_create(
    nxt_event_engine_t *engine);
static void nxt_event_engine_signal_pipe_close(nxt_task_t *task, void *obj,
    void *data);
static void nxt_event_engine_signal_pipe(nxt_task_t *task, void *obj,
    void *data);
static void nxt_event_engine_post_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_event_engine_signal_pipe_error(nxt_task_t *task, void *obj,
    void *data);
static void nxt_event_engine_signal_handler(nxt_task_t *task, void *obj,
    void *data);
static const nxt_event_sig_t *nxt_event_engine_signal_find(nxt_task_t *task,
    nxt_uint_t signo);


nxt_event_engine_t *
nxt_event_engine_create(nxt_thread_t *thr, const nxt_event_set_ops_t *event_set,
    const nxt_event_sig_t *signals, nxt_uint_t flags, nxt_uint_t batch)
{
    nxt_uint_t          events;
    nxt_event_engine_t  *engine;

    engine = nxt_zalloc(sizeof(nxt_event_engine_t));
    if (engine == NULL) {
        return NULL;
    }

    engine->task.thread = thr;
    engine->task.log = thr->log;
    engine->task.ident = nxt_task_next_ident();

    thr->engine = engine;
    thr->fiber = &engine->fibers->fiber;

    engine->batch = batch;

    if (flags & NXT_ENGINE_FIBERS) {
        engine->fibers = nxt_fiber_main_create(engine);
        if (engine->fibers == NULL) {
            goto fibers_fail;
        }
    }

    nxt_thread_work_queue_create(thr, 0);

    nxt_work_queue_name(&engine->accept_work_queue, "accept");
    nxt_work_queue_name(&engine->read_work_queue, "read");
    nxt_work_queue_name(&engine->socket_work_queue, "socket");
    nxt_work_queue_name(&engine->connect_work_queue, "connect");
    nxt_work_queue_name(&engine->write_work_queue, "write");
    nxt_work_queue_name(&engine->shutdown_work_queue, "shutdown");
    nxt_work_queue_name(&engine->close_work_queue, "close");

#if (NXT_THREADS)

    nxt_locked_work_queue_create(&engine->work_queue, 7);

#endif

    if (signals != NULL) {
        engine->signals = nxt_event_engine_signals(signals);
        if (engine->signals == NULL) {
            goto signals_fail;
        }

        engine->signals->handler = nxt_event_engine_signal_handler;

        if (!event_set->signal_support) {
            if (nxt_event_engine_signals_start(engine) != NXT_OK) {
                goto signals_fail;
            }
        }
    }

    /*
     * Number of event set and timers changes should be at least twice
     * more than number of events to avoid premature flushes of the changes.
     * Fourfold is for sure.
     */
    events = (batch != 0) ? batch : 32;

    engine->event_set = event_set->create(engine->signals, 4 * events, events);
    if (engine->event_set == NULL) {
        goto event_set_fail;
    }

    engine->event = event_set;

    if (nxt_event_engine_post_init(engine) != NXT_OK) {
        goto post_fail;
    }

    if (nxt_event_timers_init(&engine->timers, 4 * events) != NXT_OK) {
        goto timers_fail;
    }

    nxt_thread_time_update(thr);
    engine->timers.now = nxt_thread_monotonic_time(thr) / 1000000;

    engine->max_connections = 0xffffffff;

    nxt_queue_init(&engine->listen_connections);
    nxt_queue_init(&engine->idle_connections);

    engine->thread = thr;

#if !(NXT_THREADS)

    if (engine->event->signal_support) {
        thr->time.signal = -1;
    }

#endif

    return engine;

timers_fail:
post_fail:

    event_set->free(engine->event_set);

event_set_fail:
signals_fail:

    nxt_free(engine->signals);
    nxt_thread_work_queue_destroy(thr);
    nxt_free(engine->fibers);

fibers_fail:

    nxt_free(engine);
    return NULL;
}


static nxt_int_t
nxt_event_engine_post_init(nxt_event_engine_t *engine)
{
    if (engine->event->enable_post != NULL) {
        return engine->event->enable_post(engine->event_set,
                                          nxt_event_engine_post_handler);
    }

#if !(NXT_THREADS)

    /* Only signals may are posted in single-threaded mode. */

    if (engine->event->signal_support) {
        return NXT_OK;
    }

#endif

    if (nxt_event_engine_signal_pipe_create(engine) != NXT_OK) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_event_engine_signal_pipe_create(nxt_event_engine_t *engine)
{
    nxt_event_engine_pipe_t  *pipe;

    pipe = nxt_zalloc(sizeof(nxt_event_engine_pipe_t));
    if (pipe == NULL) {
        return NXT_ERROR;
    }

    engine->pipe = pipe;

    /*
     * An event engine pipe is in blocking mode for writer
     * and in non-blocking node for reader.
     */

    if (nxt_pipe_create(pipe->fds, 1, 0) != NXT_OK) {
        nxt_free(pipe);
        return NXT_ERROR;
    }

    pipe->event.fd = pipe->fds[0];
    pipe->event.read_work_queue = &engine->task.thread->work_queue.main;
    pipe->event.read_handler = nxt_event_engine_signal_pipe;
    pipe->event.write_work_queue = &engine->task.thread->work_queue.main;
    pipe->event.error_handler = nxt_event_engine_signal_pipe_error;
    pipe->event.log = &nxt_main_log;

    nxt_event_fd_enable_read(engine, &pipe->event);

    return NXT_OK;
}


static void
nxt_event_engine_signal_pipe_free(nxt_event_engine_t *engine)
{
    nxt_event_engine_pipe_t  *pipe;

    pipe = engine->pipe;

    if (pipe != NULL) {

        if (pipe->event.read_work_queue != NULL) {
            nxt_event_fd_close(engine, &pipe->event);
            nxt_pipe_close(pipe->fds);
        }

        nxt_free(pipe);
    }
}


static void
nxt_event_engine_signal_pipe_close(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_engine_pipe_t  *pipe;

    pipe = obj;

    nxt_pipe_close(pipe->fds);
    nxt_free(pipe);
}


void
nxt_event_engine_post(nxt_event_engine_t *engine, nxt_work_handler_t handler,
    nxt_task_t *task, void *obj, void *data, nxt_log_t *log)
{
    nxt_thread_log_debug("event engine post");

    nxt_locked_work_queue_add(&engine->work_queue, handler, task, obj, data);

    nxt_event_engine_signal(engine, 0);
}


void
nxt_event_engine_signal(nxt_event_engine_t *engine, nxt_uint_t signo)
{
    u_char  buf;

    nxt_thread_log_debug("event engine signal:%ui", signo);

    /*
     * A signal number may be sent in a signal context, so the signal
     * information cannot be passed via a locked work queue.
     */

    if (engine->event->signal != NULL) {
        engine->event->signal(engine->event_set, signo);
        return;
    }

    buf = (u_char) signo;
    (void) nxt_fd_write(engine->pipe->fds[1], &buf, 1);
}


static void
nxt_event_engine_signal_pipe(nxt_task_t *task, void *obj, void *data)
{
    int                    i, n;
    u_char                 signo;
    nxt_bool_t             post;
    nxt_event_fd_t         *ev;
    const nxt_event_sig_t  *sigev;
    u_char                 buf[128];

    ev = obj;

    nxt_debug(task, "engine signal pipe");

    post = 0;

    do {
        n = nxt_fd_read(ev->fd, buf, sizeof(buf));

        for (i = 0; i < n; i++) {
            signo = buf[i];

            nxt_debug(task, "engine pipe signo:%d", signo);

            if (signo == 0) {
                /* A post should be processed only once. */
                post = 1;

            } else {
                sigev = nxt_event_engine_signal_find(task, signo);

                if (nxt_fast_path(sigev != NULL)) {
                    sigev->handler(task, (void *) (uintptr_t) signo,
                                   (void *) sigev->name);
                }
            }
        }

    } while (n == sizeof(buf));

    if (post) {
        nxt_event_engine_post_handler(task, NULL, NULL);
    }
}


static void
nxt_event_engine_post_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_thread_t  *thread;

    thread = task->thread;

    nxt_locked_work_queue_move(thread, &thread->engine->work_queue,
                               &thread->work_queue.main);
}


static void
nxt_event_engine_signal_pipe_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_engine_t  *engine;

    engine = task->thread->engine;

    nxt_log(task, NXT_LOG_CRIT, "engine pipe(%FD:%FD) event error",
            engine->pipe->fds[0], engine->pipe->fds[1]);

    nxt_event_fd_close(engine, &engine->pipe->event);
    nxt_pipe_close(engine->pipe->fds);
}


static void
nxt_event_engine_signal_handler(nxt_task_t *task, void *obj, void *data)
{
    uintptr_t              signo;
    const nxt_event_sig_t  *sigev;

    signo = (uintptr_t) obj;

    sigev = nxt_event_engine_signal_find(task, signo);

    if (nxt_fast_path(sigev != NULL)) {
        sigev->handler(task, (void *) (uintptr_t) signo, (void *) sigev->name);
    }
}


static const nxt_event_sig_t *
nxt_event_engine_signal_find(nxt_task_t *task, nxt_uint_t signo)
{
    const nxt_event_sig_t  *sigev;

    for (sigev = task->thread->engine->signals->sigev;
         sigev->signo != 0;
         sigev++)
    {
        if (signo == (nxt_uint_t) sigev->signo) {
            return sigev;
        }
    }

    nxt_log(task, NXT_LOG_CRIT, "signal %ui handler not found", signo);

    return NULL;
}


nxt_int_t
nxt_event_engine_change(nxt_thread_t *thr, nxt_task_t *task,
    const nxt_event_set_ops_t *event_set, nxt_uint_t batch)
{
    nxt_uint_t          events;
    nxt_event_engine_t  *engine;

    engine = thr->engine;
    engine->batch = batch;

    if (!engine->event->signal_support && event_set->signal_support) {
        /*
         * Block signal processing if the current event
         * facility does not support signal processing.
         */
        nxt_event_engine_signals_stop(engine);

        /*
         * Add to thread main work queue the signal events possibly
         * received before the blocking signal processing.
         */
        nxt_event_engine_signal_pipe(task, &engine->pipe->event, NULL);
    }

    if (engine->pipe != NULL && event_set->enable_post != NULL) {
        /*
         * An engine pipe must be closed after all signal events
         * added above to thread main work queue will be processed.
         */
        nxt_thread_work_queue_add(thr, &thr->work_queue.main,
                                  nxt_event_engine_signal_pipe_close,
                                  &engine->task, engine->pipe, NULL);

        engine->pipe = NULL;
    }

    engine->event->free(engine->event_set);

    events = (batch != 0) ? batch : 32;

    engine->event_set = event_set->create(engine->signals, 4 * events, events);
    if (engine->event_set == NULL) {
        return NXT_ERROR;
    }

    engine->event = event_set;

    if (nxt_event_engine_post_init(engine) != NXT_OK) {
        return NXT_ERROR;
    }

    if (engine->signals != NULL) {

        if (!engine->event->signal_support) {
            return nxt_event_engine_signals_start(engine);
        }

#if (NXT_THREADS)
        /*
         * Reset the PID flag to start the signal thread if
         * some future event facility will not support signals.
         */
        engine->signals->process = 0;
#endif
    }

    return NXT_OK;
}


void
nxt_event_engine_free(nxt_event_engine_t *engine)
{
    nxt_event_engine_signal_pipe_free(engine);
    nxt_free(engine->signals);

    nxt_locked_work_queue_destroy(&engine->work_queue);
    nxt_thread_work_queue_destroy(nxt_thread());

    engine->event->free(engine->event_set);

    /* TODO: free timers */

    nxt_free(engine);
}


void
nxt_event_engine_start(nxt_event_engine_t *engine)
{
    void                *obj, *data;
    nxt_task_t          *task;
    nxt_msec_t          timeout, now;
    nxt_thread_t        *thr;
    nxt_work_handler_t  handler;

    thr = nxt_thread();

    if (engine->fibers) {
        /*
         * _setjmp() cannot be wrapped in a function since return from
         * the function clobbers stack used by future _setjmp() returns.
         */
        _setjmp(engine->fibers->fiber.jmp);

        /* A return point from fibers. */
    }

    for ( ;; ) {

        for ( ;; ) {
            handler = nxt_thread_work_queue_pop(thr, &task, &obj, &data);

            if (handler == NULL) {
                break;
            }

            handler(task, obj, data);

            thr->log = &nxt_main_log;
        }

        for ( ;; ) {
            handler = nxt_thread_last_work_queue_pop(thr, &task, &obj, &data);

            if (handler == NULL) {
                break;
            }

            handler(task, obj, data);

            thr->log = &nxt_main_log;
        }

        /* Attach some event engine work queues in preferred order. */

        nxt_work_queue_attach(thr, &engine->accept_work_queue);
        nxt_work_queue_attach(thr, &engine->read_work_queue);

        timeout = nxt_event_timer_find(engine);

        engine->event->poll(task, engine->event_set, timeout);

        /*
         * Look up expired timers only if a new zero timer has been
         * just added before the event poll or if the event poll slept
         * at least 1 millisecond, because all old eligible timers were
         * processed in the previous iterations.
         */

        now = nxt_thread_monotonic_time(thr) / 1000000;

        if (timeout == 0 || now != engine->timers.now) {
            nxt_event_timer_expire(thr, now);
        }
    }
}

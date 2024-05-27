
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static nxt_int_t nxt_thread_pool_init(nxt_thread_pool_t *tp);
static void nxt_thread_pool_exit(nxt_task_t *task, void *obj, void *data);
static void nxt_thread_pool_start(void *ctx);
static void nxt_thread_pool_loop(void *ctx);
static void nxt_thread_pool_wait(nxt_thread_pool_t *tp);


nxt_thread_pool_t *
nxt_thread_pool_create(nxt_uint_t max_threads, nxt_nsec_t timeout,
    nxt_thread_pool_init_t init, nxt_event_engine_t *engine,
    nxt_work_handler_t exit)
{
    nxt_thread_pool_t  *tp;

    tp = nxt_zalloc(sizeof(nxt_thread_pool_t));
    if (tp == NULL) {
        return NULL;
    }

    tp->max_threads = max_threads;
    tp->timeout = timeout;
    tp->engine = engine;
    tp->task.thread = engine->task.thread;
    tp->task.log = engine->task.log;
    tp->init = init;
    tp->exit = exit;

    return tp;
}


nxt_int_t
nxt_thread_pool_post(nxt_thread_pool_t *tp, nxt_work_t *work)
{
    nxt_thread_log_debug("thread pool post");

    if (nxt_slow_path(nxt_thread_pool_init(tp) != NXT_OK)) {
        return NXT_ERROR;
    }

    nxt_locked_work_queue_add(&tp->work_queue, work);

    (void) nxt_sem_post(&tp->sem);

    return NXT_OK;
}


static nxt_int_t
nxt_thread_pool_init(nxt_thread_pool_t *tp)
{
    nxt_int_t            ret;
    nxt_thread_link_t    *link;
    nxt_thread_handle_t  handle;

    if (nxt_fast_path(tp->ready)) {
        return NXT_OK;
    }

    if (tp->max_threads == 0) {
        /* The pool is being destroyed. */
        return NXT_ERROR;
    }

    nxt_thread_spin_lock(&tp->work_queue.lock);

    ret = NXT_OK;

    if (!tp->ready) {

        nxt_thread_log_debug("thread pool init");

        (void) nxt_atomic_fetch_add(&tp->threads, 1);

        if (nxt_fast_path(nxt_sem_init(&tp->sem, 0) == NXT_OK)) {

            link = nxt_zalloc(sizeof(nxt_thread_link_t));

            if (nxt_fast_path(link != NULL)) {
                link->start = nxt_thread_pool_start;
                link->work.data = tp;

                if (nxt_thread_create(&handle, link) == NXT_OK) {
                    tp->ready = 1;
                    goto done;
                }
            }

            nxt_sem_destroy(&tp->sem);
        }

        (void) nxt_atomic_fetch_add(&tp->threads, -1);

        ret = NXT_ERROR;
    }

done:

    nxt_thread_spin_unlock(&tp->work_queue.lock);

    return ret;
}


static void
nxt_thread_pool_start(void *ctx)
{
    nxt_thread_t       *thr;
    nxt_thread_pool_t  *tp;

    tp = ctx;
    thr = nxt_thread();

    tp->main = thr->handle;
    tp->task.thread = thr;

    nxt_thread_pool_loop(ctx);
}


static void
nxt_thread_pool_loop(void *ctx)
{
    void                *obj, *data;
    nxt_task_t          *task;
    nxt_thread_t        *thr;
    nxt_thread_pool_t   *tp;
    nxt_work_handler_t  handler;

    tp = ctx;
    thr = nxt_thread();

    if (tp->init != NULL) {
        tp->init();
    }

    for ( ;; ) {
        nxt_thread_pool_wait(tp);

        handler = nxt_locked_work_queue_pop(&tp->work_queue, &task, &obj,
                                            &data);

        if (nxt_fast_path(handler != NULL)) {
            task->thread = thr;

            nxt_log_debug(thr->log, "locked work queue");

            handler(task, obj, data);
        }

        thr->log = &nxt_main_log;
    }
}


static void
nxt_thread_pool_wait(nxt_thread_pool_t *tp)
{
    nxt_err_t            err;
    nxt_thread_t         *thr;
    nxt_atomic_uint_t    waiting, threads;
    nxt_thread_link_t    *link;
    nxt_thread_handle_t  handle;

    thr = nxt_thread();

    nxt_log_debug(thr->log, "thread pool wait");

    (void) nxt_atomic_fetch_add(&tp->waiting, 1);

    for ( ;; ) {
        err = nxt_sem_wait(&tp->sem, tp->timeout);

        if (err == 0) {
            waiting = nxt_atomic_fetch_add(&tp->waiting, -1);
            break;
        }

        if (err == NXT_ETIMEDOUT) {
            if (nxt_thread_handle_equal(thr->handle, tp->main)) {
                continue;
            }
        }

        (void) nxt_atomic_fetch_add(&tp->waiting, -1);
        (void) nxt_atomic_fetch_add(&tp->threads, -1);

        nxt_thread_exit(thr);
        nxt_unreachable();
    }

    nxt_log_debug(thr->log, "thread pool awake, waiting: %A", waiting);

    if (waiting > 1) {
        return;
    }

    do {
        threads = tp->threads;

        if (threads >= tp->max_threads) {
            return;
        }

    } while (!nxt_atomic_cmp_set(&tp->threads, threads, threads + 1));

    link = nxt_zalloc(sizeof(nxt_thread_link_t));

    if (nxt_fast_path(link != NULL)) {
        link->start = nxt_thread_pool_loop;
        link->work.data = tp;

        if (nxt_thread_create(&handle, link) != NXT_OK) {
            (void) nxt_atomic_fetch_add(&tp->threads, -1);
        }
    }
}


void
nxt_thread_pool_destroy(nxt_thread_pool_t *tp)
{
    nxt_thread_t  *thr;

    thr = nxt_thread();

    nxt_log_debug(thr->log, "thread pool destroy: %A", tp->ready);

    if (!tp->ready) {
        nxt_work_queue_add(&thr->engine->fast_work_queue, tp->exit,
                           &tp->engine->task, tp, NULL);
        return;
    }

    if (tp->max_threads != 0) {
        /* Disable new threads creation and mark a pool as being destroyed. */
        tp->max_threads = 0;

        nxt_work_set(&tp->work, nxt_thread_pool_exit, &tp->task, tp, NULL);

        nxt_thread_pool_post(tp, &tp->work);
    }
}


/*
 * A thread handle (pthread_t) is either pointer or integer, so it can be
 * passed as work handler pointer "data" argument.  To convert void pointer
 * to pthread_t and vice versa the source argument should be cast first to
 * uintptr_t type and then to the destination type.
 *
 * If the handle would be a struct it should be stored in thread pool and
 * the thread pool must be freed in the thread pool exit procedure after
 * the last thread of pool will exit.
 */

static void
nxt_thread_pool_exit(nxt_task_t *task, void *obj, void *data)
{
    nxt_thread_t         *thread;
    nxt_thread_pool_t    *tp;
    nxt_atomic_uint_t    threads;
    nxt_thread_handle_t  handle;

    tp = obj;
    thread = task->thread;

    nxt_debug(task, "thread pool exit");

    if (data != NULL) {
        handle = (nxt_thread_handle_t) (uintptr_t) data;
        nxt_thread_wait(handle);
    }

    threads = nxt_atomic_fetch_add(&tp->threads, -1);

    nxt_debug(task, "thread pool threads: %A", threads);

    if (threads > 1) {
        nxt_work_set(&tp->work, nxt_thread_pool_exit, &tp->task, tp,
                     (void *) (uintptr_t) thread->handle);

        nxt_thread_pool_post(tp, &tp->work);

    } else {
        nxt_debug(task, "thread pool destroy");

        nxt_sem_destroy(&tp->sem);

        nxt_work_set(&tp->work, tp->exit, &tp->engine->task, tp,
                     (void *) (uintptr_t) thread->handle);

        nxt_event_engine_post(tp->engine, &tp->work);

        /* The "tp" memory should be freed by tp->exit handler. */
    }

    nxt_thread_exit(thread);

    nxt_unreachable();
}

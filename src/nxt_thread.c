
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void *nxt_thread_trampoline(void *data);
static void nxt_thread_time_cleanup(void *data);


#if (NXT_HAVE_PTHREAD_SPECIFIC_DATA)

static void nxt_thread_key_dtor(void *data);


void
nxt_thread_init_data(nxt_thread_specific_data_t tsd)
{
    void           *p;
    nxt_err_t      err;
    pthread_key_t  key;

    while ((nxt_atomic_int_t) tsd->key < 0) {
        /*
         * Atomic allocation of a key number.
         * -1 means an uninitialized key,
         * -2 is the initializing lock to assure the single value for the key.
         */
        if (nxt_atomic_cmp_set(&tsd->key, -1, -2)) {

            err = pthread_key_create(&key, nxt_thread_key_dtor);
            if (err != 0) {
                nxt_main_log_alert("pthread_key_create() failed %E", err);
                goto fail;
            }

            tsd->key = (nxt_atomic_t) key;

            nxt_main_log_debug("pthread_key_create(): %A", tsd->key);
        }
    }

    if (pthread_getspecific((pthread_key_t) tsd->key) != NULL) {
        return;
    }

    p = nxt_zalloc(tsd->size);
    if (p == NULL) {
        goto fail;
    }

    err = pthread_setspecific((pthread_key_t) tsd->key, p);
    if (err == 0) {
        return;
    }

    nxt_main_log_alert("pthread_setspecific(%A) failed %E", tsd->key, err);

fail:

    pthread_exit(NULL);
    nxt_unreachable();
}


static void
nxt_thread_key_dtor(void *data)
{
    nxt_main_log_debug("pthread key dtor: %p", data);

    nxt_free(data);
}

#endif


nxt_int_t
nxt_thread_create(nxt_thread_handle_t *handle, nxt_thread_link_t *link)
{
    nxt_err_t  err;

    err = pthread_create(handle, NULL, nxt_thread_trampoline, link);

    if (nxt_fast_path(err == 0)) {
        nxt_thread_log_debug("pthread_create(): %PH", *handle);

        return NXT_OK;
    }

    nxt_thread_log_alert("pthread_create() failed %E", err);

    nxt_free(link);

    return NXT_ERROR;
}


static void *
nxt_thread_trampoline(void *data)
{
    nxt_thread_t        *thr;
    nxt_thread_link_t   *link;
    nxt_thread_start_t  start;

    link = data;

    thr = nxt_thread_init();

    nxt_log_debug(thr->log, "thread trampoline: %PH", thr->handle);

    pthread_cleanup_push(nxt_thread_time_cleanup, thr);

    start = link->start;
    data = link->work.data;

    if (link->work.handler != NULL) {
        thr->link = link;

    } else {
        nxt_free(link);
    }

    start(data);

    /*
     * nxt_thread_time_cleanup() should be called only if a thread
     * would be canceled, so ignore it here because nxt_thread_exit()
     * calls nxt_thread_time_free() as well.
     */
    pthread_cleanup_pop(0);

    nxt_thread_exit(thr);
    nxt_unreachable();
    return NULL;
}


nxt_thread_t *
nxt_thread_init(void)
{
    nxt_thread_t  *thr;

    nxt_thread_init_data(nxt_thread_context);

    thr = nxt_thread();

    if (thr->log == NULL) {
        thr->log = &nxt_main_log;
        thr->handle = nxt_thread_handle();

        /*
         * Threads are never preempted by asynchronous signals, since
         * the signals are processed synchronously by dedicated thread.
         */
        thr->time.signal = -1;

        nxt_thread_time_update(thr);
    }

    nxt_random_init(&thr->random);

    return thr;
}


static void
nxt_thread_time_cleanup(void *data)
{
    nxt_thread_t  *thr;

    thr = data;

    nxt_log_debug(thr->log, "thread time cleanup");

    nxt_thread_time_free(thr);
}


void
nxt_thread_exit(nxt_thread_t *thr)
{
    nxt_thread_link_t   *link;
    nxt_event_engine_t  *engine;

    nxt_log_debug(thr->log, "thread exit");

    link = thr->link;
    thr->link = NULL;

    if (link != NULL) {
        /*
         * link->work.handler is already set to an exit handler,
         * and link->work.task is already set to the correct engine->task.
         * The link should be freed by the exit handler.
         */
        link->work.obj = (void *) (uintptr_t) thr->handle;
        engine = nxt_container_of(link->work.task, nxt_event_engine_t, task);

        nxt_event_engine_post(engine, &link->work);
    }

    nxt_thread_time_free(thr);

    pthread_exit(NULL);
    nxt_unreachable();
}


void
nxt_thread_cancel(nxt_thread_handle_t handle)
{
    nxt_err_t  err;

    nxt_thread_log_debug("thread cancel: %PH", handle);

    err = pthread_cancel(handle);

    if (err != 0) {
        nxt_main_log_alert("pthread_cancel(%PH) failed %E", handle, err);
    }
}


void
nxt_thread_wait(nxt_thread_handle_t handle)
{
    nxt_err_t  err;

    nxt_thread_log_debug("thread wait: %PH", handle);

    err = pthread_join(handle, NULL);

    if (err != 0) {
        nxt_main_log_alert("pthread_join(%PH) failed %E", handle, err);
    }
}


nxt_tid_t
nxt_thread_tid(nxt_thread_t *thr)
{
#if (NXT_HAVE_THREAD_STORAGE_CLASS)

    if (nxt_slow_path(thr->tid == 0)) {
        thr->tid = nxt_thread_get_tid();
    }

    return thr->tid;

#else

    if (nxt_fast_path(thr != NULL)) {

        if (nxt_slow_path(thr->tid == 0)) {
            thr->tid = nxt_thread_get_tid();
        }

        return thr->tid;
    }

    return nxt_thread_get_tid();

#endif
}

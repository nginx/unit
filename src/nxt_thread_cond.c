
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


nxt_int_t
nxt_thread_cond_create(nxt_thread_cond_t *cond)
{
    nxt_err_t  err;

    err = pthread_cond_init(cond, NULL);
    if (err == 0) {
        nxt_thread_log_debug("pthread_cond_init(%p)", cond);
        return NXT_OK;
    }

    nxt_thread_log_alert("pthread_cond_init() failed %E", err);
    return NXT_ERROR;
}


void
nxt_thread_cond_destroy(nxt_thread_cond_t *cond)
{
    nxt_err_t  err;

    err = pthread_cond_destroy(cond);
    if (err != 0) {
        nxt_thread_log_alert("pthread_cond_destroy() failed %E", err);
    }

    nxt_thread_log_debug("pthread_cond_destroy(%p)", cond);
}


nxt_int_t
nxt_thread_cond_signal(nxt_thread_cond_t *cond)
{
    nxt_err_t  err;

    err = pthread_cond_signal(cond);
    if (nxt_fast_path(err == 0)) {
        nxt_thread_log_debug("pthread_cond_signal(%p)", cond);
        return NXT_OK;
    }

    nxt_thread_log_alert("pthread_cond_signal() failed %E", err);

    return NXT_ERROR;
}


nxt_err_t
nxt_thread_cond_wait(nxt_thread_cond_t *cond, nxt_thread_mutex_t *mtx,
    nxt_nsec_t timeout)
{
    nxt_err_t        err;
    nxt_nsec_t       ns;
    nxt_thread_t     *thr;
    nxt_realtime_t   *now;
    struct timespec  ts;

    thr = nxt_thread();

    if (timeout == NXT_INFINITE_NSEC) {
        nxt_log_debug(thr->log, "pthread_cond_wait(%p) enter", cond);

        err = pthread_cond_wait(cond, mtx);

        nxt_thread_time_update(thr);

        if (nxt_fast_path(err == 0)) {
            nxt_log_debug(thr->log, "pthread_cond_wait(%p) exit", cond);
            return 0;
        }

        nxt_log_alert(thr->log, "pthread_cond_wait() failed %E", err);

    } else {
        nxt_log_debug(thr->log, "pthread_cond_timedwait(%p, %N) enter",
                      cond, timeout);

        now = nxt_thread_realtime(thr);

        ns = now->nsec + timeout;
        ts.tv_sec = now->sec + ns / 1000000000;
        ts.tv_nsec = ns % 1000000000;

        err = pthread_cond_timedwait(cond, mtx, &ts);

        nxt_thread_time_update(thr);

        if (nxt_fast_path(err == 0 || err == NXT_ETIMEDOUT)) {
            nxt_log_debug(thr->log, "pthread_cond_timedwait(%p) exit: %d",
                          cond, err);
            return err;
        }

        nxt_log_alert(thr->log, "pthread_cond_timedwait() failed %E", err);
    }

    return NXT_ERROR;
}

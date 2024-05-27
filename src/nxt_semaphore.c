
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


#if (NXT_HAVE_SEM_TIMEDWAIT)

/*
 * Linux POSIX semaphores use atomic/futex operations in since glibc 2.3.
 *
 * FreeBSD has two POSIX semaphore implementations.  The first implementation
 * has been introduced in FreeBSD 5.0 but it has some drawbacks:
 *   1) it had a bug (http://bugs.freebsd.org/127545) fixed in FreeBSD 7.2;
 *   2) it does not use atomic operations and always calls ksem syscalls;
 *   3) a number of semaphores is just 30 by default and until FreeBSD 8.1
 *      the number cannot be changed after boot time.
 *
 * The second implementation has been introduced in FreeBSD 6.1 in libthr
 * and uses atomic operations and umtx syscall.  However, until FreeBSD 9.0
 * a choice of implementation depended on linking order of libthr and libc.
 * In FreeBSD 9.0 the umtx implementation has been moved to libc.
 *
 * Solaris have POSIX semaphores.
 *
 * MacOSX has limited POSIX semaphore implementation:
 *  1) sem_init() exists but returns ENOSYS;
 *  2) no sem_timedwait().
 */

nxt_int_t
nxt_sem_init(nxt_sem_t *sem, nxt_uint_t count)
{
    if (sem_init(sem, 0, count) == 0) {
        nxt_thread_log_debug("sem_init(%p)", sem);
        return NXT_OK;
    }

    nxt_thread_log_alert("sem_init(%p) failed %E", sem, nxt_errno);
    return NXT_ERROR;
}


void
nxt_sem_destroy(nxt_sem_t *sem)
{
    if (sem_destroy(sem) == 0) {
        nxt_thread_log_debug("sem_destroy(%p)", sem);
        return;
    }

    nxt_thread_log_alert("sem_destroy(%p) failed %E", sem, nxt_errno);
}


nxt_int_t
nxt_sem_post(nxt_sem_t *sem)
{
    nxt_thread_log_debug("sem_post(%p)", sem);

    if (nxt_fast_path(sem_post(sem) == 0)) {
        return NXT_OK;
    }

    nxt_thread_log_alert("sem_post(%p) failed %E", sem, nxt_errno);

    return NXT_ERROR;
}


nxt_err_t
nxt_sem_wait(nxt_sem_t *sem, nxt_nsec_t timeout)
{
    int              n;
    nxt_err_t        err;
    nxt_nsec_t       ns;
    nxt_thread_t     *thr;
    nxt_realtime_t   *now;
    struct timespec  ts;

    thr = nxt_thread();

    if (timeout == NXT_INFINITE_NSEC) {
        nxt_log_debug(thr->log, "sem_wait(%p) enter", sem);

        for ( ;; ) {
            n = sem_wait(sem);

            err = nxt_errno;

            nxt_thread_time_update(thr);

            if (nxt_fast_path(n == 0)) {
                nxt_thread_log_debug("sem_wait(%p) exit", sem);
                return 0;
            }

            switch (err) {

            case NXT_EINTR:
                nxt_log_error(NXT_LOG_INFO, thr->log, "sem_wait(%p) failed %E",
                              sem, err);
                continue;

            default:
                nxt_log_alert(thr->log, "sem_wait(%p) failed %E", sem, err);
                return err;
            }
        }
    }

#if (NXT_HAVE_SEM_TRYWAIT_FAST)

    nxt_log_debug(thr->log, "sem_trywait(%p) enter", sem);

    /*
     * Fast sem_trywait() using atomic operations may eliminate
     * timeout processing.
     */

    if (nxt_fast_path(sem_trywait(sem) == 0)) {
        return 0;
    }

#endif

    nxt_log_debug(thr->log, "sem_timedwait(%p, %N) enter", sem, timeout);

    now = nxt_thread_realtime(thr);
    ns = now->nsec + timeout;
    ts.tv_sec = now->sec + ns / 1000000000;
    ts.tv_nsec = ns % 1000000000;

    for ( ;; ) {
        n = sem_timedwait(sem, &ts);

        err = nxt_errno;

        nxt_thread_time_update(thr);

        if (nxt_fast_path(n == 0)) {
            nxt_thread_log_debug("sem_timedwait(%p) exit", sem);
            return 0;
        }

        switch (err) {

        case NXT_ETIMEDOUT:
            nxt_log_debug(thr->log, "sem_timedwait(%p) exit: %d", sem, err);
            return err;

        case NXT_EINTR:
            nxt_log_error(NXT_LOG_INFO, thr->log, "sem_timedwait(%p) failed %E",
                          sem, err);
            continue;

        default:
            nxt_log_alert(thr->log, "sem_timedwait(%p) failed %E", sem, err);
            return err;
        }
    }
}

#else

/* Semaphore implementation using pthread conditional variable. */

nxt_int_t
nxt_sem_init(nxt_sem_t *sem, nxt_uint_t count)
{
    if (nxt_thread_mutex_create(&sem->mutex) == NXT_OK) {

        if (nxt_thread_cond_create(&sem->cond) == NXT_OK) {
            sem->count = count;
            return NXT_OK;
        }

        nxt_thread_mutex_destroy(&sem->mutex);
    }

    return NXT_ERROR;
}


void
nxt_sem_destroy(nxt_sem_t *sem)
{
    nxt_thread_cond_destroy(&sem->cond);
    nxt_thread_mutex_destroy(&sem->mutex);
}


nxt_int_t
nxt_sem_post(nxt_sem_t *sem)
{
    nxt_int_t  ret;

    if (nxt_slow_path(nxt_thread_mutex_lock(&sem->mutex) != NXT_OK)) {
        return NXT_ERROR;
    }

    ret = nxt_thread_cond_signal(&sem->cond);

    sem->count++;

    /* NXT_ERROR overrides NXT_OK. */

    return (nxt_thread_mutex_unlock(&sem->mutex) | ret);
}


nxt_err_t
nxt_sem_wait(nxt_sem_t *sem, nxt_nsec_t timeout)
{
    nxt_err_t  err;

    err = 0;

    if (nxt_slow_path(nxt_thread_mutex_lock(&sem->mutex) != NXT_OK)) {
        return NXT_ERROR;
    }

    while (sem->count == 0) {

        err = nxt_thread_cond_wait(&sem->cond, &sem->mutex, timeout);

        if (err != 0) {
            goto error;
        }
    }

    sem->count--;

error:

    /* NXT_ERROR overrides NXT_OK and NXT_ETIMEDOUT. */

    return (nxt_thread_mutex_unlock(&sem->mutex) | err);
}

#endif

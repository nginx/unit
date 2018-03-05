
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * All modern pthread mutex implementations try to acquire a lock atomically
 * in userland before going to sleep in kernel.  Some spins on SMP systems
 * before the sleeping.
 *
 * In Solaris since version 8 all mutex types spin before sleeping.
 * The default spin count is 1000.  It can be overridden using
 * _THREAD_ADAPTIVE_SPIN=100 environment variable.
 *
 * In MacOSX all mutex types spin to acquire a lock protecting a mutex's
 * internals.  If the mutex is busy, thread calls Mach semaphore_wait().
 *
 *
 * PTHREAD_MUTEX_NORMAL lacks deadlock detection and is the fastest
 * mutex type.
 *
 *   Linux:    No spinning.  The internal name PTHREAD_MUTEX_TIMED_NP
 *             remains from the times when pthread_mutex_timedlock() was
 *             non-standard extension.  Alias name: PTHREAD_MUTEX_FAST_NP.
 *   FreeBSD:  No spinning.
 *
 *
 * PTHREAD_MUTEX_ERRORCHECK is usually as fast as PTHREAD_MUTEX_NORMAL
 * yet has lightweight deadlock detection.
 *
 *   Linux:    No spinning.  The internal name: PTHREAD_MUTEX_ERRORCHECK_NP.
 *   FreeBSD:  No spinning.
 *
 *
 * PTHREAD_MUTEX_RECURSIVE allows recursive locking.
 *
 *   Linux:    No spinning.  The internal name: PTHREAD_MUTEX_RECURSIVE_NP.
 *   FreeBSD:  No spinning.
 *
 *
 * PTHREAD_MUTEX_ADAPTIVE_NP spins on SMP systems before sleeping.
 *
 *   Linux:    No deadlock detection.  Dynamically changes a spin count
 *             for each mutex from 10 to 100 based on spin count taken
 *             previously.
 *
 *   FreeBSD:  Deadlock detection.  The default spin count is 2000.
 *             It can be overriden using LIBPTHREAD_SPINLOOPS environment
 *             variable or by pthread_mutex_setspinloops_np().  If a lock
 *             is still busy, sched_yield() can be called on both UP and
 *             SMP systems.  The default yield loop count is zero, but it
 *             can be set by LIBPTHREAD_YIELDLOOPS environment variable or
 *             by pthread_mutex_setyieldloops_np().  sched_yield() moves
 *             a thread to the end of CPU scheduler run queue and this is
 *             cheaper than removing the thread from the queue and sleeping.
 *
 *   Solaris:  No PTHREAD_MUTEX_ADAPTIVE_NP .
 *   MacOSX:   No PTHREAD_MUTEX_ADAPTIVE_NP.
 *
 *
 * PTHREAD_MUTEX_ELISION_NP is a Linux extension to elide locks using
 * Intel Restricted Transactional Memory.  It is the most suitable for
 * rwlock pattern access because it allows simultaneous reads without lock.
 * Supported since glibc 2.18.
 *
 *
 * PTHREAD_MUTEX_DEFAULT is default mutex type.
 *
 *   Linux:    PTHREAD_MUTEX_NORMAL.
 *   FreeBSD:  PTHREAD_MUTEX_ERRORCHECK.
 *   Solaris:  PTHREAD_MUTEX_NORMAL.
 *   MacOSX:   PTHREAD_MUTEX_NORMAL.
 */


nxt_int_t
nxt_thread_mutex_create(nxt_thread_mutex_t *mtx)
{
    nxt_err_t            err;
    pthread_mutexattr_t  attr;

    err = pthread_mutexattr_init(&attr);
    if (err != 0) {
        nxt_thread_log_alert("pthread_mutexattr_init() failed %E", err);
        return NXT_ERROR;
    }

    err = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    if (err != 0) {
        nxt_thread_log_alert("pthread_mutexattr_settype"
                             "(PTHREAD_MUTEX_ERRORCHECK) failed %E", err);
        return NXT_ERROR;
    }

    err = pthread_mutex_init(mtx, &attr);
    if (err != 0) {
        nxt_thread_log_alert("pthread_mutex_init() failed %E", err);
        return NXT_ERROR;
    }

    err = pthread_mutexattr_destroy(&attr);
    if (err != 0) {
        nxt_thread_log_alert("pthread_mutexattr_destroy() failed %E", err);
    }

    nxt_thread_log_debug("pthread_mutex_init(%p)", mtx);

    return NXT_OK;
}


void
nxt_thread_mutex_destroy(nxt_thread_mutex_t *mtx)
{
    nxt_err_t  err;

    err = pthread_mutex_destroy(mtx);
    if (nxt_slow_path(err != 0)) {
        nxt_thread_log_alert("pthread_mutex_destroy() failed %E", err);
    }

    nxt_thread_log_debug("pthread_mutex_destroy(%p)", mtx);
}


nxt_int_t
nxt_thread_mutex_lock(nxt_thread_mutex_t *mtx)
{
    nxt_err_t  err;

    nxt_thread_log_debug("pthread_mutex_lock(%p) enter", mtx);

    err = pthread_mutex_lock(mtx);
    if (nxt_fast_path(err == 0)) {
        return NXT_OK;
    }

    nxt_thread_log_alert("pthread_mutex_lock() failed %E", err);

    return NXT_ERROR;
}


nxt_bool_t
nxt_thread_mutex_trylock(nxt_thread_mutex_t *mtx)
{
    nxt_err_t  err;

    nxt_thread_debug(thr);

    nxt_log_debug(thr->log, "pthread_mutex_trylock(%p) enter", mtx);

    err = pthread_mutex_trylock(mtx);
    if (nxt_fast_path(err == 0)) {
        return 1;
    }

    if (err == NXT_EBUSY) {
        nxt_log_debug(thr->log, "pthread_mutex_trylock(%p) failed", mtx);

    } else {
        nxt_thread_log_alert("pthread_mutex_trylock() failed %E", err);
    }

    return 0;
}


nxt_int_t
nxt_thread_mutex_unlock(nxt_thread_mutex_t *mtx)
{
    nxt_err_t     err;
    nxt_thread_t  *thr;

    err = pthread_mutex_unlock(mtx);

    thr = nxt_thread();
    nxt_thread_time_update(thr);

    if (nxt_fast_path(err == 0)) {
        nxt_log_debug(thr->log, "pthread_mutex_unlock(%p) exit", mtx);
        return NXT_OK;
    }

    nxt_log_alert(thr->log, "pthread_mutex_unlock() failed %E", err);

    return NXT_ERROR;
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * Linux supports pthread spinlocks since glibc 2.3.  Spinlock is an
 * atomic integer with zero initial value.  On i386/amd64 however the
 * initial value is one.  Spinlock never yields control.
 *
 * FreeBSD 5.2 and Solaris 10 support pthread spinlocks.  Spinlock is a
 * structure and uses mutex implementation so it must be initialized by
 * by pthread_spin_init() and destroyed by pthread_spin_destroy().
 *
 * MacOSX supported OSSpinLockLock(), it was deprecated in 10.12 (Sierra).
 * OSSpinLockLock() tries to acquire a lock atomically.  If the lock is
 * busy, on SMP system it tests the lock 1000 times in a tight loop with
 * "pause" instruction.  If the lock has been released, OSSpinLockLock()
 * tries to acquire it again.  On failure it goes again in the tight loop.
 * If the lock has not been released during spinning in the loop or
 * on UP system, OSSpinLockLock() calls thread_switch() to run 1ms
 * with depressed (the lowest) priority.
 */


/* It should be adjusted with the "spinlock_count" directive. */
static nxt_uint_t  nxt_spinlock_count = 1000;


void
nxt_thread_spin_init(nxt_uint_t ncpu, nxt_uint_t count)
{
    switch (ncpu) {

    case 0:
        /* Explicit spinlock count. */
        nxt_spinlock_count = count;
        break;

    case 1:
        /* Spinning is useless on UP. */
        nxt_spinlock_count = 0;
        break;

    default:
        /*
         * SMP.
         *
         * TODO: The count should be 10 on a virtualized system
         * since virtualized CPUs may share the same physical CPU.
         */
        nxt_spinlock_count = 1000;
        break;
    }
}


void
nxt_thread_spin_lock(nxt_thread_spinlock_t *lock)
{
    nxt_uint_t  n;

    nxt_thread_log_debug("spin_lock(%p) enter", lock);

    for ( ;; ) {

    again:

        if (nxt_fast_path(nxt_atomic_try_lock(lock))) {
            return;
        }

        for (n = nxt_spinlock_count; n != 0; n--) {

            nxt_cpu_pause();

            if (*lock == 0) {
                goto again;
            }
        }

        nxt_thread_yield();
    }
}


nxt_bool_t
nxt_thread_spin_trylock(nxt_thread_spinlock_t *lock)
{
    nxt_thread_log_debug("spin_trylock(%p) enter", lock);

    if (nxt_fast_path(nxt_atomic_try_lock(lock))) {
        return 1;
    }

    nxt_thread_log_debug("spin_trylock(%p) failed", lock);

    return 0;
}


void
nxt_thread_spin_unlock(nxt_thread_spinlock_t *lock)
{
    nxt_atomic_release(lock);

    nxt_thread_log_debug("spin_unlock(%p) exit", lock);
}

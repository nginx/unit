
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


#if (NXT_LINUX)

/*
 * Linux thread id is a pid of thread created by clone(2),
 * glibc does not provide a wrapper for gettid().
 */

nxt_inline nxt_tid_t
nxt_thread_get_tid(void)
{
    return syscall(SYS_gettid);
}

#elif (NXT_FREEBSD)

/*
 * FreeBSD 9.0 provides pthread_getthreadid_np(), here is its
 * emulation.  Kernel thread id is the first field of struct pthread.
 * Although kernel exports a thread id as long type, lwpid_t is 32bit.
 * Thread id is a number above 100,000.
 */

nxt_inline nxt_tid_t
nxt_thread_get_tid(void)
{
    return (uint32_t) (*(long *) pthread_self());
}

#elif (NXT_SOLARIS)

/* Solaris pthread_t are numbers starting with 1 */

nxt_inline nxt_tid_t
nxt_thread_get_tid(void)
{
    return pthread_self();
}

#elif (NXT_MACOSX)

/*
 * MacOSX thread has two thread ids:
 *
 * 1) MacOSX 10.6 (Snow Leoprad) has pthread_threadid_np() returning
 *    an uint64_t value, which is obtained using the __thread_selfid()
 *    syscall.  It is a number above 300,000.
 */

nxt_inline nxt_tid_t
nxt_thread_get_tid(void)
{
    uint64_t  tid;

    (void) pthread_threadid_np(NULL, &tid);
    return tid;
}

/*
 * 2) Kernel thread mach_port_t returned by pthread_mach_thread_np().
 *    It is a number in range 100-100,000.
 *
 * return pthread_mach_thread_np(pthread_self());
 */

#elif (NXT_AIX)

/*
 * pthread_self() in main thread returns 1.
 * pthread_self() in other threads returns 258, 515, etc.
 *
 * pthread_getthrds_np(PTHRDSINFO_QUERY_TID) returns kernel tid
 * shown in "ps -ef -m -o THREAD" output.
 */

nxt_inline nxt_tid_t
nxt_thread_get_tid(void)
{
    int                  err, size;
    pthread_t            pt;
    struct __pthrdsinfo  ti;

    size = 0;
    pt = pthread_self();

    err = pthread_getthrds_np(&pt, PTHRDSINFO_QUERY_TID, &ti,
                            sizeof(struct __pthrdsinfo), NULL, size);

    if (nxt_fast_path(err == 0)) {
        return ti.__pi_tid;
    }

    nxt_main_log_alert("pthread_getthrds_np(PTHRDSINFO_QUERY_TID) failed %E",
                       err);
    return 0;
}

/*
 * AIX pthread_getunique_np() returns thread unique number starting with 1.
 * OS/400 and i5/OS have pthread_getthreadid_np(), but AIX lacks their
 * counterpart.
 *
 *
 * int        tid;
 * pthread_t  pt;
 *
 * pt = pthread_self();
 * pthread_getunique_np(&pt, &tid);
 * return tid;
 */

#elif (NXT_HPUX)

/* HP-UX pthread_t are numbers starting with 1 */

nxt_inline nxt_tid_t
nxt_thread_get_tid(void)
{
    return pthread_self();
}

#else

nxt_inline nxt_tid_t
nxt_thread_get_tid(void)
{
    return pthread_self();
}

#endif


nxt_tid_t
nxt_thread_tid(nxt_thread_t *thr)
{
    if (thr == NULL) {
        thr = nxt_thread();
    }

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

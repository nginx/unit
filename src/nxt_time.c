
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/* OS-specific real, monotonic, and local times and timezone update. */


/* Real time. */

#if (NXT_HAVE_CLOCK_REALTIME_COARSE)

/*
 * Linux clock_gettime() resides on the vDSO page.  Linux 2.6.32
 * clock_gettime(CLOCK_REALTIME_COARSE) uses only cached values and does
 * not read TSC or HPET so it has the kernel jiffy precision (1ms by default)
 * and it is several times faster than clock_gettime(CLOCK_REALTIME).
 */

void
nxt_realtime(nxt_realtime_t *now)
{
    struct timespec  ts;

    (void) clock_gettime(CLOCK_REALTIME_COARSE, &ts);

    now->sec = (nxt_time_t) ts.tv_sec;
    now->nsec = ts.tv_nsec;
}


#elif (NXT_HAVE_CLOCK_REALTIME_FAST)

/*
 * FreeBSD 7.0 specific clock_gettime(CLOCK_REALTIME_FAST) may be
 * 5-30 times faster than clock_gettime(CLOCK_REALTIME) depending
 * on kern.timecounter.hardware.  The clock has a precision of 1/HZ
 * seconds (HZ is 1000 on modern platforms, thus 1ms precision).
 * FreeBSD 9.2 clock_gettime() resides on the vDSO page and reads
 * TSC.  clock_gettime(CLOCK_REALTIME_FAST) is the same as
 * clock_gettime(CLOCK_REALTIME).
 */

void
nxt_realtime(nxt_realtime_t *now)
{
    struct timespec  ts;

    (void) clock_gettime(CLOCK_REALTIME_FAST, &ts);

    now->sec = (nxt_time_t) ts.tv_sec;
    now->nsec = ts.tv_nsec;
}


#elif (NXT_HAVE_CLOCK_REALTIME && !(NXT_HPUX))

/*
 * clock_gettime(CLOCK_REALTIME) is supported by Linux, FreeBSD 3.0,
 * Solaris 8, NetBSD 1.3, and AIX.  HP-UX supports it too, however,
 * it is implemented through a call to gettimeofday().  Linux
 * clock_gettime(CLOCK_REALTIME) resides on the vDSO page and reads
 * TSC or HPET.  FreeBSD 9.2 clock_gettime(CLOCK_REALTIME) resides
 * on the vDSO page and reads TSC.
 */

void
nxt_realtime(nxt_realtime_t *now)
{
    struct timespec  ts;

    (void) clock_gettime(CLOCK_REALTIME, &ts);

    now->sec = (nxt_time_t) ts.tv_sec;
    now->nsec = ts.tv_nsec;
}


#else

/* MacOSX, HP-UX. */

void
nxt_realtime(nxt_realtime_t *now)
{
    struct timeval  tv;

    (void) gettimeofday(&tv, NULL);

    now->sec = (nxt_time_t) tv.tv_sec;
    now->nsec = tv.tv_usec * 1000;
}

#endif


/* Monotonic time. */

#if (NXT_HAVE_CLOCK_MONOTONIC_COARSE)

/*
 * Linux clock_gettime() resides on the vDSO page.  Linux 2.6.32
 * clock_gettime(CLOCK_MONOTONIC_COARSE) uses only cached values and does
 * not read TSC or HPET so it has the kernel jiffy precision (1ms by default)
 * and it is several times faster than clock_gettime(CLOCK_MONOTONIC).
 */

void
nxt_monotonic_time(nxt_monotonic_time_t *now)
{
    struct timespec  ts;

    (void) clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);

    now->monotonic = (nxt_nsec_t) ts.tv_sec * 1000000000 + ts.tv_nsec;
}


#elif (NXT_HAVE_CLOCK_MONOTONIC_FAST)

/*
 * FreeBSD 7.0 specific clock_gettime(CLOCK_MONOTONIC_FAST) may be
 * 5-30 times faster than clock_gettime(CLOCK_MONOTONIC) depending
 * on kern.timecounter.hardware.  The clock has a precision of 1/HZ
 * seconds (HZ is 1000 on modern platforms, thus 1ms precision).
 * FreeBSD 9.2 clock_gettime() resides on the vDSO page and reads
 * TSC.  clock_gettime(CLOCK_MONOTONIC_FAST) is the same as
 * clock_gettime(CLOCK_MONOTONIC).
 */

void
nxt_monotonic_time(nxt_monotonic_time_t *now)
{
    struct timespec  ts;

    (void) clock_gettime(CLOCK_MONOTONIC_FAST, &ts);

    now->monotonic = (nxt_nsec_t) ts.tv_sec * 1000000000 + ts.tv_nsec;
}


#elif (NXT_HAVE_HG_GETHRTIME)

/*
 * HP-UX 11.31 provides fast hg_gethrtime() which uses a chunk of memory
 * shared between userspace application and the kernel, and was introduced
 * by Project Mercury ("HG").
 */

void
nxt_monotonic_time(nxt_monotonic_time_t *now)
{
    now->monotonic = (nxt_nsec_t) hg_gethrtime();
}


#elif (NXT_SOLARIS || NXT_HPUX)

/*
 * Solaris gethrtime(), clock_gettime(CLOCK_REALTIME), and gettimeofday()
 * use a fast systrap whereas clock_gettime(CLOCK_MONOTONIC) and other
 * clock_gettime()s use normal systrap.  However, the difference is
 * negligible on x86_64.
 *
 * HP-UX lacks clock_gettime(CLOCK_MONOTONIC) but has lightweight
 * system call gethrtime().
 */

void
nxt_monotonic_time(nxt_monotonic_time_t *now)
{
    now->monotonic = (nxt_nsec_t) gethrtime();
}


#elif (NXT_HAVE_CLOCK_MONOTONIC)

/*
 * clock_gettime(CLOCK_MONOTONIC) is supported by Linux, FreeBSD 5.0,
 * Solaris 8, NetBSD 1.6, and AIX.  Linux clock_gettime(CLOCK_MONOTONIC)
 * resides on the vDSO page and reads TSC or HPET.  FreeBSD 9.2
 * clock_gettime(CLOCK_MONOTONIC) resides on the vDSO page and reads TSC.
 */

void
nxt_monotonic_time(nxt_monotonic_time_t *now)
{
    struct timespec  ts;

    (void) clock_gettime(CLOCK_MONOTONIC, &ts);

    now->monotonic = (nxt_nsec_t) ts.tv_sec * 1000000000 + ts.tv_nsec;
}


#elif (NXT_MACOSX)

/*
 * MacOSX does not support clock_gettime(), but mach_absolute_time() returns
 * monotonic ticks.  To get nanoseconds the ticks should be multiplied then
 * divided by numerator/denominator returned by mach_timebase_info(), however
 * on modern MacOSX they are 1/1.  On PowerPC MacOSX these values were
 * 1000000000/33333335 or 1000000000/25000000, on iOS 4+ they were 125/3,
 * and on iOS 3 they were 1000000000/24000000.
 */

void
nxt_monotonic_time(nxt_monotonic_time_t *now)
{
    now->monotonic = mach_absolute_time();
}


#else

void
nxt_monotonic_time(nxt_monotonic_time_t *now)
{
    nxt_nsec_t      current;
    nxt_nsec_int_t  delta;
    struct timeval  tv;

    (void) gettimeofday(&tv, NULL);

    now->realtime.sec = (nxt_time_t) tv.tv_sec;
    now->realtime.nsec = tv.tv_usec * 1000;

    /*
     * Monotonic time emulation using gettimeofday()
     * for platforms which lack monotonic time.
     */

    current = (nxt_nsec_t) tv.tv_sec * 1000000000 + tv.tv_usec * 1000;
    delta = current - now->previous;
    now->previous = current;

    if (delta > 0) {
        now->monotonic += delta;

    } else {
        /* The time went backward. */
        now->monotonic++;
    }

    /*
     * Eliminate subsequent gettimeofday() call
     * in nxt_thread_realtime_update().
     */
    now->update = now->monotonic + 1;
}

#endif


/* Local time. */

#if (NXT_HAVE_LOCALTIME_R)

void
nxt_localtime(nxt_time_t s, struct tm *tm)
{
    time_t  _s;

    _s = (time_t) s;
    (void) localtime_r(&_s, tm);
}


#else

void
nxt_localtime(nxt_time_t s, struct tm *tm)
{
    time_t     _s;
    struct tm  *_tm;

    _s = (time_t) s;
    _tm = localtime(&_s);
    *tm = *_tm;
}

#endif


/* Timezone update. */

#if (NXT_LINUX)

/*
 * Linux glibc does not test /etc/localtime change
 * in localtime_r(), but tests in localtime().
 */

void
nxt_timezone_update(void)
{
    time_t  s;

    s = time(NULL);
    (void) localtime(&s);
}


#elif (NXT_FREEBSD)

/*
 * FreeBSD libc does not test /etc/localtime change, but it can be
 * worked around by calling tzset() with TZ and then without TZ
 * to update timezone.  This trick should work since FreeBSD 2.1.0.
 */

void
nxt_timezone_update(void)
{
    if (getenv("TZ") != NULL) {
        return;
    }

    /* The libc uses /etc/localtime if TZ is not set. */

    (void) putenv((char *) "TZ=UTC");
    tzset();

    (void) unsetenv("TZ");
    tzset();
}


#elif (NXT_SOLARIS)

/*
 * Solaris 10, patch 142909-17 introduced tzreload(8):
 *
 *   The tzreload command notifies active (running) processes to reread
 *   timezone information.  The timezone information is cached in each
 *   process, absent a tzreload command, is never reread until a process
 *   is restarted.  In response to a tzreload command, active processes
 *   reread the current timezone information at the next call to ctime(3C)
 *   and mktime(3C).  By default, the tzreload notification is sent to
 *   the processes within the current zone.
 */

void
nxt_timezone_update(void)
{
    time_t  s;

    s = time(NULL);
    (void) ctime(&s);
}


#else

void
nxt_timezone_update(void)
{
    return;
}

#endif

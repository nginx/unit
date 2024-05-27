
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIX_TIME_H_INCLUDED_
#define _NXT_UNIX_TIME_H_INCLUDED_


typedef uint64_t           nxt_nsec_t;
typedef int64_t            nxt_nsec_int_t;
#define NXT_INFINITE_NSEC  ((nxt_nsec_t) -1)


typedef struct {
    nxt_time_t             sec;
    nxt_uint_t             nsec;
} nxt_realtime_t;


/*
 * nxt_monotonic_time_t includes nxt_realtime_t to eliminate
 * surplus gettimeofday() call on platform without monotonic time.
 */

typedef struct {
    nxt_realtime_t         realtime;
    nxt_nsec_t             monotonic;
    nxt_nsec_t             update;

#if !(NXT_HAVE_CLOCK_MONOTONIC || NXT_SOLARIS || NXT_HPUX || NXT_MACOSX)
    nxt_nsec_t             previous;
#endif
} nxt_monotonic_time_t;


NXT_EXPORT void nxt_realtime(nxt_realtime_t *now);
NXT_EXPORT void nxt_monotonic_time(nxt_monotonic_time_t *now);
NXT_EXPORT void nxt_localtime(nxt_time_t s, struct tm *tm);
NXT_EXPORT void nxt_timezone_update(void);

/*
 * Both localtime() and localtime_r() are not Async-Signal-Safe, therefore,
 * they can not be used in signal handlers.  Since Daylight Saving Time (DST)
 * state changes no more than twice a year, a simple workaround is to use
 * a previously cached GMT offset value and nxt_gmtime():
 *
 *     nxt_gmtime(GMT seconds + GMT offset, tm);
 *
 * GMT offset with account of current DST state can be obtained only
 * using localtime()'s struct tm because:
 *
 * 1) gettimeofday() does not return GMT offset at almost all platforms.
 *    MacOSX returns a value cached after the first localtime() call.
 *    AIX returns GMT offset without account of DST state and indicates
 *    only that timezone has DST, but does not indicate current DST state.
 *
 * 2) There are the "timezone" and "daylight" variables on Linux, Solaris,
 *    HP-UX, IRIX, and other systems.  The "daylight" variable indicates
 *    only that timezone has DST, but does not indicate current DST state.
 *
 * 3) Solaris and IRIX have the "altzone" variable which contains GMT offset
 *    for timezone with DST applied, but without account of DST state.
 *
 * 4) There is the "struct tm.tm_gmtoff" field on BSD systems and modern Linux.
 *    This field contains GMT offset with account of DST state.
 *
 * 5) The "struct tm.tm_isdst" field returned by localtime() indicates
 *    current DST state on all platforms.  This field may have three values:
 *    positive means DST in effect, zero means DST is not in effect, and
 *    negative means DST state is unknown.
 */

#if (NXT_HAVE_TM_GMTOFF)

#define nxt_timezone(tm)                                                      \
    ((tm)->tm_gmtoff)

#elif (NXT_HAVE_ALTZONE)

#define nxt_timezone(tm)                                                      \
    (-(((tm)->tm_isdst > 0) ? altzone : timezone))

#else

#define nxt_timezone(tm)                                                      \
    (-(((tm)->tm_isdst > 0) ? timezone + 3600 : timezone))

#endif


typedef uint32_t           nxt_msec_t;
typedef int32_t            nxt_msec_int_t;
#define NXT_INFINITE_MSEC  ((nxt_msec_t) -1)


/*
 * Since nxt_msec_t values are stored just in 32 bits, they overflow
 * every 49 days.  This signed subtraction takes into account that overflow.
 * "nxt_msec_diff(m1, m2) < 0" means that m1 is lesser than m2.
 */
#define nxt_msec_diff(m1, m2)                                                 \
    ((int32_t) ((m1) - (m2)))


#endif /* _NXT_UNIX_TIME_H_INCLUDED_ */

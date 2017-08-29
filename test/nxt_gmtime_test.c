
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_tests.h"


#if (NXT_TIME_T_SIZE == 4)

/* A 86400-fold number below 2^31. */
#define NXT_GMTIME_MAX  2147472000

#else
/*
 * March 19, 29398 is maximum valid data if nxt_uint_t
 * is 4 bytes size whilst nxt_time_t is 8 bytes size.
 */
#define NXT_GMTIME_MAX  865550793600
#endif


nxt_int_t
nxt_gmtime_test(nxt_thread_t *thr)
{
    struct tm   tm0, *tm1;
    nxt_time_t  s;
    nxt_nsec_t  start, end;

    nxt_thread_time_update(thr);
    nxt_log_error(NXT_LOG_NOTICE, thr->log, "gmtime test started");

    for (s = 0; s < NXT_GMTIME_MAX; s += 86400) {

        nxt_gmtime(s, &tm0);
        tm1 = gmtime(&s);

        if (tm0.tm_mday != tm1->tm_mday
            || tm0.tm_mon != tm1->tm_mon
            || tm0.tm_year != tm1->tm_year
            || tm0.tm_yday != tm1->tm_yday
            || tm0.tm_wday != tm1->tm_wday)
        {
            nxt_log_alert(thr->log,
                          "gmtime test failed: %T @ %02d.%02d.%d",
                          s, tm1->tm_mday, tm1->tm_mon + 1,
                          tm1->tm_year + 1900);
            return NXT_ERROR;
        }
    }


    nxt_thread_time_update(thr);
    start = nxt_thread_monotonic_time(thr);

    for (s = 0; s < 10000000; s++) {
        nxt_gmtime(s, &tm0);
    }

    nxt_thread_time_update(thr);
    end = nxt_thread_monotonic_time(thr);

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "nxt_gmtime(): %0.1fns",
                  (end - start) / 10000000.0);


    nxt_thread_time_update(thr);
    start = nxt_thread_monotonic_time(thr);

    for (s = 0; s < 10000000; s++) {
        (void) gmtime(&s);
    }

    nxt_thread_time_update(thr);
    end = nxt_thread_monotonic_time(thr);

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "gmtime(): %0.1fns",
                  (end - start) / 10000000.0);

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "gmtime test passed");
    return NXT_OK;
}

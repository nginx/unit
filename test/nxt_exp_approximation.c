
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <math.h>


nxt_int_t
nxt_exp_approximation(nxt_thread_t *thr)
{
    double      n, e0, e1, diff;
    nxt_nsec_t  start, end;

    nxt_thread_time_update(thr);
    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "exp approximation unit test started");

    for (n = 0.0; n > -20.0; n -= 0.00001) {

        e0 = nxt_event_conn_exponential_approximation(n);
        e1 = exp(n);

        diff = fabs(e0 - e1);

        /* 0.028993 is max difference with libm exp(). */
        if (diff > 0.028993) {
            nxt_log_alert(thr->log,
                          "exp approximation unit test failed: %0.6f %0.6f",
                          n, diff);
            return NXT_ERROR;
        }
    }


    nxt_thread_time_update(thr);
    start = nxt_thread_monotonic_time(thr);

    e0 = 0;
    for (n = 0.0; n > -20.0; n -= 0.00001) {
        e0 += nxt_event_conn_exponential_approximation(n);
    }

    nxt_thread_time_update(thr);
    end = nxt_thread_monotonic_time(thr);

    /* e0 is passed but not output to eliminate optimization. */
    nxt_log_error(NXT_LOG_NOTICE, thr->log, "exp approximation: %0.1fns",
                  (end - start) / 20000000.0, e0);


    nxt_thread_time_update(thr);
    start = nxt_thread_monotonic_time(thr);

    e0 = 0;
    for (n = 0.0; n > -20.0; n -= 0.000001) {
        e0 += exp(n);
    }

    nxt_thread_time_update(thr);
    end = nxt_thread_monotonic_time(thr);

    /* e0 is passed but not output to eliminate optimization. */
    nxt_log_error(NXT_LOG_NOTICE, thr->log, "libm exp(): %0.1fns",
                  (end - start) / 20000000.0, e0);

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "exp approximation unit test passed");
    return NXT_OK;
}

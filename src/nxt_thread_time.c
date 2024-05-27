
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * Each thread keeps several time representations in its thread local
 * storage:
 *   the monotonic time in nanoseconds since unspecified point in the past,
 *   the real time in seconds and nanoseconds since the Epoch,
 *   the local time and GMT time structs,
 *   and various user-defined text representations of local and GMT times.
 *
 * The monotonic time is used mainly by engine timers and is updated after
 * a kernel operation which can block for unpredictable duration like event
 * polling.  Besides getting the monotonic time is generally faster than
 * getting the real time, so the monotonic time is also used for milestones
 * to update cached real time seconds and, if debug log enabled, milliseconds.
 * As a result, the cached real time is updated at most one time per second
 * or millisecond respectively.  If there is a signal event support or in
 * multi-threaded mode, then the cached real time and local time structs
 * are updated only on demand.  In single-threaded mode without the signal
 * event support the cached real and local time are updated synchronously
 * with the monotonic time update.  GMT time structs and text representations
 * are always updated only on demand.
 */


static void nxt_time_thread(void *data);
static void nxt_thread_time_shared(nxt_monotonic_time_t *now);
static void nxt_thread_realtime_update(nxt_thread_t *thr,
    nxt_monotonic_time_t *now);
static u_char *nxt_thread_time_string_no_cache(nxt_thread_t *thr,
    nxt_time_string_t *ts, u_char *buf);
static nxt_atomic_uint_t nxt_thread_time_string_slot(nxt_time_string_t *ts);
static nxt_time_string_cache_t *nxt_thread_time_string_cache(nxt_thread_t *thr,
    nxt_atomic_uint_t slot);


static nxt_atomic_int_t               nxt_gmtoff;
static nxt_bool_t                     nxt_use_shared_time = 0;
static volatile nxt_monotonic_time_t  nxt_shared_time;


void
nxt_thread_time_update(nxt_thread_t *thr)
{
    if (nxt_use_shared_time) {
        nxt_thread_time_shared(&thr->time.now);

    } else {
        nxt_monotonic_time(&thr->time.now);
    }
}


void
nxt_thread_time_free(nxt_thread_t *thr)
{
    nxt_uint_t               i;
    nxt_time_string_cache_t  *tsc;

    tsc = thr->time.strings;

    if (tsc) {
        thr->time.no_cache = 1;

        for (i = 0; i < thr->time.nstrings; i++) {
            nxt_free(tsc[i].string.start);
        }

        nxt_free(tsc);
        thr->time.strings = NULL;
    }
}


void
nxt_time_thread_start(nxt_msec_t interval)
{
    nxt_thread_link_t    *link;
    nxt_thread_handle_t  handle;

    link = nxt_zalloc(sizeof(nxt_thread_link_t));

    if (nxt_fast_path(link != NULL)) {
        link->start = nxt_time_thread;
        link->work.data = (void *) (uintptr_t) interval;

        (void) nxt_thread_create(&handle, link);
    }
}


static void
nxt_time_thread(void *data)
{
    nxt_nsec_t            interval, rest;
    nxt_thread_t          *thr;
    nxt_monotonic_time_t  now;

    interval = (uintptr_t) data;
    interval *= 1000000;

    thr = nxt_thread();
    /*
     * The time thread is never preempted by asynchronous signals, since
     * the signals are processed synchronously by dedicated thread.
     */
    thr->time.signal = -1;

    nxt_log_debug(thr->log, "time thread");

    nxt_memzero(&now, sizeof(nxt_monotonic_time_t));

    nxt_monotonic_time(&now);
    nxt_thread_realtime_update(thr, &now);

    nxt_shared_time = now;
    nxt_use_shared_time = 1;

    for ( ;; ) {
        rest = 1000000000 - now.realtime.nsec;

        nxt_nanosleep(nxt_min(interval, rest));

        nxt_monotonic_time(&now);
        nxt_thread_realtime_update(thr, &now);

        nxt_shared_time = now;

#if 0
        thr->time.now = now;
        nxt_log_debug(thr->log, "time thread");
#endif

#if 0
        if (nxt_exiting) {
            nxt_use_shared_time = 0;
            return;
        }
#endif
    }
}


static void
nxt_thread_time_shared(nxt_monotonic_time_t *now)
{
    nxt_uint_t  n;
    nxt_time_t  t;
    nxt_nsec_t  m, u;

    /* Lock-free thread time update. */

    for ( ;; ) {
        *now = nxt_shared_time;

        t = nxt_shared_time.realtime.sec;
        n = nxt_shared_time.realtime.nsec;
        m = nxt_shared_time.monotonic;
        u = nxt_shared_time.update;

        if (now->realtime.sec == t && now->realtime.nsec == n
            && now->monotonic == m && now->update == u)
        {
            return;
        }
    }
}


nxt_time_t
nxt_thread_time(nxt_thread_t *thr)
{
    nxt_thread_realtime_update(thr, &thr->time.now);

    return thr->time.now.realtime.sec;
}


nxt_realtime_t *
nxt_thread_realtime(nxt_thread_t *thr)
{
    nxt_thread_realtime_update(thr, &thr->time.now);

    return &thr->time.now.realtime;
}


static void
nxt_thread_realtime_update(nxt_thread_t *thr, nxt_monotonic_time_t *now)
{
    nxt_nsec_t  delta;

#if (NXT_DEBUG)

    if (nxt_slow_path(thr->log->level == NXT_LOG_DEBUG || nxt_debug)) {

        if (now->monotonic >= now->update) {
            nxt_realtime(&now->realtime);

            delta = 1000000 - now->realtime.nsec % 1000000;
            now->update = now->monotonic + delta;
        }

        return;
    }

#endif

    if (now->monotonic >= now->update) {
        nxt_realtime(&now->realtime);

        delta = 1000000000 - now->realtime.nsec;
        now->update = now->monotonic + delta;
    }
}


u_char *
nxt_thread_time_string(nxt_thread_t *thr, nxt_time_string_t *ts, u_char *buf)
{
    u_char                   *p;
    struct tm                *tm;
    nxt_time_t               s;
    nxt_bool_t               update;
    nxt_atomic_uint_t        slot;
    nxt_time_string_cache_t  *tsc;

    if (nxt_slow_path(thr == NULL || thr->time.no_cache)) {
        return nxt_thread_time_string_no_cache(thr, ts, buf);
    }

    slot = nxt_thread_time_string_slot(ts);

    tsc = nxt_thread_time_string_cache(thr, slot);
    if (tsc == NULL) {
        return buf;
    }

    if (thr->time.signal < 0) {
        /*
         * Lazy real time update:
         * signal event support or multi-threaded mode.
         */
        nxt_thread_realtime_update(thr, &thr->time.now);
    }

    s = thr->time.now.realtime.sec;

    update = (s != tsc->last);

#if (NXT_DEBUG)

    if (ts->msec == NXT_THREAD_TIME_MSEC
        && (nxt_slow_path(thr->log->level == NXT_LOG_DEBUG || nxt_debug)))
    {
        nxt_msec_t  ms;

        ms = thr->time.now.realtime.nsec / 1000000;
        update |= (ms != tsc->last_msec);
        tsc->last_msec = ms;
    }

#endif

    if (nxt_slow_path(update)) {

        if (ts->timezone == NXT_THREAD_TIME_LOCAL) {

            tm = &thr->time.localtime;

            if (nxt_slow_path(s != thr->time.last_localtime)) {

                if (thr->time.signal < 0) {
                    /*
                     * Lazy local time update:
                     * signal event support or multi-threaded mode.
                     */
                    nxt_localtime(s, &thr->time.localtime);
                    thr->time.last_localtime = s;

                } else {
                    /*
                     * "thr->time.signal >= 0" means that a thread may be
                     * interrupted by a signal handler.  Since localtime()
                     * cannot be safely called in a signal context, the
                     * thread's thr->time.localtime must be updated regularly
                     * by nxt_thread_time_update() in non-signal context.
                     * Stale timestamp means that nxt_thread_time_string()
                     * is being called in a signal context, so here is
                     * Async-Signal-Safe localtime() emulation using the
                     * latest cached GMT offset.
                     *
                     * The timestamp is not set here intentionally to update
                     * thr->time.localtime later in non-signal context.  The
                     * real previously cached thr->localtime is used because
                     * Linux and Solaris strftime() depend on tm.tm_isdst
                     * and tm.tm_gmtoff fields.
                     */
                    nxt_gmtime(s + nxt_timezone(tm), tm);
                }
            }

        } else {
            tm = &thr->time.gmtime;

            if (nxt_slow_path(s != thr->time.last_gmtime)) {
                nxt_gmtime(s, tm);
                thr->time.last_gmtime = s;
            }

        }

        p = tsc->string.start;

        if (nxt_slow_path(p == NULL)) {

            thr->time.no_cache = 1;
            p = nxt_zalloc(ts->size);
            thr->time.no_cache = 0;

            if (p == NULL) {
                return buf;
            }

            tsc->string.start = p;
        }

        p = ts->handler(p, &thr->time.now.realtime, tm, ts->size, ts->format);

        tsc->string.length = p - tsc->string.start;

        if (nxt_slow_path(tsc->string.length == 0)) {
            return buf;
        }

        tsc->last = s;
    }

    return nxt_cpymem(buf, tsc->string.start, tsc->string.length);
}


static u_char *
nxt_thread_time_string_no_cache(nxt_thread_t *thr, nxt_time_string_t *ts,
    u_char *buf)
{
    struct tm       tm;
    nxt_realtime_t  now;

    nxt_realtime(&now);

    if (ts->timezone == NXT_THREAD_TIME_LOCAL) {

        if (thr == NULL || thr->time.signal <= 0) {
            /* Non-signal context */
            nxt_localtime(now.sec, &tm);

        } else {
            nxt_gmtime(now.sec + nxt_gmtoff, &tm);
        }

    } else {
        nxt_gmtime(now.sec, &tm);
    }

    return ts->handler(buf, &now, &tm, ts->size, ts->format);
}


static nxt_atomic_uint_t
nxt_thread_time_string_slot(nxt_time_string_t *ts)
{
    static nxt_atomic_t  slot;

    while (nxt_slow_path((nxt_atomic_int_t) ts->slot < 0)) {
        /*
         * Atomic allocation of a slot number.
         * -1 means an uninitialized slot,
         * -2 is the initializing lock to assure the single value for the slot.
         */
        if (nxt_atomic_cmp_set(&ts->slot, -1, -2)) {
            ts->slot = nxt_atomic_fetch_add(&slot, 1);

            /* No "break" here since it adds only dispensable "jmp". */
        }
    }

    return (nxt_atomic_uint_t) ts->slot;
}


static nxt_time_string_cache_t *
nxt_thread_time_string_cache(nxt_thread_t *thr, nxt_atomic_uint_t slot)
{
    size_t                   size;
    nxt_atomic_uint_t        i, nstrings;
    nxt_time_string_cache_t  *tsc;

    if (nxt_fast_path(slot < thr->time.nstrings)) {
        tsc = &thr->time.strings[slot];
        nxt_prefetch(tsc->string.start);
        return tsc;
    }

    nstrings = slot + 1;
    size = nstrings * sizeof(nxt_time_string_cache_t);

    thr->time.no_cache = 1;
    tsc = nxt_realloc(thr->time.strings, size);
    thr->time.no_cache = 0;

    if (tsc == NULL) {
        return NULL;
    }

    for (i = thr->time.nstrings; i < nstrings; i++) {
        tsc[i].last = -1;
        tsc[i].string.start = NULL;
    }

    thr->time.strings = tsc;
    thr->time.nstrings = nstrings;

    return &tsc[slot];
}

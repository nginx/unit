
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_THREAD_TIME_H_INCLUDED_
#define _NXT_THREAD_TIME_H_INCLUDED_


#define NXT_THREAD_TIME_LOCAL  0
#define NXT_THREAD_TIME_GMT    1

#define NXT_THREAD_TIME_SEC    0
#define NXT_THREAD_TIME_MSEC   1


typedef struct {
    nxt_atomic_t               slot;
    u_char                     *(*handler)(u_char *buf, nxt_realtime_t *now,
                                   struct tm *tm, size_t size,
                                   const char *format);
    const char                 *format;
    size_t                     size;

    uint8_t                    timezone;  /* 1 bit */
    uint8_t                    msec;      /* 1 bit */
} nxt_time_string_t;


typedef struct {
    nxt_time_t                 last;
#if (NXT_DEBUG)
    nxt_msec_t                 last_msec;
#endif
    nxt_str_t                  string;
} nxt_time_string_cache_t;


typedef struct {
    nxt_monotonic_time_t       now;

    nxt_time_t                 last_gmtime;
    nxt_time_t                 last_localtime;
    struct tm                  gmtime;
    struct tm                  localtime;

    uint32_t                   no_cache;  /* 1 bit */

    /*
     * The flag indicating a signal state of a thread.
     * It is used to handle local time of the thread:
     *   -1 means that the thread never runs in a signal context;
     *    0 means that the thread may run in a signal context but not now;
     *   >0 means that the thread runs in a signal context right now.
     */
    nxt_atomic_int_t           signal;

    nxt_atomic_uint_t          nstrings;
    nxt_time_string_cache_t    *strings;
} nxt_thread_time_t;


NXT_EXPORT void nxt_thread_time_update(nxt_thread_t *thr);
void nxt_thread_time_free(nxt_thread_t *thr);
NXT_EXPORT nxt_time_t nxt_thread_time(nxt_thread_t *thr);
NXT_EXPORT nxt_realtime_t *nxt_thread_realtime(nxt_thread_t *thr);
NXT_EXPORT u_char *nxt_thread_time_string(nxt_thread_t *thr,
    nxt_time_string_t *ts, u_char *buf);
void nxt_time_thread_start(nxt_msec_t interval);


#define nxt_thread_monotonic_time(thr)                                        \
    (thr)->time.now.monotonic


#if (NXT_DEBUG)

#define nxt_thread_time_debug_update(thr)                                     \
    nxt_thread_time_update(thr)

#else

#define nxt_thread_time_debug_update(thr)

#endif


NXT_EXPORT void nxt_gmtime(nxt_time_t s, struct tm *tm);


#endif /* _NXT_THREAD_TIME_H_INCLUDED_ */

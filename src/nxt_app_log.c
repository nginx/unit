
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>


static nxt_time_string_t  nxt_log_error_time_cache;
static u_char *nxt_log_error_time(u_char *buf, nxt_realtime_t *now,
    struct tm *tm, size_t size, const char *format);
static nxt_time_string_t  nxt_log_debug_time_cache;
static u_char *nxt_log_debug_time(u_char *buf, nxt_realtime_t *now,
    struct tm *tm, size_t size, const char *format);


void nxt_cdecl
nxt_log_time_handler(nxt_uint_t level, nxt_log_t *log, const char *fmt, ...)
{
    u_char             *p, *end;
#if 0
    u_char             *syslogmsg;
#endif
    va_list            args;
    nxt_thread_t       *thr;
    nxt_time_string_t  *time_cache;
    u_char             msg[NXT_MAX_ERROR_STR];

    thr = nxt_thread();

    end = msg + NXT_MAX_ERROR_STR;

    time_cache = (log->level != NXT_LOG_DEBUG) ? &nxt_log_error_time_cache:
                                                 &nxt_log_debug_time_cache;

    p = nxt_thread_time_string(thr, time_cache, msg);

#if 0
    syslogmsg = p;
#endif

#if 0
    nxt_fid_t    fid;
    const char   *id;
    nxt_fiber_t  *fib;

    fib = nxt_fiber_self(thr);

    if (fib != NULL) {
        id = "[%V] %PI#%PT#%PF ";
        fid = nxt_fiber_id(fib);

    } else {
        id = "[%V] %PI#%PT ";
        fid = 0;
    }

    p = nxt_sprintf(p, end, id, &nxt_log_levels[level], nxt_pid,
                    nxt_thread_tid(thr), fid);
#else
    p = nxt_sprintf(p, end, "[%V] %PI#%PT ", &nxt_log_levels[level], nxt_pid,
                    nxt_thread_tid(thr));
#endif

    if (log->ident != 0) {
        p = nxt_sprintf(p, end, "*%D ", log->ident);
    }

    va_start(args, fmt);
    p = nxt_vsprintf(p, end, fmt, args);
    va_end(args);

    if (level != NXT_LOG_DEBUG && log->ctx_handler != NULL) {
        p = log->ctx_handler(log->ctx, p, end);
    }

    if (p > end - nxt_length("\n")) {
        p = end - nxt_length("\n");
    }

    *p++ = '\n';

    (void) nxt_write_console(nxt_stderr, msg, p - msg);

#if 0
    if (level == NXT_LOG_ALERT) {
        *(p - nxt_length("\n")) = '\0';

        /*
         * The syslog LOG_ALERT level is enough, because
         * LOG_EMERG level broadcasts a message to all users.
         */
        nxt_write_syslog(LOG_ALERT, syslogmsg);
    }
#endif
}


static nxt_time_string_t  nxt_log_error_time_cache = {
    (nxt_atomic_uint_t) -1,
    nxt_log_error_time,
    "%4d/%02d/%02d %02d:%02d:%02d ",
    nxt_length("1970/09/28 12:00:00 "),
    NXT_THREAD_TIME_LOCAL,
    NXT_THREAD_TIME_SEC,
};


static u_char *
nxt_log_error_time(u_char *buf, nxt_realtime_t *now, struct tm *tm, size_t size,
    const char *format)
{
    return nxt_sprintf(buf, buf + size, format,
                       tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                       tm->tm_hour, tm->tm_min, tm->tm_sec);
}


static nxt_time_string_t  nxt_log_debug_time_cache = {
    (nxt_atomic_uint_t) -1,
    nxt_log_debug_time,
    "%4d/%02d/%02d %02d:%02d:%02d.%03d ",
    nxt_length("1970/09/28 12:00:00.000 "),
    NXT_THREAD_TIME_LOCAL,
    NXT_THREAD_TIME_MSEC,
};


static u_char *
nxt_log_debug_time(u_char *buf, nxt_realtime_t *now, struct tm *tm, size_t size,
    const char *format)
{
    return nxt_sprintf(buf, buf + size, format,
                       tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                       tm->tm_hour, tm->tm_min, tm->tm_sec,
                       now->nsec / 1000000);
}

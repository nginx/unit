
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_THREAD_LOG_H_INCLUDED_
#define _NXT_THREAD_LOG_H_INCLUDED_


#define nxt_thread_log_alert(...)                                             \
    do {                                                                      \
        nxt_thread_t  *_thr = nxt_thread();                                   \
                                                                              \
        nxt_log_alert(_thr->log, __VA_ARGS__);                                \
                                                                              \
    } while (0)


#define nxt_thread_log_error(_level, ...)                                     \
    do {                                                                      \
        nxt_thread_t  *_thr = nxt_thread();                                   \
                                                                              \
        nxt_log_error(_level, _thr->log, __VA_ARGS__);                        \
                                                                              \
    } while (0)


#if (NXT_DEBUG)

#define nxt_thread_log_debug(...)                                             \
    do {                                                                      \
        nxt_thread_t  *_thr = nxt_thread();                                   \
                                                                              \
        nxt_log_debug(_thr->log, __VA_ARGS__);                                \
                                                                              \
    } while (0)


#define nxt_thread_debug(thr)                                                 \
    nxt_thread_t  *thr = nxt_thread()

#else

#define nxt_thread_log_debug(...)
#define nxt_thread_debug(thr)

#endif


nxt_inline nxt_log_t *
nxt_thread_log(void)
{
    nxt_thread_t  *thr;

    thr = nxt_thread();
    return thr->log;
}


#endif /* _NXT_THREAD_LOG_H_INCLUDED_ */

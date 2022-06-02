
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_LOG_H_INCLUDED_
#define _NXT_LOG_H_INCLUDED_


#define NXT_LOG_ALERT      0
#define NXT_LOG_ERR        1
#define NXT_LOG_WARN       2
#define NXT_LOG_NOTICE     3
#define NXT_LOG_INFO       4
#define NXT_LOG_DEBUG      5


#define NXT_MAX_ERROR_STR  2048


typedef void nxt_cdecl (*nxt_log_handler_t)(nxt_uint_t level, nxt_log_t *log,
    const char *fmt, ...);
typedef u_char *(*nxt_log_ctx_handler_t)(void *ctx, u_char *pos, u_char *end);


struct nxt_log_s {
    uint32_t               level;
    uint32_t               ident;
    nxt_log_handler_t      handler;
    nxt_log_ctx_handler_t  ctx_handler;
    void                   *ctx;
};


NXT_EXPORT void nxt_log_start(const char *name);
NXT_EXPORT nxt_log_t *nxt_log_set_ctx(nxt_log_t *log,
    nxt_log_ctx_handler_t handler, void *ctx);

NXT_EXPORT void nxt_cdecl nxt_log_handler(nxt_uint_t level, nxt_log_t *log,
    const char *fmt, ...);


#define nxt_log_level_enough(log, level)                                      \
    ((log)->level >= (level))


#define nxt_alert(task, ...)                                                  \
    do {                                                                      \
        nxt_log_t  *_log = (task)->log;                                       \
                                                                              \
        _log->handler(NXT_LOG_ALERT, _log, __VA_ARGS__);                      \
    } while (0)


#define nxt_log(task, _level, ...)                                            \
    do {                                                                      \
        nxt_log_t   *_log = (task)->log;                                      \
        nxt_uint_t  _level_ = (_level);                                       \
                                                                              \
        if (nxt_slow_path(_log->level >= _level_)) {                          \
            _log->handler(_level_, _log, __VA_ARGS__);                        \
        }                                                                     \
    } while (0)


#define nxt_trace(task, ...)                                                  \
    do {                                                                      \
        nxt_log_t  *_log = (task)->log;                                       \
                                                                              \
        if (nxt_slow_path(_log->level >= NXT_LOG_NOTICE || nxt_trace)) {      \
            _log->handler(NXT_LOG_NOTICE, _log, __VA_ARGS__);                 \
        }                                                                     \
    } while (0)


#define nxt_log_alert(_log, ...)                                              \
    do {                                                                      \
        nxt_log_t  *_log_ = (_log);                                           \
                                                                              \
        _log_->handler(NXT_LOG_ALERT, _log_, __VA_ARGS__);                    \
    } while (0)


#define nxt_log_error(_level, _log, ...)                                      \
    do {                                                                      \
        nxt_log_t   *_log_ = (_log);                                          \
        nxt_uint_t  _level_ = (_level);                                       \
                                                                              \
        if (nxt_slow_path(_log_->level >= _level_)) {                         \
            _log_->handler(_level_, _log_, __VA_ARGS__);                      \
        }                                                                     \
    } while (0)


#if (NXT_DEBUG)

#define nxt_debug(task, ...)                                                  \
    do {                                                                      \
        nxt_log_t  *_log = (task)->log;                                       \
                                                                              \
        if (nxt_slow_path(_log->level == NXT_LOG_DEBUG || nxt_debug)) {       \
            _log->handler(NXT_LOG_DEBUG, _log, __VA_ARGS__);                  \
        }                                                                     \
    } while (0)


#define nxt_log_debug(_log, ...)                                              \
    do {                                                                      \
        nxt_log_t  *_log_ = (_log);                                           \
                                                                              \
        if (nxt_slow_path(_log_->level == NXT_LOG_DEBUG || nxt_debug)) {      \
            _log_->handler(NXT_LOG_DEBUG, _log_, __VA_ARGS__);                \
        }                                                                     \
    } while (0)


#define nxt_assert(c)                                                         \
    do {                                                                      \
        if (nxt_slow_path(!(c))) {                                            \
            nxt_thread_log_alert("%s:%d assertion failed: %s",                \
                                 __FILE__, __LINE__, #c);                     \
            nxt_abort();                                                      \
        }                                                                     \
    } while (0)

#else

#define nxt_debug(...)

#define nxt_log_debug(...)

#define nxt_assert(c)

#endif


#if (NXT_DEBUG_ALLOC)

#define nxt_debug_alloc(...)                                                  \
    nxt_thread_log_debug(__VA_ARGS__)

#else

#define nxt_debug_alloc(...)

#endif


#define nxt_main_log_alert(...)                                               \
    nxt_log_alert(&nxt_main_log, __VA_ARGS__)


#define nxt_main_log_error(level, ...)                                        \
    nxt_log_error(level, &nxt_main_log, __VA_ARGS__)


#define nxt_main_log_debug(...)                                               \
    nxt_log_debug(&nxt_main_log, __VA_ARGS__)


NXT_EXPORT extern nxt_uint_t  nxt_debug;
NXT_EXPORT extern nxt_uint_t  nxt_trace;
NXT_EXPORT extern nxt_log_t   nxt_main_log;
NXT_EXPORT extern nxt_str_t   nxt_log_levels[];


#endif /* _NXT_LOG_H_INCLUDED_ */


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_LOG_MODERATION_H_INCLUDED_
#define _NXT_LOG_MODERATION_H_INCLUDED_


typedef struct {
    uint32_t               level;
    uint32_t               limit;
    const char             *msg;
    nxt_thread_spinlock_t  lock;
    nxt_pid_t              pid;
    nxt_uint_t             count;
    nxt_time_t             last;
    nxt_timer_t            timer;
} nxt_log_moderation_t;


#define NXT_LOG_MODERATION  0, -1, 0, 0, NXT_TIMER


#define nxt_log_alert_moderate(_mod, _log, ...)                               \
    do {                                                                      \
        nxt_log_t  *_log_ = _log;                                             \
                                                                              \
        if (nxt_log_moderate_allow(_mod)) {                                   \
            _log_->handler(NXT_LOG_ALERT, _log_, __VA_ARGS__);                \
        }                                                                     \
    } while (0)


#define nxt_log_moderate(_mod, _level, _log, ...)                             \
    do {                                                                      \
        nxt_log_t  *_log_ = _log;                                             \
                                                                              \
        if (_log_->level >= (_level) && nxt_log_moderate_allow(_mod)) {       \
            _log_->handler(_level, _log_, __VA_ARGS__);                       \
        }                                                                     \
    } while (0)


nxt_bool_t nxt_log_moderate_allow(nxt_log_moderation_t *mod);


#endif /* _NXT_LOG_MODERATION_H_INCLUDED_ */

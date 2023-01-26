
/*
 * Copyright (C) Alejandro Colomar <alx@nginx.com>
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_LOG_HTTP_H_INCLUDED_
#define _NXT_LOG_HTTP_H_INCLUDED_


#include "nxt_main.h"

#include "nxt_clang.h"
#include "nxt_log.h"


typedef enum nxt_log_http_features_e  nxt_log_http_features_t;


#define nxt_log_http(task, r, level, cond, ...)                               \
    do {                                                                      \
        if (nxt_slow_path((cond) & (r)->log_ft)) {                            \
            nxt_log(task, level, __VA_ARGS__);                                \
        }                                                                     \
    } while (0)


#define nxt_debug_http(task, r, cond, ...)                                    \
    do {                                                                      \
        if (nxt_slow_path((cond) & (r)->log_ft)) {                            \
            nxt_debug(task, level, __VA_ARGS__);                              \
        }                                                                     \
    } while (0)


enum nxt_log_http_features_e {
    NXT_LOG_HTTP_ROUTE_SELECTION = 0x01,
};


#endif  /* _NXT_LOG_HTTP_H_INCLUDED_ */

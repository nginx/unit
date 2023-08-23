/*
 * Copyright (C) Alejandro Colomar
 * Copyright (C) NGINX, Inc.
 */

#ifndef NXT_HTTP_COMPRESS_H_INCLUDED_
#define NXT_HTTP_COMPRESS_H_INCLUDED_


#include "nxt_router.h"

#include <stdint.h>

#include "nxt_http.h"
#include "nxt_main.h"
#include "nxt_router.h"
#include "nxt_string.h"
#include "nxt_types.h"


struct nxt_http_compress_conf_s {
    nxt_str_t  encoding;

    nxt_int_t  (*handler)(nxt_task_t *task,
                          nxt_http_request_t *r,
                          nxt_http_compress_conf_t *conf);

    int8_t     level;
};


nxt_int_t nxt_http_compress_init(nxt_router_conf_t *rtcf,
    nxt_http_action_t *action, nxt_http_action_conf_t *acf);

nxt_int_t nxt_http_compress_append_field(nxt_task_t *task,
    nxt_http_request_t *r, nxt_str_t *field, nxt_str_t *value);


#endif  /* NXT_HTTP_COMPRESS_H_INCLUDED_ */

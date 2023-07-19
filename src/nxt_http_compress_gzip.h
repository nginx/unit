/*
 * Copyright (C) Alejandro Colomar
 * Copyright (C) NGINX, Inc.
 */

#ifndef NXT_HTTP_COMPRESS_GZIP_H_INCLUDED_
#define NXT_HTTP_COMPRESS_GZIP_H_INCLUDED_


#include "nxt_router.h"

#include "nxt_http.h"
#include "nxt_main.h"
#include "nxt_types.h"


nxt_int_t nxt_http_compress_gzip(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_compress_conf_t *conf);


#endif  /* NXT_HTTP_COMPRESS_GZIP_H_INCLUDED_ */

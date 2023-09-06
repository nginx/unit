/*
 * Copyright (C) Alejandro Colomar
 * Copyright (C) NGINX, Inc.
 */

#ifndef NXT_HTTP_COMPRESS_GZIP_H_INCLUDED_
#define NXT_HTTP_COMPRESS_GZIP_H_INCLUDED_


#include "nxt_auto_config.h"

#include "nxt_router.h"

#include "nxt_http.h"
#include "nxt_main.h"
#include "nxt_types.h"


#if defined(NXT_HAVE_ZLIB)
#define NXT_WITH_ZLIB  1
#else
#define NXT_WITH_ZLIB  0
#endif


nxt_int_t nxt_http_compress_gzip(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_compress_conf_t *conf);


#endif  /* NXT_HTTP_COMPRESS_GZIP_H_INCLUDED_ */

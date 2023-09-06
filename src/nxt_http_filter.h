/*
 * Copyright (C) Alejandro Colomar
 * Copyright (C) NGINX, Inc.
 */

#ifndef NXT_HTTP_FILTER_H_INCLUDED_
#define NXT_HTTP_FILTER_H_INCLUDED_


#include "nxt_router.h"

#include "nxt_auto_config.h"

#include <stddef.h>

#include "nxt_clang.h"
#include "nxt_errno.h"
#include "nxt_list.h"
#include "nxt_main.h"


typedef struct nxt_http_filter_handler_s  nxt_http_filter_handler_t;


struct nxt_http_filter_handler_s {
    nxt_work_handler_t              filter_handler;
    void                            *data;
};


nxt_inline nxt_int_t nxt_http_filter_handler_add(nxt_http_request_t *r,
    nxt_work_handler_t filter_handler, void *data);


nxt_inline nxt_int_t
nxt_http_filter_handler_add(nxt_http_request_t *r,
    nxt_work_handler_t filter_handler, void *data)
{
    nxt_http_filter_handler_t  *elem;

    elem = nxt_list_add(r->response_filters);
    if (nxt_slow_path(elem == NULL)) {
        return NXT_ERROR;
    }

    elem->filter_handler = filter_handler;
    elem->data = data;

    return NXT_OK;
}


#endif  /* NXT_HTTP_FILTER_H_INCLUDED_ */

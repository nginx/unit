/*
 * Copyright (C) Alejandro Colomar
 * Copyright (C) NGINX, Inc.
 */


#include "nxt_http_compress.h"

#include <stddef.h>

#include <nxt_unit_cdefs.h>

#include "nxt_clang.h"
#include "nxt_conf.h"
#include "nxt_errno.h"
#include "nxt_http.h"
#include "nxt_list.h"
#include "nxt_main.h"
#include "nxt_mp.h"
#include "nxt_router.h"
#include "nxt_string.h"
#include "nxt_types.h"


static nxt_conf_map_t  nxt_http_compress_conf[] = {
    {
        nxt_string("encoding"),
        NXT_CONF_MAP_STR,
        offsetof(nxt_http_compress_conf_t, encoding),
    },
};


nxt_int_t
nxt_http_compress_init(nxt_router_conf_t *rtcf, nxt_http_action_t *action,
    nxt_http_action_conf_t *acf)
{
    nxt_mp_t                  *mp;
    nxt_int_t                 ret;
    nxt_http_compress_conf_t  *conf;

    mp = rtcf->mem_pool;

    conf = nxt_mp_zget(mp, sizeof(nxt_http_compress_conf_t));
    if (nxt_slow_path(conf == NULL)) {
        return NXT_ERROR;
    }

    ret = nxt_conf_map_object(mp, acf->compress, nxt_http_compress_conf,
                              nxt_nitems(nxt_http_compress_conf), conf);
    if (nxt_slow_path(ret == NXT_ERROR)) {
        return NXT_ERROR;
    }

    if (0) {

    } else {
        return NXT_ERROR;
    }

    action->compress = conf;

    return NXT_OK;
}


nxt_int_t
nxt_http_compress_append_field(nxt_task_t *task, nxt_http_request_t *r,
    nxt_str_t *field, nxt_str_t *value)
{
    nxt_http_field_t  *f;

    f = nxt_list_add(r->resp.fields);
    if (nxt_slow_path(f == NULL)) {
        return NXT_ERROR;
    }

    f->hash = 0;
    f->skip = 0;
    f->hopbyhop = 0;

    f->name_length = field->length;
    f->value_length = value->length;
    f->name = field->start;
    f->value = value->start;

    return NXT_OK;
}

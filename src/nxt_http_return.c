
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


typedef struct {
    nxt_http_status_t  status;
    nxt_tstr_t         *location;
    nxt_str_t          encoded;
} nxt_http_return_conf_t;


typedef struct {
    nxt_str_t          location;
    nxt_str_t          encoded;
} nxt_http_return_ctx_t;


static nxt_http_action_t *nxt_http_return(nxt_task_t *task,
    nxt_http_request_t *r, nxt_http_action_t *action);
static nxt_int_t nxt_http_return_encode(nxt_mp_t *mp, nxt_str_t *encoded,
    const nxt_str_t *location);
static void nxt_http_return_send_ready(nxt_task_t *task, void *obj, void *data);
static void nxt_http_return_send_error(nxt_task_t *task, void *obj, void *data);


static const nxt_http_request_state_t  nxt_http_return_send_state;


nxt_int_t
nxt_http_return_init(nxt_router_conf_t *rtcf, nxt_http_action_t *action,
    nxt_http_action_conf_t *acf)
{
    nxt_mp_t                *mp;
    nxt_str_t               str;
    nxt_http_return_conf_t  *conf;

    mp = rtcf->mem_pool;

    conf = nxt_mp_zget(mp, sizeof(nxt_http_return_conf_t));
    if (nxt_slow_path(conf == NULL)) {
        return NXT_ERROR;
    }

    action->handler = nxt_http_return;
    action->u.conf = conf;

    conf->status = nxt_conf_get_number(acf->ret);

    if (acf->location == NULL) {
        return NXT_OK;
    }

    nxt_conf_get_string(acf->location, &str);

    conf->location = nxt_tstr_compile(rtcf->tstr_state, &str, 0);
    if (nxt_slow_path(conf->location == NULL)) {
        return NXT_ERROR;
    }

    if (nxt_tstr_is_const(conf->location)) {
        nxt_tstr_str(conf->location, &str);
        return nxt_http_return_encode(mp, &conf->encoded, &str);
    }

    return NXT_OK;
}


nxt_http_action_t *
nxt_http_return(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_action_t *action)
{
    nxt_int_t               ret;
    nxt_router_conf_t       *rtcf;
    nxt_http_return_ctx_t   *ctx;
    nxt_http_return_conf_t  *conf;

    conf = action->u.conf;

#if (NXT_DEBUG)
    nxt_str_t  loc;

    if (conf->location == NULL) {
        nxt_str_set(&loc, "");

    } else {
        nxt_tstr_str(conf->location, &loc);
    }

    nxt_debug(task, "http return: %d (loc: \"%V\")", conf->status, &loc);
#endif

    if (conf->status >= NXT_HTTP_BAD_REQUEST
        && conf->status <= NXT_HTTP_SERVER_ERROR_MAX)
    {
        nxt_http_request_error(task, r, conf->status);
        return NULL;
    }

    if (conf->location == NULL) {
        ctx = NULL;

    } else {
        ctx = nxt_mp_zget(r->mem_pool, sizeof(nxt_http_return_ctx_t));
        if (nxt_slow_path(ctx == NULL)) {
            goto fail;
        }
    }

    r->status = conf->status;
    r->resp.content_length_n = 0;

    if (ctx == NULL || nxt_tstr_is_const(conf->location)) {
        if (ctx != NULL) {
            ctx->encoded = conf->encoded;
        }

        nxt_http_return_send_ready(task, r, ctx);

    } else {
        rtcf = r->conf->socket_conf->router_conf;

        ret = nxt_tstr_query_init(&r->tstr_query, rtcf->tstr_state,
                                  &r->tstr_cache, r, r->mem_pool);
        if (nxt_slow_path(ret != NXT_OK)) {
            goto fail;
        }

        nxt_tstr_query(task, r->tstr_query, conf->location, &ctx->location);

        nxt_tstr_query_resolve(task, r->tstr_query, ctx,
                               nxt_http_return_send_ready,
                               nxt_http_return_send_error);
    }

    return NULL;

fail:

    nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
    return NULL;
}


static nxt_int_t
nxt_http_return_encode(nxt_mp_t *mp, nxt_str_t *encoded,
    const nxt_str_t *location)
{
    nxt_uint_t  encode;

    if (nxt_is_complex_uri_encoded(location->start, location->length)) {
        *encoded = *location;

        return NXT_OK;
    }

    encode = nxt_encode_complex_uri(NULL, location->start, location->length);
    encoded->length = location->length + encode * 2;

    encoded->start = nxt_mp_nget(mp, encoded->length);
    if (nxt_slow_path(encoded->start == NULL)) {
        return NXT_ERROR;
    }

    nxt_encode_complex_uri(encoded->start, location->start, location->length);

    return NXT_OK;
}


static void
nxt_http_return_send_ready(nxt_task_t *task, void *obj, void *data)
{
    nxt_int_t               ret;
    nxt_http_field_t        *field;
    nxt_http_request_t      *r;
    nxt_http_return_ctx_t   *ctx;

    r = obj;
    ctx = data;

    if (ctx != NULL) {
        if (ctx->location.length > 0) {
            ret = nxt_http_return_encode(r->mem_pool, &ctx->encoded,
                                         &ctx->location);
            if (nxt_slow_path(ret == NXT_ERROR)) {
                goto fail;
            }
        }

        field = nxt_list_zero_add(r->resp.fields);
        if (nxt_slow_path(field == NULL)) {
            goto fail;
        }

        nxt_http_field_name_set(field, "Location");

        field->value = ctx->encoded.start;
        field->value_length = ctx->encoded.length;
    }

    r->state = &nxt_http_return_send_state;

    nxt_http_request_header_send(task, r, NULL, NULL);

    return;

fail:

    nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
}


static void
nxt_http_return_send_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_request_t  *r;

    r = obj;

    nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
}


static const nxt_http_request_state_t  nxt_http_return_send_state
    nxt_aligned(64) =
{
    .error_handler = nxt_http_request_error_handler,
};

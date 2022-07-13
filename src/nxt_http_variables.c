
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


static nxt_int_t nxt_http_var_method(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);
static nxt_int_t nxt_http_var_request_uri(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);
static nxt_int_t nxt_http_var_uri(nxt_task_t *task, nxt_str_t *str, void *ctx,
    uint16_t field);
static nxt_int_t nxt_http_var_host(nxt_task_t *task, nxt_str_t *str, void *ctx,
    uint16_t field);
static nxt_int_t nxt_http_var_arg(nxt_task_t *task, nxt_str_t *str, void *ctx,
    uint16_t field);
static nxt_int_t nxt_http_var_header(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);
static nxt_int_t nxt_http_var_cookie(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);


static nxt_var_decl_t  nxt_http_vars[] = {
    {
        .name = nxt_string("method"),
        .handler = nxt_http_var_method,
    }, {
        .name = nxt_string("request_uri"),
        .handler = nxt_http_var_request_uri,
    }, {
        .name = nxt_string("uri"),
        .handler = nxt_http_var_uri,
    }, {
        .name = nxt_string("host"),
        .handler = nxt_http_var_host,
    }, {
        .name = nxt_string("arg"),
        .handler = nxt_http_var_arg,
        .field_hash = nxt_http_argument_hash,
    }, {
        .name = nxt_string("header"),
        .handler = nxt_http_var_header,
        .field_hash = nxt_http_header_hash,
    }, {
        .name = nxt_string("cookie"),
        .handler = nxt_http_var_cookie,
        .field_hash = nxt_http_cookie_hash,
    },
};


nxt_int_t
nxt_http_register_variables(void)
{
    return nxt_var_register(nxt_http_vars, nxt_nitems(nxt_http_vars));
}


static nxt_int_t
nxt_http_var_method(nxt_task_t *task, nxt_str_t *str, void *ctx, uint16_t field)
{
    nxt_http_request_t  *r;

    r = ctx;

    *str = *r->method;

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_request_uri(nxt_task_t *task, nxt_str_t *str, void *ctx,
    uint16_t field)
{
    nxt_http_request_t  *r;

    r = ctx;

    *str = r->target;

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_uri(nxt_task_t *task, nxt_str_t *str, void *ctx, uint16_t field)
{
    nxt_http_request_t  *r;

    r = ctx;

    *str = *r->path;

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_host(nxt_task_t *task, nxt_str_t *str, void *ctx, uint16_t field)
{
    nxt_http_request_t  *r;

    r = ctx;

    *str = r->host;

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_arg(nxt_task_t *task, nxt_str_t *str, void *ctx, uint16_t field)
{
    nxt_array_t            *args;
    nxt_var_field_t        *vf;
    nxt_router_conf_t      *rtcf;
    nxt_http_request_t     *r;
    nxt_http_name_value_t  *nv, *start;

    r = ctx;

    rtcf = r->conf->socket_conf->router_conf;

    vf = nxt_var_field_get(rtcf->var_fields, field);

    args = nxt_http_arguments_parse(r);
    if (nxt_slow_path(args == NULL)) {
        return NXT_ERROR;
    }

    start = args->elts;
    nv = start + args->nelts - 1;

    while (nv >= start) {

        if (vf->hash == nv->hash
            && vf->name.length == nv->name_length
            && nxt_memcmp(vf->name.start, nv->name, nv->name_length) == 0)
        {
            str->start = nv->value;
            str->length = nv->value_length;

            return NXT_OK;
        }

        nv--;
    }

    nxt_str_null(str);

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_header(nxt_task_t *task, nxt_str_t *str, void *ctx, uint16_t field)
{
    nxt_var_field_t     *vf;
    nxt_http_field_t    *f;
    nxt_router_conf_t   *rtcf;
    nxt_http_request_t  *r;

    r = ctx;

    rtcf = r->conf->socket_conf->router_conf;

    vf = nxt_var_field_get(rtcf->var_fields, field);

    nxt_list_each(f, r->fields) {

        if (vf->hash == f->hash
            && vf->name.length == f->name_length
            && nxt_strncasecmp(vf->name.start, f->name, f->name_length) == 0)
        {
            str->start = f->value;
            str->length = f->value_length;

            return NXT_OK;
        }

    } nxt_list_loop;

    nxt_str_null(str);

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_cookie(nxt_task_t *task, nxt_str_t *str, void *ctx, uint16_t field)
{
    nxt_array_t            *cookies;
    nxt_var_field_t        *vf;
    nxt_router_conf_t      *rtcf;
    nxt_http_request_t     *r;
    nxt_http_name_value_t  *nv, *end;

    r = ctx;

    rtcf = r->conf->socket_conf->router_conf;

    vf = nxt_var_field_get(rtcf->var_fields, field);

    cookies = nxt_http_cookies_parse(r);
    if (nxt_slow_path(cookies == NULL)) {
        return NXT_ERROR;
    }

    nv = cookies->elts;
    end = nv + cookies->nelts;

    while (nv < end) {

        if (vf->hash == nv->hash
            && vf->name.length == nv->name_length
            && nxt_memcmp(vf->name.start, nv->name, nv->name_length) == 0)
        {
            str->start = nv->value;
            str->length = nv->value_length;

            return NXT_OK;
        }

        nv++;
    }

    nxt_str_null(str);

    return NXT_OK;
}

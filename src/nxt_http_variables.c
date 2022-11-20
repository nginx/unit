
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


static nxt_int_t nxt_http_var_dollar(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);
static nxt_int_t nxt_http_var_request_time(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);
static nxt_int_t nxt_http_var_method(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);
static nxt_int_t nxt_http_var_request_uri(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);
static nxt_int_t nxt_http_var_uri(nxt_task_t *task, nxt_str_t *str, void *ctx,
    uint16_t field);
static nxt_int_t nxt_http_var_host(nxt_task_t *task, nxt_str_t *str, void *ctx,
    uint16_t field);
static nxt_int_t nxt_http_var_remote_addr(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);
static nxt_int_t nxt_http_var_time_local(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);
static u_char *nxt_http_log_date(u_char *buf, nxt_realtime_t *now,
    struct tm *tm, size_t size, const char *format);
static nxt_int_t nxt_http_var_request_line(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);
static nxt_int_t nxt_http_var_status(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);
static nxt_int_t nxt_http_var_body_bytes_sent(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);
static nxt_int_t nxt_http_var_referer(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);
static nxt_int_t nxt_http_var_user_agent(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);
static nxt_int_t nxt_http_var_arg(nxt_task_t *task, nxt_str_t *str, void *ctx,
    uint16_t field);
static nxt_int_t nxt_http_var_header(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);
static nxt_int_t nxt_http_var_cookie(nxt_task_t *task, nxt_str_t *str,
    void *ctx, uint16_t field);


static nxt_var_decl_t  nxt_http_vars[] = {
    {
        .name = nxt_string("dollar"),
        .handler = nxt_http_var_dollar,
    }, {
        .name = nxt_string("request_time"),
        .handler = nxt_http_var_request_time,
    }, {
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
        .name = nxt_string("remote_addr"),
        .handler = nxt_http_var_remote_addr,
    }, {
        .name = nxt_string("time_local"),
        .handler = nxt_http_var_time_local,
    }, {
        .name = nxt_string("request_line"),
        .handler = nxt_http_var_request_line,
    }, {
        .name = nxt_string("status"),
        .handler = nxt_http_var_status,
    }, {
        .name = nxt_string("body_bytes_sent"),
        .handler = nxt_http_var_body_bytes_sent,
    }, {
        .name = nxt_string("header_referer"),
        .handler = nxt_http_var_referer,
    }, {
        .name = nxt_string("header_user_agent"),
        .handler = nxt_http_var_user_agent,
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
nxt_http_var_dollar(nxt_task_t *task, nxt_str_t *str, void *ctx, uint16_t field)
{
    nxt_str_set(str, "$");

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_request_time(nxt_task_t *task, nxt_str_t *str, void *ctx,
    uint16_t field)
{
    u_char              *p;
    nxt_msec_t          ms;
    nxt_nsec_t          now;
    nxt_http_request_t  *r;

    r = ctx;

    now = nxt_thread_monotonic_time(task->thread);
    ms = (now - r->start_time) / 1000000;

    str->start = nxt_mp_nget(r->mem_pool, NXT_TIME_T_LEN + 4);
    if (nxt_slow_path(str->start == NULL)) {
        return NXT_ERROR;
    }

    p = nxt_sprintf(str->start, str->start + NXT_TIME_T_LEN, "%T.%03M",
                    (nxt_time_t) ms / 1000, ms % 1000);

    str->length = p - str->start;

    return NXT_OK;
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
nxt_http_var_remote_addr(nxt_task_t *task, nxt_str_t *str, void *ctx,
    uint16_t field)
{
    nxt_http_request_t  *r;

    r = ctx;

    str->length = r->remote->address_length;
    str->start = nxt_sockaddr_address(r->remote);

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_time_local(nxt_task_t *task, nxt_str_t *str, void *ctx,
    uint16_t field)
{
    nxt_http_request_t  *r;

    static nxt_time_string_t  date_cache = {
        (nxt_atomic_uint_t) -1,
        nxt_http_log_date,
        "%02d/%s/%4d:%02d:%02d:%02d %c%02d%02d",
        nxt_length("31/Dec/1986:19:40:00 +0300"),
        NXT_THREAD_TIME_LOCAL,
        NXT_THREAD_TIME_SEC,
    };

    r = ctx;

    str->length = date_cache.size;

    str->start = nxt_mp_nget(r->mem_pool, str->length);
    if (nxt_slow_path(str->start == NULL)) {
        return NXT_ERROR;
    }

    str->length = nxt_thread_time_string(task->thread, &date_cache, str->start)
                  - str->start;

    return NXT_OK;
}


static u_char *
nxt_http_log_date(u_char *buf, nxt_realtime_t *now, struct tm *tm,
    size_t size, const char *format)
{
    u_char  sign;
    time_t  gmtoff;

    static const char  *month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    gmtoff = nxt_timezone(tm) / 60;

    if (gmtoff < 0) {
        gmtoff = -gmtoff;
        sign = '-';

    } else {
        sign = '+';
    }

    return nxt_sprintf(buf, buf + size, format,
                       tm->tm_mday, month[tm->tm_mon], tm->tm_year + 1900,
                       tm->tm_hour, tm->tm_min, tm->tm_sec,
                       sign, gmtoff / 60, gmtoff % 60);
}


static nxt_int_t
nxt_http_var_request_line(nxt_task_t *task, nxt_str_t *str, void *ctx,
    uint16_t field)
{
    size_t              length;
    u_char              *p, *start;
    nxt_http_request_t  *r;

    r = ctx;

    length = r->method->length + 1 + r->target.length + 1 + r->version.length;

    start = nxt_mp_nget(r->mem_pool, length);
    if (nxt_slow_path(start == NULL)) {
        return NXT_ERROR;
    }

    p = start;

    if (r->method->length != 0) {
        p = nxt_cpymem(p, r->method->start, r->method->length);

        if (r->target.length != 0) {
            *p++ = ' ';
            p = nxt_cpymem(p, r->target.start, r->target.length);

            if (r->version.length != 0) {
                *p++ = ' ';
                p = nxt_cpymem(p, r->version.start, r->version.length);
            }
        }

    } else {
        *p++ = '-';
    }

    str->start = start;
    str->length = p - start;

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_body_bytes_sent(nxt_task_t *task, nxt_str_t *str, void *ctx,
    uint16_t field)
{
    nxt_off_t           bytes;
    nxt_http_request_t  *r;

    r = ctx;

    str->start = nxt_mp_nget(r->mem_pool, NXT_OFF_T_LEN);
    if (nxt_slow_path(str->start == NULL)) {
        return NXT_ERROR;
    }

    bytes = nxt_http_proto[r->protocol].body_bytes_sent(task, r->proto);

    str->length = nxt_sprintf(str->start, str->start + NXT_OFF_T_LEN, "%O",
                              bytes) - str->start;

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_status(nxt_task_t *task, nxt_str_t *str, void *ctx, uint16_t field)
{
    nxt_http_request_t  *r;

    r = ctx;

    str->start = nxt_mp_nget(r->mem_pool, 3);
    if (nxt_slow_path(str->start == NULL)) {
        return NXT_ERROR;
    }

    str->length = nxt_sprintf(str->start, str->start + 3, "%03d", r->status)
                  - str->start;

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_referer(nxt_task_t *task, nxt_str_t *str, void *ctx,
    uint16_t field)
{
    nxt_http_request_t  *r;

    r = ctx;

    if (r->referer != NULL) {
        str->start = r->referer->value;
        str->length = r->referer->value_length;

    } else {
        nxt_str_null(str);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_user_agent(nxt_task_t *task, nxt_str_t *str, void *ctx,
    uint16_t field)
{
    nxt_http_request_t  *r;

    r = ctx;

    if (r->user_agent != NULL) {
        str->start = r->user_agent->value;
        str->length = r->user_agent->value_length;

    } else {
        nxt_str_null(str);
    }

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

    vf = nxt_var_field_get(rtcf->tstr_state->var_fields, field);

    args = nxt_http_arguments_parse(r);
    if (nxt_slow_path(args == NULL)) {
        return NXT_ERROR;
    }

    start = args->elts;
    nv = start + args->nelts - 1;

    while (nv >= start) {

        if (vf->hash == nv->hash
            && vf->name.length == nv->name_length
            && memcmp(vf->name.start, nv->name, nv->name_length) == 0)
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

    vf = nxt_var_field_get(rtcf->tstr_state->var_fields, field);

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

    vf = nxt_var_field_get(rtcf->tstr_state->var_fields, field);

    cookies = nxt_http_cookies_parse(r);
    if (nxt_slow_path(cookies == NULL)) {
        return NXT_ERROR;
    }

    nv = cookies->elts;
    end = nv + cookies->nelts;

    while (nv < end) {

        if (vf->hash == nv->hash
            && vf->name.length == nv->name_length
            && memcmp(vf->name.start, nv->name, nv->name_length) == 0)
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

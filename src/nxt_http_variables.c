
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>
#include <nxt_h1proto.h>


static nxt_int_t nxt_http_var_dollar(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data);
static nxt_int_t nxt_http_var_request_time(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data);
static nxt_int_t nxt_http_var_method(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data);
static nxt_int_t nxt_http_var_request_uri(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data);
static nxt_int_t nxt_http_var_uri(nxt_task_t *task, nxt_str_t *str, void *ctx,
    void *data);
static nxt_int_t nxt_http_var_host(nxt_task_t *task, nxt_str_t *str, void *ctx,
    void *data);
static nxt_int_t nxt_http_var_remote_addr(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data);
static nxt_int_t nxt_http_var_time_local(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data);
static u_char *nxt_http_log_date(u_char *buf, nxt_realtime_t *now,
    struct tm *tm, size_t size, const char *format);
static nxt_int_t nxt_http_var_request_line(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data);
static nxt_int_t nxt_http_var_request_id(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data);
static nxt_int_t nxt_http_var_status(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data);
static nxt_int_t nxt_http_var_body_bytes_sent(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data);
static nxt_int_t nxt_http_var_referer(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data);
static nxt_int_t nxt_http_var_user_agent(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data);
static nxt_int_t nxt_http_var_response_connection(nxt_task_t *task,
    nxt_str_t *str, void *ctx, void *data);
static nxt_int_t nxt_http_var_response_content_length(nxt_task_t *task,
    nxt_str_t *str, void *ctx, void *data);
static nxt_int_t nxt_http_var_response_transfer_encoding(nxt_task_t *task,
    nxt_str_t *str, void *ctx, void *data);
static nxt_int_t nxt_http_var_arg(nxt_task_t *task, nxt_str_t *str, void *ctx,
    void *data);
static nxt_int_t nxt_http_var_header(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data);
static nxt_int_t nxt_http_var_cookie(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data);
static nxt_int_t nxt_http_var_response_header(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data);


static nxt_var_decl_t  nxt_http_vars[] = {
    {
        .name = nxt_string("dollar"),
        .handler = nxt_http_var_dollar,
        .cacheable = 1,
    }, {
        .name = nxt_string("request_time"),
        .handler = nxt_http_var_request_time,
        .cacheable = 1,
    }, {
        .name = nxt_string("method"),
        .handler = nxt_http_var_method,
        .cacheable = 1,
    }, {
        .name = nxt_string("request_uri"),
        .handler = nxt_http_var_request_uri,
        .cacheable = 1,
    }, {
        .name = nxt_string("uri"),
        .handler = nxt_http_var_uri,
        .cacheable = 0,
    }, {
        .name = nxt_string("host"),
        .handler = nxt_http_var_host,
        .cacheable = 1,
    }, {
        .name = nxt_string("remote_addr"),
        .handler = nxt_http_var_remote_addr,
        .cacheable = 1,
    }, {
        .name = nxt_string("time_local"),
        .handler = nxt_http_var_time_local,
        .cacheable = 1,
    }, {
        .name = nxt_string("request_line"),
        .handler = nxt_http_var_request_line,
        .cacheable = 1,
    }, {
        .name = nxt_string("request_id"),
        .handler = nxt_http_var_request_id,
        .cacheable = 1,
    }, {
        .name = nxt_string("status"),
        .handler = nxt_http_var_status,
        .cacheable = 1,
    }, {
        .name = nxt_string("body_bytes_sent"),
        .handler = nxt_http_var_body_bytes_sent,
        .cacheable = 1,
    }, {
        .name = nxt_string("header_referer"),
        .handler = nxt_http_var_referer,
        .cacheable = 1,
    }, {
        .name = nxt_string("response_header_connection"),
        .handler = nxt_http_var_response_connection,
        .cacheable = 1,
    }, {
        .name = nxt_string("response_header_content_length"),
        .handler = nxt_http_var_response_content_length,
        .cacheable = 1,
    }, {
        .name = nxt_string("response_header_transfer_encoding"),
        .handler = nxt_http_var_response_transfer_encoding,
        .cacheable = 1,
    }, {
        .name = nxt_string("header_user_agent"),
        .handler = nxt_http_var_user_agent,
        .cacheable = 1,
    },
};


nxt_int_t
nxt_http_register_variables(void)
{
    return nxt_var_register(nxt_http_vars, nxt_nitems(nxt_http_vars));
}


nxt_int_t
nxt_http_unknown_var_ref(nxt_mp_t *mp, nxt_var_ref_t *ref, nxt_str_t *name)
{
    int64_t    hash;
    nxt_str_t  str, *lower;

    if (nxt_str_start(name, "response_header_", 16)) {
        ref->handler = nxt_http_var_response_header;
        ref->cacheable = 0;

        str.start = name->start + 16;
        str.length = name->length - 16;

        if (str.length == 0) {
            return NXT_ERROR;
        }

        lower = nxt_str_alloc(mp, str.length);
        if (nxt_slow_path(lower == NULL)) {
            return NXT_ERROR;
        }

        nxt_memcpy_lowcase(lower->start, str.start, str.length);

        ref->data = lower;

        return NXT_OK;
    }

    if (nxt_str_start(name, "header_", 7)) {
        ref->handler = nxt_http_var_header;
        ref->cacheable = 1;

        str.start = name->start + 7;
        str.length = name->length - 7;

        if (str.length == 0) {
            return NXT_ERROR;
        }

        hash = nxt_http_header_hash(mp, &str);
        if (nxt_slow_path(hash == -1)) {
            return NXT_ERROR;
        }

    } else if (nxt_str_start(name, "arg_", 4)) {
        ref->handler = nxt_http_var_arg;
        ref->cacheable = 1;

        str.start = name->start + 4;
        str.length = name->length - 4;

        if (str.length == 0) {
            return NXT_ERROR;
        }

        hash = nxt_http_argument_hash(mp, &str);
        if (nxt_slow_path(hash == -1)) {
            return NXT_ERROR;
        }

    } else if (nxt_str_start(name, "cookie_", 7)) {
        ref->handler = nxt_http_var_cookie;
        ref->cacheable = 1;

        str.start = name->start + 7;
        str.length = name->length - 7;

        if (str.length == 0) {
            return NXT_ERROR;
        }

        hash = nxt_http_cookie_hash(mp, &str);
        if (nxt_slow_path(hash == -1)) {
            return NXT_ERROR;
        }

    } else {
        return NXT_ERROR;
    }

    ref->data = nxt_var_field_new(mp, &str, (uint32_t) hash);
    if (nxt_slow_path(ref->data == NULL)) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_dollar(nxt_task_t *task, nxt_str_t *str, void *ctx, void *data)
{
    nxt_str_set(str, "$");

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_request_time(nxt_task_t *task, nxt_str_t *str, void *ctx,
    void *data)
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
nxt_http_var_method(nxt_task_t *task, nxt_str_t *str, void *ctx, void *data)
{
    nxt_http_request_t  *r;

    r = ctx;

    *str = *r->method;

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_request_uri(nxt_task_t *task, nxt_str_t *str, void *ctx,
    void *data)
{
    nxt_http_request_t  *r;

    r = ctx;

    *str = r->target;

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_uri(nxt_task_t *task, nxt_str_t *str, void *ctx, void *data)
{
    nxt_http_request_t  *r;

    r = ctx;

    *str = *r->path;

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_host(nxt_task_t *task, nxt_str_t *str, void *ctx, void *data)
{
    nxt_http_request_t  *r;

    r = ctx;

    *str = r->host;

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_remote_addr(nxt_task_t *task, nxt_str_t *str, void *ctx,
    void *data)
{
    nxt_http_request_t  *r;

    r = ctx;

    str->length = r->remote->address_length;
    str->start = nxt_sockaddr_address(r->remote);

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_time_local(nxt_task_t *task, nxt_str_t *str, void *ctx, void *data)
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

    static const char * const  month[] = { "Jan", "Feb", "Mar", "Apr", "May",
                                           "Jun", "Jul", "Aug", "Sep", "Oct",
                                           "Nov", "Dec" };

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
    void *data)
{
    nxt_http_request_t  *r;

    r = ctx;

    *str = r->request_line;

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_request_id(nxt_task_t *task, nxt_str_t *str, void *ctx,
    void *data)
{
    nxt_random_t        *rand;
    nxt_http_request_t  *r;

    r = ctx;

    str->start = nxt_mp_nget(r->mem_pool, 32);
    if (nxt_slow_path(str->start == NULL)) {
        return NXT_ERROR;
    }

    str->length = 32;

    rand = &task->thread->random;

    (void) nxt_sprintf(str->start, str->start + 32, "%08xD%08xD%08xD%08xD",
                       nxt_random(rand), nxt_random(rand),
                       nxt_random(rand), nxt_random(rand));

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_body_bytes_sent(nxt_task_t *task, nxt_str_t *str, void *ctx,
    void *data)
{
    u_char              *p;
    nxt_off_t           bytes;
    nxt_http_request_t  *r;

    r = ctx;

    str->start = nxt_mp_nget(r->mem_pool, NXT_OFF_T_LEN);
    if (nxt_slow_path(str->start == NULL)) {
        return NXT_ERROR;
    }

    bytes = nxt_http_proto[r->protocol].body_bytes_sent(task, r->proto);

    p = nxt_sprintf(str->start, str->start + NXT_OFF_T_LEN, "%O", bytes);

    str->length = p - str->start;

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_status(nxt_task_t *task, nxt_str_t *str, void *ctx, void *data)
{
    nxt_http_request_t  *r;

    r = ctx;

    str->start = nxt_mp_nget(r->mem_pool, 3);
    if (nxt_slow_path(str->start == NULL)) {
        return NXT_ERROR;
    }

    (void) nxt_sprintf(str->start, str->start + 3, "%03d", r->status);

    str->length = 3;

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_referer(nxt_task_t *task, nxt_str_t *str, void *ctx, void *data)
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
nxt_http_var_user_agent(nxt_task_t *task, nxt_str_t *str, void *ctx, void *data)
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
nxt_http_var_response_connection(nxt_task_t *task, nxt_str_t *str, void *ctx,
    void *data)
{
    nxt_int_t           conn;
    nxt_bool_t          http11;
    nxt_h1proto_t       *h1p;
    nxt_http_request_t  *r;

    static const nxt_str_t  connection[3] = {
        nxt_string("close"),
        nxt_string("keep-alive"),
        nxt_string("Upgrade"),
    };

    r = ctx;
    h1p = r->proto.h1;

    conn = -1;

    if (r->websocket_handshake && r->status == NXT_HTTP_SWITCHING_PROTOCOLS) {
        conn = 2;

    } else {
        http11 = nxt_h1p_is_http11(h1p);

        if (http11 ^ h1p->keepalive) {
            conn = h1p->keepalive;
        }
    }

    if (conn >= 0) {
        *str = connection[conn];

    } else {
        nxt_str_null(str);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_response_content_length(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data)
{
    u_char              *p;
    nxt_http_request_t  *r;

    r = ctx;

    if (r->resp.content_length != NULL) {
        str->length = r->resp.content_length->value_length;
        str->start = r->resp.content_length->value;

        return NXT_OK;
    }

    if (r->resp.content_length_n >= 0) {
        str->start = nxt_mp_nget(r->mem_pool, NXT_OFF_T_LEN);
        if (str->start == NULL) {
            return NXT_ERROR;
        }

        p = nxt_sprintf(str->start, str->start + NXT_OFF_T_LEN,
                        "%O", r->resp.content_length_n);

        str->length = p - str->start;

        return NXT_OK;
    }

    nxt_str_null(str);

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_response_transfer_encoding(nxt_task_t *task, nxt_str_t *str,
    void *ctx, void *data)
{
    nxt_http_request_t  *r;

    r = ctx;

    if (r->proto.h1->chunked) {
        nxt_str_set(str, "chunked");

    } else {
        nxt_str_null(str);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_arg(nxt_task_t *task, nxt_str_t *str, void *ctx, void *data)
{
    nxt_array_t            *args;
    nxt_var_field_t        *vf;
    nxt_http_request_t     *r;
    nxt_http_name_value_t  *nv, *start;

    r = ctx;
    vf = data;

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
nxt_http_var_header(nxt_task_t *task, nxt_str_t *str, void *ctx, void *data)
{
    nxt_var_field_t     *vf;
    nxt_http_field_t    *f;
    nxt_http_request_t  *r;

    r = ctx;
    vf = data;

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
nxt_http_var_cookie(nxt_task_t *task, nxt_str_t *str, void *ctx, void *data)
{
    nxt_array_t            *cookies;
    nxt_var_field_t        *vf;
    nxt_http_request_t     *r;
    nxt_http_name_value_t  *nv, *end;

    r = ctx;
    vf = data;

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


static int
nxt_http_field_name_cmp(nxt_str_t *name, nxt_http_field_t *field)
{
    size_t  i;
    u_char  c1, c2;

    if (name->length != field->name_length) {
        return 1;
    }

    for (i = 0; i < name->length; i++) {
        c1 = name->start[i];
        c2 = field->name[i];

        if (c2 >= 'A' && c2 <= 'Z') {
            c2 |= 0x20;

        } else if (c2 == '-') {
            c2 = '_';
        }

        if (c1 != c2) {
            return 1;
        }
    }

    return 0;
}


static nxt_int_t
nxt_http_var_response_header(nxt_task_t *task, nxt_str_t *str, void *ctx,
    void *data)
{
    nxt_str_t           *name;
    nxt_http_field_t    *f;
    nxt_http_request_t  *r;

    r = ctx;
    name = data;

    nxt_list_each(f, r->resp.fields) {

        if (f->skip) {
            continue;
        }

        if (nxt_http_field_name_cmp(name, f) == 0) {
            str->start = f->value;
            str->length = f->value_length;

            return NXT_OK;
        }

    } nxt_list_loop;

    nxt_str_null(str);

    return NXT_OK;
}

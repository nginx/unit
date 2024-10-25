
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>

#if(NXT_HAVE_OTEL)
#include <nxt_otel.h>
#endif


static nxt_int_t nxt_http_validate_host(nxt_str_t *host, nxt_mp_t *mp);
static void nxt_http_request_start(nxt_task_t *task, void *obj, void *data);
static nxt_int_t nxt_http_request_forward(nxt_task_t *task,
    nxt_http_request_t *r, nxt_http_forward_t *forward);
static void nxt_http_request_forward_client_ip(nxt_http_request_t *r,
    nxt_http_forward_t *forward, nxt_array_t *fields);
static nxt_sockaddr_t *nxt_http_request_client_ip_sockaddr(
    nxt_http_request_t *r, u_char *start, size_t len);
static void nxt_http_request_forward_protocol(nxt_http_request_t *r,
    nxt_http_field_t *field);
static void nxt_http_request_ready(nxt_task_t *task, void *obj, void *data);
static void nxt_http_request_proto_info(nxt_task_t *task,
    nxt_http_request_t *r);
static void nxt_http_request_mem_buf_completion(nxt_task_t *task, void *obj,
    void *data);
static void nxt_http_request_done(nxt_task_t *task, void *obj, void *data);

static u_char *nxt_http_date_cache_handler(u_char *buf, nxt_realtime_t *now,
    struct tm *tm, size_t size, const char *format);

static nxt_http_name_value_t *nxt_http_argument(nxt_array_t *array,
    u_char *name, size_t name_length, uint32_t hash, u_char *start,
    const u_char *end);
static nxt_int_t nxt_http_cookie_parse(nxt_array_t *cookies, u_char *start,
    const u_char *end);
static nxt_http_name_value_t *nxt_http_cookie(nxt_array_t *array, u_char *name,
    size_t name_length, u_char *start, const u_char *end);


#define NXT_HTTP_COOKIE_HASH                                                  \
    (nxt_http_field_hash_end(                                                 \
     nxt_http_field_hash_char(                                                \
     nxt_http_field_hash_char(                                                \
     nxt_http_field_hash_char(                                                \
     nxt_http_field_hash_char(                                                \
     nxt_http_field_hash_char(                                                \
     nxt_http_field_hash_char(NXT_HTTP_FIELD_HASH_INIT,                       \
        'c'), 'o'), 'o'), 'k'), 'i'), 'e')) & 0xFFFF)


static const nxt_http_request_state_t  nxt_http_request_init_state;
static const nxt_http_request_state_t  nxt_http_request_body_state;


nxt_time_string_t  nxt_http_date_cache = {
    (nxt_atomic_uint_t) -1,
    nxt_http_date_cache_handler,
    NULL,
    NXT_HTTP_DATE_LEN,
    NXT_THREAD_TIME_GMT,
    NXT_THREAD_TIME_SEC,
};


nxt_int_t
nxt_http_init(nxt_task_t *task)
{
    nxt_int_t  ret;

    ret = nxt_h1p_init(task);

    if (ret != NXT_OK) {
        return ret;
    }

    return nxt_http_response_hash_init(task);
}


nxt_int_t
nxt_http_request_host(void *ctx, nxt_http_field_t *field, uintptr_t data)
{
    nxt_int_t           ret;
    nxt_str_t           host;
    nxt_http_request_t  *r;

    r = ctx;

    if (nxt_slow_path(r->host.start != NULL)) {
        return NXT_HTTP_BAD_REQUEST;
    }

    host.length = field->value_length;
    host.start = field->value;

    ret = nxt_http_validate_host(&host, r->mem_pool);

    if (nxt_fast_path(ret == NXT_OK)) {
        r->host = host;
    }

    return ret;
}


static nxt_int_t
nxt_http_validate_host(nxt_str_t *host, nxt_mp_t *mp)
{
    u_char      *h, ch;
    size_t      i, dot_pos, host_length;
    nxt_bool_t  lowcase;

    enum {
        sw_usual,
        sw_literal,
        sw_rest
    } state;

    dot_pos = host->length;
    host_length = host->length;

    h = host->start;

    lowcase = 0;
    state = sw_usual;

    for (i = 0; i < host->length; i++) {
        ch = h[i];

        if (ch > ']') {
            /* Short path. */
            continue;
        }

        switch (ch) {

        case '.':
            if (dot_pos == i - 1) {
                return NXT_HTTP_BAD_REQUEST;
            }

            dot_pos = i;
            break;

        case ':':
            if (state == sw_usual) {
                host_length = i;
                state = sw_rest;
            }

            break;

        case '[':
            if (i == 0) {
                state = sw_literal;
            }

            break;

        case ']':
            if (state == sw_literal) {
                host_length = i + 1;
                state = sw_rest;
            }

            break;

        case '/':
            return NXT_HTTP_BAD_REQUEST;

        default:
            if (ch >= 'A' && ch <= 'Z') {
                lowcase = 1;
            }

            break;
        }
    }

    if (dot_pos == host_length - 1) {
        host_length--;
    }

    host->length = host_length;

    if (lowcase) {
        host->start = nxt_mp_nget(mp, host_length);
        if (nxt_slow_path(host->start == NULL)) {
            return NXT_HTTP_INTERNAL_SERVER_ERROR;
        }

        nxt_memcpy_lowcase(host->start, h, host_length);
    }

    return NXT_OK;
}


nxt_int_t
nxt_http_request_field(void *ctx, nxt_http_field_t *field, uintptr_t offset)
{
    nxt_http_request_t  *r;

    r = ctx;

    nxt_value_at(nxt_http_field_t *, r, offset) = field;

    return NXT_OK;
}


nxt_int_t
nxt_http_request_content_length(void *ctx, nxt_http_field_t *field,
    uintptr_t data)
{
    nxt_off_t           n, max_body_size;
    nxt_http_request_t  *r;

    r = ctx;

    if (nxt_fast_path(r->content_length == NULL)) {
        r->content_length = field;

        n = nxt_off_t_parse(field->value, field->value_length);

        if (nxt_fast_path(n >= 0)) {
            r->content_length_n = n;

            max_body_size = r->conf->socket_conf->max_body_size;

            if (nxt_slow_path(n > max_body_size)) {
                return NXT_HTTP_PAYLOAD_TOO_LARGE;
            }

            return NXT_OK;
        }
    }

    return NXT_HTTP_BAD_REQUEST;
}


nxt_http_request_t *
nxt_http_request_create(nxt_task_t *task)
{
    nxt_mp_t            *mp;
    nxt_buf_t           *last;
    nxt_http_request_t  *r;

    mp = nxt_mp_create(4096, 128, 512, 32);
    if (nxt_slow_path(mp == NULL)) {
        return NULL;
    }

    r = nxt_mp_zget(mp, sizeof(nxt_http_request_t));
    if (nxt_slow_path(r == NULL)) {
        goto fail;
    }

    r->resp.fields = nxt_list_create(mp, 8, sizeof(nxt_http_field_t));
    if (nxt_slow_path(r->resp.fields == NULL)) {
        goto fail;
    }

    last = nxt_mp_zget(mp, NXT_BUF_SYNC_SIZE);
    if (nxt_slow_path(last == NULL)) {
        goto fail;
    }

    nxt_buf_set_sync(last);
    nxt_buf_set_last(last);
    last->completion_handler = nxt_http_request_done;
    last->parent = r;
    r->last = last;

    r->mem_pool = mp;
    r->content_length_n = -1;
    r->resp.content_length_n = -1;
    r->state = &nxt_http_request_init_state;

    r->start_time = nxt_thread_monotonic_time(task->thread);

    task->thread->engine->requests_cnt++;

    r->tstr_cache.var.pool = mp;
#if (NXT_HAVE_OTEL)
    if (nxt_otel_rs_is_init()) {
        r->otel = nxt_mp_zget(r->mem_pool, sizeof(nxt_otel_state_t));
        if (r->otel == NULL) {
            goto fail;
        }
        r->otel->status = NXT_OTEL_INIT_STATE;
    }
#endif
    return r;

fail:

    nxt_mp_release(mp);

    return NULL;
}


static const nxt_http_request_state_t  nxt_http_request_init_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_http_request_start,
    .error_handler = nxt_http_request_close_handler,
};


static void
nxt_http_request_start(nxt_task_t *task, void *obj, void *data)
{
    nxt_int_t           ret;
    nxt_socket_conf_t   *skcf;
    nxt_http_request_t  *r;

    r = obj;

#if (NXT_HAVE_OTEL)
    nxt_otel_test_and_call_state(task, r);
#endif

    r->state = &nxt_http_request_body_state;

    skcf = r->conf->socket_conf;

    if (skcf->forwarded != NULL) {
        ret = nxt_http_request_forward(task, r, skcf->forwarded);
        if (nxt_slow_path(ret != NXT_OK)) {
            goto fail;
        }
    }

    if (skcf->client_ip != NULL) {
        ret = nxt_http_request_forward(task, r, skcf->client_ip);
        if (nxt_slow_path(ret != NXT_OK)) {
            goto fail;
        }
    }

    nxt_http_request_read_body(task, r);

    return;

fail:
    nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
}


static nxt_int_t
nxt_http_request_forward(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_forward_t *forward)
{
    nxt_int_t                  ret;
    nxt_array_t                *client_ip_fields;
    nxt_http_field_t           *f, **fields, *protocol_field;
    nxt_http_forward_header_t  *client_ip, *protocol;

    ret = nxt_http_route_addr_rule(r, forward->source, r->remote);
    if (ret <= 0) {
        return NXT_OK;
    }

    client_ip = &forward->client_ip;
    protocol = &forward->protocol;

    if (client_ip->header != NULL) {
        client_ip_fields = nxt_array_create(r->mem_pool, 1,
                                            sizeof(nxt_http_field_t *));
        if (nxt_slow_path(client_ip_fields == NULL)) {
            return NXT_ERROR;
        }

    } else {
        client_ip_fields = NULL;
    }

    protocol_field = NULL;

    nxt_list_each(f, r->fields) {
        if (client_ip_fields != NULL
            && f->hash == client_ip->header_hash
            && f->value_length > 0
            && f->name_length == client_ip->header->length
            && nxt_memcasecmp(f->name, client_ip->header->start,
                              client_ip->header->length) == 0)
        {
            fields = nxt_array_add(client_ip_fields);
            if (nxt_slow_path(fields == NULL)) {
                return NXT_ERROR;
            }

            *fields = f;
        }

        if (protocol->header != NULL
            && protocol_field == NULL
            && f->hash == protocol->header_hash
            && f->value_length > 0
            && f->name_length == protocol->header->length
            && nxt_memcasecmp(f->name, protocol->header->start,
                              protocol->header->length) == 0)
        {
            protocol_field = f;
        }
    } nxt_list_loop;

    if (client_ip_fields != NULL) {
        nxt_http_request_forward_client_ip(r, forward, client_ip_fields);
    }

    if (protocol_field != NULL) {
        nxt_http_request_forward_protocol(r, protocol_field);
    }

    return NXT_OK;
}


static void
nxt_http_request_forward_client_ip(nxt_http_request_t *r,
    nxt_http_forward_t *forward, nxt_array_t *fields)
{
    u_char            *start, *p;
    nxt_int_t         ret, i, len;
    nxt_sockaddr_t    *sa, *prev_sa;
    nxt_http_field_t  **f;

    prev_sa = r->remote;
    f = (nxt_http_field_t **) fields->elts;

    i = fields->nelts;

    while (i-- > 0) {
        start = f[i]->value;
        len = f[i]->value_length;

        do {
            for (p = start + len - 1; p > start; p--, len--) {
                if (*p != ' ' && *p != ',') {
                    break;
                }
            }

            for (/* void */; p > start; p--) {
                if (*p == ' ' || *p == ',') {
                    p++;
                    break;
                }
            }

            sa = nxt_http_request_client_ip_sockaddr(r, p, len - (p - start));
            if (nxt_slow_path(sa == NULL)) {
                if (prev_sa != NULL) {
                    r->remote = prev_sa;
                }

                return;
            }

            if (!forward->recursive) {
                r->remote = sa;
                return;
            }

            ret = nxt_http_route_addr_rule(r, forward->source, sa);
            if (ret <= 0 || (i == 0 && p == start)) {
                r->remote = sa;
                return;
            }

            prev_sa = sa;
            len = p - 1 - start;

        } while (len > 0);
    }
}


static nxt_sockaddr_t *
nxt_http_request_client_ip_sockaddr(nxt_http_request_t *r, u_char *start,
    size_t len)
{
    nxt_str_t       addr;
    nxt_sockaddr_t  *sa;

    addr.start = start;
    addr.length = len;

    sa = nxt_sockaddr_parse_optport(r->mem_pool, &addr);
    if (nxt_slow_path(sa == NULL)) {
        return NULL;
    }

    switch (sa->u.sockaddr.sa_family) {
        case AF_INET:
            if (sa->u.sockaddr_in.sin_addr.s_addr == INADDR_ANY) {
                return NULL;
            }

            break;

#if (NXT_INET6)
        case AF_INET6:
            if (IN6_IS_ADDR_UNSPECIFIED(&sa->u.sockaddr_in6.sin6_addr)) {
                return NULL;
            }

            break;
#endif /* NXT_INET6 */

        default:
            return NULL;
    }

    return sa;
}


static void
nxt_http_request_forward_protocol(nxt_http_request_t *r,
    nxt_http_field_t *field)
{
    if (field->value_length == 4) {
        if (nxt_memcasecmp(field->value, "http", 4) == 0) {
            r->tls = 0;
        }

    } else if (field->value_length == 5) {
        if (nxt_memcasecmp(field->value, "https", 5) == 0) {
            r->tls = 1;
        }

    } else if (field->value_length == 2) {
        if (nxt_memcasecmp(field->value, "on", 2) == 0) {
            r->tls = 1;
        }
    }
}


static const nxt_http_request_state_t  nxt_http_request_body_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_http_request_ready,
    .error_handler = nxt_http_request_close_handler,
};


static nxt_int_t
nxt_http_request_chunked_transform(nxt_http_request_t *r)
{
    size_t            size;
    u_char            *p, *end;
    nxt_http_field_t  *f;

    r->chunked_field->skip = 1;

    size = r->body->file_end;

    f = nxt_list_zero_add(r->fields);
    if (nxt_slow_path(f == NULL)) {
        return NXT_ERROR;
    }

    nxt_http_field_name_set(f, "Content-Length");

    p = nxt_mp_nget(r->mem_pool, NXT_OFF_T_LEN);
    if (nxt_slow_path(p == NULL)) {
        return NXT_ERROR;
    }

    f->value = p;
    end = nxt_sprintf(p, p + NXT_OFF_T_LEN, "%uz", size);
    f->value_length = end - p;

    r->content_length = f;
    r->content_length_n = size;

    return NXT_OK;
}


static void
nxt_http_request_ready(nxt_task_t *task, void *obj, void *data)
{
    nxt_int_t           ret;
    nxt_http_action_t   *action;
    nxt_http_request_t  *r;

    r = obj;
    action = r->conf->socket_conf->action;

#if (NXT_HAVE_OTEL)
    nxt_otel_test_and_call_state(task, r);
#endif

    if (r->chunked) {
        ret = nxt_http_request_chunked_transform(r);
        if (nxt_slow_path(ret != NXT_OK)) {
            nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    nxt_http_request_action(task, r, action);
}


void
nxt_http_request_action(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_action_t *action)
{
    nxt_int_t  ret;

    if (nxt_fast_path(action != NULL)) {

        do {
            ret = nxt_http_rewrite(task, r);
            if (nxt_slow_path(ret != NXT_OK)) {
                break;
            }

            action = action->handler(task, r, action);

            if (action == NULL) {
                return;
            }

            if (action == NXT_HTTP_ACTION_ERROR) {
                break;
            }

        } while (r->pass_count++ < 255);
    }

    nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
}


nxt_http_action_t *
nxt_http_application_handler(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_action_t *action)
{
    nxt_debug(task, "http application handler");

    /*
     * TODO: need an application flag to get local address
     * required by "SERVER_ADDR" in Pyhton and PHP. Not used in Go.
     */
    nxt_http_request_proto_info(task, r);

    if (r->host.length != 0) {
        r->server_name = r->host;

    } else {
        nxt_str_set(&r->server_name, "localhost");
    }

    nxt_router_process_http_request(task, r, action);

    return NULL;
}


static void
nxt_http_request_proto_info(nxt_task_t *task, nxt_http_request_t *r)
{
    if (nxt_fast_path(r->proto.any != NULL)) {
        nxt_http_proto[r->protocol].local_addr(task, r);
    }
}


void
nxt_http_request_read_body(nxt_task_t *task, nxt_http_request_t *r)
{
    if (nxt_fast_path(r->proto.any != NULL)) {
        nxt_http_proto[r->protocol].body_read(task, r);
    }
}


void
nxt_http_request_header_send(nxt_task_t *task, nxt_http_request_t *r,
    nxt_work_handler_t body_handler, void *data)
{
    u_char             *p, *end, *server_string;
    nxt_int_t          ret;
    nxt_http_field_t   *server, *date, *content_length;
    nxt_socket_conf_t  *skcf;

    ret = nxt_http_set_headers(r);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    /*
     * TODO: "Server", "Date", and "Content-Length" processing should be moved
     * to the last header filter.
     */

    server = nxt_list_zero_add(r->resp.fields);
    if (nxt_slow_path(server == NULL)) {
        goto fail;
    }

    skcf = r->conf->socket_conf;
    server_string = (u_char *) (skcf->server_version ? NXT_SERVER : NXT_NAME);

    nxt_http_field_name_set(server, "Server");
    server->value = server_string;
    server->value_length = nxt_strlen(server_string);

    if (r->resp.date == NULL) {
        date = nxt_list_zero_add(r->resp.fields);
        if (nxt_slow_path(date == NULL)) {
            goto fail;
        }

        nxt_http_field_name_set(date, "Date");

        p = nxt_mp_nget(r->mem_pool, nxt_http_date_cache.size);
        if (nxt_slow_path(p == NULL)) {
            goto fail;
        }

        (void) nxt_thread_time_string(task->thread, &nxt_http_date_cache, p);

        date->value = p;
        date->value_length = nxt_http_date_cache.size;

        r->resp.date = date;
    }

    if (r->resp.content_length_n != -1
        && (r->resp.content_length == NULL || r->resp.content_length->skip))
    {
        content_length = nxt_list_zero_add(r->resp.fields);
        if (nxt_slow_path(content_length == NULL)) {
            goto fail;
        }

        nxt_http_field_name_set(content_length, "Content-Length");

        p = nxt_mp_nget(r->mem_pool, NXT_OFF_T_LEN);
        if (nxt_slow_path(p == NULL)) {
            goto fail;
        }

        content_length->value = p;
        end = nxt_sprintf(p, p + NXT_OFF_T_LEN, "%O", r->resp.content_length_n);
        content_length->value_length = end - p;

        r->resp.content_length = content_length;
    }

    if (nxt_fast_path(r->proto.any != NULL)) {
        nxt_http_proto[r->protocol].header_send(task, r, body_handler, data);
    }

    return;

fail:

    nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
}


void
nxt_http_request_ws_frame_start(nxt_task_t *task, nxt_http_request_t *r,
    nxt_buf_t *ws_frame)
{
    if (r->proto.any != NULL) {
        nxt_http_proto[r->protocol].ws_frame_start(task, r, ws_frame);
    }
}


void
nxt_http_request_send(nxt_task_t *task, nxt_http_request_t *r, nxt_buf_t *out)
{
    if (nxt_fast_path(r->proto.any != NULL)) {
        nxt_http_proto[r->protocol].send(task, r, out);
    }
}


nxt_buf_t *
nxt_http_buf_mem(nxt_task_t *task, nxt_http_request_t *r, size_t size)
{
    nxt_buf_t  *b;

    b = nxt_buf_mem_alloc(r->mem_pool, size, 0);
    if (nxt_fast_path(b != NULL)) {
        b->completion_handler = nxt_http_request_mem_buf_completion;
        b->parent = r;
        nxt_mp_retain(r->mem_pool);

    } else {
        nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
    }

    return b;
}


static void
nxt_http_request_mem_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t           *b, *next;
    nxt_http_request_t  *r;

    b = obj;
    r = data;

    do {
        next = b->next;

        nxt_mp_free(r->mem_pool, b);
        nxt_mp_release(r->mem_pool);

        b = next;
    } while (b != NULL);
}


nxt_buf_t *
nxt_http_buf_last(nxt_http_request_t *r)
{
    nxt_buf_t  *last;

    last = r->last;
    r->last = NULL;

    return last;
}


static void
nxt_http_request_done(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_request_t  *r;

    r = data;

    nxt_debug(task, "http request done");

    nxt_http_request_close_handler(task, r, r->proto.any);
}


void
nxt_http_request_error_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_proto_t    proto;
    nxt_http_request_t  *r;

    r = obj;
    proto.any = data;

    nxt_debug(task, "http request error handler");

    r->error = 1;

    if (nxt_fast_path(proto.any != NULL)) {
        nxt_http_proto[r->protocol].discard(task, r, nxt_http_buf_last(r));
    }
}


void
nxt_http_request_close_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_proto_t         proto;
    nxt_router_conf_t        *rtcf;
    nxt_http_request_t       *r;
    nxt_http_protocol_t      protocol;
    nxt_socket_conf_joint_t  *conf;
    nxt_router_access_log_t  *access_log;

    r = obj;
    proto.any = data;

    conf = r->conf;
    rtcf = conf->socket_conf->router_conf;

    if (!r->logged) {
        r->logged = 1;

        if (rtcf->access_log != NULL) {
            access_log = rtcf->access_log;

            if (nxt_http_cond_value(task, r, &rtcf->log_cond)) {
                access_log->handler(task, r, access_log, rtcf->log_format);
                return;
            }
        }
    }

    nxt_debug(task, "http request close handler");

    r->proto.any = NULL;

    if (r->body != NULL && nxt_buf_is_file(r->body)
        && r->body->file->fd != -1)
    {
        nxt_fd_close(r->body->file->fd);

        r->body->file->fd = -1;
    }

    if (r->tstr_query != NULL) {
        nxt_tstr_query_release(r->tstr_query);
    }

    if (nxt_fast_path(proto.any != NULL)) {
        protocol = r->protocol;

        nxt_http_proto[protocol].close(task, proto, conf);

        nxt_mp_release(r->mem_pool);
    }
}


static u_char *
nxt_http_date_cache_handler(u_char *buf, nxt_realtime_t *now, struct tm *tm,
    size_t size, const char *format)
{
    return nxt_http_date(buf, tm);
}


nxt_array_t *
nxt_http_arguments_parse(nxt_http_request_t *r)
{
    size_t                 name_length;
    u_char                 *p, *dst, *dst_start, *start, *end, *name;
    uint8_t                d0, d1;
    uint32_t               hash;
    nxt_array_t            *args;
    nxt_http_name_value_t  *nv;

    if (r->arguments != NULL) {
        return r->arguments;
    }

    args = nxt_array_create(r->mem_pool, 2, sizeof(nxt_http_name_value_t));
    if (nxt_slow_path(args == NULL)) {
        return NULL;
    }

    if (nxt_slow_path(r->args->start == NULL)) {
        goto end;
    }

    hash = NXT_HTTP_FIELD_HASH_INIT;
    name = NULL;
    name_length = 0;

    dst_start = nxt_mp_nget(r->mem_pool, r->args->length);
    if (nxt_slow_path(dst_start == NULL)) {
        return NULL;
    }

    r->args_decoded.start = dst_start;

    start = r->args->start;
    end = start + r->args->length;

    for (p = start, dst = dst_start; p < end; p++, dst++) {
        *dst = *p;

        switch (*p) {
        case '=':
            if (name == NULL) {
                name_length = dst - dst_start;
                name = dst_start;
                dst_start = dst + 1;
            }

            continue;

        case '&':
            if (name_length != 0 || dst != dst_start) {
                nv = nxt_http_argument(args, name, name_length, hash, dst_start,
                                       dst);
                if (nxt_slow_path(nv == NULL)) {
                    return NULL;
                }
            }

            hash = NXT_HTTP_FIELD_HASH_INIT;
            name_length = 0;
            name = NULL;
            dst_start = dst + 1;

            continue;

        case '+':
            *dst = ' ';

            break;

        case '%':
            if (nxt_slow_path(end - p <= 2)) {
                break;
            }

            d0 = nxt_hex2int[p[1]];
            d1 = nxt_hex2int[p[2]];

            if (nxt_slow_path((d0 | d1) >= 16)) {
                break;
            }

            p += 2;
            *dst = (d0 << 4) + d1;

            break;
        }

        if (name == NULL) {
            hash = nxt_http_field_hash_char(hash, *dst);
        }
    }

    r->args_decoded.length = dst - r->args_decoded.start;

    if (name_length != 0 || dst != dst_start) {
        nv = nxt_http_argument(args, name, name_length, hash, dst_start, dst);
        if (nxt_slow_path(nv == NULL)) {
            return NULL;
        }
    }

end:

    r->arguments = args;

    return args;
}


static nxt_http_name_value_t *
nxt_http_argument(nxt_array_t *array, u_char *name, size_t name_length,
    uint32_t hash, u_char *start, const u_char *end)
{
    size_t                 length;
    nxt_http_name_value_t  *nv;

    nv = nxt_array_add(array);
    if (nxt_slow_path(nv == NULL)) {
        return NULL;
    }

    nv->hash = nxt_http_field_hash_end(hash) & 0xFFFF;

    length = end - start;

    if (name == NULL) {
        name_length = length;
        name = start;
        length = 0;
    }

    nv->name_length = name_length;
    nv->value_length = length;
    nv->name = name;
    nv->value = start;

    return nv;
}


nxt_array_t *
nxt_http_cookies_parse(nxt_http_request_t *r)
{
    nxt_int_t         ret;
    nxt_array_t       *cookies;
    nxt_http_field_t  *f;

    if (r->cookies != NULL) {
        return r->cookies;
    }

    cookies = nxt_array_create(r->mem_pool, 2, sizeof(nxt_http_name_value_t));
    if (nxt_slow_path(cookies == NULL)) {
        return NULL;
    }

    nxt_list_each(f, r->fields) {

        if (f->hash != NXT_HTTP_COOKIE_HASH
            || f->name_length != 6
            || nxt_strncasecmp(f->name, (u_char *) "Cookie", 6) != 0)
        {
            continue;
        }

        ret = nxt_http_cookie_parse(cookies, f->value,
                                    f->value + f->value_length);
        if (ret != NXT_OK) {
            return NULL;
        }

    } nxt_list_loop;

    r->cookies = cookies;

    return cookies;
}


static nxt_int_t
nxt_http_cookie_parse(nxt_array_t *cookies, u_char *start, const u_char *end)
{
    size_t                 name_length;
    u_char                 c, *p, *name;
    nxt_http_name_value_t  *nv;

    name = NULL;
    name_length = 0;

    for (p = start; p < end; p++) {
        c = *p;

        if (c == '=' && name == NULL) {
            while (start[0] == ' ') { start++; }

            name_length = p - start;
            name = start;

            start = p + 1;

        } else if (c == ';') {
            if (name != NULL) {
                nv = nxt_http_cookie(cookies, name, name_length, start, p);
                if (nxt_slow_path(nv == NULL)) {
                    return NXT_ERROR;
                }
            }

            name = NULL;
            start = p + 1;
         }
    }

    if (name != NULL) {
        nv = nxt_http_cookie(cookies, name, name_length, start, p);
        if (nxt_slow_path(nv == NULL)) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


static nxt_http_name_value_t *
nxt_http_cookie(nxt_array_t *array, u_char *name, size_t name_length,
    u_char *start, const u_char *end)
{
    u_char                 c, *p;
    uint32_t               hash;
    nxt_http_name_value_t  *nv;

    nv = nxt_array_add(array);
    if (nxt_slow_path(nv == NULL)) {
        return NULL;
    }

    nv->name_length = name_length;
    nv->name = name;

    hash = NXT_HTTP_FIELD_HASH_INIT;

    for (p = name; p < name + name_length; p++) {
        c = *p;
        hash = nxt_http_field_hash_char(hash, c);
    }

    nv->hash = nxt_http_field_hash_end(hash) & 0xFFFF;

    while (start < end && end[-1] == ' ') { end--; }

    nv->value_length = end - start;
    nv->value = start;

    return nv;
}


int64_t
nxt_http_field_hash(nxt_mp_t *mp, nxt_str_t *name, nxt_bool_t case_sensitive,
    uint8_t encoding)
{
    u_char      c, *p, *src, *start, *end, plus;
    uint8_t     d0, d1;
    uint32_t    hash;
    nxt_str_t   str;
    nxt_uint_t  i;

    str.length = name->length;

    str.start = nxt_mp_nget(mp, str.length);
    if (nxt_slow_path(str.start == NULL)) {
        return -1;
    }

    p = str.start;

    hash = NXT_HTTP_FIELD_HASH_INIT;

    if (encoding == NXT_HTTP_URI_ENCODING_NONE) {
        for (i = 0; i < name->length; i++) {
            c = name->start[i];
            *p++ = c;

            c = case_sensitive ? c : nxt_lowcase(c);
            hash = nxt_http_field_hash_char(hash, c);
        }

        goto end;
    }

    plus = (encoding == NXT_HTTP_URI_ENCODING_PLUS) ? ' ' : '+';

    start = name->start;
    end = start + name->length;

    for (src = start; src < end; src++) {
        c = *src;

        switch (c) {
        case '%':
            if (nxt_slow_path(end - src <= 2)) {
                return -1;
            }

            d0 = nxt_hex2int[src[1]];
            d1 = nxt_hex2int[src[2]];
            src += 2;

            if (nxt_slow_path((d0 | d1) >= 16)) {
                return -1;
            }

            c = (d0 << 4) + d1;
            *p++ = c;
            break;

        case '+':
            c = plus;
            *p++ = c;
            break;

        default:
            *p++ = c;
            break;
        }

        c = case_sensitive ? c : nxt_lowcase(c);
        hash = nxt_http_field_hash_char(hash, c);
    }

    str.length = p - str.start;

end:

    *name = str;

    return nxt_http_field_hash_end(hash) & 0xFFFF;
}


int64_t
nxt_http_argument_hash(nxt_mp_t *mp, nxt_str_t *name)
{
    return nxt_http_field_hash(mp, name, 1, NXT_HTTP_URI_ENCODING_PLUS);
}


int64_t
nxt_http_header_hash(nxt_mp_t *mp, nxt_str_t *name)
{
    u_char     c, *p;
    uint32_t   i, hash;
    nxt_str_t  str;

    str.length = name->length;

    str.start = nxt_mp_nget(mp, str.length);
    if (nxt_slow_path(str.start == NULL)) {
        return -1;
    }

    p = str.start;
    hash = NXT_HTTP_FIELD_HASH_INIT;

    for (i = 0; i < name->length; i++) {
        c = name->start[i];

        if (c >= 'A' && c <= 'Z') {
            *p = c | 0x20;

        } else if (c == '_') {
            *p = '-';

        } else {
            *p = c;
        }

        hash = nxt_http_field_hash_char(hash, *p);
        p++;
    }

    *name = str;

    return nxt_http_field_hash_end(hash) & 0xFFFF;
}


int64_t
nxt_http_cookie_hash(nxt_mp_t *mp, nxt_str_t *name)
{
    return nxt_http_field_hash(mp, name, 1, NXT_HTTP_URI_ENCODING_NONE);
}


int
nxt_http_cond_value(nxt_task_t *task, nxt_http_request_t *r,
    nxt_tstr_cond_t *cond)
{
    nxt_int_t          ret;
    nxt_str_t          str;
    nxt_bool_t         expr;
    nxt_router_conf_t  *rtcf;

    rtcf = r->conf->socket_conf->router_conf;

    expr = 1;

    if (cond->expr != NULL) {

        if (nxt_tstr_is_const(cond->expr)) {
            nxt_tstr_str(cond->expr, &str);

        } else {
            ret = nxt_tstr_query_init(&r->tstr_query, rtcf->tstr_state,
                                      &r->tstr_cache, r, r->mem_pool);
            if (nxt_slow_path(ret != NXT_OK)) {
                return -1;
            }

            ret = nxt_tstr_query(task, r->tstr_query, cond->expr, &str);
            if (nxt_slow_path(ret != NXT_OK)) {
                return -1;
            }
        }

        if (str.length == 0
            || nxt_str_eq(&str, "0", 1)
            || nxt_str_eq(&str, "false", 5)
            || nxt_str_eq(&str, "null", 4)
            || nxt_str_eq(&str, "undefined", 9))
        {
            expr = 0;
        }
    }

    return cond->negate ^ expr;
}

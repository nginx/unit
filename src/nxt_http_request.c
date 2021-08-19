
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


static nxt_int_t nxt_http_validate_host(nxt_str_t *host, nxt_mp_t *mp);
static void nxt_http_request_start(nxt_task_t *task, void *obj, void *data);
static nxt_int_t nxt_http_request_client_ip(nxt_task_t *task,
    nxt_http_request_t *r);
static nxt_sockaddr_t *nxt_http_request_client_ip_sockaddr(
    nxt_http_request_t *r, u_char *start, size_t len);
static void nxt_http_request_ready(nxt_task_t *task, void *obj, void *data);
static void nxt_http_request_proto_info(nxt_task_t *task,
    nxt_http_request_t *r);
static void nxt_http_request_mem_buf_completion(nxt_task_t *task, void *obj,
    void *data);
static void nxt_http_request_done(nxt_task_t *task, void *obj, void *data);

static u_char *nxt_http_date_cache_handler(u_char *buf, nxt_realtime_t *now,
    struct tm *tm, size_t size, const char *format);


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
    nxt_http_request_t  *r;

    r = obj;

    r->state = &nxt_http_request_body_state;

    ret = nxt_http_request_client_ip(task, r);
    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
    }

    nxt_http_request_read_body(task, r);
}


static nxt_int_t
nxt_http_request_client_ip(nxt_task_t *task, nxt_http_request_t *r)
{
    u_char                *start, *p;
    nxt_int_t             ret, i, len;
    nxt_str_t             *header;
    nxt_array_t           *fields_arr;  /* of nxt_http_field_t * */
    nxt_sockaddr_t        *sa, *prev_sa;
    nxt_http_field_t      *f, **fields;
    nxt_http_client_ip_t  *client_ip;

    client_ip = r->conf->socket_conf->client_ip;

    if (client_ip == NULL) {
        return NXT_OK;
    }

    ret = nxt_http_route_addr_rule(r, client_ip->source, r->remote);
    if (ret <= 0) {
        return NXT_OK;
    }

    header = client_ip->header;

    fields_arr = nxt_array_create(r->mem_pool, 2, sizeof(nxt_http_field_t *));
    if (nxt_slow_path(fields_arr == NULL)) {
        return NXT_ERROR;
    }

    nxt_list_each(f, r->fields) {
        if (f->hash == client_ip->header_hash
            && f->name_length == client_ip->header->length
            && f->value_length > 0
            && nxt_memcasecmp(f->name, header->start, header->length) == 0)
        {
            fields = nxt_array_add(fields_arr);
            if (nxt_slow_path(fields == NULL)) {
                return NXT_ERROR;
            }

            *fields = f;
        }
    } nxt_list_loop;

    prev_sa = r->remote;
    fields = (nxt_http_field_t **) fields_arr->elts;

    i = fields_arr->nelts;

    while (i-- > 0) {
        f = fields[i];
        start = f->value;
        len = f->value_length;

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

                return NXT_OK;
            }

            if (!client_ip->recursive) {
                r->remote = sa;

                return NXT_OK;
            }

            ret = nxt_http_route_addr_rule(r, client_ip->source, sa);
            if (ret <= 0 || (i == 0 && p == start)) {
                r->remote = sa;

                return NXT_OK;
            }

            prev_sa = sa;
            len = p - 1 - start;

        } while (len > 0);
    }

    return NXT_OK;
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


static const nxt_http_request_state_t  nxt_http_request_body_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_http_request_ready,
    .error_handler = nxt_http_request_close_handler,
};


static void
nxt_http_request_ready(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_action_t   *action;
    nxt_http_request_t  *r;

    r = obj;
    action = r->conf->socket_conf->action;

    nxt_http_request_action(task, r, action);
}


void
nxt_http_request_action(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_action_t *action)
{
    if (nxt_fast_path(action != NULL)) {

        do {
            nxt_debug(task, "http request route: %V", &action->name);

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
    u_char            *p, *end;
    nxt_http_field_t  *server, *date, *content_length;

    /*
     * TODO: "Server", "Date", and "Content-Length" processing should be moved
     * to the last header filter.
     */

    server = nxt_list_zero_add(r->resp.fields);
    if (nxt_slow_path(server == NULL)) {
        goto fail;
    }

    nxt_http_field_set(server, "Server", NXT_SERVER);

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
    nxt_http_request_t       *r;
    nxt_http_protocol_t      protocol;
    nxt_socket_conf_joint_t  *conf;
    nxt_router_access_log_t  *access_log;

    r = obj;
    proto.any = data;

    nxt_debug(task, "http request close handler");

    conf = r->conf;

    if (!r->logged) {
        r->logged = 1;

        access_log = conf->socket_conf->router_conf->access_log;

        if (access_log != NULL) {
            access_log->handler(task, r, access_log);
        }
    }

    r->proto.any = NULL;

    if (r->body != NULL && nxt_buf_is_file(r->body)
        && r->body->file->fd != -1)
    {
        nxt_fd_close(r->body->file->fd);

        r->body->file->fd = -1;
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

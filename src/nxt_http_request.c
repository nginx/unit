
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


static nxt_int_t nxt_http_validate_host(nxt_str_t *host, nxt_mp_t *mp);
static void nxt_http_request_start(nxt_task_t *task, void *obj, void *data);
static void nxt_http_request_pass(nxt_task_t *task, void *obj, void *data);
static void nxt_http_request_proto_info(nxt_task_t *task,
    nxt_http_request_t *r);
static void nxt_http_request_mem_buf_completion(nxt_task_t *task, void *obj,
    void *data);
static void nxt_http_request_done(nxt_task_t *task, void *obj, void *data);

static u_char *nxt_http_date(u_char *buf, nxt_realtime_t *now, struct tm *tm,
    size_t size, const char *format);


static const nxt_http_request_state_t  nxt_http_request_init_state;
static const nxt_http_request_state_t  nxt_http_request_body_state;


nxt_time_string_t  nxt_http_date_cache = {
    (nxt_atomic_uint_t) -1,
    nxt_http_date,
    "%s, %02d %s %4d %02d:%02d:%02d GMT",
    nxt_length("Wed, 31 Dec 1986 16:40:00 GMT"),
    NXT_THREAD_TIME_GMT,
    NXT_THREAD_TIME_SEC,
};


nxt_int_t
nxt_http_init(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_int_t  ret;

    ret = nxt_h1p_init(task, rt);

    if (ret != NXT_OK) {
        return ret;
    }

    return nxt_http_response_hash_init(task, rt);
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
    nxt_off_t           n;
    nxt_http_request_t  *r;

    r = ctx;

    if (nxt_fast_path(r->content_length == NULL)) {
        r->content_length = field;

        n = nxt_off_t_parse(field->value, field->value_length);

        if (nxt_fast_path(n >= 0)) {
            r->content_length_n = n;
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

    mp = nxt_mp_create(1024, 128, 256, 32);
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
    nxt_http_request_t  *r;

    r = obj;

    r->state = &nxt_http_request_body_state;

    nxt_http_request_read_body(task, r);
}


static const nxt_http_request_state_t  nxt_http_request_body_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_http_request_pass,
    .error_handler = nxt_http_request_close_handler,
};


static void
nxt_http_request_pass(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_pass_t     *pass;
    nxt_http_request_t  *r;

    r = obj;

    pass = r->conf->socket_conf->pass;

    if (nxt_fast_path(pass != NULL)) {

        do {
            nxt_debug(task, "http request route: %V", &pass->name);

            pass = pass->handler(task, r, pass);

            if (pass == NULL) {
                return;
            }

            if (pass == NXT_HTTP_PASS_ERROR) {
                break;
            }

        } while (r->pass_count++ < 255);
    }

    nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
}


nxt_http_pass_t *
nxt_http_request_application(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_pass_t *pass)
{
    nxt_event_engine_t  *engine;

    nxt_debug(task, "http request application");

    nxt_mp_retain(r->mem_pool);

    engine = task->thread->engine;
    r->timer.task = &engine->task;
    r->timer.work_queue = &engine->fast_work_queue;
    r->timer.log = engine->task.log;
    r->timer.bias = NXT_TIMER_DEFAULT_BIAS;

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

    nxt_router_process_http_request(task, r, pass->u.application);

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
nxt_http_request_header_send(nxt_task_t *task, nxt_http_request_t *r)
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
        nxt_http_proto[r->protocol].header_send(task, r);
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
    nxt_buf_t           *b;
    nxt_http_request_t  *r;

    b = obj;
    r = data;

    nxt_mp_free(r->mem_pool, b);

    nxt_mp_release(r->mem_pool);
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

    if (nxt_fast_path(proto.any != NULL)) {
        protocol = r->protocol;

        nxt_mp_release(r->mem_pool);

        nxt_http_proto[protocol].close(task, proto, conf);
    }
}


static u_char *
nxt_http_date(u_char *buf, nxt_realtime_t *now, struct tm *tm, size_t size,
    const char *format)
{
    static const char  *week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri",
                                   "Sat" };

    static const char  *month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    return nxt_sprintf(buf, buf + size, format,
                       week[tm->tm_wday], tm->tm_mday,
                       month[tm->tm_mon], tm->tm_year + 1900,
                       tm->tm_hour, tm->tm_min, tm->tm_sec);
}

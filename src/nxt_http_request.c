
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


static void nxt_http_request_start(nxt_task_t *task, void *obj, void *data);
static void nxt_http_app_request(nxt_task_t *task, void *obj, void *data);
static void nxt_http_request_done(nxt_task_t *task, void *obj, void *data);


static const nxt_http_request_state_t  nxt_http_request_init_state;
static const nxt_http_request_state_t  nxt_http_request_body_state;


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
    nxt_http_request_t  *r;

    r = ctx;

    /* TODO: validate host. */

    r->host = field;

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
    nxt_http_request_t  *r;

    r = ctx;

    r->content_length = field;
    r->content_length_n = nxt_off_t_parse(field->value, field->value_length);

    return NXT_OK;
}


nxt_http_request_t *
nxt_http_request_create(nxt_task_t *task)
{
    nxt_mp_t            *mp;
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
    .ready_handler = nxt_http_app_request,
    .error_handler = nxt_http_request_close_handler,
};


static void
nxt_http_app_request(nxt_task_t *task, void *obj, void *data)
{
    nxt_int_t            ret;
    nxt_event_engine_t   *engine;
    nxt_http_request_t   *r;
    nxt_app_parse_ctx_t  *ar;

    r = obj;

    ar = nxt_mp_zget(r->mem_pool, sizeof(nxt_app_parse_ctx_t));
    if (nxt_slow_path(ar == NULL)) {
        nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ar->request = r;
    ar->mem_pool = r->mem_pool;
    nxt_mp_retain(r->mem_pool);

    // STUB
    engine = task->thread->engine;
    ar->timer.task = &engine->task;
    ar->timer.work_queue = &engine->fast_work_queue;
    ar->timer.log = engine->task.log;
    ar->timer.precision = NXT_TIMER_DEFAULT_PRECISION;

    ar->r.remote.start = nxt_sockaddr_address(r->remote);
    ar->r.remote.length = r->remote->address_length;

    /*
     * TODO: need an application flag to get local address
     * required by "SERVER_ADDR" in Pyhton and PHP. Not used in Go.
     */
    nxt_http_request_local_addr(task, r);

    if (nxt_fast_path(r->local != NULL)) {
        ar->r.local.start = nxt_sockaddr_address(r->local);
        ar->r.local.length = r->local->address_length;
    }

    ar->r.header.fields = r->fields;
    ar->r.header.done = 1;
    ar->r.header.version = r->version;

    if (r->method != NULL) {
        ar->r.header.method = *r->method;
    }

    ar->r.header.target = r->target;

    if (r->path != NULL) {
        ar->r.header.path = *r->path;
    }

    if (r->args != NULL) {
        ar->r.header.query = *r->args;
    }

    if (r->host != NULL) {
        ar->r.header.host.length = r->host->value_length;
        ar->r.header.host.start = r->host->value;
    }

    if (r->content_type != NULL) {
        ar->r.header.content_type.length = r->content_type->value_length;
        ar->r.header.content_type.start = r->content_type->value;
    }

    if (r->content_length != NULL) {
        ar->r.header.content_length.length = r->content_length->value_length;
        ar->r.header.content_length.start = r->content_length->value;
    }

    if (r->cookie != NULL) {
        ar->r.header.cookie.length = r->cookie->value_length;
        ar->r.header.cookie.start = r->cookie->value;
    }

    if (r->body != NULL) {
        ar->r.body.buf = r->body;
        ar->r.body.preread_size = r->content_length_n;
        ar->r.header.parsed_content_length = r->content_length_n;
    }

    ar->r.body.done = 1;

    ret = nxt_http_parse_request_init(&ar->resp_parser, r->mem_pool);
    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    nxt_router_process_http_request(task, ar);
}


void
nxt_http_request_read_body(nxt_task_t *task, nxt_http_request_t *r)
{
    if (r->proto.any != NULL) {
        nxt_http_proto_body_read[r->protocol](task, r);
    }
}


void
nxt_http_request_local_addr(nxt_task_t *task, nxt_http_request_t *r)
{
    if (r->proto.any != NULL) {
        nxt_http_proto_local_addr[r->protocol](task, r);
    }
}


void
nxt_http_request_header_send(nxt_task_t *task, nxt_http_request_t *r)
{
    u_char            *p, *end;
    nxt_http_field_t  *server, *content_length;

    /*
     * TODO: "Server" and "Content-Length" processing should be moved
     * to the last header filter.
     */

    server = nxt_list_zero_add(r->resp.fields);
    if (nxt_slow_path(server == NULL)) {
        goto fail;
    }

    nxt_http_field_set(server, "Server", "unit/" NXT_VERSION);

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

    if (r->proto.any != NULL) {
        nxt_http_proto_header_send[r->protocol](task, r);
    }

    return;

fail:

    nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
}


void
nxt_http_request_send(nxt_task_t *task, nxt_http_request_t *r, nxt_buf_t *out)
{
    if (r->proto.any != NULL) {
        nxt_http_proto_send[r->protocol](task, r, out);
    }
}


nxt_buf_t *
nxt_http_request_last_buffer(nxt_task_t *task, nxt_http_request_t *r)
{
    nxt_buf_t  *b;

    b = nxt_buf_mem_alloc(r->mem_pool, 0, 0);

    if (nxt_fast_path(b != NULL)) {
        nxt_buf_set_sync(b);
        nxt_buf_set_last(b);
        b->completion_handler = nxt_http_request_done;
        b->parent = r;

    } else {
        nxt_http_request_release(task, r);
    }

    return b;
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
nxt_http_request_release(nxt_task_t *task, nxt_http_request_t *r)
{
    nxt_debug(task, "http request release");

    nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                       nxt_http_request_close_handler, task, r, r->proto.any);
}


void
nxt_http_request_close_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_proto_t        proto;
    nxt_http_request_t      *r;
    nxt_http_proto_close_t  handler;

    r = obj;
    proto.any = data;

    nxt_debug(task, "http request close handler");

    if (!r->logged) {
        r->logged = 1;
        // STUB
        nxt_debug(task, "http request log: \"%*s \"%V %V %V\" %d\"",
                  r->remote->address_length, nxt_sockaddr_address(r->remote),
                  r->method, &r->target, &r->version, r->status);
    }

    handler = nxt_http_proto_close[r->protocol];

    r->proto.any = NULL;
    nxt_mp_release(r->mem_pool);

    if (proto.any != NULL) {
        handler(task, proto);
    }
}

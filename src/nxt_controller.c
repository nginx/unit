
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_master_process.h>
#include <nxt_conf.h>


typedef struct {
    nxt_http_request_parse_t  parser;
    size_t                    length;

    nxt_conf_json_value_t     *conf;
} nxt_controller_request_t;


static void nxt_controller_conn_init(nxt_task_t *task, void *obj, void *data);
static void nxt_controller_conn_read(nxt_task_t *task, void *obj, void *data);
static nxt_msec_t nxt_controller_conn_timeout_value(nxt_event_conn_t *c,
    uintptr_t data);
static void nxt_controller_conn_read_error(nxt_task_t *task, void *obj,
    void *data);
static void nxt_controller_conn_read_timeout(nxt_task_t *task, void *obj,
    void *data);
static void nxt_controller_conn_body_read(nxt_task_t *task, void *obj,
    void *data);
static void nxt_controller_conn_write(nxt_task_t *task, void *obj, void *data);
static void nxt_controller_conn_write_error(nxt_task_t *task, void *obj,
    void *data);
static void nxt_controller_conn_write_timeout(nxt_task_t *task, void *obj,
    void *data);
static void nxt_controller_conn_close(nxt_task_t *task, void *obj, void *data);
static void nxt_controller_conn_free(nxt_task_t *task, void *obj, void *data);

static nxt_int_t nxt_controller_request_content_length(void *ctx,
    nxt_str_t *name, nxt_str_t *value, uintptr_t data);

static void nxt_controller_process_request(nxt_task_t *task,
    nxt_event_conn_t *c, nxt_controller_request_t *r);
static nxt_int_t nxt_controller_request_body_parse(nxt_task_t *task,
    nxt_event_conn_t *c, nxt_controller_request_t *r);
static void nxt_controller_conf_output(nxt_task_t *task, nxt_event_conn_t *c,
    nxt_controller_request_t *r);


static nxt_http_fields_t  nxt_controller_request_fields[] = {
    { nxt_string("Content-Length"),
      &nxt_controller_request_content_length, 0 },

    { nxt_null_string, NULL, 0 }
};


static nxt_http_fields_hash_t  *nxt_controller_request_fields_hash;


static const nxt_event_conn_state_t  nxt_controller_conn_read_state;
static const nxt_event_conn_state_t  nxt_controller_conn_body_read_state;
static const nxt_event_conn_state_t  nxt_controller_conn_write_state;
static const nxt_event_conn_state_t  nxt_controller_conn_close_state;


nxt_int_t
nxt_controller_start(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_http_fields_hash_t  *hash;

    hash = nxt_http_fields_hash(nxt_controller_request_fields, rt->mem_pool);

    if (nxt_slow_path(hash == NULL)) {
        return NXT_ERROR;
    }

    nxt_controller_request_fields_hash = hash;

    if (nxt_event_conn_listen(task, rt->controller_socket) != NXT_OK) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


nxt_int_t
nxt_runtime_controller_socket(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_sockaddr_t       *sa;
    nxt_listen_socket_t  *ls;

    sa = rt->controller_listen;

    if (rt->controller_listen == NULL) {
        sa = nxt_sockaddr_alloc(rt->mem_pool, sizeof(struct sockaddr_in),
                                NXT_INET_ADDR_STR_LEN);
        if (sa == NULL) {
            return NXT_ERROR;
        }

        sa->type = SOCK_STREAM;
        sa->u.sockaddr_in.sin_family = AF_INET;
        sa->u.sockaddr_in.sin_port = htons(8443);

        nxt_sockaddr_text(sa);

        rt->controller_listen = sa;
    }

    ls = nxt_mem_alloc(rt->mem_pool, sizeof(nxt_listen_socket_t));
    if (ls == NULL) {
        return NXT_ERROR;
    }

    ls->sockaddr = nxt_sockaddr_create(rt->mem_pool, &sa->u.sockaddr,
                                       sa->socklen, sa->length);
    if (ls->sockaddr == NULL) {
        return NXT_ERROR;
    }

    ls->sockaddr->type = sa->type;

    nxt_sockaddr_text(ls->sockaddr);

    ls->socket = -1;
    ls->backlog = NXT_LISTEN_BACKLOG;
    ls->read_after_accept = 1;
    ls->flags = NXT_NONBLOCK;

#if 0
    /* STUB */
    wq = nxt_mem_zalloc(cf->mem_pool, sizeof(nxt_work_queue_t));
    if (wq == NULL) {
        return NXT_ERROR;
    }
    nxt_work_queue_name(wq, "listen");
    /**/

    ls->work_queue = wq;
#endif
    ls->handler = nxt_controller_conn_init;

    /*
     * Connection memory pool chunk size is tunned to
     * allocate the most data in one mem_pool chunk.
     */
    ls->mem_pool_size = nxt_listen_socket_pool_min_size(ls)
                        + sizeof(nxt_event_conn_proxy_t)
                        + sizeof(nxt_event_conn_t)
                        + 4 * sizeof(nxt_buf_t);

    if (nxt_listen_socket_create(task, ls, 0) != NXT_OK) {
        return NXT_ERROR;
    }

    rt->controller_socket = ls;

    return NXT_OK;
}


static void
nxt_controller_conn_init(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t                 *b;
    nxt_event_conn_t          *c;
    nxt_event_engine_t        *engine;
    nxt_controller_request_t  *r;

    c = obj;

    nxt_debug(task, "controller conn init fd:%d", c->socket.fd);

    r = nxt_mem_zalloc(c->mem_pool, sizeof(nxt_controller_request_t));
    if (nxt_slow_path(r == NULL)) {
        nxt_controller_conn_free(task, c, NULL);
        return;
    }

    r->parser.hash = nxt_controller_request_fields_hash;
    r->parser.ctx = r;

    b = nxt_buf_mem_alloc(c->mem_pool, 1024, 0);
    if (nxt_slow_path(b == NULL)) {
        nxt_controller_conn_free(task, c, NULL);
        return;
    }

    c->read = b;
    c->socket.data = r;
    c->socket.read_ready = 1;
    c->read_state = &nxt_controller_conn_read_state;

    engine = task->thread->engine;
    c->read_work_queue = &engine->read_work_queue;
    c->write_work_queue = &engine->write_work_queue;

    nxt_event_conn_read(engine, c);
}


static const nxt_event_conn_state_t  nxt_controller_conn_read_state
    nxt_aligned(64) =
{
    NXT_EVENT_NO_BUF_PROCESS,
    NXT_EVENT_TIMER_NO_AUTORESET,

    nxt_controller_conn_read,
    nxt_controller_conn_close,
    nxt_controller_conn_read_error,

    nxt_controller_conn_read_timeout,
    nxt_controller_conn_timeout_value,
    60 * 1000,
};


static void
nxt_controller_conn_read(nxt_task_t *task, void *obj, void *data)
{
    size_t                    preread;
    nxt_buf_t                 *b;
    nxt_int_t                 rc;
    nxt_event_conn_t          *c;
    nxt_controller_request_t  *r;

    c = obj;
    r = data;

    nxt_debug(task, "controller conn read");

    nxt_queue_remove(&c->link);
    nxt_queue_self(&c->link);

    b = c->read;

    rc = nxt_http_parse_request(&r->parser, &b->mem);

    if (nxt_slow_path(rc != NXT_DONE)) {

        if (rc == NXT_AGAIN) {
            if (nxt_buf_mem_free_size(&b->mem) == 0) {
                nxt_log(task, NXT_LOG_ERR, "too long request headers");
                nxt_controller_conn_close(task, c, r);
                return;
            }

            nxt_event_conn_read(task->thread->engine, c);
            return;
        }

        /* rc == NXT_ERROR */

        nxt_log(task, NXT_LOG_ERR, "parsing error");

        nxt_controller_conn_close(task, c, r);
        return;
    }

    preread = nxt_buf_mem_used_size(&b->mem);

    nxt_debug(task, "controller request header parsing complete, "
                    "body length: %O, preread: %uz",
                    r->length, preread);

    if (preread >= r->length) {
        nxt_controller_process_request(task, c, r);
        return;
    }

    if (r->length - preread > (size_t) nxt_buf_mem_free_size(&b->mem)) {
        b = nxt_buf_mem_alloc(c->mem_pool, r->length, 0);
        if (nxt_slow_path(b == NULL)) {
            nxt_controller_conn_free(task, c, NULL);
            return;
        }

        b->mem.free = nxt_cpymem(b->mem.free, c->read->mem.pos, preread);

        c->read = b;
    }

    c->read_state = &nxt_controller_conn_body_read_state;

    nxt_event_conn_read(task->thread->engine, c);
}


static nxt_msec_t
nxt_controller_conn_timeout_value(nxt_event_conn_t *c, uintptr_t data)
{
    return (nxt_msec_t) data;
}


static void
nxt_controller_conn_read_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_t  *c;

    c = obj;

    nxt_debug(task, "controller conn read error");

    nxt_controller_conn_close(task, c, data);
}


static void
nxt_controller_conn_read_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_timer_t       *ev;
    nxt_event_conn_t  *c;

    ev = obj;

    c = nxt_event_read_timer_conn(ev);
    c->socket.timedout = 1;
    c->socket.closed = 1;

    nxt_debug(task, "controller conn read timeout");

    nxt_controller_conn_close(task, c, data);
}


static const nxt_event_conn_state_t  nxt_controller_conn_body_read_state
    nxt_aligned(64) =
{
    NXT_EVENT_NO_BUF_PROCESS,
    NXT_EVENT_TIMER_AUTORESET,

    nxt_controller_conn_body_read,
    nxt_controller_conn_close,
    nxt_controller_conn_read_error,

    nxt_controller_conn_read_timeout,
    nxt_controller_conn_timeout_value,
    60 * 1000,
};


static void
nxt_controller_conn_body_read(nxt_task_t *task, void *obj, void *data)
{
    size_t            rest;
    nxt_buf_t         *b;
    nxt_event_conn_t  *c;

    c = obj;

    nxt_debug(task, "controller conn body read");

    b = c->read;

    rest = nxt_buf_mem_free_size(&b->mem);

    if (rest == 0) {
        nxt_debug(task, "controller conn body read complete");

        nxt_controller_process_request(task, c, data);
        return;
    }

    nxt_debug(task, "controller conn body read again, rest: %uz", rest);

    nxt_event_conn_read(task->thread->engine, c);
}


static const nxt_event_conn_state_t  nxt_controller_conn_write_state
    nxt_aligned(64) =
{
    NXT_EVENT_NO_BUF_PROCESS,
    NXT_EVENT_TIMER_AUTORESET,

    nxt_controller_conn_write,
    NULL,
    nxt_controller_conn_write_error,

    nxt_controller_conn_write_timeout,
    nxt_controller_conn_timeout_value,
    60 * 1000,
};


static void
nxt_controller_conn_write(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t         *b;
    nxt_event_conn_t  *c;

    c = obj;

    nxt_debug(task, "controller conn write");

    b = c->write;

    if (b->mem.pos != b->mem.free) {
        nxt_event_conn_write(task->thread->engine, c);
        return;
    }

    nxt_debug(task, "controller conn write complete");

    nxt_controller_conn_close(task, c, data);
}


static void
nxt_controller_conn_write_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_t  *c;

    c = obj;

    nxt_debug(task, "controller conn write error");

    nxt_controller_conn_close(task, c, data);
}


static void
nxt_controller_conn_write_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_timer_t       *ev;
    nxt_event_conn_t  *c;

    ev = obj;

    c = nxt_event_write_timer_conn(ev);
    c->socket.timedout = 1;
    c->socket.closed = 1;

    nxt_debug(task, "controller conn write timeout");

    nxt_controller_conn_close(task, c, data);
}


static const nxt_event_conn_state_t  nxt_controller_conn_close_state
    nxt_aligned(64) =
{
    NXT_EVENT_NO_BUF_PROCESS,
    NXT_EVENT_TIMER_NO_AUTORESET,

    nxt_controller_conn_free,
    NULL,
    NULL,

    NULL,
    NULL,
    0,
};


static void
nxt_controller_conn_close(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_t  *c;

    c = obj;

    nxt_debug(task, "controller conn close");

    nxt_queue_remove(&c->link);

    c->write_state = &nxt_controller_conn_close_state;

    nxt_event_conn_close(task->thread->engine, c);
}


static void
nxt_controller_conn_free(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_t  *c;

    c = obj;

    nxt_debug(task, "controller conn free");

    nxt_mem_pool_destroy(c->mem_pool);

    //nxt_free(c);
}


static nxt_int_t
nxt_controller_request_content_length(void *ctx, nxt_str_t *name,
    nxt_str_t *value, uintptr_t data)
{
    off_t                     length;
    nxt_controller_request_t  *r;

    r = ctx;

    length = nxt_off_t_parse(value->start, value->length);

    if (nxt_fast_path(length > 0)) {
        /* TODO length too big */

        r->length = length;
        return NXT_OK;
    }

    /* TODO logging (task?) */

    return NXT_ERROR;
}


static void
nxt_controller_process_request(nxt_task_t *task, nxt_event_conn_t *c,
    nxt_controller_request_t *r)
{
    nxt_buf_t  *b;

    static const nxt_str_t resp418
        = nxt_string("HTTP/1.0 418 I'm a teapot\r\n\r\nerror\r\n");

    if (nxt_controller_request_body_parse(task, c, r) != NXT_OK) {
        goto error;
    }

    nxt_controller_conf_output(task, c, r);

    return;

error:

    b = nxt_buf_mem_alloc(c->mem_pool, resp418.length, 0);
    if (nxt_slow_path(b == NULL)) {
        nxt_controller_conn_close(task, c, r);
        return;
    }

    b->mem.free = nxt_cpymem(b->mem.free, resp418.start, resp418.length);

    c->write = b;
    c->write_state = &nxt_controller_conn_write_state;

    nxt_event_conn_write(task->thread->engine, c);
}


static nxt_int_t
nxt_controller_request_body_parse(nxt_task_t *task, nxt_event_conn_t *c,
    nxt_controller_request_t *r)
{
    nxt_buf_t              *b;
    nxt_conf_json_value_t  *value;

    b = c->read;

    value = nxt_conf_json_parse(&b->mem, c->mem_pool);

    if (value == NULL) {
        return NXT_ERROR;
    }

    r->conf = value;

    return NXT_OK;
}


static void
nxt_controller_conf_output(nxt_task_t *task, nxt_event_conn_t *c,
    nxt_controller_request_t *r)
{
    nxt_buf_t  *b;

    static const nxt_str_t head = nxt_string("HTTP/1.0 200 OK\r\n\r\n");

    b = nxt_buf_mem_alloc(c->mem_pool, head.length, 0);
    if (nxt_slow_path(b == NULL)) {
        nxt_controller_conn_close(task, c, r);
        return;
    }

    b->mem.free = nxt_cpymem(b->mem.free, head.start, head.length);

    c->write = b;

    b = nxt_conf_json_print(r->conf, c->mem_pool);

    if (b == NULL) {
        nxt_controller_conn_close(task, c, r);
        return;
    }

    c->write->next = b;
    c->write_state = &nxt_controller_conn_write_state;

    nxt_event_conn_write(task->thread->engine, c);
    return;
}

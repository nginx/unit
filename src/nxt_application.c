
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_cycle.h>
#include <nxt_application.h>


#define NXT_PARSE_AGAIN  (u_char *) -1


static void nxt_app_thread(void *ctx);
static nxt_app_request_t *nxt_app_request_create(nxt_socket_t s,
    nxt_log_t *log);
static void nxt_app_conn_update(nxt_thread_t *thr, nxt_event_conn_t *c,
    nxt_log_t *log);
static nxt_int_t nxt_app_write_finish(nxt_app_request_t *r);
static void nxt_app_buf_send(nxt_event_conn_t *c, nxt_buf_t *out);
static void nxt_app_buf_completion(nxt_task_t *task, void *obj, void *data);
static void nxt_app_delivery_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_app_delivery_ready(nxt_task_t *task, void *obj, void *data);
static void nxt_app_delivery_completion(nxt_task_t *task, void *obj,
    void *data);
static void nxt_app_delivery_error(nxt_task_t *task, void *obj, void *data);
static void nxt_app_delivery_timeout(nxt_task_t *task, void *obj, void *data);
static nxt_msec_t nxt_app_delivery_timer_value(nxt_event_conn_t *c,
    uintptr_t data);
static void nxt_app_delivery_done(nxt_task_t *task, nxt_event_conn_t *c);
static void nxt_app_close_request(nxt_task_t *task, void *obj, void *data);


typedef struct nxt_app_http_parse_state_s  nxt_app_http_parse_state_t;

struct nxt_app_http_parse_state_s {
    u_char     *pos;
    nxt_int_t  (*handler)(nxt_app_request_header_t *h, u_char *start,
                          u_char *end, nxt_app_http_parse_state_t *state);
};


typedef struct {
     nxt_work_t  work;
     nxt_buf_t   buf;
} nxt_app_buf_t;


static nxt_int_t nxt_app_http_parse_request(nxt_app_request_t *r, u_char *buf,
    size_t size);
static nxt_int_t nxt_app_http_parse_request_line(nxt_app_request_header_t *h,
    u_char *start, u_char *end, nxt_app_http_parse_state_t *state);
static nxt_int_t nxt_app_http_parse_field_value(nxt_app_request_header_t *h,
    u_char *start, u_char *end, nxt_app_http_parse_state_t *state);
static nxt_int_t nxt_app_http_parse_field_name(nxt_app_request_header_t *h,
    u_char *start, u_char *end, nxt_app_http_parse_state_t *state);

static nxt_int_t nxt_app_http_process_headers(nxt_app_request_t *r);


static const nxt_event_conn_state_t  nxt_app_delivery_write_state;

static nxt_application_module_t  *nxt_app = &nxt_python_module;

static nxt_thread_mutex_t        nxt_app_mutex;
static nxt_thread_cond_t         nxt_app_cond;

static nxt_buf_t                 *nxt_app_buf_free;
static nxt_buf_t                 *nxt_app_buf_done;

static nxt_event_engine_t        *nxt_app_engine;
static nxt_mem_pool_t            *nxt_app_mem_pool;

static nxt_uint_t                nxt_app_buf_current_number;
static nxt_uint_t                nxt_app_buf_max_number = 16;


nxt_int_t
nxt_app_start(nxt_cycle_t *cycle)
{
    nxt_thread_link_t    *link;
    nxt_thread_handle_t  handle;

    if (nxt_slow_path(nxt_thread_mutex_create(&nxt_app_mutex) != NXT_OK)) {
        return NXT_ERROR;
    }

    if (nxt_slow_path(nxt_thread_cond_create(&nxt_app_cond) != NXT_OK)) {
        return NXT_ERROR;
    }

    link = nxt_zalloc(sizeof(nxt_thread_link_t));

    if (nxt_fast_path(link != NULL)) {
        link->start = nxt_app_thread;
        link->data = cycle;

        return nxt_thread_create(&handle, link);
    }

    return NXT_ERROR;
}


#define SIZE  4096

static void
nxt_app_thread(void *ctx)
{
    ssize_t                 n;
    nxt_err_t               err;
    nxt_cycle_t             *cycle;
    nxt_socket_t            s;
    nxt_thread_t            *thr;
    nxt_app_request_t       *r;
    nxt_event_engine_t      **engines;
    nxt_listen_socket_t     *ls;
    u_char                  buf[SIZE];
    const size_t            size = SIZE;
    nxt_app_header_field_t  fields[128];

    thr = nxt_thread();

    nxt_log_debug(thr->log, "app thread");

    cycle = ctx;
    engines = cycle->engines->elts;

    nxt_app_engine = engines[0];

    nxt_app_mem_pool = nxt_mem_pool_create(512);
    if (nxt_slow_path(nxt_app_mem_pool == NULL)) {
        return;
    }

    if (nxt_slow_path(nxt_app->init(thr) != NXT_OK)) {
        nxt_log_debug(thr->log, "application init failed");
    }

    ls = cycle->listen_sockets->elts;

    for ( ;; ) {
        nxt_log_debug(thr->log, "wait on accept");

        s = accept(ls->socket, NULL, NULL);

        nxt_thread_time_update(thr);

        if (nxt_slow_path(s == -1)) {
            err = nxt_socket_errno;

            nxt_log_error(NXT_LOG_ERR, thr->log, "accept(%d) failed %E",
                          ls->socket, err);

            if (err == EBADF) {
                /* STUB: ls->socket has been closed on exit. */
                return;
            }

            continue;
        }

        nxt_log_debug(thr->log, "accept(%d): %d", ls->socket, s);

        n = recv(s, buf, size, 0);

        if (nxt_slow_path(n <= 0)) {
            err = (n == 0) ? 0 : nxt_socket_errno;

            nxt_log_error(NXT_LOG_ERR, thr->log, "recv(%d, %uz) failed %E",
                          s, size, err);
            close(s);
            continue;
        }

        nxt_log_debug(thr->log, "recv(%d, %uz): %z", s, size, n);

        r = nxt_app_request_create(s, thr->log);
        if (nxt_slow_path(r == NULL)) {
            goto fail;
        }

        r->header.fields = fields;

        //nxt_app->start(r);

        if (nxt_app_http_parse_request(r, buf, n) != NXT_OK) {
            nxt_log_debug(thr->log, "nxt_app_http_parse_request() failed");
            nxt_mem_pool_destroy(r->mem_pool);
            goto fail;
        }

        if (nxt_app_http_process_headers(r) != NXT_OK) {
            nxt_log_debug(thr->log, "nxt_app_http_process_headers() failed");
            nxt_mem_pool_destroy(r->mem_pool);
            goto fail;
        }

        nxt_app->run(r);

        nxt_log_debug(thr->log, "app request done");

        if (nxt_slow_path(nxt_app_write_finish(r) == NXT_ERROR)) {
            goto fail;
        }

        continue;

    fail:

        close(s);
        nxt_nanosleep(1000000000);  /* 1s */
    }
}


static nxt_app_request_t *
nxt_app_request_create(nxt_socket_t s, nxt_log_t *log)
{
    nxt_mem_pool_t     *mp;
    nxt_event_conn_t   *c;
    nxt_app_request_t  *r;

    mp = nxt_mem_pool_create(1024);
    if (nxt_slow_path(mp == NULL)) {
        return NULL;
    }

    r = nxt_mem_zalloc(mp, sizeof(nxt_app_request_t));
    if (nxt_slow_path(r == NULL)) {
        return NULL;
    }

    c = nxt_mem_zalloc(mp, sizeof(nxt_event_conn_t));
    if (nxt_slow_path(c == NULL)) {
        return NULL;
    }

    c->socket.fd = s;
    c->socket.data = r;

    c->task.thread = nxt_thread();
    c->task.log = log;
    c->task.ident = log->ident;
    c->socket.task = &c->task;
    c->read_timer.task = &c->task;
    c->write_timer.task = &c->task;

    r->mem_pool = mp;
    r->event_conn = c;
    r->log = log;

    return r;
}


static nxt_int_t
nxt_app_http_parse_request(nxt_app_request_t *r, u_char *buf, size_t size)
{
    u_char                      *end;
    ssize_t                     n;
    nxt_err_t                   err;
    nxt_socket_t                s;
    nxt_app_http_parse_state_t  state;

    end = buf + size;

    state.pos = buf;
    state.handler = nxt_app_http_parse_request_line;

    for ( ;; ) {
        switch (state.handler(&r->header, state.pos, end, &state)) {

        case NXT_OK:
            continue;

        case NXT_DONE:
            r->body_preread.len = end - state.pos;
            r->body_preread.data = state.pos;

            return NXT_OK;

        case NXT_AGAIN:
            s = r->event_conn->socket.fd;
            n = recv(s, end, SIZE - size, 0);

            if (nxt_slow_path(n <= 0)) {
                err = (n == 0) ? 0 : nxt_socket_errno;

                nxt_log_error(NXT_LOG_ERR, r->log, "recv(%d, %uz) failed %E",
                              s, size, err);

                return NXT_ERROR;
            }

            nxt_log_debug(r->log, "recv(%d, %uz): %z", s, SIZE - size, n);

            size += n;
            end += n;

            continue;
        }

        return NXT_ERROR;
    }
}


static nxt_int_t
nxt_app_http_parse_request_line(nxt_app_request_header_t *h, u_char *start,
    u_char *end, nxt_app_http_parse_state_t *state)
{
    u_char  *p;

    for (p = start; /* void */; p++) {

        if (nxt_slow_path(p == end)) {
            state->pos = p;
            return NXT_AGAIN;
        }

        if (*p == ' ') {
            break;
        }
    }

    h->method.len = p - start;
    h->method.data = start;

    start = p + 1;

    p = nxt_memchr(start, ' ', end - start);

    if (nxt_slow_path(p == NULL)) {
        return NXT_AGAIN;
    }

    h->path.len = p - start;
    h->path.data = start;

    start = p + 1;

    if (nxt_slow_path((size_t) (end - start) < sizeof("HTTP/1.1\n") - 1)) {
        return NXT_AGAIN;
    }

    h->version.len = sizeof("HTTP/1.1") - 1;
    h->version.data = start;

    p = start + sizeof("HTTP/1.1") - 1;

    if (nxt_slow_path(*p == '\n')) {
        return nxt_app_http_parse_field_name(h, p + 1, end, state);
    }

    if (nxt_slow_path(end - p < 2)) {
        return NXT_AGAIN;
    }

    return nxt_app_http_parse_field_name(h, p + 2, end, state);
}


static nxt_int_t
nxt_app_http_parse_field_name(nxt_app_request_header_t *h, u_char *start,
    u_char *end, nxt_app_http_parse_state_t *state)
{
    u_char                  *p;
    nxt_app_header_field_t  *fld;

    if (nxt_slow_path(start == end)) {
        goto again;
    }

    if (nxt_slow_path(*start == '\n')) {
        state->pos = start + 1;
        return NXT_DONE;
    }

    if (*start == '\r') {
        if (nxt_slow_path(end - start < 2)) {
            goto again;
        }

        if (nxt_slow_path(start[1] != '\n')) {
            return NXT_ERROR;
        }

        state->pos = start + 2;
        return NXT_DONE;
    }

    p = nxt_memchr(start, ':', end - start);

    if (nxt_slow_path(p == NULL)) {
        goto again;
    }

    fld = &h->fields[h->fields_num];

    fld->name.len = p - start;
    fld->name.data = start;

    return nxt_app_http_parse_field_value(h, p + 1, end, state);

again:

    state->pos = start;
    state->handler = nxt_app_http_parse_field_name;

    return NXT_AGAIN;
}


static nxt_int_t
nxt_app_http_parse_field_value(nxt_app_request_header_t *h, u_char *start,
    u_char *end, nxt_app_http_parse_state_t *state)
{
    u_char                  *p;
    nxt_app_header_field_t  *fld;

    for ( ;; ) {
        if (nxt_slow_path(start == end)) {
            goto again;
        }

        if (*start != ' ') {
            break;
        }

        start++;
    }

    p = nxt_memchr(start, '\n', end - start);

    if (nxt_slow_path(p == NULL)) {
        goto again;
    }

    fld = &h->fields[h->fields_num];

    fld->value.len = p - start;
    fld->value.data = start;

    fld->value.len -= (p[-1] == '\r');

    h->fields_num++;

    state->pos = p + 1;
    state->handler = nxt_app_http_parse_field_name;

    return NXT_OK;

again:

    state->pos = start;
    state->handler = nxt_app_http_parse_field_value;

    return NXT_AGAIN;
}


static nxt_int_t
nxt_app_http_process_headers(nxt_app_request_t *r)
{
    nxt_uint_t               i;
    nxt_app_header_field_t  *fld;

    static const u_char content_length[14] = "Content-Length";
    static const u_char content_type[12] = "Content-Type";

    for (i = 0; i < r->header.fields_num; i++) {
        fld = &r->header.fields[i];

        if (fld->name.len == sizeof(content_length)
            && nxt_memcasecmp(fld->name.data, content_length,
                              sizeof(content_length)) == 0)
        {
            r->header.content_length = &fld->value;
            r->body_rest = nxt_off_t_parse(fld->value.data, fld->value.len);
            continue;
        }

        if (fld->name.len == sizeof(content_type)
            && nxt_memcasecmp(fld->name.data, content_type,
                              sizeof(content_type)) == 0)
        {
            r->header.content_type = &fld->value;
            continue;
        }
    }

    return NXT_OK;
}


static void
nxt_app_conn_update(nxt_thread_t *thr, nxt_event_conn_t *c, nxt_log_t *log)
{
    c->socket.write_ready = 1;

    c->socket.log = &c->log;
    c->log = *log;

    /* The while loop skips possible uint32_t overflow. */

    while (c->log.ident == 0) {
        c->log.ident = nxt_task_next_ident();
    }

    thr->engine->connections++;

    c->task.thread = thr;
    c->task.log = &c->log;
    c->task.ident = c->log.ident;

    c->io = thr->engine->event->io;
    c->max_chunk = NXT_INT32_T_MAX;
    c->sendfile = NXT_CONN_SENDFILE_UNSET;

    c->socket.read_work_queue = &thr->engine->read_work_queue;
    c->socket.write_work_queue = &thr->engine->write_work_queue;
    c->read_work_queue = &thr->engine->read_work_queue;
    c->write_work_queue = &thr->engine->write_work_queue;

    nxt_event_conn_timer_init(&c->read_timer, c, c->socket.read_work_queue);
    nxt_event_conn_timer_init(&c->write_timer, c, c->socket.write_work_queue);

    nxt_log_debug(&c->log, "event connections: %uD", thr->engine->connections);
}


nxt_int_t
nxt_app_http_read_body(nxt_app_request_t *r, u_char *data, size_t len)
{
    size_t     preread;
    ssize_t    n;
    nxt_err_t  err;

    if ((off_t) len > r->body_rest) {
        len = (size_t) r->body_rest;
    }

    preread = 0;

    if (r->body_preread.len != 0) {
        preread = nxt_min(r->body_preread.len, len);

        nxt_memcpy(data, r->body_preread.data, preread);

        r->body_preread.len -= preread;
        r->body_preread.data += preread;

        r->body_rest -= preread;

        len -= preread;
    }

    if (len == 0) {
        return NXT_OK;
    }

    n = recv(r->event_conn->socket.fd, data + preread, len, 0);

    if (nxt_slow_path(n < (ssize_t) len)) {
        if (n <= 0) {
            err = (n == 0) ? 0 : nxt_socket_errno;

            nxt_log_error(NXT_LOG_ERR, r->log, "recv(%d, %uz) failed %E",
                          r->event_conn->socket.fd, len, err);

            return NXT_ERROR;
        }

        nxt_log_error(NXT_LOG_ERR, r->log,
                      "client prematurely closed connection");

        return NXT_ERROR;
    }

    r->body_rest -= n;

    return NXT_OK;
}


nxt_int_t
nxt_app_write(nxt_app_request_t *r, const u_char *data, size_t len)
{
    void           *start;
    size_t         free;
    nxt_err_t      err;
    nxt_buf_t      *b, *out, **next;
    nxt_uint_t     bufs;
    nxt_app_buf_t  *ab;

    out = NULL;
    next = &out;

    b = r->output_buf;

    if (b == NULL) {
        bufs = 0;
        goto get_buf;
    }

    bufs = 1;

    for ( ;; ) {
        free = nxt_buf_mem_free_size(&b->mem);

        if (free > len) {
            b->mem.free = nxt_cpymem(b->mem.free, data, len);
            break;
        }

        b->mem.free = nxt_cpymem(b->mem.free, data, free);

        data += free;
        len -= free;

        *next = b;
        next = &b->next;

        if (len == 0) {
            b = NULL;
            break;
        }

        if (bufs == nxt_app_buf_max_number) {
            bufs = 0;
            *next = NULL;

            nxt_app_buf_send(r->event_conn, out);

            out = NULL;
            next = &out;
        }

    get_buf:

        if (nxt_slow_path(nxt_thread_mutex_lock(&nxt_app_mutex) != NXT_OK)) {
            return NXT_ERROR;
        }

        for ( ;; ) {
            b = nxt_app_buf_free;

            if (b != NULL) {
                nxt_app_buf_free = b->next;
                break;
            }

            if (nxt_app_buf_current_number < nxt_app_buf_max_number) {
                break;
            }

            err = nxt_thread_cond_wait(&nxt_app_cond, &nxt_app_mutex,
                                       NXT_INFINITE_NSEC);

            if (nxt_slow_path(err != 0)) {
                (void) nxt_thread_mutex_unlock(&nxt_app_mutex);
                return NXT_ERROR;
            }
        }

        (void) nxt_thread_mutex_unlock(&nxt_app_mutex);

        if (b == NULL) {
            start = nxt_malloc(4096);
            if (nxt_slow_path(start == NULL)) {
                return NXT_ERROR;
            }

            ab = nxt_zalloc(sizeof(nxt_app_buf_t));
            if (nxt_slow_path(ab == NULL)) {
                return NXT_ERROR;
            }

            b = &ab->buf;

            nxt_buf_mem_init(b, start, 4096);

            b->completion_handler = nxt_app_buf_completion;

            nxt_app_buf_current_number++;
        }

        bufs++;
    }

    r->output_buf = b;

    if (out != NULL) {
        *next = NULL;

        nxt_app_buf_send(r->event_conn, out);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_app_write_finish(nxt_app_request_t *r)
{
    nxt_buf_t  *b, *out;

    b = nxt_buf_sync_alloc(r->mem_pool, NXT_BUF_SYNC_LAST);
    if (nxt_slow_path(b == NULL)) {
        return NXT_ERROR;
    }

    b->completion_handler = nxt_app_buf_completion;
    b->parent = (nxt_buf_t *) r;

    out = r->output_buf;

    if (out != NULL) {
        r->output_buf = NULL;
        out->next = b;

    } else {
        out = b;
    }

    nxt_app_buf_send(r->event_conn, out);

    return NXT_OK;
}


static void
nxt_app_buf_send(nxt_event_conn_t *c, nxt_buf_t *out)
{
    nxt_app_buf_t  *ab;

    ab = nxt_container_of(out, nxt_app_buf_t, buf);

    nxt_work_set(&ab->work, nxt_app_delivery_handler, &c->task, c, out);

    nxt_event_engine_post(nxt_app_engine, &ab->work);
}


static void
nxt_app_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t  *b;

    b = obj;

    nxt_debug(task, "app buf completion");

    b->next = nxt_app_buf_done;
    nxt_app_buf_done = b;
}


static void
nxt_app_delivery_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t         *b;
    nxt_mem_pool_t    *mp;
    nxt_event_conn_t  *c;

    c = obj;
    b = data;

    nxt_debug(task, "app delivery handler");

    if (c->write != NULL) {
        nxt_buf_chain_add(&c->write, b);
        return;
    }

    if (c->mem_pool == NULL) {
        mp = nxt_mem_pool_create(256);
        if (nxt_slow_path(mp == NULL)) {
            close(c->socket.fd);
            return;
        }

        c->mem_pool = mp;
        nxt_app_conn_update(task->thread, c, &nxt_main_log);
    }

    if (c->socket.timedout || c->socket.error != 0) {
        nxt_buf_chain_add(&nxt_app_buf_done, b);
        nxt_work_queue_add(c->write_work_queue, nxt_app_delivery_completion,
                           task, c, NULL);
        return;
    }

    c->write = b;
    c->write_state = &nxt_app_delivery_write_state;

    nxt_event_conn_write(task, c);
}


static const nxt_event_conn_state_t  nxt_app_delivery_write_state
    nxt_aligned(64) =
{
    NXT_EVENT_BUF_PROCESS,
    NXT_EVENT_TIMER_AUTORESET,

    nxt_app_delivery_ready,
    NULL,
    nxt_app_delivery_error,

    nxt_app_delivery_timeout,
    nxt_app_delivery_timer_value,
    0,
};


static void
nxt_app_delivery_ready(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_t  *c;

    c = obj;

    nxt_debug(task, "app delivery ready");

    nxt_work_queue_add(c->write_work_queue,
                       nxt_app_delivery_completion, task, c, NULL);
}


static void
nxt_app_delivery_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t          *b, *bn, *free;
    nxt_app_request_t  *r;

    nxt_debug(task, "app delivery completion");

    free = NULL;

    for (b = nxt_app_buf_done; b; b = bn) {
        bn = b->next;

        if (nxt_buf_is_mem(b)) {
            b->mem.pos = b->mem.start;
            b->mem.free = b->mem.start;

            b->next = free;
            free = b;

            continue;
        }

        if (nxt_buf_is_last(b)) {
            r = (nxt_app_request_t *) b->parent;

            nxt_work_queue_add(&task->thread->engine->final_work_queue,
                               nxt_app_close_request, task, r, NULL);
        }
    }

    nxt_app_buf_done = NULL;

    if (free == NULL) {
        return;
    }

    if (nxt_slow_path(nxt_thread_mutex_lock(&nxt_app_mutex) != NXT_OK)) {
        return;
    }

    nxt_buf_chain_add(&nxt_app_buf_free, free);

    (void) nxt_thread_mutex_unlock(&nxt_app_mutex);

    nxt_thread_time_update(task->thread);

    (void) nxt_thread_cond_signal(&nxt_app_cond);
}


static void
nxt_app_delivery_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_t  *c;

    c = obj;

    nxt_debug(task, "app delivery error");

    nxt_app_delivery_done(task, c);
}


static void
nxt_app_delivery_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_t  *c;

    c = obj;

    nxt_debug(task, "app delivery timeout");

    nxt_app_delivery_done(task, c);
}


static nxt_msec_t
nxt_app_delivery_timer_value(nxt_event_conn_t *c, uintptr_t data)
{
    /* 30000 ms */
    return 30000;
}


static void
nxt_app_delivery_done(nxt_task_t *task, nxt_event_conn_t *c)
{
    if (c->write == NULL) {
        return;
    }

    nxt_debug(task, "app delivery done");

    nxt_buf_chain_add(&nxt_app_buf_done, c->write);

    c->write = NULL;

    nxt_work_queue_add(c->write_work_queue,
                       nxt_app_delivery_completion, task, c, NULL);
}


static void
nxt_app_close_request(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_t   *c;
    nxt_app_request_t  *r;

    r = obj;
    c = r->event_conn;

    nxt_debug(task, "app close connection");

    nxt_event_conn_close(task, c);

    nxt_mem_pool_destroy(c->mem_pool);
    nxt_mem_pool_destroy(r->mem_pool);
}

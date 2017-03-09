
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_master_process.h>


static void nxt_controller_conn_init(nxt_task_t *task, void *obj, void *data);
static void nxt_controller_conn_read(nxt_task_t *task, void *obj, void *data);
static nxt_msec_t nxt_controller_conn_timeout_value(nxt_event_conn_t *c,
    uintptr_t data);
static void nxt_controller_conn_read_error(nxt_task_t *task, void *obj,
    void *data);
static void nxt_controller_conn_read_timeout(nxt_task_t *task, void *obj,
    void *data);
static void nxt_controller_conn_close(nxt_task_t *task, void *obj, void *data);
static void nxt_controller_conn_free(nxt_task_t *task, void *obj, void *data);


static const nxt_event_conn_state_t  nxt_controller_conn_read_state;
static const nxt_event_conn_state_t  nxt_controller_conn_close_state;


nxt_int_t
nxt_controller_start(nxt_task_t *task, nxt_runtime_t *rt)
{
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
    nxt_buf_t           *b;
    nxt_event_conn_t    *c;
    nxt_event_engine_t  *engine;

    c = obj;

    nxt_debug(task, "controller conn init fd:%d", c->socket.fd);

    b = nxt_buf_mem_alloc(c->mem_pool, 1024, 0);
    if (nxt_slow_path(b == NULL)) {
        nxt_controller_conn_free(task, c, NULL);
        return;
    }

    c->read = b;
    c->socket.read_ready = 1;
    c->read_state = &nxt_controller_conn_read_state;

    engine = task->thread->engine;
    c->read_work_queue = &engine->read_work_queue;

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
    nxt_event_conn_t  *c;

    c = obj;

    nxt_debug(task, "controller conn read");

    nxt_controller_conn_close(task, c, c->socket.data);
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

    nxt_controller_conn_close(task, c, c->socket.data);
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

    nxt_controller_conn_close(task, c, c->socket.data);
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

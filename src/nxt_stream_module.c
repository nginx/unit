
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>


static void nxt_stream_connection_peer(nxt_task_t *task,
    nxt_upstream_peer_t *up);
static void nxt_stream_connection_close(nxt_task_t *task, void *obj,
    void *data);


void
nxt_stream_connection_init(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t           *c;
    nxt_runtime_t        *rt;
    nxt_upstream_peer_t  *up;

    c = obj;

    nxt_debug(task, "stream connection init");

    up = nxt_mp_zget(c->mem_pool, sizeof(nxt_upstream_peer_t));
    if (nxt_slow_path(up == NULL)) {
        goto fail;
    }

    up->data = c;

    rt = task->thread->runtime;

    if (rt->upstream.length != 0) {
        up->addr = rt->upstream;

    } else {
        nxt_str_set(&up->addr, "127.0.0.1:8080");
    }

    up->ready_handler = nxt_stream_connection_peer;
    up->mem_pool = c->mem_pool;

    nxt_upstream_round_robin_peer(task, up);
    return;

fail:

    /* TODO: close connection */
    return;
}


static void
nxt_stream_connection_peer(nxt_task_t *task, nxt_upstream_peer_t *up)
{
    nxt_conn_t        *c;
    nxt_conn_proxy_t  *p;

    c = up->data;

    up->sockaddr->type = SOCK_STREAM;

    nxt_log_debug(c->socket.log, "stream connection peer %*s",
                  (size_t) up->sockaddr->length,
                  nxt_sockaddr_start(up->sockaddr));

    p = nxt_conn_proxy_create(c);
    if (nxt_slow_path(p == NULL)) {
        goto fail;
    }

    p->client->socket.data = p;
    p->peer->socket.data = p;

    p->client_buffer_size = 1024;
    p->peer_buffer_size = 4096;
    //p->client_wait_timeout = 9000;
    p->connect_timeout = 7000;
    p->reconnect_timeout = 500;
    //p->peer_wait_timeout = 5000;
    p->client_write_timeout = 3000;
    p->peer_write_timeout = 3000;
    p->completion_handler = nxt_stream_connection_close;
    //p->retries = 10;
    p->peer->remote = up->sockaddr;

    if (0) {
        nxt_event_engine_t      *engine;
        nxt_event_write_rate_t  *rate;

        rate = nxt_mp_get(c->mem_pool, sizeof(nxt_event_write_rate_t));

        if (nxt_slow_path(rate == NULL)) {
            goto fail;
        }

        c->rate = rate;

        rate->limit = 1024;
        rate->limit_after = 0;
        rate->average = rate->limit;

        engine = nxt_thread_event_engine();
        rate->last = engine->timers.now;
    }

    nxt_conn_proxy(task, p);
    return;

fail:

    /* TODO: close connection */
    return;
}


static void
nxt_stream_connection_close(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_proxy_t  *p;

    p = obj;

    nxt_log_debug(p->client->socket.log, "stream connection close");

    nxt_mp_destroy(p->client->mem_pool);
}

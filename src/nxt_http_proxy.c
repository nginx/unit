
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>
#include <nxt_upstream.h>


struct nxt_upstream_proxy_s {
    nxt_sockaddr_t  *sockaddr;
    uint8_t         protocol;
};


static void nxt_http_proxy_server_get(nxt_task_t *task,
    nxt_upstream_server_t *us);
static void nxt_http_proxy_upstream_ready(nxt_task_t *task,
    nxt_upstream_server_t *us);
static void nxt_http_proxy_upstream_error(nxt_task_t *task,
    nxt_upstream_server_t *us);
static nxt_http_action_t *nxt_http_proxy(nxt_task_t *task,
    nxt_http_request_t *r, nxt_http_action_t *action);
static void nxt_http_proxy_header_send(nxt_task_t *task, void *obj, void *data);
static void nxt_http_proxy_header_sent(nxt_task_t *task, void *obj, void *data);
static void nxt_http_proxy_header_read(nxt_task_t *task, void *obj, void *data);
static void nxt_http_proxy_send_body(nxt_task_t *task, void *obj, void *data);
static void nxt_http_proxy_buf_mem_completion(nxt_task_t *task, void *obj,
    void *data);
static void nxt_http_proxy_error(nxt_task_t *task, void *obj, void *data);


static const nxt_http_request_state_t  nxt_http_proxy_header_send_state;
static const nxt_http_request_state_t  nxt_http_proxy_header_sent_state;
static const nxt_http_request_state_t  nxt_http_proxy_header_read_state;
static const nxt_http_request_state_t  nxt_http_proxy_read_state;


static const nxt_upstream_server_proto_t  nxt_upstream_simple_proto = {
    .get = nxt_http_proxy_server_get,
};


static const nxt_upstream_peer_state_t  nxt_upstream_proxy_state = {
    .ready = nxt_http_proxy_upstream_ready,
    .error = nxt_http_proxy_upstream_error,
};


nxt_int_t
nxt_http_proxy_init(nxt_mp_t *mp, nxt_http_action_t *action,
    nxt_http_action_conf_t *acf)
{
    nxt_str_t             name;
    nxt_sockaddr_t        *sa;
    nxt_upstream_t        *up;
    nxt_upstream_proxy_t  *proxy;

    sa = NULL;
    nxt_conf_get_string(acf->proxy, &name);

    if (nxt_str_start(&name, "http://", 7)) {
        name.length -= 7;
        name.start += 7;

        sa = nxt_sockaddr_parse(mp, &name);
        if (nxt_slow_path(sa == NULL)) {
            return NXT_ERROR;
        }

        sa->type = SOCK_STREAM;
    }

    if (sa != NULL) {
        up = nxt_mp_alloc(mp, sizeof(nxt_upstream_t));
        if (nxt_slow_path(up == NULL)) {
            return NXT_ERROR;
        }

        up->name.length = sa->length;
        up->name.start = nxt_sockaddr_start(sa);
        up->proto = &nxt_upstream_simple_proto;

        proxy = nxt_mp_alloc(mp, sizeof(nxt_upstream_proxy_t));
        if (nxt_slow_path(proxy == NULL)) {
            return NXT_ERROR;
        }

        proxy->sockaddr = sa;
        proxy->protocol = NXT_HTTP_PROTO_H1;
        up->type.proxy = proxy;

        action->u.upstream = up;
        action->handler = nxt_http_proxy;
    }

    return NXT_OK;
}


static nxt_http_action_t *
nxt_http_proxy(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_action_t *action)
{
    nxt_upstream_t  *u;

    u = action->u.upstream;

    nxt_debug(task, "http proxy: \"%V\"", &u->name);

    return nxt_upstream_proxy_handler(task, r, u);
}


nxt_http_action_t *
nxt_upstream_proxy_handler(nxt_task_t *task, nxt_http_request_t *r,
    nxt_upstream_t *upstream)
{
    nxt_http_peer_t        *peer;
    nxt_upstream_server_t  *us;

    us = nxt_mp_zalloc(r->mem_pool, sizeof(nxt_upstream_server_t));
    if (nxt_slow_path(us == NULL)) {
        nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    peer = nxt_mp_zalloc(r->mem_pool, sizeof(nxt_http_peer_t));
    if (nxt_slow_path(peer == NULL)) {
        nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    peer->request = r;
    r->peer = peer;

    nxt_mp_retain(r->mem_pool);

    us->state = &nxt_upstream_proxy_state;
    us->peer.http = peer;
    peer->server = us;

    us->upstream = upstream;
    upstream->proto->get(task, us);

    return NULL;
}


static void
nxt_http_proxy_server_get(nxt_task_t *task, nxt_upstream_server_t *us)
{
    nxt_upstream_proxy_t  *proxy;

    proxy = us->upstream->type.proxy;

    us->sockaddr = proxy->sockaddr;
    us->protocol = proxy->protocol;

    us->state->ready(task, us);
}


static void
nxt_http_proxy_upstream_ready(nxt_task_t *task, nxt_upstream_server_t *us)
{
    nxt_http_peer_t  *peer;

    peer = us->peer.http;

    peer->protocol = us->protocol;

    peer->request->state = &nxt_http_proxy_header_send_state;

    nxt_http_proto[peer->protocol].peer_connect(task, peer);
}


static void
nxt_http_proxy_upstream_error(nxt_task_t *task, nxt_upstream_server_t *us)
{
    nxt_http_request_t  *r;

    r = us->peer.http->request;

    nxt_mp_release(r->mem_pool);

    nxt_http_request_error(task, r, NXT_HTTP_BAD_GATEWAY);
}


static const nxt_http_request_state_t  nxt_http_proxy_header_send_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_http_proxy_header_send,
    .error_handler = nxt_http_proxy_error,
};


static void
nxt_http_proxy_header_send(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_peer_t     *peer;
    nxt_http_request_t  *r;

    r = obj;
    peer = data;
    r->state = &nxt_http_proxy_header_sent_state;

    nxt_http_proto[peer->protocol].peer_header_send(task, peer);
}


static const nxt_http_request_state_t  nxt_http_proxy_header_sent_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_http_proxy_header_sent,
    .error_handler = nxt_http_proxy_error,
};


static void
nxt_http_proxy_header_sent(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_peer_t     *peer;
    nxt_http_request_t  *r;

    r = obj;
    peer = data;
    r->state = &nxt_http_proxy_header_read_state;

    nxt_http_proto[peer->protocol].peer_header_read(task, peer);
}


static const nxt_http_request_state_t  nxt_http_proxy_header_read_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_http_proxy_header_read,
    .error_handler = nxt_http_proxy_error,
};


static void
nxt_http_proxy_header_read(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_peer_t     *peer;
    nxt_http_field_t    *f, *field;
    nxt_http_request_t  *r;

    r = obj;
    peer = data;

    r->status = peer->status;

    nxt_debug(task, "http proxy status: %d", peer->status);

    nxt_list_each(field, peer->fields) {

        nxt_debug(task, "http proxy header: \"%*s: %*s\"",
                  (size_t) field->name_length, field->name,
                  (size_t) field->value_length, field->value);

        if (!field->skip) {
            f = nxt_list_add(r->resp.fields);
            if (nxt_slow_path(f == NULL)) {
                nxt_http_proxy_error(task, r, peer);
                return;
            }

            *f = *field;
        }

    } nxt_list_loop;

    r->state = &nxt_http_proxy_read_state;

    nxt_http_request_header_send(task, r, nxt_http_proxy_send_body, peer);
}


static const nxt_http_request_state_t  nxt_http_proxy_read_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_http_proxy_send_body,
    .error_handler = nxt_http_proxy_error,
};


static void
nxt_http_proxy_send_body(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t           *out;
    nxt_http_peer_t     *peer;
    nxt_http_request_t  *r;

    r = obj;
    peer = data;
    out = peer->body;

    if (out != NULL) {
        peer->body = NULL;
        nxt_http_request_send(task, r, out);
    }

    if (!peer->closed) {
        nxt_http_proto[peer->protocol].peer_read(task, peer);

    } else {
        nxt_http_proto[peer->protocol].peer_close(task, peer);

        nxt_mp_release(r->mem_pool);
    }
}


nxt_buf_t *
nxt_http_proxy_buf_mem_alloc(nxt_task_t *task, nxt_http_request_t *r,
    size_t size)
{
    nxt_buf_t  *b;

    b = nxt_event_engine_buf_mem_alloc(task->thread->engine, size);
    if (nxt_fast_path(b != NULL)) {
        b->completion_handler = nxt_http_proxy_buf_mem_completion;
        b->parent = r;
        nxt_mp_retain(r->mem_pool);

    } else {
        nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
    }

    return b;
}


static void
nxt_http_proxy_buf_mem_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t           *b, *next;
    nxt_http_peer_t     *peer;
    nxt_http_request_t  *r;

    b = obj;
    r = data;

    peer = r->peer;

    do {
        next = b->next;

        nxt_http_proxy_buf_mem_free(task, r, b);

        b = next;
    } while (b != NULL);

    if (!peer->closed) {
        nxt_http_proto[peer->protocol].peer_read(task, peer);
    }
}


void
nxt_http_proxy_buf_mem_free(nxt_task_t *task, nxt_http_request_t *r,
    nxt_buf_t *b)
{
    nxt_event_engine_buf_mem_free(task->thread->engine, b);

    nxt_mp_release(r->mem_pool);
}


static void
nxt_http_proxy_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_peer_t     *peer;
    nxt_http_request_t  *r;

    r = obj;
    peer = r->peer;

    nxt_http_proto[peer->protocol].peer_close(task, peer);

    nxt_mp_release(r->mem_pool);

    nxt_http_request_error(&r->task, r, peer->status);
}


nxt_int_t
nxt_http_proxy_date(void *ctx, nxt_http_field_t *field, uintptr_t data)
{
    nxt_http_request_t  *r;

    r = ctx;

    r->resp.date = field;

    return NXT_OK;
}


nxt_int_t
nxt_http_proxy_content_length(void *ctx, nxt_http_field_t *field,
    uintptr_t data)
{
    nxt_off_t           n;
    nxt_http_request_t  *r;

    r = ctx;

    r->resp.content_length = field;

    n = nxt_off_t_parse(field->value, field->value_length);

    if (nxt_fast_path(n >= 0)) {
        r->resp.content_length_n = n;
    }

    return NXT_OK;
}


nxt_int_t
nxt_http_proxy_skip(void *ctx, nxt_http_field_t *field, uintptr_t data)
{
    field->skip = 1;

    return NXT_OK;
}

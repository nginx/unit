
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


typedef void (*nxt_http_upstream_connect_t)(nxt_task_t *task,
    nxt_http_upstream_t *upstream, nxt_http_peer_t *peer);


struct nxt_http_upstream_s {
    uint32_t                     current;
    uint32_t                     n;
    uint8_t                      protocol;
    nxt_http_upstream_connect_t  connect;
    nxt_sockaddr_t               *sockaddr[1];
};


static void nxt_http_upstream_connect(nxt_task_t *task,
    nxt_http_upstream_t *upstream, nxt_http_peer_t *peer);
static nxt_http_action_t *nxt_http_proxy_handler(nxt_task_t *task,
    nxt_http_request_t *r, nxt_http_action_t *action);
static void nxt_http_proxy_header_send(nxt_task_t *task, void *obj, void *data);
static void nxt_http_proxy_header_sent(nxt_task_t *task, void *obj, void *data);
static void nxt_http_proxy_header_read(nxt_task_t *task, void *obj, void *data);
static void nxt_http_proxy_send_body(nxt_task_t *task, void *obj, void *data);
static void nxt_http_proxy_request_send(nxt_task_t *task,
    nxt_http_request_t *r, nxt_buf_t *out);
static void nxt_http_proxy_read(nxt_task_t *task, void *obj, void *data);
static void nxt_http_proxy_buf_mem_completion(nxt_task_t *task, void *obj,
    void *data);
static void nxt_http_proxy_error(nxt_task_t *task, void *obj, void *data);


static const nxt_http_request_state_t  nxt_http_proxy_header_send_state;
static const nxt_http_request_state_t  nxt_http_proxy_header_sent_state;
static const nxt_http_request_state_t  nxt_http_proxy_header_read_state;
static const nxt_http_request_state_t  nxt_http_proxy_read_state;


nxt_int_t
nxt_http_proxy_create(nxt_mp_t *mp, nxt_http_action_t *action)
{
    nxt_str_t            name;
    nxt_sockaddr_t       *sa;
    nxt_http_upstream_t  *upstream;

    sa = NULL;
    name = action->name;

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
        upstream = nxt_mp_alloc(mp, sizeof(nxt_http_upstream_t));
        if (nxt_slow_path(upstream == NULL)) {
            return NXT_ERROR;
        }

        upstream->current = 0;
        upstream->n = 1;
        upstream->protocol = NXT_HTTP_PROTO_H1;
        upstream->connect = nxt_http_upstream_connect;
        upstream->sockaddr[0] = sa;

        action->u.upstream = upstream;
        action->handler = nxt_http_proxy_handler;
    }

    return NXT_OK;
}


static nxt_http_action_t *
nxt_http_proxy_handler(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_action_t *action)
{
    nxt_http_peer_t  *peer;

    peer = nxt_mp_zalloc(r->mem_pool, sizeof(nxt_http_peer_t));
    if (nxt_slow_path(peer == NULL)) {
        nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    peer->request = r;
    r->peer = peer;

    nxt_mp_retain(r->mem_pool);

    action->u.upstream->connect(task, action->u.upstream, peer);

    return NULL;
}


static void
nxt_http_upstream_connect(nxt_task_t *task, nxt_http_upstream_t *upstream,
    nxt_http_peer_t *peer)
{
    peer->protocol = upstream->protocol;
    peer->sockaddr = upstream->sockaddr[0];

    peer->request->state = &nxt_http_proxy_header_send_state;

    nxt_http_proto[peer->protocol].peer_connect(task, peer);
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

    if (r->resp.content_length_n > 0) {
        peer->remainder = r->resp.content_length_n;
    }

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

    nxt_http_request_header_send(task, r, nxt_http_proxy_send_body, peer);
}


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
        nxt_http_proxy_request_send(task, r, out);
    }

    r->state = &nxt_http_proxy_read_state;

    nxt_http_proto[peer->protocol].peer_read(task, peer);
}


static void
nxt_http_proxy_request_send(nxt_task_t *task, nxt_http_request_t *r,
    nxt_buf_t *out)
{
    size_t  length;

    if (r->peer->remainder > 0) {
        length = nxt_buf_chain_length(out);
        r->peer->remainder -= length;
    }

    nxt_http_request_send(task, r, out);
}


static const nxt_http_request_state_t  nxt_http_proxy_read_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_http_proxy_read,
    .error_handler = nxt_http_proxy_error,
};


static void
nxt_http_proxy_read(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t           *out;
    nxt_bool_t          last;
    nxt_http_peer_t     *peer;
    nxt_http_request_t  *r;

    r = obj;
    peer = data;
    out = peer->body;
    peer->body = NULL;
    last = nxt_buf_is_last(out);

    nxt_http_proxy_request_send(task, r, out);

    if (!last) {
        nxt_http_proto[peer->protocol].peer_read(task, peer);

    } else {
        r->inconsistent = (peer->remainder != 0);

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

    nxt_http_request_error(task, r, peer->status);
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

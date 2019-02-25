
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_port_rpc.h>


static nxt_atomic_t  nxt_stream_ident = 1;

typedef struct nxt_port_rpc_reg_s nxt_port_rpc_reg_t;

struct nxt_port_rpc_reg_s {
    uint32_t                stream;

    nxt_pid_t               peer;
    nxt_queue_link_t        link;
    nxt_bool_t              link_first;

    nxt_port_rpc_handler_t  ready_handler;
    nxt_port_rpc_handler_t  error_handler;
    void                    *data;
};


static void
nxt_port_rpc_remove_from_peers(nxt_task_t *task, nxt_port_t *port,
    nxt_port_rpc_reg_t *reg);


static nxt_int_t
nxt_rpc_reg_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    return NXT_OK;
}


static const nxt_lvlhsh_proto_t  lvlhsh_rpc_reg_proto  nxt_aligned(64) = {
    NXT_LVLHSH_DEFAULT,
    nxt_rpc_reg_test,
    nxt_lvlhsh_alloc,
    nxt_lvlhsh_free,
};


nxt_inline void
nxt_port_rpc_lhq_stream(nxt_lvlhsh_query_t *lhq, uint32_t *stream)
{
    lhq->key_hash = nxt_murmur_hash2(stream, sizeof(*stream));
    lhq->key.length = sizeof(*stream);
    lhq->key.start = (u_char *) stream;
    lhq->proto = &lvlhsh_rpc_reg_proto;
}


nxt_inline void
nxt_port_rpc_lhq_peer(nxt_lvlhsh_query_t *lhq, nxt_pid_t *peer)
{
    lhq->key_hash = nxt_murmur_hash2(peer, sizeof(*peer));
    lhq->key.length = sizeof(*peer);
    lhq->key.start = (u_char *) peer;
    lhq->proto = &lvlhsh_rpc_reg_proto;
}


uint32_t
nxt_port_rpc_register_handler(nxt_task_t *task, nxt_port_t *port,
    nxt_port_rpc_handler_t ready_handler, nxt_port_rpc_handler_t error_handler,
    nxt_pid_t peer, void *data)
{
    void                *ex;
    nxt_port_rpc_reg_t  *reg;

    ex = nxt_port_rpc_register_handler_ex(task, port, ready_handler,
                                          error_handler, 0);

    if (ex == NULL) {
        return 0;
    }

    if (peer != -1) {
        nxt_port_rpc_ex_set_peer(task, port, ex, peer);
    }

    reg = nxt_pointer_to(ex, -sizeof(nxt_port_rpc_reg_t));

    nxt_assert(reg->data == ex);

    reg->data = data;

    return reg->stream;
}


void *
nxt_port_rpc_register_handler_ex(nxt_task_t *task, nxt_port_t *port,
    nxt_port_rpc_handler_t ready_handler, nxt_port_rpc_handler_t error_handler,
    size_t ex_size)
{
    uint32_t            stream;
    nxt_port_rpc_reg_t  *reg;
    nxt_lvlhsh_query_t  lhq;

    nxt_assert(port->pair[0] != -1);

    stream =
        (uint32_t) nxt_atomic_fetch_add(&nxt_stream_ident, 1) & 0x3FFFFFFF;

    reg = nxt_mp_zalloc(port->mem_pool, sizeof(nxt_port_rpc_reg_t) + ex_size);

    if (nxt_slow_path(reg == NULL)) {
        nxt_debug(task, "rpc: stream #%uD failed to allocate reg", stream);

        return NULL;
    }

    reg->stream = stream;
    reg->peer = -1;
    reg->ready_handler = ready_handler;
    reg->error_handler = error_handler;
    reg->data = reg + 1;

    nxt_port_rpc_lhq_stream(&lhq, &stream);
    lhq.replace = 0;
    lhq.value = reg;
    lhq.pool = port->mem_pool;

    switch (nxt_lvlhsh_insert(&port->rpc_streams, &lhq)) {

    case NXT_OK:
        break;

    default:
        nxt_log_error(NXT_LOG_ERR, task->log, "rpc: stream #%uD failed to add "
                      "reg ", stream);

        nxt_mp_free(port->mem_pool, reg);

        return NULL;
    }

    nxt_debug(task, "rpc: stream #%uD registered", stream);

    nxt_port_inc_use(port);

    return reg->data;
}


uint32_t
nxt_port_rpc_ex_stream(void *ex)
{
    nxt_port_rpc_reg_t  *reg;

    reg = nxt_pointer_to(ex, -sizeof(nxt_port_rpc_reg_t));

    nxt_assert(reg->data == ex);

    return reg->stream;
}


void
nxt_port_rpc_ex_set_peer(nxt_task_t *task, nxt_port_t *port,
    void *ex, nxt_pid_t peer)
{
    nxt_int_t           ret;
    nxt_queue_link_t    *peer_link;
    nxt_port_rpc_reg_t  *reg;
    nxt_lvlhsh_query_t  lhq;

    reg = nxt_pointer_to(ex, -sizeof(nxt_port_rpc_reg_t));

    nxt_assert(reg->data == ex);

    if (nxt_slow_path(peer == reg->peer)) {
        return;
    }

    if (reg->peer != -1) {
        nxt_port_rpc_remove_from_peers(task, port, reg);

        reg->peer = -1;
    }

    if (peer == -1) {
        return;
    }

    reg->peer = peer;

    nxt_port_rpc_lhq_peer(&lhq, &peer);
    lhq.replace = 0;
    lhq.value = &reg->link;
    lhq.pool = port->mem_pool;

    ret = nxt_lvlhsh_insert(&port->rpc_peers, &lhq);

    switch (ret) {

    case NXT_OK:
        reg->link_first = 1;
        nxt_queue_self(&reg->link);

        nxt_debug(task, "rpc: stream #%uD assigned uniq pid %PI (%p)",
                  reg->stream, reg->peer, reg->link.next);
        break;

    case NXT_DECLINED:
        reg->link_first = 0;
        peer_link = lhq.value;
        nxt_queue_insert_after(peer_link, &reg->link);

        nxt_debug(task, "rpc: stream #%uD assigned duplicate pid %PI (%p)",
                  reg->stream, reg->peer, reg->link.next);
        break;

    default:
        nxt_log_error(NXT_LOG_ERR, task->log, "rpc: failed to add "
                      "peer for stream #%uD (%d)", reg->stream, ret);

        reg->peer = -1;
        break;
    }

}


static void
nxt_port_rpc_remove_from_peers(nxt_task_t *task, nxt_port_t *port,
    nxt_port_rpc_reg_t *reg)
{
    uint32_t            stream;
    nxt_int_t           ret;
    nxt_lvlhsh_query_t  lhq;
    nxt_port_rpc_reg_t  *r;

    stream = reg->stream;

    if (reg->link_first != 0) {
        nxt_port_rpc_lhq_peer(&lhq, &reg->peer);
        lhq.pool = port->mem_pool;

        if (reg->link.next == &reg->link) {
            nxt_assert(reg->link.prev == &reg->link);

            nxt_debug(task, "rpc: stream #%uD remove first and last pid %PI "
                      "registration (%p)", stream, reg->peer, reg->link.next);

            ret = nxt_lvlhsh_delete(&port->rpc_peers, &lhq);

        } else {
            nxt_debug(task, "rpc: stream #%uD remove first pid %PI "
                      "registration (%p)", stream, reg->peer, reg->link.next);

            lhq.replace = 1;
            lhq.value = reg->link.next;

            r = nxt_queue_link_data(reg->link.next, nxt_port_rpc_reg_t, link);
            r->link_first = 1;

            nxt_queue_remove(&reg->link);

            ret = nxt_lvlhsh_insert(&port->rpc_peers, &lhq);
        }

    } else {
        nxt_debug(task, "rpc: stream #%uD remove pid %PI "
                  "registration (%p)", stream, reg->peer, reg->link.next);

        nxt_queue_remove(&reg->link);
        ret = NXT_OK;
    }

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_log_error(NXT_LOG_ERR, task->log, "rpc: stream #%uD failed"
                      " to delete peer %PI (%d)", stream, reg->peer, ret);
    }
}


void
nxt_port_rpc_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    uint8_t              last;
    uint32_t             stream;
    nxt_int_t            ret;
    nxt_port_t           *port;
    nxt_port_rpc_reg_t   *reg;
    nxt_lvlhsh_query_t   lhq;
    nxt_port_msg_type_t  type;

    stream = msg->port_msg.stream;
    port = msg->port;
    last = msg->port_msg.last;
    type = msg->port_msg.type;

    nxt_port_rpc_lhq_stream(&lhq, &stream);
    lhq.pool = port->mem_pool;

    if (last != 0) {
        ret = nxt_lvlhsh_delete(&port->rpc_streams, &lhq);

    } else {
        ret = nxt_lvlhsh_find(&port->rpc_streams, &lhq);
    }

    if (ret != NXT_OK) {
        nxt_debug(task, "rpc: stream #%uD no handler found", stream);

        return;
    }

    nxt_debug(task, "rpc: stream #%uD %shandler, type %d", stream,
                    (last ? "last " : ""), type);

    reg = lhq.value;

    if (type == _NXT_PORT_MSG_RPC_ERROR) {
        reg->error_handler(task, msg, reg->data);

    } else {
        reg->ready_handler(task, msg, reg->data);
    }

    if (last == 0) {
        return;
    }

    if (reg->peer != -1) {
        nxt_port_rpc_remove_from_peers(task, port, reg);
    }

    nxt_debug(task, "rpc: stream #%uD free registration", stream);

    nxt_mp_free(port->mem_pool, reg);

    nxt_port_use(task, port, -1);
}


void
nxt_port_rpc_remove_peer(nxt_task_t *task, nxt_port_t *port, nxt_pid_t peer)
{
    uint8_t              last;
    uint32_t             stream;
    nxt_int_t            ret;
    nxt_buf_t            buf;
    nxt_queue_link_t     *peer_link, *next_link;
    nxt_port_rpc_reg_t   *reg;
    nxt_lvlhsh_query_t   lhq;
    nxt_port_recv_msg_t  msg;

    nxt_port_rpc_lhq_peer(&lhq, &peer);
    lhq.pool = port->mem_pool;

    ret = nxt_lvlhsh_delete(&port->rpc_peers, &lhq);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_debug(task, "rpc: no reg found for peer %PI", peer);

        return;
    }

    nxt_memzero(&msg, sizeof(msg));
    nxt_memzero(&buf, sizeof(buf));

    msg.fd = -1;
    msg.buf = &buf;
    msg.port = port;

    msg.port_msg.pid = peer;
    msg.port_msg.type = _NXT_PORT_MSG_REMOVE_PID;

    peer_link = lhq.value;
    last = 0;

    while (last == 0) {

        reg = nxt_queue_link_data(peer_link, nxt_port_rpc_reg_t, link);

        nxt_assert(reg->peer == peer);

        stream = reg->stream;

        nxt_debug(task, "rpc: stream #%uD trigger error", stream);

        msg.port_msg.stream = stream;
        msg.port_msg.last = 1;

        if (peer_link == peer_link->next) {
            nxt_assert(peer_link->prev == peer_link);

            last = 1;

        } else {
            nxt_assert(peer_link->next->prev == peer_link);
            nxt_assert(peer_link->prev->next == peer_link);

            next_link = peer_link->next;
            nxt_queue_remove(peer_link);

            peer_link = next_link;
        }

        reg->peer = -1;

        reg->error_handler(task, &msg, reg->data);

        /* Reset 'last' flag to preserve rpc handler. */
        if (msg.port_msg.last == 0) {
            continue;
        }

        nxt_port_rpc_lhq_stream(&lhq, &stream);
        lhq.pool = port->mem_pool;

        ret = nxt_lvlhsh_delete(&port->rpc_streams, &lhq);

        if (nxt_slow_path(ret != NXT_OK)) {
            nxt_log_error(NXT_LOG_ERR, task->log,
                          "rpc: stream #%uD failed to delete handler", stream);

            return;
        }

        nxt_mp_free(port->mem_pool, reg);

        nxt_port_use(task, port, -1);
    }
}


void
nxt_port_rpc_cancel(nxt_task_t *task, nxt_port_t *port, uint32_t stream)
{
    nxt_int_t           ret;
    nxt_port_rpc_reg_t  *reg;
    nxt_lvlhsh_query_t  lhq;

    nxt_port_rpc_lhq_stream(&lhq, &stream);
    lhq.pool = port->mem_pool;

    ret = nxt_lvlhsh_delete(&port->rpc_streams, &lhq);

    if (ret != NXT_OK) {
        nxt_debug(task, "rpc: stream #%uD no handler found", stream);

        return;
    }

    reg = lhq.value;

    if (reg->peer != -1) {
        nxt_port_rpc_remove_from_peers(task, port, reg);
    }

    nxt_debug(task, "rpc: stream #%uD cancel registration", stream);

    nxt_mp_free(port->mem_pool, reg);

    nxt_port_use(task, port, -1);
}

static nxt_buf_t  nxt_port_close_dummy_buf;

void
nxt_port_rpc_close(nxt_task_t *task, nxt_port_t *port)
{
    nxt_port_rpc_reg_t   *reg;
    nxt_port_recv_msg_t  msg;

    for ( ;; ) {
        reg = nxt_lvlhsh_peek(&port->rpc_streams, &lvlhsh_rpc_reg_proto);
        if (reg == NULL) {
            return;
        }

        msg.fd = -1;
        msg.buf = &nxt_port_close_dummy_buf;
        msg.port = port;
        msg.port_msg.stream = reg->stream;
        msg.port_msg.pid = nxt_pid;
        msg.port_msg.type = _NXT_PORT_MSG_RPC_ERROR;
        msg.port_msg.last = 1;
        msg.port_msg.mmap = 0;
        msg.port_msg.nf = 0;
        msg.port_msg.mf = 0;
        msg.port_msg.tracking = 0;
        msg.size = 0;
        msg.cancelled = 0;
        msg.u.data = NULL;

        nxt_port_rpc_handler(task, &msg);
    }
}

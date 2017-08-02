
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_port_rpc.h>


typedef struct nxt_port_rpc_reg_s nxt_port_rpc_reg_t;

struct nxt_port_rpc_reg_s {
    uint32_t                stream;

    nxt_pid_t               peer;
    nxt_queue_link_t        link;

    nxt_port_rpc_handler_t  ready_handler;
    nxt_port_rpc_handler_t  error_handler;
    void                    *data;
};


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
    uint32_t            stream;
    nxt_queue_link_t    *peer_link;
    nxt_port_rpc_reg_t  *reg;
    nxt_lvlhsh_query_t  lhq;


    nxt_assert(port->pair[0] != -1);  

    stream = port->next_stream++;

    reg = nxt_mp_zalloc(port->mem_pool, sizeof(nxt_port_rpc_reg_t));

    if (nxt_slow_path(reg == NULL)) {
        nxt_log_error(NXT_LOG_ERR, task->log, "rpc: failed to allocate "
                      "reg for stream #%uD", stream);

        return 0;
    }

    reg->stream = stream;
    reg->peer = peer;
    reg->ready_handler = ready_handler;
    reg->error_handler = error_handler;
    reg->data = data;


    nxt_port_rpc_lhq_stream(&lhq, &stream);
    lhq.replace = 0;
    lhq.value = reg;
    lhq.pool = port->mem_pool;

    switch (nxt_lvlhsh_insert(&port->rpc_streams, &lhq)) {

    case NXT_OK:
        break;

    default:
        nxt_log_error(NXT_LOG_ERR, task->log, "rpc: failed to add handler "
                      "for stream #%uD", stream);

        nxt_mp_free(port->mem_pool, reg);

        return 0;
    }


    nxt_port_rpc_lhq_peer(&lhq, &peer);
    lhq.replace = 0;
    lhq.value = &reg->link;
    lhq.pool = port->mem_pool;

    switch (nxt_lvlhsh_insert(&port->rpc_peers, &lhq)) {

    case NXT_OK:
        nxt_queue_self(&reg->link);
        break;

    case NXT_DECLINED:
        peer_link = lhq.value;
        nxt_queue_insert_before(peer_link, &reg->link);
        break;

    default:
        nxt_log_error(NXT_LOG_ERR, task->log, "rpc: failed to add peer "
                      "for stream #%uD", stream);
        break;
    }

    return stream;
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

    nxt_debug(task, "rpc: handler for stream #%uD, type %d", stream, type);

    nxt_port_rpc_lhq_stream(&lhq, &stream);
    lhq.pool = port->mem_pool;

    if (last != 0) {
        ret = nxt_lvlhsh_delete(&port->rpc_streams, &lhq);
    } else {
        ret = nxt_lvlhsh_find(&port->rpc_streams, &lhq);
    }

    if (ret != NXT_OK) {
        nxt_debug(task, "rpc: no handler found for stream #%uD", stream);

        return;
    }

    reg = lhq.value;

    nxt_assert(reg->peer == msg->port_msg.pid);

    if (type == _NXT_PORT_MSG_RPC_ERROR) {
        reg->error_handler(task, msg, reg->data);
    } else {
        reg->ready_handler(task, msg, reg->data);
    }

    if (last == 0) {
        nxt_debug(task, "rpc: keep handler for stream #%uD", stream);

        return;
    }

    if (reg->link.next == &reg->link) {
        nxt_port_rpc_lhq_peer(&lhq, &reg->peer);
        lhq.pool = port->mem_pool;

        ret = nxt_lvlhsh_delete(&port->rpc_peers, &lhq);

        if (nxt_slow_path(ret != NXT_OK)) {
            nxt_log_error(NXT_LOG_ERR, task->log, "rpc: failed to delete "
                          "peer %PI", reg->peer);
        }
    } else {
        nxt_queue_remove(&reg->link);
    }

    nxt_mp_free(port->mem_pool, reg);
}


void
nxt_port_rpc_remove_peer(nxt_task_t *task, nxt_port_t *port, nxt_pid_t peer)
{
    uint8_t              last;
    uint32_t             stream;
    nxt_int_t            ret;
    nxt_buf_t            buf;
    nxt_queue_link_t     *peer_link;
    nxt_port_rpc_reg_t   *reg;
    nxt_lvlhsh_query_t   lhq;
    nxt_port_recv_msg_t  msg;

    nxt_port_rpc_lhq_peer(&lhq, &peer);
    lhq.pool = port->mem_pool;

    ret = nxt_lvlhsh_delete(&port->rpc_peers, &lhq);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_debug(task, "rpc: no handler found for peer %PI", peer);

        return;
    }

    nxt_memzero(&msg, sizeof(msg));
    nxt_memzero(&buf, sizeof(buf));

    msg.fd = -1;
    msg.buf = &buf;
    msg.port = port;

    msg.port_msg.pid = peer;
    msg.port_msg.type = _NXT_PORT_MSG_REMOVE_PID;
    msg.port_msg.last = 1;

    peer_link = lhq.value;
    last = 0;

    while (last == 0) {

        reg = nxt_queue_link_data(peer_link, nxt_port_rpc_reg_t, link);

        nxt_debug(task, "rpc: trigger error for stream #%uD", reg->stream);

        msg.port_msg.stream = reg->stream;

        reg->error_handler(task, &msg, reg->data);


        stream = reg->stream;

        nxt_port_rpc_lhq_stream(&lhq, &stream);
        lhq.pool = port->mem_pool;

        ret = nxt_lvlhsh_delete(&port->rpc_streams, &lhq);

        if (nxt_slow_path(ret != NXT_OK)) {
            nxt_log_error(NXT_LOG_ERR, task->log, "rpc: failed to delete "
                          "handler for stream #%uD", stream);

            return;
        }

        if (peer_link == peer_link->next) {
            last = 1;

        } else {
            peer_link = peer_link->next;
            nxt_queue_remove(peer_link->prev);
        }

        nxt_mp_free(port->mem_pool, reg);
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
        nxt_debug(task, "rpc: no handler found for stream %uxD", stream);

        return;
    }

    reg = lhq.value;

    if (reg->link.next == &reg->link) {
        nxt_port_rpc_lhq_peer(&lhq, &reg->peer);
        lhq.pool = port->mem_pool;

        ret = nxt_lvlhsh_delete(&port->rpc_peers, &lhq);

        if (nxt_slow_path(ret != NXT_OK)) {
            nxt_log_error(NXT_LOG_ERR, task->log, "rpc: failed to delete "
                          "peer %PI", reg->peer);
        }
    } else {
        nxt_queue_remove(&reg->link);
    }

    nxt_mp_free(port->mem_pool, reg);
}

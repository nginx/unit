
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_port_hash.h>


// Explicitly using 32 bit types to avoid possible alignment.
typedef struct {
    int32_t   pid;
    uint32_t  port_id;
} nxt_pid_port_id_t;


static nxt_int_t
nxt_port_hash_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_port_t         *port;
    nxt_pid_port_id_t  *pid_port_id;

    port = data;
    pid_port_id = (nxt_pid_port_id_t *) lhq->key.start;

    if (lhq->key.length == sizeof(nxt_pid_port_id_t) &&
        pid_port_id->pid == port->pid &&
        pid_port_id->port_id == port->id) {
        return NXT_OK;
    }

    return NXT_DECLINED;
}

static const nxt_lvlhsh_proto_t  lvlhsh_ports_proto  nxt_aligned(64) = {
    NXT_LVLHSH_DEFAULT,
    nxt_port_hash_test,
    nxt_lvlhsh_alloc,
    nxt_lvlhsh_free,
};


nxt_port_t *
nxt_port_hash_first(nxt_lvlhsh_t *port_hash, nxt_lvlhsh_each_t *lhe)
{
    nxt_memzero(lhe, sizeof(nxt_lvlhsh_each_t));

    lhe->proto = &lvlhsh_ports_proto;

    return nxt_port_hash_next(port_hash, lhe);
}


void
nxt_port_hash_add(nxt_lvlhsh_t *port_hash, nxt_mp_t *mem_pool,
    nxt_port_t *port)
{
    nxt_pid_port_id_t   pid_port;
    nxt_lvlhsh_query_t  lhq;

    pid_port.pid = port->pid;
    pid_port.port_id = port->id;

    lhq.key_hash = nxt_murmur_hash2(&pid_port, sizeof(pid_port));
    lhq.key.length = sizeof(pid_port);
    lhq.key.start = (u_char *) &pid_port;
    lhq.proto = &lvlhsh_ports_proto;
    lhq.replace = 0;
    lhq.value = port;
    lhq.pool = mem_pool;

    switch (nxt_lvlhsh_insert(port_hash, &lhq)) {

    case NXT_OK:
        break;

    default:
        nxt_thread_log_error(NXT_LOG_WARN, "port #%d for pid %PI add failed",
                             port->id, port->pid);
        break;
    }
}


void
nxt_port_hash_remove(nxt_lvlhsh_t *port_hash, nxt_mp_t *mem_pool,
    nxt_port_t *port)
{
    nxt_pid_port_id_t   pid_port;
    nxt_lvlhsh_query_t  lhq;

    pid_port.pid = port->pid;
    pid_port.port_id = port->id;

    lhq.key_hash = nxt_murmur_hash2(&pid_port, sizeof(pid_port));
    lhq.key.length = sizeof(pid_port);
    lhq.key.start = (u_char *) &pid_port;
    lhq.proto = &lvlhsh_ports_proto;
    lhq.replace = 0;
    lhq.value = port;
    lhq.pool = mem_pool;

    switch (nxt_lvlhsh_delete(port_hash, &lhq)) {

    case NXT_OK:
        break;

    default:
        break;
    }
}


nxt_port_t *
nxt_port_hash_find(nxt_lvlhsh_t *port_hash, nxt_pid_t pid,
    nxt_port_id_t port_id)
{
    nxt_pid_port_id_t   pid_port;
    nxt_lvlhsh_query_t  lhq;

    pid_port.pid = pid;
    pid_port.port_id = port_id;

    lhq.key_hash = nxt_murmur_hash2(&pid_port, sizeof(pid_port));
    lhq.key.length = sizeof(pid_port);
    lhq.key.start = (u_char *) &pid_port;
    lhq.proto = &lvlhsh_ports_proto;

    /* TODO lock ports */

    if (nxt_lvlhsh_find(port_hash, &lhq) == NXT_OK) {
        nxt_thread_log_debug("process port (%PI, %d) found", pid, port_id);
        return lhq.value;
    }

    nxt_thread_log_debug("process port (%PI, %d) not found", pid, port_id);

    return NULL;
}

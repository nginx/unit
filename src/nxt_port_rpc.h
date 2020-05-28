
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PORT_RPC_H_INCLUDED_
#define _NXT_PORT_RPC_H_INCLUDED_


typedef void (*nxt_port_rpc_handler_t)(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);

nxt_int_t nxt_port_rpc_init(void);

uint32_t nxt_port_rpc_register_handler(nxt_task_t *task, nxt_port_t *port,
    nxt_port_rpc_handler_t ready_handler, nxt_port_rpc_handler_t error_handler,
    nxt_pid_t peer, void *data);
void *nxt_port_rpc_register_handler_ex(nxt_task_t *task, nxt_port_t *port,
    nxt_port_rpc_handler_t ready_handler, nxt_port_rpc_handler_t error_handler,
    size_t ex_size);

uint32_t nxt_port_rpc_ex_stream(void *ex);
void nxt_port_rpc_ex_set_peer(nxt_task_t *task, nxt_port_t *port,
    void *ex, nxt_pid_t peer);

void nxt_port_rpc_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_port_rpc_remove_peer(nxt_task_t *task, nxt_port_t *port,
    nxt_pid_t peer);
void nxt_port_rpc_cancel(nxt_task_t *task, nxt_port_t *port, uint32_t stream);
void nxt_port_rpc_close(nxt_task_t *task, nxt_port_t *port);


#endif /* _NXT_PORT_RPC_H_INCLUDED_ */


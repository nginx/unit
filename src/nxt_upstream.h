
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UPSTREAM_H_INCLUDED_
#define _NXT_UPSTREAM_H_INCLUDED_


typedef struct nxt_upstream_peer_s    nxt_upstream_peer_t;


struct nxt_upstream_peer_s {
    /* STUB */
    void            *upstream;
    void            *data;
    /**/

    nxt_sockaddr_t  *sockaddr;
    nxt_nsec_t      delay;

    uint32_t        tries;
    in_port_t       port;

    nxt_str_t       addr;
    nxt_mp_t        *mem_pool;
    void            (*ready_handler)(nxt_task_t *task, nxt_upstream_peer_t *up);

    void            (*protocol_handler)(nxt_upstream_source_t *us);
};


typedef struct {
    void                        (*ready_handler)(void *data);
    nxt_work_handler_t          completion_handler;
    nxt_work_handler_t          error_handler;
} nxt_upstream_state_t;


/* STUB */
NXT_EXPORT void nxt_upstream_round_robin_peer(nxt_task_t *task,
    nxt_upstream_peer_t *up);
/**/


#endif /* _NXT_UPSTREAM_H_INCLUDED_ */

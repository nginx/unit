
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UPSTREAM_H_INCLUDED_
#define _NXT_UPSTREAM_H_INCLUDED_


typedef struct nxt_upstream_proxy_s            nxt_upstream_proxy_t;
typedef struct nxt_upstream_round_robin_s      nxt_upstream_round_robin_t;
typedef struct nxt_upstream_round_robin_server_s
    nxt_upstream_round_robin_server_t;


typedef void (*nxt_upstream_peer_ready_t)(nxt_task_t *task,
    nxt_upstream_server_t *us);
typedef void (*nxt_upstream_peer_error_t)(nxt_task_t *task,
    nxt_upstream_server_t *us);


typedef struct {
    nxt_upstream_peer_ready_t                  ready;
    nxt_upstream_peer_error_t                  error;
} nxt_upstream_peer_state_t;


typedef nxt_upstream_t *(*nxt_upstream_joint_create_t)(
    nxt_router_temp_conf_t *tmcf, nxt_upstream_t *upstream);
typedef void (*nxt_upstream_server_get_t)(nxt_task_t *task,
    nxt_upstream_server_t *us);


typedef struct {
    nxt_upstream_joint_create_t                joint_create;
    nxt_upstream_server_get_t                  get;
} nxt_upstream_server_proto_t;


struct nxt_upstream_s {
    const nxt_upstream_server_proto_t          *proto;

    union {
        nxt_upstream_proxy_t                   *proxy;
        nxt_upstream_round_robin_t             *round_robin;
    } type;

    nxt_str_t                                  name;
};


struct nxt_upstreams_s {
    uint32_t                                   items;
    nxt_upstream_t                             upstream[];
};


struct nxt_upstream_server_s {
    nxt_sockaddr_t                             *sockaddr;
    const nxt_upstream_peer_state_t            *state;
    nxt_upstream_t                             *upstream;

    uint8_t                                    protocol;

    union {
        nxt_upstream_round_robin_server_t      *round_robin;
    } server;

    union {
        nxt_http_peer_t                        *http;
    } peer;
};


nxt_int_t nxt_upstream_round_robin_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_conf_value_t *upstream_conf,
    nxt_upstream_t *upstream);


#endif /* _NXT_UPSTREAM_H_INCLUDED_ */

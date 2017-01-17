
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


typedef struct {
    void   (*peer_get)(nxt_upstream_peer_t *up);
    void   (*peer_free)(nxt_upstream_peer_t *up);
} nxt_upstream_name_t;


static const nxt_upstream_name_t  nxt_upstream_names[] = {

    { "round_robin", &nxt_upstream_round_robin },
};


void
nxt_upstream_create(nxt_upstream_peer_t *up)
{
    /* TODO: dynamic balancer add & lvlhsh */
    nxt_upstream_names[0].create(up);
}


void
nxt_upstream_peer(nxt_upstream_peer_t *up)
{
    nxt_upstream_t  *u;

    u = up->upstream;

    if (u != NULL) {
        u->peer_get(up);
        return;
    }

    nxt_upstream_create(up);
}

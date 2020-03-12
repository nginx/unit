
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>
#include <nxt_upstream.h>


struct nxt_upstream_round_robin_server_s {
    nxt_sockaddr_t                     *sockaddr;

    int32_t                            current_weight;
    int32_t                            effective_weight;
    int32_t                            weight;

    uint8_t                            protocol;
};


struct nxt_upstream_round_robin_s {
    uint32_t                           items;
    nxt_upstream_round_robin_server_t  server[0];
};


static nxt_upstream_t *nxt_upstream_round_robin_joint_create(
    nxt_router_temp_conf_t *tmcf, nxt_upstream_t *upstream);
static void nxt_upstream_round_robin_server_get(nxt_task_t *task,
    nxt_upstream_server_t *us);


static const nxt_upstream_server_proto_t  nxt_upstream_round_robin_proto = {
    .joint_create = nxt_upstream_round_robin_joint_create,
    .get          = nxt_upstream_round_robin_server_get,
};


static nxt_conf_map_t  nxt_upstream_round_robin_server_conf[] = {
    {
        nxt_string("weight"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_upstream_round_robin_server_t, weight),
    },
};


nxt_int_t
nxt_upstream_round_robin_create(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_conf_value_t *upstream_conf, nxt_upstream_t *upstream)
{
    size_t                      size;
    uint32_t                    i, n, next;
    nxt_mp_t                    *mp;
    nxt_str_t                   name;
    nxt_sockaddr_t              *sa;
    nxt_conf_value_t            *servers_conf, *srvcf;
    nxt_upstream_round_robin_t  *urr;

    static nxt_str_t  servers = nxt_string("servers");

    mp = tmcf->router_conf->mem_pool;

    servers_conf = nxt_conf_get_object_member(upstream_conf, &servers, NULL);
    n = nxt_conf_object_members_count(servers_conf);

    size = sizeof(nxt_upstream_round_robin_t)
           + n * sizeof(nxt_upstream_round_robin_server_t);

    urr = nxt_mp_zalloc(mp, size);
    if (nxt_slow_path(urr == NULL)) {
        return NXT_ERROR;
    }

    urr->items = n;
    next = 0;

    for (i = 0; i < n; i++) {
        srvcf = nxt_conf_next_object_member(servers_conf, &name, &next);

        sa = nxt_sockaddr_parse(mp, &name);
        if (nxt_slow_path(sa == NULL)) {
            return NXT_ERROR;
        }

        sa->type = SOCK_STREAM;

        urr->server[i].sockaddr = sa;
        urr->server[i].weight = 1;
        urr->server[i].protocol = NXT_HTTP_PROTO_H1;

        nxt_conf_map_object(mp, srvcf, nxt_upstream_round_robin_server_conf,
                            nxt_nitems(nxt_upstream_round_robin_server_conf),
                            &urr->server[i]);

        urr->server[i].effective_weight = urr->server[i].weight;
    }

    upstream->proto = &nxt_upstream_round_robin_proto;
    upstream->type.round_robin = urr;

    return NXT_OK;
}


static nxt_upstream_t *
nxt_upstream_round_robin_joint_create(nxt_router_temp_conf_t *tmcf,
    nxt_upstream_t *upstream)
{
    size_t                      size;
    uint32_t                    i, n;
    nxt_mp_t                    *mp;
    nxt_upstream_t              *u;
    nxt_upstream_round_robin_t  *urr, *urrcf;

    mp = tmcf->router_conf->mem_pool;

    u = nxt_mp_alloc(mp, sizeof(nxt_upstream_t));
    if (nxt_slow_path(u == NULL)) {
        return NULL;
    }

    *u = *upstream;

    urrcf = upstream->type.round_robin;

    size = sizeof(nxt_upstream_round_robin_t)
           + urrcf->items * sizeof(nxt_upstream_round_robin_server_t);

    urr = nxt_mp_alloc(mp, size);
    if (nxt_slow_path(urr == NULL)) {
        return NULL;
    }

    u->type.round_robin = urr;

    n = urrcf->items;
    urr->items = n;

    for (i = 0; i < n; i++) {
        urr->server[i] = urrcf->server[i];
    }

    return u;
}


static void
nxt_upstream_round_robin_server_get(nxt_task_t *task, nxt_upstream_server_t *us)
{
    int32_t                            total;
    uint32_t                           i, n;
    nxt_upstream_round_robin_t         *round_robin;
    nxt_upstream_round_robin_server_t  *s, *best;

    best = NULL;
    total = 0;

    round_robin = us->upstream->type.round_robin;

    s = round_robin->server;
    n = round_robin->items;

    for (i = 0; i < n; i++) {

        s[i].current_weight += s[i].effective_weight;
        total += s[i].effective_weight;

        if (s[i].effective_weight < s[i].weight) {
            s[i].effective_weight++;
        }

        if (best == NULL || s[i].current_weight > best->current_weight) {
            best = &s[i];
        }
    }

    if (best == NULL) {
        us->state->error(task, us);
        return;
    }

    best->current_weight -= total;
    us->sockaddr = best->sockaddr;
    us->protocol = best->protocol;
    us->server.round_robin = best;

    us->state->ready(task, us);
}

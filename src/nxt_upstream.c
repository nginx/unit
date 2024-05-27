
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>
#include <nxt_upstream.h>


static nxt_http_action_t *nxt_upstream_handler(nxt_task_t *task,
    nxt_http_request_t *r, nxt_http_action_t *action);


nxt_int_t
nxt_upstreams_create(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_conf_value_t *conf)
{
    size_t            size;
    uint32_t          i, n, next;
    nxt_mp_t          *mp;
    nxt_int_t         ret;
    nxt_str_t         name, *string;
    nxt_upstreams_t   *upstreams;
    nxt_conf_value_t  *upstreams_conf, *upcf;

    static const nxt_str_t  upstreams_name = nxt_string("upstreams");

    upstreams_conf = nxt_conf_get_object_member(conf, &upstreams_name, NULL);

    if (upstreams_conf == NULL) {
        return NXT_OK;
    }

    n = nxt_conf_object_members_count(upstreams_conf);

    if (n == 0) {
        return NXT_OK;
    }

    mp = tmcf->router_conf->mem_pool;
    size = sizeof(nxt_upstreams_t) + n * sizeof(nxt_upstream_t);

    upstreams = nxt_mp_zalloc(mp, size);
    if (nxt_slow_path(upstreams == NULL)) {
        return NXT_ERROR;
    }

    upstreams->items = n;
    next = 0;

    for (i = 0; i < n; i++) {
        upcf = nxt_conf_next_object_member(upstreams_conf, &name, &next);

        string = nxt_str_dup(mp, &upstreams->upstream[i].name, &name);
        if (nxt_slow_path(string == NULL)) {
            return NXT_ERROR;
        }

        ret = nxt_upstream_round_robin_create(task, tmcf, upcf,
                                              &upstreams->upstream[i]);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }
    }

    tmcf->router_conf->upstreams = upstreams;

    return NXT_OK;
}


nxt_int_t
nxt_upstream_find(nxt_upstreams_t *upstreams, nxt_str_t *name,
    nxt_http_action_t *action)
{
    uint32_t        i, n;
    nxt_upstream_t  *upstream;

    if (upstreams == NULL) {
        return NXT_DECLINED;
    }

    upstream = &upstreams->upstream[0];
    n = upstreams->items;

    for (i = 0; i < n; i++) {
        if (nxt_strstr_eq(&upstream[i].name, name)) {
            action->u.upstream_number = i;
            action->handler = nxt_upstream_handler;

            return NXT_OK;
        }
    }

    return NXT_DECLINED;
}


nxt_int_t
nxt_upstreams_joint_create(nxt_router_temp_conf_t *tmcf,
    nxt_upstream_t ***upstream_joint)
{
    uint32_t           i, n;
    nxt_upstream_t     *u, **up;
    nxt_upstreams_t    *upstreams;
    nxt_router_conf_t  *router_conf;

    router_conf = tmcf->router_conf;
    upstreams = router_conf->upstreams;

    if (upstreams == NULL) {
        *upstream_joint = NULL;
        return NXT_OK;
    }

    n = upstreams->items;

    up = nxt_mp_zalloc(router_conf->mem_pool, n * sizeof(nxt_upstream_t *));
    if (nxt_slow_path(up == NULL)) {
        return NXT_ERROR;
    }

    u = &upstreams->upstream[0];

    for (i = 0; i < n; i++) {
        up[i] = u[i].proto->joint_create(tmcf, &u[i]);
        if (nxt_slow_path(up[i] == NULL)) {
            return NXT_ERROR;
        }
    }

    *upstream_joint = up;

    return NXT_OK;
}


static nxt_http_action_t *
nxt_upstream_handler(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_action_t *action)
{
    nxt_upstream_t  *u;

    u = r->conf->upstreams[action->u.upstream_number];

    nxt_debug(task, "upstream handler: \"%V\"", &u->name);

    return nxt_upstream_proxy_handler(task, r, u);
}

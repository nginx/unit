
/*
 * Copyright (C) Zhidao HONG
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


nxt_int_t
nxt_http_rewrite_init(nxt_router_conf_t *rtcf, nxt_http_action_t *action,
    nxt_http_action_conf_t *acf)
{
    nxt_str_t  str;

    nxt_conf_get_string(acf->rewrite, &str);

    action->rewrite = nxt_tstr_compile(rtcf->tstr_state, &str, 0);
    if (nxt_slow_path(action->rewrite == NULL)) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


nxt_int_t
nxt_http_rewrite(nxt_task_t *task, nxt_http_request_t *r)
{
    nxt_int_t                 ret;
    nxt_str_t                 str;
    nxt_router_conf_t         *rtcf;
    nxt_http_action_t         *action;
    nxt_http_request_parse_t  rp;

    action = r->action;

    if (action == NULL || action->rewrite == NULL) {
        return NXT_OK;
    }

    if (nxt_tstr_is_const(action->rewrite)) {
        nxt_tstr_str(action->rewrite, &str);

    } else {
        rtcf = r->conf->socket_conf->router_conf;

        ret = nxt_tstr_query_init(&r->tstr_query, rtcf->tstr_state,
                                  &r->tstr_cache, r, r->mem_pool);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }

        nxt_tstr_query(task, r->tstr_query, action->rewrite, &str);

        if (nxt_slow_path(nxt_tstr_query_failed(r->tstr_query))) {
            return NXT_ERROR;
        }
    }

    nxt_memzero(&rp, sizeof(nxt_http_request_parse_t));

    rp.mem_pool = r->mem_pool;

    rp.target_start = str.start;
    rp.target_end = str.start + str.length;

    ret = nxt_http_parse_complex_target(&rp);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    r->path = nxt_mp_alloc(r->mem_pool, sizeof(nxt_str_t));
    if (nxt_slow_path(r->path == NULL)) {
        return NXT_ERROR;
    }

    *r->path = rp.path;

    r->uri_changed = 1;
    r->quoted_target = rp.quoted_target;

    if (nxt_slow_path(r->log_route)) {
        nxt_log(task, NXT_LOG_NOTICE, "URI rewritten to \"%V\"", r->path);
    }

    return NXT_OK;
}

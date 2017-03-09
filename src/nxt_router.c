
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_master_process.h>


static nxt_int_t nxt_router_listen_socket(nxt_task_t *task, nxt_runtime_t *rt);


nxt_int_t
nxt_router_start(nxt_task_t *task, nxt_runtime_t *rt)
{
    if (nxt_router_listen_socket(task, rt) != NXT_OK) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_router_listen_socket(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_sockaddr_t       *sa;
    nxt_listen_socket_t  *ls;

    sa = nxt_sockaddr_alloc(rt->mem_pool, sizeof(struct sockaddr_in),
                            NXT_INET_ADDR_STR_LEN);
    if (sa == NULL) {
        return NXT_ERROR;
    }

    sa->type = SOCK_STREAM;
    sa->u.sockaddr_in.sin_family = AF_INET;
    sa->u.sockaddr_in.sin_port = htons(8000);

    nxt_sockaddr_text(sa);

    ls = nxt_runtime_listen_socket_add(rt, sa);
    if (ls == NULL) {
        return NXT_ERROR;
    }

    ls->read_after_accept = 1;

    ls->flags = NXT_NONBLOCK;

#if 0
    /* STUB */
    wq = nxt_mem_zalloc(cf->mem_pool, sizeof(nxt_work_queue_t));
    if (wq == NULL) {
        return NXT_ERROR;
    }
    nxt_work_queue_name(wq, "listen");
    /**/

    ls->work_queue = wq;
#endif
    ls->handler = nxt_stream_connection_init;

    /*
     * Connection memory pool chunk size is tunned to
     * allocate the most data in one mem_pool chunk.
     */
    ls->mem_pool_size = nxt_listen_socket_pool_min_size(ls)
                        + sizeof(nxt_event_conn_proxy_t)
                        + sizeof(nxt_event_conn_t)
                        + 4 * sizeof(nxt_buf_t);

    if (nxt_listen_socket_create(task, ls, 0) != NXT_OK) {
        return NXT_ERROR;
    }

    if (nxt_event_conn_listen(task, ls) != NXT_OK) {
        return NXT_ERROR;
    }

    return NXT_OK;
}

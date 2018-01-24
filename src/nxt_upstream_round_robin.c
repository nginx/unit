
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


typedef struct {
    int32_t                          weight;
    int32_t                          effective_weight;
    int32_t                          current_weight;
    uint32_t                         down;              /* 1 bit */
    nxt_msec_t                       last_accessed;
    nxt_sockaddr_t                   *sockaddr;
} nxt_upstream_round_robin_peer_t;


typedef struct {
    nxt_uint_t                       npeers;
    nxt_upstream_round_robin_peer_t  *peers;
    nxt_thread_spinlock_t            lock;
} nxt_upstream_round_robin_t;


static void nxt_upstream_round_robin_create(nxt_task_t *task, void *obj,
    void *data);
static void nxt_upstream_round_robin_peer_error(nxt_task_t *task, void *obj,
    void *data);
static void nxt_upstream_round_robin_get_peer(nxt_task_t *task,
    nxt_upstream_peer_t *up);


void
nxt_upstream_round_robin_peer(nxt_task_t *task, nxt_upstream_peer_t *up)
{
    nxt_job_sockaddr_parse_t  *jbs;

    if (up->upstream != NULL) {
        nxt_upstream_round_robin_get_peer(task, up);
    }

    jbs = nxt_job_create(up->mem_pool, sizeof(nxt_job_sockaddr_parse_t));
    if (nxt_slow_path(jbs == NULL)) {
        up->ready_handler(task, up);
        return;
    }

    jbs->resolve.job.task = task;
    jbs->resolve.job.data = up;
    jbs->resolve.port = up->port;
    jbs->resolve.log_level = NXT_LOG_ERR;
    jbs->resolve.ready_handler = nxt_upstream_round_robin_create;
    jbs->resolve.error_handler = nxt_upstream_round_robin_peer_error;
    jbs->addr = up->addr;

    nxt_job_sockaddr_parse(jbs);
}


static void
nxt_upstream_round_robin_create(nxt_task_t *task, void *obj, void *data)
{
    nxt_uint_t                       i;
    nxt_sockaddr_t                   *sa;
    nxt_upstream_peer_t              *up;
    nxt_job_sockaddr_parse_t         *jbs;
    nxt_upstream_round_robin_t       *urr;
    nxt_upstream_round_robin_peer_t  *peer;

    jbs = obj;
    up = jbs->resolve.job.data;

    urr = nxt_mp_zget(up->mem_pool, sizeof(nxt_upstream_round_robin_t));
    if (nxt_slow_path(urr == NULL)) {
        goto fail;
    }

    urr->npeers = jbs->resolve.count;

    peer = nxt_mp_zget(up->mem_pool,
                       urr->npeers * sizeof(nxt_upstream_round_robin_peer_t));
    if (nxt_slow_path(peer == NULL)) {
        goto fail;
    }

    urr->peers = peer;

    for (i = 0; i < urr->npeers; i++) {
        peer[i].weight = 1;
        peer[i].effective_weight = 1;

        sa = jbs->resolve.sockaddrs[i];

        /* STUB */
        sa->type = SOCK_STREAM;

        nxt_sockaddr_text(sa);

        nxt_debug(task, "upstream peer: %*s",
                  (size_t) sa->length, nxt_sockaddr_start(sa));

        /* TODO: memcpy to shared memory pool. */
        peer[i].sockaddr = sa;
    }

    up->upstream = urr;

    /* STUB */
    up->sockaddr = peer[0].sockaddr;

    nxt_job_destroy(task, jbs);
    up->ready_handler(task, up);

    //nxt_upstream_round_robin_get_peer(up);
    return;

fail:

    nxt_job_destroy(task, jbs);

    up->ready_handler(task, up);
}


static void
nxt_upstream_round_robin_peer_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_upstream_peer_t       *up;
    nxt_job_sockaddr_parse_t  *jbs;

    jbs = obj;
    up = jbs->resolve.job.data;

    up->ready_handler(task, up);
}


static void
nxt_upstream_round_robin_get_peer(nxt_task_t *task, nxt_upstream_peer_t *up)
{
    int32_t                          effective_weights;
    nxt_uint_t                       i;
    nxt_msec_t                       now;
    nxt_upstream_round_robin_t       *urr;
    nxt_upstream_round_robin_peer_t  *peer, *best;

    urr = up->upstream;

    now = task->thread->engine->timers.now;

    nxt_thread_spin_lock(&urr->lock);

    best = NULL;
    effective_weights = 0;
    peer = urr->peers;

    for (i = 0; i < urr->npeers; i++) {

        if (peer[i].down) {
            continue;
        }

#if 0
        if (peer[i].max_fails != 0 && peer[i].fails >= peer->max_fails) {
            good = peer[i].last_accessed + peer[i].fail_timeout;

            if (nxt_msec_diff(now, peer[i].last_accessed) <= 0) {
                continue;
            }
        }
#endif

        peer[i].current_weight += peer[i].effective_weight;
        effective_weights += peer[i].effective_weight;

        if (peer[i].effective_weight < peer[i].weight) {
            peer[i].effective_weight++;
        }

        if (best == NULL || peer[i].current_weight > best->current_weight) {
            best = &peer[i];
        }
    }

    if (best != NULL) {
        best->current_weight -= effective_weights;
        best->last_accessed = now;

        up->sockaddr = best->sockaddr;

    } else {
        up->sockaddr = NULL;
    }

    nxt_thread_spin_unlock(&urr->lock);

    up->ready_handler(task, up);
}

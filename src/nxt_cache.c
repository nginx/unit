
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/* A cache time resolution is 10ms. */
#define                                                                       \
nxt_cache_time(thr)                                                           \
    (uint64_t) (nxt_thread_time(thr) * 100)


static nxt_int_t nxt_cache_lvlhsh_test(nxt_lvlhsh_query_t *lhq, void *data);
static nxt_work_handler_t nxt_cache_query_locked(nxt_cache_t *cache,
    nxt_cache_query_t *q, nxt_lvlhsh_query_t *lhq);
static nxt_work_handler_t nxt_cache_node_hold(nxt_cache_t *cache,
    nxt_cache_query_t *q, nxt_lvlhsh_query_t *lhq);
static nxt_work_handler_t nxt_cache_node_test(nxt_cache_t *cache,
    nxt_cache_query_t *q);

static void nxt_cache_wait_handler(nxt_thread_t *thr, void *obj, void *data);
static void nxt_cache_timeout_handler(nxt_thread_t *thr, void *obj, void *data);
static void nxt_cache_wake_handler(nxt_thread_t *thr, void *obj, void *data);
static ssize_t nxt_cache_release_locked(nxt_cache_t *cache,
    nxt_cache_query_t *q, u_char *buf, size_t size);

static nxt_cache_node_t *nxt_cache_node_alloc(nxt_cache_t *cache);
static void nxt_cache_node_free(nxt_cache_t *cache, nxt_cache_node_t *node,
    nxt_bool_t fast);
static nxt_cache_query_wait_t *nxt_cache_query_wait_alloc(nxt_cache_t *cache,
    nxt_bool_t *slow);
static void nxt_cache_query_wait_free(nxt_cache_t *cache,
    nxt_cache_query_wait_t *qw);


/* STUB */
nxt_int_t nxt_cache_shm_create(nxt_mem_zone_t *pool);
static void *nxt_cache_shm_alloc(void *data, size_t size, nxt_uint_t nalloc);
/**/


nxt_int_t
nxt_cache_shm_create(nxt_mem_zone_t *mz)
{
    nxt_cache_t  *cache;

    static const nxt_lvlhsh_proto_t  proto  nxt_aligned(64) = {
        NXT_LVLHSH_LARGE_SLAB,
        0,
        nxt_cache_lvlhsh_test,
        (nxt_lvlhsh_alloc_t) nxt_cache_shm_alloc,
        (nxt_lvlhsh_free_t) nxt_mem_zone_free,
    };

    cache = nxt_mem_zone_zalloc(mz, sizeof(nxt_cache_t));

    if (cache == NULL) {
        return NXT_ERROR;
    }

    cache->proto = &proto;
    cache->pool = mz;

    cache->start_time = nxt_cache_time(nxt_thread());

    return NXT_OK;
}


static void *
nxt_cache_shm_alloc(void *data, size_t size, nxt_uint_t nalloc)
{
    return nxt_mem_zone_align(data, size, size);
}


void
nxt_cache_init(nxt_cache_t *cache)
{
    static const nxt_lvlhsh_proto_t  proto  nxt_aligned(64) = {
        NXT_LVLHSH_LARGE_MEMALIGN,
        0,
        nxt_cache_lvlhsh_test,
        nxt_lvlhsh_alloc,
        nxt_lvlhsh_free,
    };

    cache->proto = &proto;

    cache->start_time = nxt_cache_time(nxt_thread());
}


static nxt_int_t
nxt_cache_lvlhsh_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_cache_node_t  *node;

    node = data;

    if (nxt_str_eq(&lhq->key, node->key_data, node->key_len)) {
        return NXT_OK;
    }

    return NXT_DECLINED;
}


nxt_inline void
nxt_cache_lock(nxt_cache_t *cache)
{
    if (cache->shared) {
        nxt_thread_spin_lock(&cache->lock);
    }
}


nxt_inline void
nxt_cache_unlock(nxt_cache_t *cache)
{
    if (cache->shared) {
        nxt_thread_spin_unlock(&cache->lock);
    }
}


void
nxt_cache_query(nxt_cache_t *cache, nxt_cache_query_t *q)
{
    nxt_thread_t        *thr;
    nxt_lvlhsh_query_t  lhq;
    nxt_work_handler_t  handler;

    thr = nxt_thread();

    if (cache != NULL) {
        lhq.key_hash = nxt_murmur_hash2(q->key_data, q->key_len);
        lhq.replace = 0;
        lhq.key.len = q->key_len;
        lhq.key.data = q->key_data;
        lhq.proto = cache->proto;
        lhq.pool = cache->pool;

        q->now = nxt_cache_time(thr);

        nxt_cache_lock(cache);

        handler = nxt_cache_query_locked(cache, q, &lhq);

        nxt_cache_unlock(cache);

    } else {
        handler = q->state->nocache_handler;
    }

    handler(thr, q, NULL);
}


static nxt_work_handler_t
nxt_cache_query_locked(nxt_cache_t *cache, nxt_cache_query_t *q,
    nxt_lvlhsh_query_t *lhq)
{
    nxt_int_t                ret;
    nxt_time_t               expiry;
    nxt_cache_node_t         *node;
    nxt_cache_query_state_t  *state;

    if (q->hold) {
        return nxt_cache_node_hold(cache, q, lhq);
    }

    ret = nxt_lvlhsh_find(&cache->lvlhsh, lhq);

    state = q->state;

    if (ret != NXT_OK) {
        /* NXT_DECLINED */
        return state->nocache_handler;
    }

    node = lhq->value;
    node->count++;
    q->node = node;

    expiry = cache->start_time + node->expiry;

    if (q->now < expiry) {
        return state->ready_handler;
    }

    q->stale = 1;

    return state->stale_handler;
}


static nxt_work_handler_t
nxt_cache_node_hold(nxt_cache_t *cache, nxt_cache_query_t *q,
    nxt_lvlhsh_query_t *lhq)
{
    nxt_int_t                ret;
    nxt_bool_t               slow;
    nxt_cache_node_t         *node, *sentinel;
    nxt_work_handler_t       handler;
    nxt_cache_query_wait_t   *qw;
    nxt_cache_query_state_t  *state;

    state = q->state;
    sentinel = nxt_cache_node_alloc(cache);

    if (nxt_slow_path(sentinel == NULL)) {
        return state->error_handler;
    }

    sentinel->key_data = q->key_data;
    sentinel->key_len = q->key_len;
    lhq->value = sentinel;

    /*
     * Try to insert an empty sentinel node to hold updating
     * process if there is no existent cache node in cache.
     */
    ret = nxt_lvlhsh_insert(&cache->lvlhsh, lhq);

    if (ret == NXT_OK) {
        /* The sentinel node was successully added. */

        q->node = sentinel;
        sentinel->updating = 1;
        return state->update_handler;
    }

    nxt_cache_node_free(cache, sentinel, 1);

    if (ret == NXT_ERROR) {
        return state->error_handler;
    }

    /* NXT_DECLINED: a cache node exists. */

    node = lhq->value;
    node->count++;
    q->node = node;

    handler = nxt_cache_node_test(cache, q);
    if (handler != NULL) {
        return handler;
    }

    /* Add the node to a wait queue. */

    qw = nxt_cache_query_wait_alloc(cache, &slow);
    if (nxt_slow_path(qw == NULL)) {
        return state->error_handler;
    }

    if (slow) {
        /* The node state may have been changed during slow allocation. */

        handler = nxt_cache_node_test(cache, q);
        if (handler != NULL) {
            nxt_cache_query_wait_free(cache, qw);
            return handler;
        }
    }

    qw->query = q;
    qw->next = node->waiting;
    qw->busy = 0;
    qw->deleted = 0;
    qw->pid = nxt_pid;
    qw->engine = nxt_thread_event_engine();
    qw->handler = nxt_cache_wake_handler;
    qw->cache = cache;

    node->waiting = qw;

    return nxt_cache_wait_handler;
}


static nxt_work_handler_t
nxt_cache_node_test(nxt_cache_t *cache, nxt_cache_query_t *q)
{
    nxt_time_t               expiry;
    nxt_cache_node_t         *node;
    nxt_cache_query_state_t  *state;

    q->stale = 0;
    state = q->state;
    node = q->node;

    expiry = cache->start_time + node->expiry;

    if (q->now < expiry) {
        return state->ready_handler;
    }

    /*
     * A valid stale or empty sentinel cache node.
     * The sentinel node can be only in updating state.
     */

    if (node->updating) {

        if (node->expiry != 0) {
            /* A valid stale cache node. */

            q->stale = 1;

            if (q->use_stale) {
                return state->stale_handler;
            }
        }

        /* A sentinel node. */
        return NULL;
    }

    /* A valid stale cache node is not being updated now. */

    q->stale = 1;

    if (q->use_stale) {

        if (q->update_stale) {
            node->updating = 1;
            return state->update_stale_handler;
        }

        return state->stale_handler;
    }

    node->updating = 1;
    return state->update_handler;
}


static void
nxt_cache_wait_handler(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_event_timer_t  *ev;
    nxt_cache_query_t  *cq;

    cq = obj;

    if (cq->timeout != 0) {

        ev = &cq->timer;

        if (ev->state == NXT_EVENT_TIMER_DISABLED) {
            ev->handler = nxt_cache_timeout_handler;
            nxt_event_timer_ident(ev, -1);

            nxt_event_timer_add(thr->engine, ev, cq->timeout);
        }
    }
}


static void
nxt_cache_timeout_handler(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_cache_query_t  *cq;
    nxt_event_timer_t  *ev;

    ev = obj;

    cq = nxt_event_timer_data(ev, nxt_cache_query_t, timer);

    cq->state->timeout_handler(thr, cq, NULL);
}


static void
nxt_cache_wake_handler(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_cache_t             *cache;
    nxt_work_handler_t      handler;
    nxt_cache_query_t       *q;
    nxt_cache_query_wait_t  *qw;

    qw = obj;
    q = qw->query;
    cache = qw->cache;

    nxt_cache_lock(cache);

    handler = nxt_cache_node_test(cache, q);

    if (handler != NULL) {
        nxt_cache_query_wait_free(cache, qw);

    } else {
        /* Wait again. */
        qw->next = q->node->waiting;
        q->node->waiting = qw;
    }

    nxt_cache_unlock(cache);

    handler(thr, q, NULL);
}


nxt_int_t
nxt_cache_update(nxt_cache_t *cache, nxt_cache_query_t *q)
{
    nxt_int_t           ret;
    nxt_cache_node_t    *node;
    nxt_lvlhsh_query_t  lhq;

    node = q->node;

    node->accessed = nxt_cache_time(nxt_thread()) - cache->start_time;

    node->updating = 0;
    node->count = 1;

    lhq.key_hash = nxt_murmur_hash2(node->key_data, node->key_len);
    lhq.replace = 1;
    lhq.key.len = node->key_len;
    lhq.key.data = node->key_data;
    lhq.value = node;
    lhq.proto = cache->proto;
    lhq.pool = cache->pool;

    nxt_cache_lock(cache);

    ret = nxt_lvlhsh_insert(&cache->lvlhsh, &lhq);

    if (nxt_fast_path(ret != NXT_OK)) {

        nxt_queue_insert_head(&cache->expiry_queue, &node->link);

        node = lhq.value;

        if (node != NULL) {
            /* A replaced node. */

            nxt_queue_remove(&node->link);

            if (node->count != 0) {
                node->deleted = 1;

            } else {
                // delete cache node
            }
        }
    }

    nxt_cache_unlock(cache);

    return ret;
}


void
nxt_cache_release(nxt_cache_t *cache, nxt_cache_query_t *q)
{
    u_char        *p, *data;
    size_t        size;
    ssize_t       ret;
    nxt_thread_t  *thr;
    u_char        buf[1024];

    thr = nxt_thread();
    q->now = nxt_cache_time(thr);

    p = buf;
    size = sizeof(buf);

    for ( ;; ) {
        nxt_cache_lock(cache);

        ret = nxt_cache_release_locked(cache, q, p, size);

        nxt_cache_unlock(cache);

        if (ret == 0) {
            return;
        }

        size = nxt_abs(ret);

        data = nxt_malloc(size);

        if (data == NULL) {
            /* TODO: retry */
            return;
        }

        if (ret < 0) {
            p = data;
            continue;
        }

        if (p != data) {
            nxt_memcpy(data, p, size);
        }

        nxt_thread_work_queue_add(thr, &thr->work_queue.main,
                                  cache->delete_handler, data, NULL, thr->log);
    }
}


static ssize_t
nxt_cache_release_locked(nxt_cache_t *cache, nxt_cache_query_t *q,
    u_char *buf, size_t size)
{
    ssize_t           ret;
    nxt_cache_node_t  *node;

    node = q->node;
    node->count--;

    if (node->count != 0) {
        return 0;
    }

    if (!node->deleted) {
        /*
         * A cache node is locked whilst its count is non zero.
         * To minimize number of operations the node's place in expiry
         * queue can be updated only if the node is not currently used.
         */
        node->accessed = q->now - cache->start_time;

        nxt_queue_remove(&node->link);
        nxt_queue_insert_head(&cache->expiry_queue, &node->link);

        return 0;
    }

    ret = 0;
#if 0

    ret = cache->delete_copy(cache, node, buf, size);

    if (ret < 0) {
        return ret;
    }

#endif

    nxt_cache_node_free(cache, node, 0);

    return ret;
}


static nxt_cache_node_t *
nxt_cache_node_alloc(nxt_cache_t *cache)
{
    nxt_queue_link_t  *link;
    nxt_cache_node_t  *node;

    link = nxt_queue_first(&cache->free_nodes);

    if (nxt_fast_path(link != nxt_queue_tail(&cache->free_nodes))) {
        cache->nfree_nodes--;
        nxt_queue_remove(link);

        node = nxt_queue_link_data(link, nxt_cache_node_t, link);
        nxt_memzero(node, sizeof(nxt_cache_node_t));

        return node;
    }

    nxt_cache_unlock(cache);

    node = cache->alloc(cache->data, sizeof(nxt_cache_node_t));

    nxt_cache_lock(cache);

    return node;
}


static void
nxt_cache_node_free(nxt_cache_t *cache, nxt_cache_node_t *node, nxt_bool_t fast)
{
    if (fast || cache->nfree_nodes < 32) {
        nxt_queue_insert_head(&cache->free_nodes, &node->link);
        cache->nfree_nodes++;
        return;
    }

    nxt_cache_unlock(cache);

    cache->free(cache->data, node);

    nxt_cache_lock(cache);
}


static nxt_cache_query_wait_t *
nxt_cache_query_wait_alloc(nxt_cache_t *cache, nxt_bool_t *slow)
{
    nxt_cache_query_wait_t  *qw;

    qw = cache->free_query_wait;

    if (nxt_fast_path(qw != NULL)) {
        cache->free_query_wait = qw->next;
        cache->nfree_query_wait--;

        *slow = 0;
        return qw;
    }

    nxt_cache_unlock(cache);

    qw = cache->alloc(cache->data, sizeof(nxt_cache_query_wait_t));
    *slow = 1;

    nxt_cache_lock(cache);

    return qw;
}


static void
nxt_cache_query_wait_free(nxt_cache_t *cache, nxt_cache_query_wait_t *qw)
{
    if (cache->nfree_query_wait < 32) {
        qw->next = cache->free_query_wait;
        cache->free_query_wait = qw;
        cache->nfree_query_wait++;
        return;
    }

    nxt_cache_unlock(cache);

    cache->free(cache->data, qw);

    nxt_cache_lock(cache);
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static nxt_int_t nxt_file_cache_lvlhsh_test(nxt_lvlhsh_key_t *hkey, void *data);
static nxt_work_handler_t nxt_file_cache_query_locked(nxt_file_cache_t *cache,
    nxt_file_cache_query_t *q, nxt_lvlhsh_key_t *hkey);
static nxt_work_handler_t nxt_file_cache_node_hold(nxt_file_cache_t *cache,
    nxt_file_cache_query_t *q, nxt_lvlhsh_key_t *hkey);
static nxt_work_handler_t nxt_file_cache_node_test(nxt_file_cache_t *cache,
    nxt_file_cache_query_t *q);

static void nxt_file_cache_wait_handler(void *data);
static void nxt_file_cache_timeout_handler(nxt_event_timer_t *ev);
static void nxt_file_cache_wake_handler(void *data);

static nxt_file_cache_node_t *nxt_file_cache_node_alloc(nxt_cache_t *cache);
static void nxt_file_cache_node_free(nxt_file_cache_t *cache,
    nxt_file_cache_node_t *node, nxt_bool_t fast);
static nxt_file_cache_query_wait_t *nxt_file_cache_query_wait_alloc(
    nxt_file_cache_t *cache, nxt_bool_t *fast);
static void nxt_file_cache_query_wait_free(nxt_file_cache_t *cache,
    nxt_file_cache_query_wait_t *qw);
static void nxt_file_cache_lock(nxt_file_cache_t *cache);
static void nxt_file_cache_unlock(nxt_file_cache_t *cache);


void
nxt_file_cache_init(nxt_cache_t *cache)
{
    static const nxt_lvlhsh_ctx_t  ctx = {
        nxt_file_cache_lvlhsh_test,
        nxt_lvlhsh_alloc,
        nxt_lvlhsh_free,
        0,
    };

    /* lvlhsh with large first level. */
    cache->lvlhsh.shift[1] = 10;

    cache->lvlhsh.ctx = &ctx;

    cache->start_time = nxt_thread_time();
}


static nxt_int_t
nxt_file_cache_lvlhsh_test(nxt_lvlhsh_key_t *hkey, void *data)
{
    nxt_file_cache_node_t  *node;

    node = data;

    if (nxt_strmem_eq(&hkey->key, node->key_data, node->key_len)) {
        return NXT_OK;
    }

    return NXT_DECLINED;
}


void
nxt_file_cache_query(nxt_file_cache_t *cache, nxt_file_cache_query_t *q)
{
    nxt_lvlhsh_key_t    hkey;
    nxt_work_handler_t  handler;

    if (cache != NULL) {
        hkey.key.len = q->key_len;
        hkey.key.data = q->key_data;
        hkey.key_hash = nxt_murmur_hash2(q->key_data, q->key_len);
        hkey.replace = 0;

        nxt_file_cache_lock(cache);

        handler = nxt_file_cache_query_locked(cache, q, &hkey);

        nxt_file_cache_unlock(cache);

    } else {
        handler = q->state->nocache_handler;
    }

    handler(q);
}


static nxt_work_handler_t
nxt_file_cache_query_locked(nxt_file_cache_t *cache, nxt_file_cache_query_t *q,
    nxt_lvlhsh_key_t *hkey)
{
    nxt_int_t                     ret;
    nxt_bool_t                    fast;
    nxt_work_handler_t            handler;
    nxt_file_cache_node_t         *node, *sentinel;
    nxt_file_cache_query_wait_t   *qw;
    nxt_file_cache_query_state_t  *state;

    state = q->state;
    sentinel = nxt_file_cache_node_alloc(cache);

    if (nxt_slow_path(sentinel == NULL)) {
        return state->error_handler;
    }

    sentinel->key_data = q->key_data;
    sentinel->key_len = q->key_len;
    hkey->value = sentinel;

    /*
     * Try to insert an empty sentinel node to hold updating
     * process if there is no existent cache node in cache.
     */

    ret = nxt_lvlhsh_insert(&cache->lvlhsh, hkey);

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

    node = hkey->value;
    node->count++;
    q->node = node;

    handler = nxt_cache_node_test(cache, q);

    if (handler == NULL) {
        /* Add the node to a wait queue. */

        qw = nxt_cache_query_wait_alloc(cache, &fast);
        if (nxt_slow_path(qw == NULL)) {
            return state->error_handler;
        }

        if (!fast) {
            /* The node state may be changed during slow allocation. */
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

    return handler;
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

    if (nxt_thread_time() < expiry) {
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
nxt_cache_wait_handler(void *data)
{
    nxt_thread_t       *thr;
    nxt_event_timer_t  *ev;
    nxt_cache_query_t  *q;

    q = data;

    if (&q->timeout == 0) {
        return;
    }

    ev = &q->timer;

    if (!nxt_event_timer_is_set(ev)) {
        thr = nxt_thread();
        ev->log = thr->log;
        ev->handler = nxt_cache_timeout_handler;
        ev->data = q;
        nxt_event_timer_ident(ev, -1);

        nxt_event_timer_add(thr->engine, ev, q->timeout);
    }
}


static void
nxt_cache_timeout_handler(nxt_event_timer_t *ev)
{
    nxt_cache_query_t  *q;

    q = ev->data;

    q->state->timeout_handler(q);
}


static void
nxt_cache_wake_handler(void *data)
{
    nxt_cache_t             *cache;
    nxt_work_handler_t      handler;
    nxt_cache_query_t       *q;
    nxt_cache_query_wait_t  *qw;

    qw = data;
    q = qw->query;
    cache = qw->cache;

    nxt_cache_lock(cache);

    handler = nxt_cache_node_test(cache, q);

    if (handler == NULL) {
        /* Wait again. */
        qw->next = q->node->waiting;
        q->node->waiting = qw;
    }

    nxt_cache_unlock(cache);

    if (handler != NULL) {
        nxt_cache_query_wait_free(cache, qw);
    }

    handler(q);
}


static nxt_cache_node_t *
nxt_cache_node_alloc(nxt_cache_t *cache)
{
    nxt_queue_node_t  *qn;
    nxt_cache_node_t  *node;

    qn = nxt_queue_first(&cache->free_nodes);

    if (nxt_fast_path(qn != nxt_queue_tail(&cache->free_nodes))) {
        cache->nfree_nodes--;
        nxt_queue_remove(qn);

        node = nxt_queue_node_data(qn, nxt_cache_node_t, queue);
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
        nxt_queue_insert_head(&cache->free_nodes, &node->queue);
        cache->nfree_nodes++;
        return;
    }

    nxt_cache_unlock(cache);

    cache->free(cache->data, node);

    nxt_cache_lock(cache);
}


static nxt_cache_query_wait_t *
nxt_cache_query_wait_alloc(nxt_cache_t *cache, nxt_bool_t *fast)
{
    nxt_cache_query_wait_t  *qw;

    qw = cache->free_query_wait;

    if (nxt_fast_path(qw != NULL)) {
        cache->free_query_wait = qw->next;
        cache->nfree_query_wait--;

        *fast = 1;
        return qw;
    }

    nxt_cache_unlock(cache);

    qw = cache->alloc(cache->data, sizeof(nxt_cache_query_wait_t));
    *fast = 0;

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


#if 0

nxt_int_t
nxt_cache_update(nxt_cache_t *cache, nxt_cache_node_t *node)
{
    nxt_lvlhsh_key_t  hkey;

    if (node->expiry == 0) {
        /* An empty sentinel node. */
        nxt_cache_release(cache, node);
        return;
    }

    hkey.key.len = node->key_len;
    hkey.key.data = node->key_data;
    hkey.key_hash = nxt_murmur_hash2(node->key_data, node->key_len);
    hkey.replace = 1;
    hkey.value = node;

    node->count = 1;

    if (nxt_lvlhsh_insert(&cache->lvlhsh, &hkey) != NXT_OK) {
        return NXT_ERROR;
    }

    node = hkey.value;

    if (node != NULL) {
        if (node->count != 0) {
            node->delete = 1;

        } else {
            // delete cache node
        }
    }

    return NXT_OK;
}

#endif


void
nxt_cache_node_release(nxt_cache_t *cache, nxt_cache_node_t *node)
{
    nxt_bool_t  delete;

    nxt_cache_lock(cache);

    delete = nxt_cache_node_release_locked(cache, node);

    nxt_cache_unlock(cache);

    if (delete) {
        nxt_thread_work_queue_add(cache->delete_handler, node);
    }
}


nxt_bool_t
nxt_cache_node_release_locked(nxt_cache_t *cache, nxt_cache_node_t *node)
{
#if 0
    nxt_lvlhsh_key_t  hkey;
#endif

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
        node->accessed = nxt_thread_time() - cache->start_time;

        nxt_queue_remove(&node->queue);
        nxt_queue_insert_head(&cache->expiry_queue, &node->queue);

        return 0;
    }

#if 0
    hkey.key.len = node->key_len;
    hkey.key.data = node->key_data;
    hkey.key_hash = nxt_murmur_hash2(node->key_data, node->key_len);

    nxt_lvlhsh_delete(&cache->lvlhsh, &hkey);
#endif

    return 1;
}


static void
nxt_file_cache_lock(nxt_file_cache_t *cache)
{
    if (cache->shared) {
        nxt_thread_spin_lock(&cache->lock);
    }
}


static void
nxt_file_cache_unlock(nxt_file_cache_t *cache)
{
    if (cache->shared) {
        nxt_thread_spin_unlock(&cache->lock);
    }
}

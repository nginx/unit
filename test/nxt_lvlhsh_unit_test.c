
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static nxt_int_t
nxt_lvlhsh_unit_test_key_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    if (*(uintptr_t *) lhq->key.start == (uintptr_t) data) {
        return NXT_OK;
    }

    return NXT_DECLINED;
}


static void *
nxt_lvlhsh_unit_test_pool_alloc(void *pool, size_t size, nxt_uint_t nalloc)
{
    return nxt_mem_cache_align(pool, size, size);
}


static void
nxt_lvlhsh_unit_test_pool_free(void *pool, void *p, size_t size)
{
    nxt_mem_cache_free(pool, p);
}


static const nxt_lvlhsh_proto_t  malloc_proto  nxt_aligned(64) = {
    //NXT_LVLHSH_LARGE_MEMALIGN,
    NXT_LVLHSH_DEFAULT,
    0,
    nxt_lvlhsh_unit_test_key_test,
    nxt_lvlhsh_alloc,
    nxt_lvlhsh_free,
};

static const nxt_lvlhsh_proto_t  pool_proto  nxt_aligned(64) = {
    NXT_LVLHSH_LARGE_SLAB,
    0,
    nxt_lvlhsh_unit_test_key_test,
    nxt_lvlhsh_unit_test_pool_alloc,
    nxt_lvlhsh_unit_test_pool_free,
};


static nxt_int_t
nxt_lvlhsh_unit_test_add(nxt_lvlhsh_t *lh, const nxt_lvlhsh_proto_t *proto,
    void *pool, uintptr_t key)
{
    nxt_lvlhsh_query_t  lhq;

    lhq.key_hash = key;
    lhq.replace = 0;
    lhq.key.length = sizeof(uintptr_t);
    lhq.key.start = (u_char *) &key;
    lhq.value = (void *) key;
    lhq.proto = proto;
    lhq.pool = pool;

    switch (nxt_lvlhsh_insert(lh, &lhq)) {

    case NXT_OK:
        return NXT_OK;

    case NXT_DECLINED:
        nxt_thread_log_alert("lvlhsh unit test failed: "
                             "key %p is already in hash", key);
        /* Fall through. */
    default:
        return NXT_ERROR;
    }
}


static nxt_int_t
nxt_lvlhsh_unit_test_get(nxt_lvlhsh_t *lh, const nxt_lvlhsh_proto_t *proto,
    uintptr_t key)
{
    nxt_lvlhsh_query_t  lhq;

    lhq.key_hash = key;
    lhq.key.length = sizeof(uintptr_t);
    lhq.key.start = (u_char *) &key;
    lhq.proto = proto;

    if (nxt_lvlhsh_find(lh, &lhq) == NXT_OK) {

        if (key == (uintptr_t) lhq.value) {
            return NXT_OK;
        }
    }

    nxt_thread_log_alert("lvlhsh unit test failed: "
                         "key %p not found in hash", key);

    return NXT_ERROR;
}


static nxt_int_t
nxt_lvlhsh_unit_test_delete(nxt_lvlhsh_t *lh, const nxt_lvlhsh_proto_t *proto,
    void *pool, uintptr_t key)
{
    nxt_int_t           ret;
    nxt_lvlhsh_query_t  lhq;

    lhq.key_hash = key;
    lhq.key.length = sizeof(uintptr_t);
    lhq.key.start = (u_char *) &key;
    lhq.proto = proto;
    lhq.pool = pool;

    ret = nxt_lvlhsh_delete(lh, &lhq);

    if (ret != NXT_OK) {
        nxt_thread_log_alert("lvlhsh unit test failed: "
                             "key %p not found in hash", key);
    }

    return ret;
}


nxt_int_t
nxt_lvlhsh_unit_test(nxt_thread_t *thr, nxt_uint_t n, nxt_bool_t use_pool)
{
    uintptr_t                 key;
    nxt_nsec_t                start, end;
    nxt_uint_t                i;
    nxt_lvlhsh_t              lh;
    nxt_lvlhsh_each_t         lhe;
    nxt_mem_cache_pool_t      *pool;
    const nxt_lvlhsh_proto_t  *proto;

    const size_t              min_chunk_size = 32;
    const size_t              page_size = 1024;
    const size_t              page_alignment = 128;
    const size_t              cluster_size = 4096;

    nxt_thread_time_update(thr);
    start = nxt_thread_monotonic_time(thr);

    if (use_pool) {
        pool = nxt_mem_cache_pool_create(cluster_size, page_alignment,
                                        page_size, min_chunk_size);
        if (pool == NULL) {
            return NXT_ERROR;
        }

        nxt_log_error(NXT_LOG_NOTICE, thr->log,
                      "lvlhsh unit test started: %uD pool", n);
        proto = &pool_proto;

    } else {
        nxt_log_error(NXT_LOG_NOTICE, thr->log,
                      "lvlhsh unit test started: %uD malloc", n);
        proto = &malloc_proto;
        pool = NULL;
    }

    nxt_memzero(&lh, sizeof(nxt_lvlhsh_t));

    key = 0;
    for (i = 0; i < n; i++) {
        key = nxt_murmur_hash2(&key, sizeof(uint32_t));

        if (nxt_lvlhsh_unit_test_add(&lh, proto, pool, key) != NXT_OK) {
            nxt_log_error(NXT_LOG_NOTICE, thr->log,
                          "lvlhsh add unit test failed at %ui", i);
            return NXT_ERROR;
        }
    }

    key = 0;
    for (i = 0; i < n; i++) {
        key = nxt_murmur_hash2(&key, sizeof(uint32_t));

        if (nxt_lvlhsh_unit_test_get(&lh, proto, key) != NXT_OK) {
            return NXT_ERROR;
        }
    }

    nxt_memzero(&lhe, sizeof(nxt_lvlhsh_each_t));
    lhe.proto = proto;

    for (i = 0; i < n + 1; i++) {
        if (nxt_lvlhsh_each(&lh, &lhe) == NULL) {
            break;
        }
    }

    if (i != n) {
        nxt_log_error(NXT_LOG_NOTICE, thr->log,
                      "lvlhsh each unit test failed at %ui of %ui", i, n);
        return NXT_ERROR;
    }

    key = 0;
    for (i = 0; i < n; i++) {
        key = nxt_murmur_hash2(&key, sizeof(uint32_t));

        if (nxt_lvlhsh_unit_test_delete(&lh, proto, pool, key) != NXT_OK) {
            return NXT_ERROR;
        }
    }

    if (pool != NULL) {
        if (!nxt_mem_cache_pool_is_empty(pool)) {
            nxt_log_error(NXT_LOG_NOTICE, thr->log,
                          "mem cache pool is not empty");
            return NXT_ERROR;
        }

        nxt_mem_cache_pool_destroy(pool);
    }

    nxt_thread_time_update(thr);
    end = nxt_thread_monotonic_time(thr);

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "lvlhsh unit test passed: %0.3fs",
                  (end - start) / 1000000000.0);

    return NXT_OK;
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_tests.h"


static nxt_int_t
nxt_lvlhsh_test_key_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    if (*(uintptr_t *) lhq->key.start == (uintptr_t) data) {
        return NXT_OK;
    }

    return NXT_DECLINED;
}


static void *
nxt_lvlhsh_test_pool_alloc(void *pool, size_t size)
{
    return nxt_mp_align(pool, size, size);
}


static void
nxt_lvlhsh_test_pool_free(void *pool, void *p)
{
    nxt_mp_free(pool, p);
}


static const nxt_lvlhsh_proto_t  malloc_proto  nxt_aligned(64) = {
    //NXT_LVLHSH_LARGE_MEMALIGN,
    NXT_LVLHSH_DEFAULT,
    nxt_lvlhsh_test_key_test,
    nxt_lvlhsh_alloc,
    nxt_lvlhsh_free,
};

static const nxt_lvlhsh_proto_t  pool_proto  nxt_aligned(64) = {
    NXT_LVLHSH_LARGE_SLAB,
    nxt_lvlhsh_test_key_test,
    nxt_lvlhsh_test_pool_alloc,
    nxt_lvlhsh_test_pool_free,
};


static nxt_int_t
nxt_lvlhsh_test_add(nxt_lvlhsh_t *lh, const nxt_lvlhsh_proto_t *proto,
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
        nxt_thread_log_alert("lvlhsh test failed: "
                             "key %p is already in hash", key);
        /* Fall through. */
    default:
        return NXT_ERROR;
    }
}


static nxt_int_t
nxt_lvlhsh_test_get(nxt_lvlhsh_t *lh, const nxt_lvlhsh_proto_t *proto,
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

    nxt_thread_log_alert("lvlhsh test failed: "
                         "key %p not found in hash", key);

    return NXT_ERROR;
}


static nxt_int_t
nxt_lvlhsh_test_delete(nxt_lvlhsh_t *lh, const nxt_lvlhsh_proto_t *proto,
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
        nxt_thread_log_alert("lvlhsh test failed: "
                             "key %p not found in hash", key);
    }

    return ret;
}


nxt_int_t
nxt_lvlhsh_test(nxt_thread_t *thr, nxt_uint_t n, nxt_bool_t use_pool)
{
    void                      *value;
    uint32_t                  key;
    nxt_mp_t                  *mp;
    nxt_nsec_t                start, end;
    nxt_uint_t                i;
    nxt_lvlhsh_t              lh;
    nxt_lvlhsh_each_t         lhe;
    const nxt_lvlhsh_proto_t  *proto;

    const size_t              min_chunk_size = 32;
    const size_t              page_size = 1024;
    const size_t              page_alignment = 128;
    const size_t              cluster_size = 4096;

    nxt_thread_time_update(thr);
    start = nxt_thread_monotonic_time(thr);

    if (use_pool) {
        mp = nxt_mp_create(cluster_size, page_alignment, page_size,
                           min_chunk_size);
        if (mp == NULL) {
            return NXT_ERROR;
        }

        nxt_log_error(NXT_LOG_NOTICE, thr->log,
                      "lvlhsh test started: %uD pool", n);
        proto = &pool_proto;

    } else {
        nxt_log_error(NXT_LOG_NOTICE, thr->log,
                      "lvlhsh test started: %uD malloc", n);
        proto = &malloc_proto;
        mp = NULL;
    }

    nxt_memzero(&lh, sizeof(nxt_lvlhsh_t));

    key = 0;
    for (i = 0; i < n; i++) {
        key = nxt_murmur_hash2(&key, sizeof(uint32_t));

        if (nxt_lvlhsh_test_add(&lh, proto, mp, key) != NXT_OK) {
            nxt_log_error(NXT_LOG_NOTICE, thr->log,
                          "lvlhsh add test failed at %ui", i);
            return NXT_ERROR;
        }
    }

    key = 0;
    for (i = 0; i < n; i++) {
        key = nxt_murmur_hash2(&key, sizeof(uint32_t));

        if (nxt_lvlhsh_test_get(&lh, proto, key) != NXT_OK) {
            return NXT_ERROR;
        }
    }

    nxt_lvlhsh_each_init(&lhe, proto);

    for (i = 0; i < n + 1; i++) {
        if (nxt_lvlhsh_each(&lh, &lhe) == NULL) {
            break;
        }
    }

    if (i != n) {
        nxt_log_error(NXT_LOG_NOTICE, thr->log,
                      "lvlhsh each test failed at %ui of %ui", i, n);
        return NXT_ERROR;
    }

    for (i = 0; i < n; i++) {
        value = nxt_lvlhsh_peek(&lh, proto);

        if (value == NULL) {
            break;
        }

        key = (uintptr_t) value;

        if (nxt_lvlhsh_test_delete(&lh, proto, mp, key) != NXT_OK) {
            return NXT_ERROR;
        }
    }

    if (i != n) {
        nxt_log_error(NXT_LOG_NOTICE, thr->log,
                      "lvlhsh peek test failed at %ui of %ui", i, n);
        return NXT_ERROR;
    }

    if (!nxt_lvlhsh_is_empty(&lh)) {
        nxt_log_error(NXT_LOG_NOTICE, thr->log,
                      "lvlhsh is not empty after deletion");
        return NXT_ERROR;
    }

    key = 0;
    for (i = 0; i < n; i++) {
        key = nxt_murmur_hash2(&key, sizeof(uint32_t));

        if (nxt_lvlhsh_test_add(&lh, proto, mp, key) != NXT_OK) {
            nxt_log_error(NXT_LOG_NOTICE, thr->log,
                          "lvlhsh add test failed at %ui", i);
            return NXT_ERROR;
        }
    }

    for (i = 0; i < n; i++) {
        value = nxt_lvlhsh_retrieve(&lh, proto, mp);

        if (value == NULL) {
            break;
        }
    }

    if (i != n) {
        nxt_log_error(NXT_LOG_NOTICE, thr->log,
                      "lvlhsh retrieve test failed at %ui of %ui", i, n);
        return NXT_ERROR;
    }

    if (!nxt_lvlhsh_is_empty(&lh)) {
        nxt_log_error(NXT_LOG_NOTICE, thr->log,
                      "lvlhsh is not empty after retrieving");
        return NXT_ERROR;
    }

    if (mp != NULL) {
        if (!nxt_mp_is_empty(mp)) {
            nxt_log_error(NXT_LOG_NOTICE, thr->log, "mem pool is not empty");
            return NXT_ERROR;
        }

        nxt_mp_destroy(mp);
    }

    nxt_thread_time_update(thr);
    end = nxt_thread_monotonic_time(thr);

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "lvlhsh test passed: %0.3fs",
                  (end - start) / 1000000000.0);

    return NXT_OK;
}

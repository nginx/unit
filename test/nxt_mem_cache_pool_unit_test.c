
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


nxt_int_t
nxt_mem_cache_pool_unit_test(nxt_thread_t *thr, nxt_uint_t runs,
    nxt_uint_t nblocks, size_t max_size)
{
    void                  **blocks;
    size_t                total;
    uint32_t              size;
    nxt_uint_t            i, n;
    nxt_mem_cache_pool_t  *pool;

    const size_t          min_chunk_size = 16;
    const size_t          page_size = 128;
    const size_t          page_alignment = 128;
    const size_t          cluster_size = page_size * 8;

    nxt_thread_time_update(thr);
    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "mem cache pool unit test started, max:%uz", max_size);

    blocks = nxt_malloc(nblocks * sizeof(void *));
    if (blocks == NULL) {
        return NXT_ERROR;
    }

    pool = nxt_mem_cache_pool_create(cluster_size, page_alignment,
                                     page_size, min_chunk_size);
    if (pool == NULL) {
        return NXT_ERROR;
    }

    size = 0;

    for (i = 0; i < runs; i++) {

        total = 0;

        for (n = 0; n < nblocks; n++) {
            size = nxt_murmur_hash2(&size, sizeof(uint32_t));

            total += size & max_size;
            blocks[n] = nxt_mem_cache_alloc(pool, size & max_size);

            if (blocks[n] == NULL) {
                nxt_log_error(NXT_LOG_NOTICE, thr->log,
                              "mem cache pool unit test failed: %uz", total);
                return NXT_ERROR;
            }
        }

        for (n = 0; n < nblocks; n++) {
            nxt_mem_cache_free(pool, blocks[n]);
        }
    }

    if (!nxt_mem_cache_pool_is_empty(pool)) {
        nxt_log_error(NXT_LOG_NOTICE, thr->log, "mem cache pool is not empty");
        return NXT_ERROR;
    }

    nxt_mem_cache_pool_destroy(pool);

    nxt_thread_time_update(thr);
    nxt_log_error(NXT_LOG_NOTICE, thr->log, "mem cache pool unit test passed");

    return NXT_OK;
}

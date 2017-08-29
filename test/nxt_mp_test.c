
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_tests.h"


nxt_int_t
nxt_mp_test(nxt_thread_t *thr, nxt_uint_t runs, nxt_uint_t nblocks,
    size_t max_size)
{
    void          **blocks;
    size_t        total;
    uint32_t      value, size;
    nxt_mp_t      *mp;
    nxt_bool_t    valid;
    nxt_uint_t    i, n;

    const size_t  min_chunk_size = 16;
    const size_t  page_size = 128;
    const size_t  page_alignment = 128;
    const size_t  cluster_size = page_size * 8;

    nxt_thread_time_update(thr);
    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "mem pool test started, max:%uz", max_size);

    blocks = nxt_malloc(nblocks * sizeof(void *));
    if (blocks == NULL) {
        return NXT_ERROR;
    }

    valid = nxt_mp_test_sizes(cluster_size, page_alignment, page_size,
                              min_chunk_size);
    if (!valid) {
        return NXT_ERROR;
    }

    mp = nxt_mp_create(cluster_size, page_alignment, page_size, min_chunk_size);
    if (mp == NULL) {
        return NXT_ERROR;
    }

    value = 0;

    for (i = 0; i < runs; i++) {

        total = 0;

        for (n = 0; n < nblocks; n++) {
            value = nxt_murmur_hash2(&value, sizeof(uint32_t));

            size = value & max_size;

            if (size == 0) {
                size++;
            }

            total += size;
            blocks[n] = nxt_mp_alloc(mp, size);

            if (blocks[n] == NULL) {
                nxt_log_error(NXT_LOG_NOTICE, thr->log,
                              "mem pool test failed: %uz", total);
                return NXT_ERROR;
            }
        }

        for (n = 0; n < nblocks; n++) {
            nxt_mp_free(mp, blocks[n]);
        }
    }

    if (!nxt_mp_is_empty(mp)) {
        nxt_log_error(NXT_LOG_NOTICE, thr->log, "mem pool is not empty");
        return NXT_ERROR;
    }

    nxt_mp_destroy(mp);

    nxt_free(blocks);

    nxt_thread_time_update(thr);
    nxt_log_error(NXT_LOG_NOTICE, thr->log, "mem pool test passed");

    return NXT_OK;
}

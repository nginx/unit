
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_tests.h"


nxt_int_t
nxt_mem_zone_test(nxt_thread_t *thr, nxt_uint_t runs, nxt_uint_t nblocks,
    size_t max_size)
{
    void            *start, **blocks;
    size_t          total, zone_size;
    uint32_t        size;
    nxt_uint_t      i, n;
    nxt_mem_zone_t  *zone;
    const size_t    page_size = 4096;

    nxt_thread_time_update(thr);
    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "mem zone test started, max:%uz", max_size);

    zone_size = (max_size + 1) * nblocks;

    start = nxt_memalign(page_size, zone_size);
    if (start == NULL) {
        return NXT_ERROR;
    }

    zone = nxt_mem_zone_init(start, zone_size, page_size);
    if (zone == NULL) {
        return NXT_ERROR;
    }

    blocks = nxt_malloc(nblocks * sizeof(void *));
    if (blocks == NULL) {
        return NXT_ERROR;
    }

    size = 0;

    for (i = 0; i < runs; i++) {

        total = 0;

        for (n = 0; n < nblocks; n++) {
            size = nxt_murmur_hash2(&size, sizeof(uint32_t));

            total += size & max_size;
            blocks[n] = nxt_mem_zone_alloc(zone, size & max_size);

            if (blocks[n] == NULL) {
                nxt_log_error(NXT_LOG_NOTICE, thr->log,
                              "mem zone test failed: %uz", total);
                return NXT_ERROR;
            }
        }

        for (n = 0; n < nblocks; n++) {
            nxt_mem_zone_free(zone, blocks[n]);
        }
    }

    nxt_free(blocks);
    nxt_free(zone);

    nxt_thread_time_update(thr);
    nxt_log_error(NXT_LOG_NOTICE, thr->log, "mem zone test passed");

    return NXT_OK;
}

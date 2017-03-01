
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


extern char  **environ;


/* The function is defined here to prevent inline optimizations. */
static nxt_bool_t
nxt_msec_less(nxt_msec_t first, nxt_msec_t second)
{
    return (nxt_msec_diff(first, second) < 0);
}


int nxt_cdecl
main(int argc, char **argv)
{
    nxt_thread_t  *thr;

    if (nxt_lib_start("lib_unit_test", argv, &environ) != NXT_OK) {
        return 1;
    }

    nxt_main_log.level = NXT_LOG_INFO;

    thr = nxt_thread();

#if (NXT_UNIT_TEST_RTDTSC)

    if (nxt_process_argv[1] != NULL
        && nxt_memcmp(nxt_process_argv[1], "rbm", 3) == 0)
    {
        if (nxt_rbtree1_mb_start(thr) != NXT_OK) {
            return 1;
        }

        if (nxt_rbtree_mb_start(thr) != NXT_OK) {
            return 1;
        }

        if (nxt_lvlhsh_unit_test(thr, 500 * 1000, 0) != NXT_OK) {
            return 1;
        }

        nxt_rbtree1_mb_insert(thr);
        nxt_rbtree_mb_insert(thr);

        if (nxt_lvlhsh_unit_test(thr, 500 * 1000, 0) != NXT_OK) {
            return 1;
        }

        nxt_rbtree1_mb_delete(thr);
        nxt_rbtree_mb_delete(thr);

        return 0;
    }

#endif

#if !(NXT_HAVE_ARC4RANDOM)
    if (nxt_random_unit_test(thr) != NXT_OK) {
        return 1;
    }
#endif

    if (nxt_term_parse_unit_test(thr) != NXT_OK) {
        return 1;
    }

    if (nxt_msec_diff_unit_test(thr, nxt_msec_less) != NXT_OK) {
        return 1;
    }

    if (nxt_rbtree_unit_test(thr, 100 * 1000) != NXT_OK) {
        return 1;
    }

    if (nxt_rbtree_unit_test(thr, 1000 * 1000) != NXT_OK) {
        return 1;
    }

    if (nxt_rbtree1_unit_test(thr, 100 * 1000) != NXT_OK) {
        return 1;
    }

    if (nxt_rbtree1_unit_test(thr, 1000 * 1000) != NXT_OK) {
        return 1;
    }

    if (nxt_mem_cache_pool_unit_test(thr, 100, 40000, 128 - 1) != NXT_OK) {
        return 1;
    }

    if (nxt_mem_cache_pool_unit_test(thr, 100, 1000, 4096 - 1) != NXT_OK) {
        return 1;
    }

    if (nxt_mem_cache_pool_unit_test(thr, 1000, 100, 64 * 1024 - 1) != NXT_OK) {
        return 1;
    }

    if (nxt_mem_zone_unit_test(thr, 100, 20000, 128 - 1) != NXT_OK) {
        return 1;
    }

    if (nxt_mem_zone_unit_test(thr, 100, 10000, 4096 - 1) != NXT_OK) {
        return 1;
    }

    if (nxt_mem_zone_unit_test(thr, 1000, 40, 64 * 1024 - 1) != NXT_OK) {
        return 1;
    }

    if (nxt_lvlhsh_unit_test(thr, 2, 1) != NXT_OK) {
        return 1;
    }

    if (nxt_lvlhsh_unit_test(thr, 100 * 1000, 1) != NXT_OK) {
        return 1;
    }

    if (nxt_lvlhsh_unit_test(thr, 100 * 1000, 0) != NXT_OK) {
        return 1;
    }

    if (nxt_lvlhsh_unit_test(thr, 1000 * 1000, 1) != NXT_OK) {
        return 1;
    }

    if (nxt_gmtime_unit_test(thr) != NXT_OK) {
        return 1;
    }

    if (nxt_sprintf_unit_test(thr) != NXT_OK) {
        return 1;
    }

    if (nxt_malloc_unit_test(thr) != NXT_OK) {
        return 1;
    }

    if (nxt_utf8_unit_test(thr) != NXT_OK) {
        return 1;
    }

    if (nxt_http_parse_unit_test(thr) != NXT_OK) {
        return 1;
    }

    return 0;
}

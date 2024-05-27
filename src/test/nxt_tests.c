
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_tests.h"


extern char  **environ;

nxt_module_init_t  nxt_init_modules[1];
nxt_uint_t         nxt_init_modules_n;


/* The function is defined here to prevent inline optimizations. */
static nxt_bool_t
nxt_msec_less(nxt_msec_t first, nxt_msec_t second)
{
    return (nxt_msec_diff(first, second) < 0);
}


int nxt_cdecl
main(int argc, char **argv)
{
    nxt_task_t    task;
    nxt_thread_t  *thr;

    if (nxt_lib_start("tests", argv, &environ) != NXT_OK) {
        return 1;
    }

    nxt_main_log.level = NXT_LOG_INFO;
    task.log  = &nxt_main_log;

    thr = nxt_thread();
    thr->task = &task;

#if (NXT_TEST_RTDTSC)

    if (nxt_process_argv[1] != NULL
        && memcmp(nxt_process_argv[1], "rbm", 3) == 0)
    {
        if (nxt_rbtree1_mb_start(thr) != NXT_OK) {
            return 1;
        }

        if (nxt_rbtree_mb_start(thr) != NXT_OK) {
            return 1;
        }

        if (nxt_lvlhsh_test(thr, 500 * 1000, 0) != NXT_OK) {
            return 1;
        }

        nxt_rbtree1_mb_insert(thr);
        nxt_rbtree_mb_insert(thr);

        if (nxt_lvlhsh_test(thr, 500 * 1000, 0) != NXT_OK) {
            return 1;
        }

        nxt_rbtree1_mb_delete(thr);
        nxt_rbtree_mb_delete(thr);

        return 0;
    }

#endif

    if (nxt_random_test(thr) != NXT_OK) {
        return 1;
    }

    if (nxt_term_parse_test(thr) != NXT_OK) {
        return 1;
    }

    if (nxt_msec_diff_test(thr, nxt_msec_less) != NXT_OK) {
        return 1;
    }

    if (nxt_rbtree_test(thr, 100 * 1000) != NXT_OK) {
        return 1;
    }

    if (nxt_rbtree_test(thr, 1000 * 1000) != NXT_OK) {
        return 1;
    }

    if (nxt_rbtree1_test(thr, 100 * 1000) != NXT_OK) {
        return 1;
    }

    if (nxt_rbtree1_test(thr, 1000 * 1000) != NXT_OK) {
        return 1;
    }

    if (nxt_mp_test(thr, 100, 40000, 128 - 1) != NXT_OK) {
        return 1;
    }

    if (nxt_mp_test(thr, 100, 1000, 4096 - 1) != NXT_OK) {
        return 1;
    }

    if (nxt_mp_test(thr, 1000, 100, 64 * 1024 - 1) != NXT_OK) {
        return 1;
    }

    if (nxt_mem_zone_test(thr, 100, 20000, 128 - 1) != NXT_OK) {
        return 1;
    }

    if (nxt_mem_zone_test(thr, 100, 10000, 4096 - 1) != NXT_OK) {
        return 1;
    }

    if (nxt_mem_zone_test(thr, 1000, 40, 64 * 1024 - 1) != NXT_OK) {
        return 1;
    }

    if (nxt_lvlhsh_test(thr, 2, 1) != NXT_OK) {
        return 1;
    }

    if (nxt_lvlhsh_test(thr, 100 * 1000, 1) != NXT_OK) {
        return 1;
    }

    if (nxt_lvlhsh_test(thr, 100 * 1000, 0) != NXT_OK) {
        return 1;
    }

    if (nxt_lvlhsh_test(thr, 1000 * 1000, 1) != NXT_OK) {
        return 1;
    }

    if (nxt_gmtime_test(thr) != NXT_OK) {
        return 1;
    }

    if (nxt_sprintf_test(thr) != NXT_OK) {
        return 1;
    }

    if (nxt_malloc_test(thr) != NXT_OK) {
        return 1;
    }

    if (nxt_utf8_test(thr) != NXT_OK) {
        return 1;
    }

    if (nxt_http_parse_test(thr) != NXT_OK) {
        return 1;
    }

    if (nxt_strverscmp_test(thr) != NXT_OK) {
        return 1;
    }

    if (nxt_base64_test(thr) != NXT_OK) {
        return 1;
    }

#if (NXT_HAVE_CLONE_NEWUSER)
    if (nxt_clone_creds_test(thr) != NXT_OK) {
        return 1;
    }
#endif

    return 0;
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_TESTS_H_INCLUDED_
#define _NXT_TESTS_H_INCLUDED_


typedef nxt_bool_t (*nxt_msec_less_t)(nxt_msec_t first, nxt_msec_t second);


#define NXT_RBT_NODES  1500


#if (__i386__ || __i386 || __amd64__ || __amd64)
#if (NXT_GCC || NXT_CLANG)

#define NXT_TEST_RTDTSC  1

nxt_inline uint64_t
nxt_rdtsc(void)
{
    uint32_t  eax, edx;

    __asm__ volatile ("rdtsc" : "=a" (eax), "=d" (edx));

    return ((uint64_t) edx << 32) | eax;
}

#endif
#endif


nxt_int_t nxt_term_parse_test(nxt_thread_t *thr);
nxt_int_t nxt_msec_diff_test(nxt_thread_t *thr, nxt_msec_less_t);

nxt_int_t nxt_rbtree_test(nxt_thread_t *thr, nxt_uint_t n);
nxt_int_t nxt_rbtree1_test(nxt_thread_t *thr, nxt_uint_t n);

#if (NXT_TEST_RTDTSC)

nxt_int_t nxt_rbtree_mb_start(nxt_thread_t *thr);
void nxt_rbtree_mb_insert(nxt_thread_t *thr);
void nxt_rbtree_mb_delete(nxt_thread_t *thr);

nxt_int_t nxt_rbtree1_mb_start(nxt_thread_t *thr);
void nxt_rbtree1_mb_insert(nxt_thread_t *thr);
void nxt_rbtree1_mb_delete(nxt_thread_t *thr);

#endif

nxt_int_t nxt_mp_test(nxt_thread_t *thr, nxt_uint_t runs, nxt_uint_t nblocks,
    size_t max_size);
nxt_int_t nxt_mem_zone_test(nxt_thread_t *thr, nxt_uint_t runs,
    nxt_uint_t nblocks, size_t max_size);
nxt_int_t nxt_lvlhsh_test(nxt_thread_t *thr, nxt_uint_t n,
    nxt_bool_t use_pool);

nxt_int_t nxt_gmtime_test(nxt_thread_t *thr);
nxt_int_t nxt_sprintf_test(nxt_thread_t *thr);
nxt_int_t nxt_malloc_test(nxt_thread_t *thr);
nxt_int_t nxt_utf8_test(nxt_thread_t *thr);
nxt_int_t nxt_http_parse_test(nxt_thread_t *thr);
nxt_int_t nxt_strverscmp_test(nxt_thread_t *thr);
nxt_int_t nxt_base64_test(nxt_thread_t *thr);
nxt_int_t nxt_clone_creds_test(nxt_thread_t *thr);


#endif /* _NXT_TESTS_H_INCLUDED_ */

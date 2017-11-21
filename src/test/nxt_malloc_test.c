
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_tests.h"


#define TIMES  1000


typedef struct {
    size_t      size;
    size_t      alignment;
    nxt_bool_t  tight;
} nxt_malloc_size_t;


static nxt_malloc_size_t *
nxt_malloc_run_test(nxt_thread_t *thr, nxt_malloc_size_t *last, size_t size,
    nxt_uint_t times)
{
    size_t         a, s, alignment;
    uintptr_t      n;
    nxt_uint_t     i, tight;
    static u_char  *p[TIMES + 1];

    alignment = (size_t) -1;
    tight = 0;

    for (i = 1; i < times; i++) {

        p[i] = nxt_malloc(size);
        if (p[i] == NULL) {
            return NULL;
        }

        n = (uintptr_t) p[i];
        a = 0;

        while ((n & 1) == 0) {
            a++;
            n >>= 1;
        }

        alignment = nxt_min(alignment, a);
    }


    for (i = 1; i < times; i++) {
        s = size;
        nxt_malloc_usable_size(p[i], s);

        if (p[i - 1] + s == p[i] || p[i - 1] == p[i] + s) {
            tight++;
        }

        nxt_free(p[i]);
    }

    alignment = 1 << alignment;

#if 0
    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "malloc: %uz, %uz, %ui", size, alignment, tight);
#endif

    while (last->alignment >= alignment) {
        last--;
    }

    last++;

    last->size = size;
    last->alignment = alignment;
    last->tight = times * 9 / 10 < tight;

    return last;
}


nxt_int_t
nxt_malloc_test(nxt_thread_t *thr)
{
    size_t                    size;
    nxt_malloc_size_t         *last, *s;
    static nxt_malloc_size_t  sizes[100];

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "malloc test started");

    last = &sizes[0];

    for (size = 1; size < 64; size++) {
        last = nxt_malloc_run_test(thr, last, size, TIMES);
        if (last == NULL) {
            return NXT_ERROR;
        }
    }

    for (size = 64; size < 16384; size += 8) {
        last = nxt_malloc_run_test(thr, last, size, TIMES / 4);
        if (last == NULL) {
            return NXT_ERROR;
        }
    }

    for (size = 16384; size < 512 * 1024 + 129; size += 128) {
        last = nxt_malloc_run_test(thr, last, size, TIMES / 16);
        if (last == NULL) {
            return NXT_ERROR;
        }
    }

    for (s = &sizes[1]; s <= last; s++) {
        nxt_log_error(NXT_LOG_NOTICE, thr->log,
                      "malloc sizes: %uz-%uz alignment:%uz tight:%ui",
                      s[-1].size + 1, s->size, s->alignment, s->tight);
    }

    return NXT_OK;
}

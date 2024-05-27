
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_RANDOM_H_INCLUDED_
#define _NXT_RANDOM_H_INCLUDED_


typedef struct {
    uint8_t  i;
    uint8_t  j;
    uint8_t  s[256];
    int32_t  count;
} nxt_random_t;


void nxt_random_init(nxt_random_t *r);
uint32_t nxt_random(nxt_random_t *r);

#if (NXT_TESTS)
nxt_int_t nxt_random_test(nxt_thread_t *thr);
#endif


#endif /* _NXT_RANDOM_H_INCLUDED_ */

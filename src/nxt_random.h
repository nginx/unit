
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_RANDOM_H_INCLUDED_
#define _NXT_RANDOM_H_INCLUDED_


#if (NXT_HAVE_ARC4RANDOM)

/*
 * arc4random() has been introduced in OpenBSD 2.1 and then was ported
 * to FreeBSD 2.2.6, NetBSD 2.0, MacOSX and SmartOS.
 *
 * arc4random() automatically initializes itself in the first call and
 * then reinitializes itself in the first call in every forked processes.
 */

typedef void  *nxt_random_t;


#define nxt_random_init(r)
#define nxt_random(r)       arc4random()

#else

typedef struct {
    uint8_t  i;
    uint8_t  j;
    uint8_t  s[256];
    int32_t  count;
} nxt_random_t;


void nxt_random_init(nxt_random_t *r);
uint32_t nxt_random(nxt_random_t *r);

#if (NXT_LIB_UNIT_TEST)
nxt_int_t nxt_random_unit_test(nxt_thread_t *thr);
#endif

#endif


#endif /* _NXT_RANDOM_H_INCLUDED_ */

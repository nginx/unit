/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_CAPABILITY_INCLUDED_
#define _NXT_CAPABILITY_INCLUDED_

typedef struct {
    uint8_t  setid;     /* 1 bit */
    uint8_t  chroot;    /* 1 bit */
} nxt_capabilities_t;


NXT_EXPORT nxt_int_t nxt_capability_set(nxt_task_t *task,
    nxt_capabilities_t *cap);

#endif /* _NXT_CAPABILITY_INCLUDED_ */

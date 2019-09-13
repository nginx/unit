/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_CAPABILITY_INCLUDED_
#define _NXT_CAPABILITY_INCLUDED_

typedef struct {
    uint8_t setid;
} nxt_capability_t;

NXT_EXPORT nxt_int_t nxt_capability_set(nxt_task_t *task,
    nxt_capability_t *cap);
NXT_EXPORT void nxt_capability_log_hint(nxt_task_t *task);

#endif /* _NXT_CAPABILITY_INCLUDED_ */
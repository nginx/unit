/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_CAPABILITY_INCLUDED_
#define _NXT_CAPABILITY_INCLUDED_

typedef struct {
    uint8_t setid;
} nxt_capability_t;

NXT_EXPORT nxt_int_t nxt_capability_set(nxt_task_t *task, nxt_capability_t *cap);
NXT_EXPORT void nxt_capability_log_hint(nxt_task_t *task);

#ifdef NXT_HAVE_LINUX_CAPABILITY

#include <linux/capability.h>
#include <sys/syscall.h>

#define nxt_capget(hdrp, datap)                                               \
            syscall(SYS_capget, hdrp, datap)
#define nxt_capset(hdrp, datap)                                               \
            syscall(SYS_capset, hdrp, datap)

#elif NXT_HAVE_SOLARIS_PRIVILEGE

#include <priv.h>
#include <sys/tsol/priv.h>

#endif /* NXT_HAVE_LINUX_CAPABILITY */

#endif /* _NXT_CAPABILITY_INCLUDED_ */
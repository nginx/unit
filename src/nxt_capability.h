/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_CAPABILITY_INCLUDED_
#define _NXT_CAPABILITY_INCLUDED_

typedef struct {
    uint8_t setuid;
    uint8_t setgid;
} nxt_capability_t;

NXT_EXPORT nxt_int_t nxt_capability_set(nxt_task_t *task, nxt_capability_t *cap);
NXT_EXPORT void nxt_capability_insufficient(nxt_task_t *task);

#ifdef NXT_LINUX
#include <linux/capability.h>
#include <sys/syscall.h>

#if !defined(_LINUX_CAPABILITY_VERSION)
# warning "Linux capability API version not found"
# warning "System misconfigured or kernel older than 2.2"
# warning "Fallback to basic unix privilege model"
#elif !defined(_LINUX_CAPABILITY_VERSION_2)
# warning "Linux kernel does not support 64-bit capabilities"
# warning "Fallback to basic unix privilege model"
#else

nxt_int_t
nxt_capability_linux_set(nxt_task_t *task, nxt_capability_t *cap);

#define nxt_capget(hdrp, datap)                                               \
            syscall(SYS_capget, hdrp, datap)
#define nxt_capset(hdrp, datap)                                               \
            syscall(SYS_capset, hdrp, datap)

#endif

#elif NXT_SOLARIS 

#include <priv.h>
#include <sys/tsol/priv.h>

nxt_int_t 
nxt_capability_solaris_set(nxt_task_t *task, nxt_capability_t *cap);

#endif /* NXT_LINUX */

#endif /* _NXT_CAPABILITY_INCLUDED_ */
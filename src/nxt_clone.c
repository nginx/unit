/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */
#include <nxt_main.h>
#include <sys/types.h>
#include <nxt_clone.h>

#if (NXT_HAVE_CLONE)

pid_t 
nxt_clone(nxt_int_t flags)
{
#if defined(__s390x__) || defined(__s390__) || defined(__CRIS__)
    return syscall(__NR_clone, NULL, flags);
#else
    return syscall(__NR_clone, flags, NULL);
#endif
}

#endif
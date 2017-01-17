
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


void *
nxt_mem_mmap(void *addr, size_t len, nxt_uint_t protection, nxt_uint_t flags,
    nxt_fd_t fd, nxt_off_t offset)
{
    void  *p;

    p = mmap(addr, len, protection, flags, fd, offset);

    if (nxt_fast_path(p != MAP_FAILED)) {
        nxt_thread_log_debug("mmap(%p, %uz, %uxi, %uxi, %FD, %O): %p",
                       addr, len, protection, flags, fd, offset, p);

    } else {
        nxt_thread_log_alert("mmap(%p, %uz, %ui, %ui, %FD, %O) failed %E",
                       addr, len, protection, flags, fd, offset, nxt_errno);
    }

    return p;
}


void
nxt_mem_munmap(void *addr, size_t len)
{
    if (nxt_fast_path(munmap(addr, len) == 0)) {
        nxt_thread_log_debug("munmap(%p, %uz)", addr, len);

    } else {
        nxt_thread_log_alert("munmap(%p, %uz) failed %E", addr, len, nxt_errno);
    }
}

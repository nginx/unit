
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIX_MEM_MAP_H_INCLUDED_
#define _NXT_UNIX_MEM_MAP_H_INCLUDED_


#define NXT_MEM_MAP_FAILED    MAP_FAILED


#define NXT_MEM_MAP_READ      PROT_READ
#define NXT_MEM_MAP_WRITE     PROT_WRITE


#if (NXT_HAVE_MAP_ANONYMOUS)
#define NXT_MEM_MAP_ANON      MAP_ANONYMOUS
#else
#define NXT_MEM_MAP_ANON      MAP_ANON
#endif

#define NXT_MEM_MAP_SHARED    (MAP_SHARED | NXT_MEM_MAP_ANON)


#if (NXT_HAVE_MAP_POPULATE)
/*
 * Linux MAP_POPULATE reads ahead and wires pages.
 * (MAP_POPULATE | MAP_NONBLOCK) wires only resident pages
 * without read ahead but it does not work since Linux 2.6.23.
 */
#define NXT_MEM_MAP_PREFAULT  MAP_POPULATE

#elif (NXT_HAVE_MAP_PREFAULT_READ)
/* FreeBSD MAP_PREFAULT_READ wires resident pages without read ahead. */
#define NXT_MEM_MAP_PREFAULT  MAP_PREFAULT_READ

#else
#define NXT_MEM_MAP_PREFAULT  0
#endif

#define NXT_MEM_MAP_FILE      (MAP_SHARED | NXT_MEM_MAP_PREFAULT)


#define     nxt_mem_map_file_ctx_t(ctx)


#define nxt_mem_map(addr, ctx, len, protection, flags, fd, offset)            \
    nxt_mem_mmap(addr, len, protection, flags, fd, offset)


#define nxt_mem_unmap(addr, ctx, len)                                         \
    nxt_mem_munmap(addr, len)


NXT_EXPORT void *nxt_mem_mmap(void *addr, size_t len, nxt_uint_t protection,
    nxt_uint_t flags, nxt_fd_t fd, nxt_off_t offset);
NXT_EXPORT void nxt_mem_munmap(void *addr, size_t len);


#endif /* _NXT_UNIX_MEM_MAP_H_INCLUDED_ */

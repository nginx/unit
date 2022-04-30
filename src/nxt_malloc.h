
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIX_MALLOC_H_INCLUDED_
#define _NXT_UNIX_MALLOC_H_INCLUDED_


NXT_EXPORT void *nxt_malloc(size_t size)
    NXT_MALLOC_LIKE;
NXT_EXPORT void *nxt_zalloc(size_t size)
    NXT_MALLOC_LIKE;
NXT_EXPORT void *nxt_realloc(void *p, size_t size)
    NXT_MALLOC_LIKE;
NXT_EXPORT void *nxt_memalign(size_t alignment, size_t size)
    NXT_MALLOC_LIKE;


#if (NXT_DEBUG)

NXT_EXPORT void nxt_free(void *p);

#else

#define nxt_free(p)                                                           \
    free(p)

#endif


#if (NXT_HAVE_MALLOC_USABLE_SIZE)

/*
 * Due to allocation strategies malloc() allocators may allocate more
 * memory than is requested, so malloc_usable_size() allows to use all
 * allocated memory.  It is helpful for socket buffers or unaligned disk
 * file I/O.  However, they may be suboptimal for aligned disk file I/O.
 */

#if (NXT_LINUX)

/*
 * Linux glibc stores bookkeeping information together with allocated
 * memory itself.  Size of the bookkeeping information is 12 or 24 bytes
 * on 32-bit and 64-bit platforms respectively.  Due to alignment there
 * are usually 4 or 8 spare bytes respectively.  However, if allocation
 * is larger than about 128K, spare size may be up to one page: glibc aligns
 * sum of allocation and bookkeeping size to a page.  So if requirement
 * of the large allocation size is not strict it is better to allocate
 * with small cutback and then to adjust size with malloc_usable_size().
 * Glibc malloc_usable_size() is fast operation.
 */

#define nxt_malloc_usable_size(p, size)                                       \
    size = malloc_usable_size(p)

#define nxt_malloc_cutback(cutback, size)                                     \
    size = ((cutback) && size > 127 * 1024) ? size - 32 : size

#elif (NXT_FREEBSD)

/*
 * FreeBSD prior to 7.0 (phkmalloc) aligns sizes to
 *        16 - 2048   a power of two
 *      2049 -  ...   aligned to 4K
 *
 * FreeBSD 7.0 (jemalloc) aligns sizes to:
 *         2 -    8   a power of two
 *         9 -  512   aligned to 16
 *       513 - 2048   a power of two, i.e. aligned to 1K
 *      2049 -    1M  aligned to 4K
 *         1M-  ...   aligned to 1M
 * See table in src/lib/libc/stdlib/malloc.c
 *
 * FreeBSD 7.0 malloc_usable_size() is fast for allocations, which
 * are lesser than 1M.  Larger allocations require mutex acquiring.
 */

#define nxt_malloc_usable_size(p, size)                                       \
    size = malloc_usable_size(p)

#define nxt_malloc_cutback(cutback, size)

#endif

#elif (NXT_HAVE_MALLOC_GOOD_SIZE)

/*
 * MacOSX aligns sizes to
 *        16 -  496   aligned to 16, 32-bit
 *        16 -  992   aligned to 16, 64-bit
 *   497/993 -   15K  aligned to 512, if lesser than 1G RAM
 *   497/993 -  127K  aligned to 512, otherwise
 *   15K/127K-  ...   aligned to 4K
 *
 * malloc_good_size() is faster than malloc_size()
 */

#define nxt_malloc_usable_size(p, size)                                       \
    size = malloc_good_size(size)

#define nxt_malloc_cutback(cutback, size)

#else

#define nxt_malloc_usable_size(p, size)

#define nxt_malloc_cutback(cutback, size)

#endif


#if (NXT_HAVE_POSIX_MEMALIGN || NXT_HAVE_MEMALIGN)
#define NXT_MAX_MEMALIGN_SHIFT  32

#elif (NXT_FREEBSD)
#define NXT_MAX_MEMALIGN_SHIFT  12

#else
#define NXT_MAX_MEMALIGN_SHIFT  3
#endif


#endif /* _NXT_UNIX_MALLOC_H_INCLUDED_ */

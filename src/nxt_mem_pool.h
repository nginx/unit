
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_MEM_POOL_H_INCLUDED_
#define _NXT_MEM_POOL_H_INCLUDED_


#define NXT_MEM_POOL_MIN_EXT_SIZE      nxt_pagesize


typedef void (*nxt_mem_pool_cleanup_handler_t)(void *data);
typedef struct nxt_mem_pool_cleanup_s  nxt_mem_pool_cleanup_t;
typedef struct nxt_mem_pool_cache_s    nxt_mem_pool_cache_t;
typedef struct nxt_mem_pool_chunk_s    nxt_mem_pool_chunk_t;
typedef struct nxt_mem_pool_ext_s      nxt_mem_pool_ext_t;


struct nxt_mem_pool_cleanup_s {
    nxt_mem_pool_cleanup_handler_t     handler;
    void                               *data;
    nxt_mem_pool_cleanup_t             *next;
};


struct nxt_mem_pool_ext_s {
    void                               *data;
    nxt_mem_pool_ext_t                 *next;
};


struct nxt_mem_pool_chunk_s {
    u_char                             *free;
    u_char                             *end;
    nxt_mem_pool_chunk_t               *next;
    uint32_t                           fails;  /* 8 bits */
};


struct nxt_mem_pool_cache_s {
    uint32_t                           size;
    uint32_t                           nalloc;
    void                               *free;
    nxt_mem_pool_cache_t               *next;
};


struct nxt_mem_pool_s {
    nxt_mem_pool_chunk_t               chunk;
    uint32_t                           min_ext_size;
    uint32_t                           chunk_size;
    nxt_mem_pool_chunk_t               *current;
    nxt_mem_pool_ext_t                 *ext;
    nxt_mem_pool_cache_t               *cache;
    nxt_mem_pool_cleanup_t             *cleanup;

#if (NXT_DEBUG)
    nxt_pid_t                          pid;
    nxt_tid_t                          tid;
#endif
};


NXT_EXPORT nxt_mem_pool_t *nxt_mem_pool_create(size_t size)
    NXT_MALLOC_LIKE;
NXT_EXPORT void nxt_mem_pool_destroy(nxt_mem_pool_t *mp);


/*
 * Generic aligned allocation, suitable for struct allocations
 * without "long double" and SIMD values.
 */
#define                                                                       \
nxt_mem_alloc(mp, size)                                                       \
    nxt_mem_align((mp), NXT_ALIGNMENT, (size))


NXT_EXPORT void *nxt_mem_align(nxt_mem_pool_t *mp, size_t alignment,
    size_t size)
    NXT_MALLOC_LIKE;

NXT_EXPORT void *nxt_mem_zalign(nxt_mem_pool_t *mp, size_t alignment,
    size_t size)
    NXT_MALLOC_LIKE;

NXT_EXPORT void *nxt_mem_nalloc(nxt_mem_pool_t *mp, size_t size)
    NXT_MALLOC_LIKE;

NXT_EXPORT void *nxt_mem_zalloc(nxt_mem_pool_t *mp, size_t size)
    NXT_MALLOC_LIKE;


/*
 * nxt_mem_buf() is intended to allocate I/O buffers.
 * Unix network buffers usually have no size restrictions, so
 * NXT_MEM_BUF_CUTBACK and NXT_MEM_BUF_USABLE options allow to
 * utilize better allocated memory (details in unix/nxt_malloc.h).
 * Windows locks buffers in kernel memory on page basis for both
 * network and file operations, so nxt_mem_buf() should minimize
 * number of allocated pages.  However, these allocations are not
 * necessary page-aligned.
 */
#define NXT_MEM_BUF_CUTBACK  1
#define NXT_MEM_BUF_USABLE   2

NXT_EXPORT void *nxt_mem_buf(nxt_mem_pool_t *mp, size_t *sizep,
    nxt_uint_t flags);


/*
 * Aligned allocation, suitable for generic allocations compatible
 * with malloc() alignment.
 */
#define                                                                       \
nxt_mem_malloc(mp, size)                                                      \
    nxt_mem_align((mp), NXT_MAX_ALIGNMENT, (size))


NXT_EXPORT nxt_int_t nxt_mem_free(nxt_mem_pool_t *mp, void *p);
NXT_EXPORT nxt_mem_pool_cleanup_t *nxt_mem_pool_cleanup(nxt_mem_pool_t *mp,
    size_t size);

NXT_EXPORT void *nxt_mem_cache_alloc0(nxt_mem_pool_t *mp, size_t size)
    NXT_MALLOC_LIKE;
NXT_EXPORT void *nxt_mem_cache_zalloc0(nxt_mem_pool_t *mp, size_t size)
    NXT_MALLOC_LIKE;
NXT_EXPORT void nxt_mem_cache_free0(nxt_mem_pool_t *mp, void *p, size_t size);

NXT_EXPORT void *nxt_mem_lvlhsh_alloc(void *ctx, size_t size,
    nxt_uint_t nalloc);
NXT_EXPORT void nxt_mem_lvlhsh_free(void *ctx, void *p, size_t size);


#if (NXT_DEBUG)

#define                                                                       \
nxt_mem_pool_debug_lock(_mp, _tid)                                            \
    (_mp->tid) = _tid

#else

#define                                                                       \
nxt_mem_pool_debug_lock(_mp, _tid)

#endif


#endif /* _NXT_MEM_POOL_H_INCLUDED_ */

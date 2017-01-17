
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_MEM_CACHE_POOL_H_INCLUDED_
#define _NXT_MEM_CACHE_POOL_H_INCLUDED_


typedef struct nxt_mem_cache_pool_s  nxt_mem_cache_pool_t;


NXT_EXPORT nxt_mem_cache_pool_t *nxt_mem_cache_pool_create(size_t cluster_size,
    size_t page_alignment, size_t page_size, size_t min_chunk_size)
    NXT_MALLOC_LIKE;
NXT_EXPORT nxt_mem_cache_pool_t *
    nxt_mem_cache_pool_fast_create(size_t cluster_size,
    size_t page_alignment, size_t page_size, size_t min_chunk_size)
    NXT_MALLOC_LIKE;
NXT_EXPORT nxt_bool_t nxt_mem_cache_pool_is_empty(nxt_mem_cache_pool_t *pool);
NXT_EXPORT void nxt_mem_cache_pool_destroy(nxt_mem_cache_pool_t *pool);

NXT_EXPORT void *nxt_mem_cache_alloc(nxt_mem_cache_pool_t *pool, size_t size)
    NXT_MALLOC_LIKE;
NXT_EXPORT void *nxt_mem_cache_zalloc(nxt_mem_cache_pool_t *pool, size_t size)
    NXT_MALLOC_LIKE;
NXT_EXPORT void *nxt_mem_cache_align(nxt_mem_cache_pool_t *pool,
    size_t alignment, size_t size)
    NXT_MALLOC_LIKE;
NXT_EXPORT void *nxt_mem_cache_zalign(nxt_mem_cache_pool_t *pool,
    size_t alignment, size_t size)
    NXT_MALLOC_LIKE;
NXT_EXPORT void nxt_mem_cache_free(nxt_mem_cache_pool_t *pool, void *p);


extern const nxt_mem_proto_t  nxt_mem_cache_proto;


#endif /* _NXT_MEM_CACHE_POOL_H_INCLUDED_ */

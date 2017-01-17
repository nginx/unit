
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


typedef struct nxt_lvlhsh_pool_cache_s  nxt_lvlhsh_pool_cache_t;

struct nxt_lvlhsh_pool_cache_s {
    uint32_t                 size;
    uint32_t                 nalloc;
    void                     *free;
    nxt_lvlhsh_pool_cache_t  *next;
};


typedef struct {
    nxt_mem_pool_t           *mem_pool;
    void                     *free;
    nxt_lvlhsh_pool_cache_t  *next;
} nxt_lvlhsh_pool_t;


/*
 * lvlhsh requires allocations aligned to a size of the allocations.
 * This is not issue for slab-like allocators, but glibc allocator may
 * waste memory on such aligned allocations.  So nxt_lvlhsh_pool_alloc()
 * allocates memory in chunks specified by the "nalloc" parameter
 * except the first allocation.  The first lvlhsh allocation is a bucket
 * allocation and it is enough for a small hash or for early stage of
 * a large hash.  By default lvlhsh uses 128-bytes or 64-bytes buckets
 * and levels on 64-bit and 32-bit platforms respectively.
 * This allows to search up to 10 entries in one memory access and
 * up to 160 entries in two memory accesses on 64-bit platform.
 * And on 32-bit platform up to 7 entries and up to 112 entries
 * respectively.
 *
 * After the bucket has been filled up with 10 64-bit entries
 * or 7 32-bit entries, lvlhsh expands it to a level and spreads
 * content of the first bucket to the level's new buckets.
 * Number of the new allocations may be up to 11 on 64-bit or
 * 8 on 32-bit platforms.  It's better to allocate them together
 * to eliminate wasting memory and CPU time.
 *
 * The "nalloc" should be 16.
 */


static void *nxt_lvlhsh_pool_alloc_chunk(nxt_mem_pool_cache_t *cache,
    size_t size, nxt_uint_t nalloc);


/* Allocation of lvlhsh level or bucket with specified size. */

void *
nxt_lvlhsh_pool_alloc(void *ctx, size_t size, nxt_uint_t nalloc)
{
    void                  *p, **pp;
    nxt_mem_pool_t        *mp;
    nxt_mem_pool_cache_t  *cache;

    mp = ctx;

    for (cache = mp->cache; cache != NULL; cache = cache->next) {

        if (cache->size == size && cache->nalloc != 0) {

            if (cache->free != NULL) {
                pp = cache->free;
                cache->free = *pp;
                return pp;
            }

            return nxt_lvlhsh_pool_alloc_chunk(cache, size, nalloc);
        }
    }

    cache = nxt_mem_alloc(mp, sizeof(nxt_mem_pool_cache_t));

    if (nxt_fast_path(cache != NULL)) {

        p = nxt_memalign(size, size);

        if (nxt_fast_path(p != NULL)) {
            cache->size = size;
            cache->nalloc = nalloc;
            cache->free = NULL;
            cache->next = mp->cache;
            mp->cache = cache;
            return p;
        }
    }

    return NULL;
}


static void *
nxt_lvlhsh_pool_alloc_chunk(nxt_mem_pool_cache_t *cache, size_t size,
    nxt_uint_t nalloc)
{
    char    *m, *p, *end;
    void    **pp;
    size_t  n;

    n = (nalloc == 0) ? 1 : nalloc;
    n *= size;

    m = nxt_memalign(size, n);

    if (nxt_fast_path(m != NULL)) {

        pp = &cache->free;
        end = m + n;

        for (p = m + size; p < end; p = p + size) {
            *pp = p;
            pp = (void **) p;
        }

        *pp = NULL;
    }

    return m;
}



/* Deallocation of lvlhsh level or bucket with specified size. */

void
nxt_lvlhsh_pool_free(void *ctx, void *p, size_t size)
{
    void                  **pp;
    nxt_mem_pool_t        *mp;
    nxt_mem_pool_cache_t  *cache;

    mp = ctx;

    pp = p;

    for (cache = mp->cache; cache != NULL; cache = cache->next) {

        if (cache->size == size && cache->nalloc != 0) {
            *pp = cache->free;
            cache->free = p;
            return;
        }
    }
}

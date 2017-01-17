
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * The pool allocator provides cheap allocation of small objects.
 * The objects are allocated from larger preallocated chunks.
 *
 *   aligned and non-aligned allocations,
 *   cache of reusable objects, lvlhsh-specific cache
 *   eliminating align padding
 *   data locality
 *   freeing on pool destruction
 *   freeing large allocations
 */


static void *nxt_mem_pool_align(nxt_mem_pool_t *mp, size_t alignment,
    size_t size);
static void *nxt_mem_pool_ext(nxt_mem_pool_t *mp, size_t size);
static nxt_mem_pool_chunk_t *nxt_mem_pool_next_chunk(nxt_mem_pool_t *mp,
    nxt_mem_pool_chunk_t *chunk);
static nxt_mem_pool_chunk_t *nxt_mem_pool_chunk(nxt_mem_pool_t *mp);
static void *nxt_mem_lvlhsh_alloc_chunk(nxt_mem_pool_cache_t *cache,
    size_t size, nxt_uint_t nalloc);


#if (NXT_DEBUG)

static nxt_bool_t
nxt_mem_pool_thread_is_invalid(nxt_mem_pool_t *mp)
{
    nxt_tid_t     tid;
    nxt_thread_t  *thr;

    thr = nxt_thread();
    tid = nxt_thread_tid(thr);

    if (nxt_slow_path(mp->tid != tid)) {

        if (mp->pid == nxt_pid) {
            nxt_log_alert(thr->log, "mem_pool locked by thread %PT", mp->tid);
            nxt_abort();
            return 1;
        }

        mp->pid = nxt_pid;
        mp->tid = tid;
    }

    return 0;
}


/* SunC does not support C99 variadic macro with empty __VA_ARGS__. */

#define                                                                       \
nxt_mem_pool_thread_assert(mp)                                                \
    if (nxt_mem_pool_thread_is_invalid(mp))                                   \
        return


#define                                                                       \
nxt_mem_pool_thread_assert_return(mp, ret)                                    \
    if (nxt_mem_pool_thread_is_invalid(mp))                                   \
        return ret


#else /* !(NXT_DEBUG) */

#define                                                                       \
nxt_mem_pool_thread_assert(mp)

#define                                                                       \
nxt_mem_pool_thread_assert_return(mp, ret)

#endif


nxt_mem_pool_t *
nxt_mem_pool_create(size_t size)
{
    u_char          *p;
    size_t          min_ext_size;
    nxt_mem_pool_t  *mp;

    mp = nxt_malloc(size);

    if (nxt_fast_path(mp != NULL)) {

        mp->chunk_size = (uint32_t) size;

        min_ext_size = size - sizeof(nxt_mem_pool_t) + 1;
        mp->min_ext_size = (uint32_t) nxt_min(min_ext_size,
                                              NXT_MEM_POOL_MIN_EXT_SIZE);

        nxt_malloc_usable_size(mp, size);

        p = (u_char *) mp;

        mp->chunk.free = p + sizeof(nxt_mem_pool_t);
        mp->chunk.end = p + size;
        mp->chunk.next = NULL;
        mp->chunk.fails = 0;

        mp->current = &mp->chunk;
        mp->ext = NULL;
        mp->cleanup = NULL;
        mp->cache = NULL;

        nxt_thread_log_debug("mem pool chunk size:%uz avail:%uz",
                             size, mp->chunk.end - mp->chunk.free);

        nxt_mem_pool_debug_lock(mp, nxt_thread_tid(NULL));
    }

    return mp;
}


void
nxt_mem_pool_destroy(nxt_mem_pool_t *mp)
{
    nxt_mem_pool_ext_t      *ext;
    nxt_mem_pool_chunk_t    *chunk, *next;
    nxt_mem_pool_cleanup_t  *mpcl;

    nxt_mem_pool_thread_assert(mp);

    for (mpcl = mp->cleanup; mpcl != NULL; mpcl = mpcl->next) {
        if (mpcl->handler != NULL) {
            nxt_thread_log_debug("mem pool cleanup: %p", mpcl);
            mpcl->handler(mpcl->data);
        }
    }

    for (ext = mp->ext; ext != NULL; ext = ext->next) {
        if (ext->data != NULL) {
            nxt_free(ext->data);
        }
    }

    chunk = &mp->chunk;

    do {
        nxt_thread_log_debug("mem pool chunk fails:%uD unused:%uz",
                             chunk->fails, chunk->end - chunk->free);
        next = chunk->next;
        nxt_free(chunk);
        chunk = next;

    } while (chunk != NULL);
}


void *
nxt_mem_align(nxt_mem_pool_t *mp, size_t alignment, size_t size)
{
    nxt_mem_pool_thread_assert_return(mp, NULL);

    if (nxt_fast_path(size < mp->min_ext_size)) {
        return nxt_mem_pool_align(mp, alignment, size);
    }

    return nxt_mem_pool_ext(mp, size);
}


void *
nxt_mem_zalign(nxt_mem_pool_t *mp, size_t alignment, size_t size)
{
    void  *p;

    p = nxt_mem_align(mp, alignment, size);

    if (nxt_fast_path(p != NULL)) {
        nxt_memzero(p, size);
    }

    return p;
}


/*
 * Zero-filled aligned allocation, suitable for struct
 * allocation without long double and SIMD values.
 */

void *
nxt_mem_zalloc(nxt_mem_pool_t *mp, size_t size)
{
    void  *p;

    p = nxt_mem_alloc(mp, size);

    if (nxt_fast_path(p != NULL)) {
        nxt_memzero(p, size);
    }

    return p;
}


void *
nxt_mem_buf(nxt_mem_pool_t *mp, size_t *sizep, nxt_uint_t flags)
{
    u_char  *p;
    size_t  size;

    nxt_mem_pool_thread_assert_return(mp, NULL);

    size = *sizep;

    if (nxt_fast_path(size >= mp->min_ext_size)) {

        nxt_malloc_cutback(flags & NXT_MEM_BUF_CUTBACK, size);

        /* Windows only: try to minimize number of allocated pages. */
        p = nxt_mem_pool_ext(mp, size);
        if (p != NULL) {

            if (flags & NXT_MEM_BUF_USABLE) {
                nxt_malloc_usable_size(p, size);
            }

            *sizep = size;
        }

        return p;
    }

    return nxt_mem_pool_align(mp, NXT_ALIGNMENT, size);
}


/* Non-aligned allocation, suitable for string allocation. */

void *
nxt_mem_nalloc(nxt_mem_pool_t *mp, size_t size)
{
    u_char                *p;
    nxt_mem_pool_chunk_t  *chunk;

    nxt_mem_pool_thread_assert_return(mp, NULL);

    if (nxt_slow_path(size >= mp->min_ext_size)) {
        return nxt_mem_pool_ext(mp, size);
    }

    chunk = mp->current;

    for ( ;; ) {
        p = chunk->end - size;

        if (nxt_fast_path(p >= chunk->free)) {
            chunk->end = p;
            return p;
        }

        chunk = nxt_mem_pool_next_chunk(mp, chunk);

        if (nxt_slow_path(chunk == NULL)) {
            return NULL;
        }
    }
}


/* An attempt to deallocate a large allocation outside pool. */

nxt_int_t
nxt_mem_free(nxt_mem_pool_t *mp, void *p)
{
    nxt_mem_pool_ext_t  *ext;

    nxt_mem_pool_thread_assert_return(mp, NXT_DECLINED);

    for (ext = mp->ext; ext != NULL; ext = ext->next) {

        if (p == ext->data) {
            nxt_free(ext->data);
            ext->data = NULL;

            return NXT_OK;
        }
    }

    return NXT_DECLINED;
}


static void *
nxt_mem_pool_ext(nxt_mem_pool_t *mp, size_t size)
{
    void                *p;
    nxt_mem_pool_ext_t  *ext;

    ext = nxt_mem_pool_align(mp, sizeof(void *), sizeof(nxt_mem_pool_ext_t));

    if (nxt_fast_path(ext != NULL)) {
        p = nxt_malloc(size);

        if (nxt_fast_path(p != NULL)) {
            ext->data = p;
            ext->next = mp->ext;
            mp->ext = ext;

            return p;
        }
    }

    return NULL;
}


static void *
nxt_mem_pool_align(nxt_mem_pool_t *mp, size_t alignment, size_t size)
{
    u_char                *p, *f;
    nxt_mem_pool_chunk_t  *chunk;

    chunk = mp->current;

    for ( ;; ) {

        p = nxt_align_ptr(chunk->free, alignment);
        f = p + size;

        if (nxt_fast_path(f <= chunk->end)) {
            chunk->free = f;
            return p;
        }

        chunk = nxt_mem_pool_next_chunk(mp, chunk);

        if (nxt_slow_path(chunk == NULL)) {
            return NULL;
        }
    }
}


static nxt_mem_pool_chunk_t *
nxt_mem_pool_next_chunk(nxt_mem_pool_t *mp, nxt_mem_pool_chunk_t *chunk)
{
    nxt_bool_t  full;

    full = (chunk->free == chunk->end || chunk->fails++ > 10);

    chunk = chunk->next;

    if (chunk == NULL) {
        chunk = nxt_mem_pool_chunk(mp);

        if (nxt_slow_path(chunk == NULL)) {
            return NULL;
        }
    }

    if (full) {
        mp->current = chunk;
    }

    return chunk;
}


static nxt_mem_pool_chunk_t *
nxt_mem_pool_chunk(nxt_mem_pool_t *mp)
{
    u_char                *p;
    size_t                size;
    nxt_mem_pool_chunk_t  *ch, *chunk;

    size = mp->chunk_size;

    chunk = nxt_malloc(size);

    if (nxt_fast_path(chunk != NULL)) {

        nxt_malloc_usable_size(chunk, size);

        p = (u_char *) chunk;

        chunk->free = p + sizeof(nxt_mem_pool_chunk_t);
        chunk->end = p + size;
        chunk->next = NULL;
        chunk->fails = 0;

        for (ch = mp->current; ch->next; ch = ch->next) { /* void */ }

        ch->next = chunk;
    }

    return chunk;
}


nxt_mem_pool_cleanup_t *
nxt_mem_pool_cleanup(nxt_mem_pool_t *mp, size_t size)
{
    nxt_mem_pool_cleanup_t  *mpcl;

    nxt_mem_pool_thread_assert_return(mp, NULL);

    mpcl = nxt_mem_pool_align(mp, sizeof(void *),
                              sizeof(nxt_mem_pool_cleanup_t));
    if (nxt_fast_path(mpcl != NULL)) {

        mpcl->handler = NULL;
        mpcl->data = NULL;

        if (size != 0) {
            mpcl->data = nxt_mem_alloc(mp, size);
            if (nxt_slow_path(mpcl->data == NULL)) {
                return NULL;
            }
        }

        mpcl->next = mp->cleanup;
        mp->cleanup = mpcl;

        nxt_thread_log_debug("mem pool cleanup add: %p", mpcl);
    }

    return mpcl;
}


/* Allocation of reusable object with specified size. */

void *
nxt_mem_cache_alloc0(nxt_mem_pool_t *mp, size_t size)
{
    void                  **pp;
    nxt_mem_pool_cache_t  *cache;

    nxt_mem_pool_thread_assert_return(mp, NULL);

    for (cache = mp->cache; cache != NULL; cache = cache->next) {

        if (cache->size == size && cache->nalloc == 0) {

            if (cache->free != NULL) {
                pp = cache->free;
                cache->free = *pp;
                return pp;
            }

            break;
        }
    }

    return nxt_mem_alloc(mp, size);
}


void *
nxt_mem_cache_zalloc0(nxt_mem_pool_t *mp, size_t size)
{
    void  *p;

    p = nxt_mem_cache_alloc0(mp, size);

    if (nxt_fast_path(p != NULL)) {
        nxt_memzero(p, size);
    }

    return p;
}


/* Deallocation of reusable object with specified size. */

void
nxt_mem_cache_free0(nxt_mem_pool_t *mp, void *p, size_t size)
{
    void                  **pp;
    nxt_mem_pool_cache_t  *cache, **pcache;

    nxt_mem_pool_thread_assert(mp);

    pp = p;

    pcache = &mp->cache;
    for (cache = mp->cache; cache != NULL; cache = cache->next) {

        if (cache->size == size && cache->nalloc == 0) {
            *pp = cache->free;
            cache->free = p;
            return;
        }

        pcache = &cache->next;
    }

    /* Non-lvlhash caches are created only on return. */

    cache = nxt_mem_pool_align(mp, sizeof(void *),
                               sizeof(nxt_mem_pool_cache_t));
    if (nxt_fast_path(cache != NULL)) {
        *pp = NULL;
        cache->size = (uint32_t) size;
        cache->nalloc = 0;
        cache->free = p;
        cache->next = NULL;
        *pcache = cache;
    }
}


/*
 * lvlhsh requires allocations aligned to a size of the allocations.
 * This is not issue for slab-like allocators, but glibc allocator may
 * waste memory on such aligned allocations.  So nxt_mem_lvlhsh_alloc()
 * allocates memory in chunks specified by the "nalloc" parameter
 * except the first allocation.  The first lvlhsh allocation is a bucket
 * allocation and it is enough for small hashes and for early stage
 * of a hash.  By default lvlhsh uses 128-bytes buckets and levels.
 * This allows to search up to 10 entries in one memory access and
 * up to 160 entries in two memory accesses on 64-bit platform.
 * And on 32-bit platform up to 15 entries and up to 480 entries
 * respectively.
 *
 * After the bucket will be filled up with 10 64-bit entries or 15
 * 32-bit entries, lvlhsh will expand it to a level and content
 * of the first bucket will spread to the level's new buckets.
 * Number of the new buckets may be up to 11 on 64-bit or 16 on 32-bit
 * platforms.  It's better to allocate them together to eliminate
 * wasting memory and CPU time.
 *
 * The "nalloc" should be 16 if bucket size is 128 bytes.
 */


/* Allocation of lvlhsh level or bucket with specified size. */

void *
nxt_mem_lvlhsh_alloc(void *ctx, size_t size, nxt_uint_t nalloc)
{
    void                  *p, **pp;
    nxt_mem_pool_t        *mp;
    nxt_mem_pool_cache_t  *cache;

    mp = ctx;

    nxt_mem_pool_thread_assert_return(mp, NULL);

    for (cache = mp->cache; cache != NULL; cache = cache->next) {

        if (cache->size == size && cache->nalloc != 0) {

            if (cache->free != NULL) {
                pp = cache->free;
                cache->free = *pp;
                return pp;
            }

            return nxt_mem_lvlhsh_alloc_chunk(cache, size, nalloc);
        }
    }

    cache = nxt_mem_pool_align(mp, sizeof(void *),
                               sizeof(nxt_mem_pool_cache_t));
    if (nxt_fast_path(cache != NULL)) {

        p = nxt_memalign(size, size);

        if (nxt_fast_path(p != NULL)) {
            cache->size = (uint32_t) size;
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
nxt_mem_lvlhsh_alloc_chunk(nxt_mem_pool_cache_t *cache, size_t size,
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
nxt_mem_lvlhsh_free(void *ctx, void *p, size_t size)
{
    void                  **pp;
    nxt_mem_pool_t        *mp;
    nxt_mem_pool_cache_t  *cache;

    mp = ctx;

    nxt_mem_pool_thread_assert(mp);

    pp = p;

    for (cache = mp->cache; cache != NULL; cache = cache->next) {

        if (cache->size == size && cache->nalloc != 0) {
            *pp = cache->free;
            cache->free = p;
            return;
        }
    }
}

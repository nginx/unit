
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * A memory cache pool allocates memory in clusters of specified size and
 * aligned to page_alignment.  A cluster is divided on pages of specified
 * size.  Page size must be a power of 2.  A page can be used entirely or
 * can be divided on chunks of equal size.  Chunk size must be a power of 2.
 * A cluster can contains pages with different chunk sizes.  Cluster size
 * must be multiple of page size and may be not a power of 2.  Allocations
 * greater than page are allocated outside clusters.  Start addresses and
 * sizes of clusters and large allocations are stored in rbtree to find
 * them on free operations.  The rbtree nodes are sorted by start addresses.
 */


typedef struct nxt_mem_cache_page_s  nxt_mem_cache_page_t;

struct nxt_mem_cache_page_s {
    /* Chunk bitmap.  There can be no more than 32 chunks in a page. */
    uint8_t                  map[4];

    /* Number of free chunks of a chunked page. */
    uint8_t                  chunks;

    /*
     * Size of chunks or page shifted by pool->chunk_size_shift.
     * Zero means that page is free.
     */
    uint8_t                  size;

    /*
     * Page number in page cluster.
     * There can be no more than 65536 pages in a cluster.
     */
    uint16_t                 number;

    /*
     * Used to link pages with free chunks in pool chunk slot list
     * or to link free pages in clusters.
     */
    nxt_queue_link_t         link;
};


typedef struct {
    NXT_RBTREE_NODE          (node);
    uint8_t                  type;
    uint32_t                 size;

    u_char                   *start;
    nxt_mem_cache_page_t     pages[];
} nxt_mem_cache_block_t;


typedef struct {
    nxt_queue_t              pages;
#if (NXT_64BIT)
    uint32_t                 size;
    uint32_t                 chunks;
#else
    uint16_t                 size;
    uint16_t                 chunks;
#endif
} nxt_mem_cache_slot_t;


struct nxt_mem_cache_pool_s {
    /* rbtree of nxt_mem_cache_block_t. */
    nxt_rbtree_t             pages;

    nxt_queue_t              free_pages;

    uint8_t                  chunk_size_shift;
    uint8_t                  page_size_shift;
    uint32_t                 page_size;
    uint32_t                 page_alignment;
    uint32_t                 cluster_size;

    nxt_mem_cache_slot_t     slots[];
};


/* A cluster cache block. */
#define NXT_MEM_CACHE_CLUSTER_BLOCK   0

/* A discrete cache block of large allocation. */
#define NXT_MEM_CACHE_DISCRETE_BLOCK  1
/*
 * An embedded cache block allocated together with large allocation
 * just after the allocation.
 */
#define NXT_MEM_CACHE_EMBEDDED_BLOCK  2


#define                                                                       \
nxt_mem_cache_chunk_is_free(map, chunk)                                       \
    ((map[chunk / 8] & (0x80 >> (chunk & 7))) == 0)


#define                                                                       \
nxt_mem_cache_chunk_set_free(map, chunk)                                      \
    map[chunk / 8] &= ~(0x80 >> (chunk & 7))


#define                                                                       \
nxt_mem_cache_free_junk(p, size)                                              \
    nxt_memset((p), 0x5A, size)


static nxt_uint_t nxt_mem_cache_shift(nxt_uint_t n);
static void *nxt_mem_cache_alloc_small(nxt_mem_cache_pool_t *pool, size_t size);
static nxt_uint_t nxt_mem_cache_alloc_chunk(u_char *map, nxt_uint_t size);
static nxt_mem_cache_page_t *
    nxt_mem_cache_alloc_page(nxt_mem_cache_pool_t *pool);
static nxt_mem_cache_block_t *
    nxt_mem_cache_alloc_cluster(nxt_mem_cache_pool_t *pool);
static void *nxt_mem_cache_alloc_large(nxt_mem_cache_pool_t *pool,
    size_t alignment, size_t size);
static nxt_int_t nxt_mem_cache_rbtree_compare(nxt_rbtree_node_t *node1,
    nxt_rbtree_node_t *node2);
static nxt_mem_cache_block_t *nxt_mem_cache_find_block(nxt_rbtree_t *tree,
    u_char *p);
static const char *nxt_mem_cache_chunk_free(nxt_mem_cache_pool_t *pool,
    nxt_mem_cache_block_t *cluster, u_char *p);


nxt_mem_cache_pool_t *
nxt_mem_cache_pool_create(size_t cluster_size, size_t page_alignment,
    size_t page_size, size_t min_chunk_size)
{
    /* Alignment and sizes must be a power of 2. */

    if (nxt_slow_path((page_alignment & (page_alignment - 1)) != 0
                      || (page_size & (page_size - 1)) != 0
                      || (min_chunk_size & (min_chunk_size - 1)) != 0))
    {
        return NULL;
    }

    page_alignment = nxt_max(page_alignment, NXT_MAX_ALIGNMENT);

    if (nxt_slow_path(page_size < 64
                      || page_size < page_alignment
                      || page_size < min_chunk_size
                      || min_chunk_size * 32 < page_size
                      || cluster_size < page_size
                      || cluster_size % page_size != 0))
    {
        return NULL;
    }

    return nxt_mem_cache_pool_fast_create(cluster_size, page_alignment,
                                          page_size, min_chunk_size);
}


nxt_mem_cache_pool_t *
nxt_mem_cache_pool_fast_create(size_t cluster_size, size_t page_alignment,
    size_t page_size, size_t min_chunk_size)
{
    nxt_uint_t            slots, chunk_size;
    nxt_mem_cache_slot_t  *slot;
    nxt_mem_cache_pool_t  *pool;

    slots = 0;
    chunk_size = page_size;

    do {
        slots++;
        chunk_size /= 2;
    } while (chunk_size > min_chunk_size);

    pool = nxt_zalloc(sizeof(nxt_mem_cache_pool_t)
                      + slots * sizeof(nxt_mem_cache_slot_t));

    if (nxt_fast_path(pool != NULL)) {

        pool->page_size = page_size;
        pool->page_alignment = nxt_max(page_alignment, NXT_MAX_ALIGNMENT);
        pool->cluster_size = cluster_size;

        slot = pool->slots;

        do {
            nxt_queue_init(&slot->pages);

            slot->size = chunk_size;
            /* slot->chunks should be one less than actual number of chunks. */
            slot->chunks = (page_size / chunk_size) - 1;

            slot++;
            chunk_size *= 2;
        } while (chunk_size < page_size);

        pool->chunk_size_shift = nxt_mem_cache_shift(min_chunk_size);
        pool->page_size_shift = nxt_mem_cache_shift(page_size);

        nxt_rbtree_init(&pool->pages, nxt_mem_cache_rbtree_compare, NULL);

        nxt_queue_init(&pool->free_pages);
    }

    return pool;
}


static nxt_uint_t
nxt_mem_cache_shift(nxt_uint_t n)
{
    nxt_uint_t  shift;

    shift = 0;
    n /= 2;

    do {
        shift++;
        n /= 2;
    } while (n != 0);

    return shift;
}


nxt_bool_t
nxt_mem_cache_pool_is_empty(nxt_mem_cache_pool_t *pool)
{
    return (nxt_rbtree_is_empty(&pool->pages)
            && nxt_queue_is_empty(&pool->free_pages));
}


void
nxt_mem_cache_pool_destroy(nxt_mem_cache_pool_t *pool)
{
    void                   *p;
    nxt_rbtree_node_t      *node, *next;
    nxt_mem_cache_block_t  *block;

    for (node = nxt_rbtree_min(&pool->pages);
         nxt_rbtree_is_there_successor(&pool->pages, node);
         node = next)
    {
        next = nxt_rbtree_node_successor(&pool->pages, node);

        block = (nxt_mem_cache_block_t *) node;

        nxt_rbtree_delete(&pool->pages, &block->node);

        p = block->start;

        if (block->type != NXT_MEM_CACHE_EMBEDDED_BLOCK) {
            nxt_free(block);
        }

        nxt_free(p);
    }

    nxt_free(pool);
}


nxt_inline u_char *
nxt_mem_cache_page_addr(nxt_mem_cache_pool_t *pool, nxt_mem_cache_page_t *page)
{
    nxt_mem_cache_block_t  *block;

    block = (nxt_mem_cache_block_t *)
                ((u_char *) page - page->number * sizeof(nxt_mem_cache_page_t)
                 - offsetof(nxt_mem_cache_block_t, pages));

    return block->start + (page->number << pool->page_size_shift);
}


void *
nxt_mem_cache_alloc(nxt_mem_cache_pool_t *pool, size_t size)
{
    nxt_thread_log_debug("mem cache alloc: %uz", size);

    if (size <= pool->page_size) {
        return nxt_mem_cache_alloc_small(pool, size);
    }

    return nxt_mem_cache_alloc_large(pool, NXT_MAX_ALIGNMENT, size);
}


void *
nxt_mem_cache_zalloc(nxt_mem_cache_pool_t *pool, size_t size)
{
    void  *p;

    p = nxt_mem_cache_alloc(pool, size);

    if (nxt_fast_path(p != NULL)) {
        nxt_memzero(p, size);
    }

    return p;
}


void *
nxt_mem_cache_align(nxt_mem_cache_pool_t *pool, size_t alignment, size_t size)
{
    nxt_thread_log_debug("mem cache align: @%uz:%uz", alignment, size);

    /* Alignment must be a power of 2. */

    if (nxt_fast_path((alignment - 1) & alignment) == 0) {

        if (size <= pool->page_size && alignment <= pool->page_alignment) {
            size = nxt_max(size, alignment);

            if (size <= pool->page_size) {
                return nxt_mem_cache_alloc_small(pool, size);
            }
        }

        return nxt_mem_cache_alloc_large(pool, alignment, size);
    }

    return NULL;
}


void *
nxt_mem_cache_zalign(nxt_mem_cache_pool_t *pool, size_t alignment, size_t size)
{
    void  *p;

    p = nxt_mem_cache_align(pool, alignment, size);

    if (nxt_fast_path(p != NULL)) {
        nxt_memzero(p, size);
    }

    return p;
}


static void *
nxt_mem_cache_alloc_small(nxt_mem_cache_pool_t *pool, size_t size)
{
    u_char                *p;
    nxt_queue_link_t      *link;
    nxt_mem_cache_page_t  *page;
    nxt_mem_cache_slot_t  *slot;

    p = NULL;

    if (size <= pool->page_size / 2) {

        /* Find a slot with appropriate chunk size. */
        for (slot = pool->slots; slot->size < size; slot++) { /* void */ }

        size = slot->size;

        if (nxt_fast_path(!nxt_queue_is_empty(&slot->pages))) {

            link = nxt_queue_first(&slot->pages);
            page = nxt_queue_link_data(link, nxt_mem_cache_page_t, link);

            p = nxt_mem_cache_page_addr(pool, page);
            p += nxt_mem_cache_alloc_chunk(page->map, size);

            page->chunks--;

            if (page->chunks == 0) {
                /*
                 * Remove full page from the pool chunk slot list
                 * of pages with free chunks.
                 */
                nxt_queue_remove(&page->link);
            }

        } else {
            page = nxt_mem_cache_alloc_page(pool);

            if (nxt_fast_path(page != NULL)) {

                nxt_queue_insert_head(&slot->pages, &page->link);

                /* Mark the first chunk as busy. */
                page->map[0] = 0x80;
                page->map[1] = 0;
                page->map[2] = 0;
                page->map[3] = 0;

                /* slot->chunks are already one less. */
                page->chunks = slot->chunks;
                page->size = size >> pool->chunk_size_shift;

                p = nxt_mem_cache_page_addr(pool, page);
            }
        }

    } else {
        page = nxt_mem_cache_alloc_page(pool);

        if (nxt_fast_path(page != NULL)) {
            page->size = pool->page_size >> pool->chunk_size_shift;

            p = nxt_mem_cache_page_addr(pool, page);
        }

#if (NXT_DEBUG)
        size = pool->page_size;
#endif
    }

    nxt_thread_log_debug("mem cache chunk:%uz alloc: %p", size, p);

    return p;
}


static nxt_uint_t
nxt_mem_cache_alloc_chunk(uint8_t *map, nxt_uint_t size)
{
    uint8_t     mask;
    nxt_uint_t  n, offset;

    offset = 0;
    n = 0;

    /* The page must have at least one free chunk. */

    for ( ;; ) {
        if (map[n] != 0xff) {

            mask = 0x80;

            do {
                if ((map[n] & mask) == 0) {
                    /* A free chunk is found. */
                    map[n] |= mask;
                    return offset;
                }

                offset += size;
                mask >>= 1;

            } while (mask != 0);

        } else {
            /* Fast-forward: all 8 chunks are occupied. */
            offset += size * 8;
        }

        n++;
    }
}


static nxt_mem_cache_page_t *
nxt_mem_cache_alloc_page(nxt_mem_cache_pool_t *pool)
{
    nxt_queue_link_t       *link;
    nxt_mem_cache_page_t   *page;
    nxt_mem_cache_block_t  *cluster;

    if (nxt_queue_is_empty(&pool->free_pages)) {
        cluster = nxt_mem_cache_alloc_cluster(pool);
        if (nxt_slow_path(cluster == NULL)) {
            return NULL;
        }
    }

    link = nxt_queue_first(&pool->free_pages);
    nxt_queue_remove(link);

    page = nxt_queue_link_data(link, nxt_mem_cache_page_t, link);

    return page;
}


static nxt_mem_cache_block_t *
nxt_mem_cache_alloc_cluster(nxt_mem_cache_pool_t *pool)
{
    nxt_uint_t             n;
    nxt_mem_cache_block_t  *cluster;

    n = pool->cluster_size >> pool->page_size_shift;

    cluster = nxt_zalloc(sizeof(nxt_mem_cache_block_t)
                         + n * sizeof(nxt_mem_cache_page_t));

    if (nxt_slow_path(cluster == NULL)) {
        return NULL;
    }

    /* NXT_MEM_CACHE_CLUSTER_BLOCK type is zero. */

    cluster->size = pool->cluster_size;

    cluster->start = nxt_memalign(pool->page_alignment, pool->cluster_size);
    if (nxt_slow_path(cluster->start == NULL)) {
        nxt_free(cluster);
        return NULL;
    }

    n--;
    cluster->pages[n].number = n;
    nxt_queue_insert_head(&pool->free_pages, &cluster->pages[n].link);

    while (n != 0) {
        n--;
        cluster->pages[n].number = n;
        nxt_queue_insert_before(&cluster->pages[n + 1].link,
                                &cluster->pages[n].link);
    }

    nxt_rbtree_insert(&pool->pages, &cluster->node);

    return cluster;
}


static void *
nxt_mem_cache_alloc_large(nxt_mem_cache_pool_t *pool, size_t alignment,
    size_t size)
{
    u_char                 *p;
    size_t                 aligned_size;
    uint8_t                type;
    nxt_mem_cache_block_t  *block;

    if (nxt_slow_path((size - 1) & size) != 0) {
        aligned_size = nxt_align_size(size, sizeof(uintptr_t));

        p = nxt_memalign(alignment,
                         aligned_size + sizeof(nxt_mem_cache_block_t));

        if (nxt_slow_path(p == NULL)) {
            return NULL;
        }

        block = (nxt_mem_cache_block_t *) (p + aligned_size);
        type = NXT_MEM_CACHE_EMBEDDED_BLOCK;

    } else {
        block = nxt_malloc(sizeof(nxt_mem_cache_block_t));
        if (nxt_slow_path(block == NULL)) {
            nxt_free(block);
            return NULL;
        }

        p = nxt_memalign(alignment, size);
        if (nxt_slow_path(p == NULL)) {
            return NULL;
        }

        type = NXT_MEM_CACHE_DISCRETE_BLOCK;
    }

    block->type = type;
    block->size = size;
    block->start = p;

    nxt_rbtree_insert(&pool->pages, &block->node);

    return p;
}


static nxt_int_t
nxt_mem_cache_rbtree_compare(nxt_rbtree_node_t *node1, nxt_rbtree_node_t *node2)
{
    nxt_mem_cache_block_t  *block1, *block2;

    block1 = (nxt_mem_cache_block_t *) node1;
    block2 = (nxt_mem_cache_block_t *) node2;

    return (uintptr_t) block1->start - (uintptr_t) block2->start;
}


void
nxt_mem_cache_free(nxt_mem_cache_pool_t *pool, void *p)
{
    const char             *err;
    nxt_mem_cache_block_t  *block;

    nxt_thread_log_debug("mem cache free %p", p);

    block = nxt_mem_cache_find_block(&pool->pages, p);

    if (nxt_fast_path(block != NULL)) {

        if (block->type == NXT_MEM_CACHE_CLUSTER_BLOCK) {
            err = nxt_mem_cache_chunk_free(pool, block, p);

        } else if (nxt_fast_path(p == block->start)) {
            nxt_rbtree_delete(&pool->pages, &block->node);

            if (block->type == NXT_MEM_CACHE_DISCRETE_BLOCK) {
                nxt_free(block);
            }

            nxt_free(p);

            err = NULL;

        } else {
            err = "pointer to wrong page";
        }

    } else {
        err = "pointer is out of pool";
    }

    if (nxt_slow_path(err != NULL)) {
        nxt_thread_log_alert("nxt_mem_cache_pool_free(%p): %s", p, err);
    }
}


static nxt_mem_cache_block_t *
nxt_mem_cache_find_block(nxt_rbtree_t *tree, u_char *p)
{
    nxt_rbtree_node_t      *node, *sentinel;
    nxt_mem_cache_block_t  *block;

    node = nxt_rbtree_root(tree);
    sentinel = nxt_rbtree_sentinel(tree);

    while (node != sentinel) {

        block = (nxt_mem_cache_block_t *) node;

        if (p < block->start) {
            node = node->left;

        } else if (p >= block->start + block->size) {
            node = node->right;

        } else {
            return block;
        }
    }

    return NULL;
}


static const char *
nxt_mem_cache_chunk_free(nxt_mem_cache_pool_t *pool,
    nxt_mem_cache_block_t *cluster, u_char *p)
{
    u_char                *start;
    uintptr_t             offset;
    nxt_uint_t            n, size, chunk;
    nxt_mem_cache_page_t  *page;
    nxt_mem_cache_slot_t  *slot;

    n = (p - cluster->start) >> pool->page_size_shift;
    start = cluster->start + (n << pool->page_size_shift);

    page = &cluster->pages[n];

    if (page->size == 0) {
        return "page is already free";
    }

    size = page->size << pool->chunk_size_shift;

    if (size != pool->page_size) {

        offset = (uintptr_t) (p - start) & (pool->page_size - 1);
        chunk = offset / size;

        if (nxt_slow_path(offset != chunk * size)) {
            return "pointer to wrong chunk";
        }

        if (nxt_slow_path(nxt_mem_cache_chunk_is_free(page->map, chunk))) {
            return "chunk is already free";
        }

        nxt_mem_cache_chunk_set_free(page->map, chunk);

        /* Find a slot with appropriate chunk size. */
        for (slot = pool->slots; slot->size < size; slot++) { /* void */ }

        if (page->chunks != slot->chunks) {
            page->chunks++;

            if (page->chunks == 1) {
                /*
                 * Add the page to the head of pool chunk slot list
                 * of pages with free chunks.
                 */
                nxt_queue_insert_head(&slot->pages, &page->link);
            }

            nxt_mem_cache_free_junk(p, size);

            return NULL;

        } else {
            /*
             * All chunks are free, remove the page from pool chunk slot
             * list of pages with free chunks.
             */
            nxt_queue_remove(&page->link);
        }

    } else if (nxt_slow_path(p != start)) {
        return "invalid pointer to chunk";
    }

    /* Add the free page to the pool's free pages tree. */

    page->size = 0;
    nxt_queue_insert_head(&pool->free_pages, &page->link);

    nxt_mem_cache_free_junk(p, size);

    /* Test if all pages in the cluster are free. */

    page = cluster->pages;
    n = pool->cluster_size >> pool->page_size_shift;

    do {
         if (page->size != 0) {
             return NULL;
         }

         page++;
         n--;
    } while (n != 0);

    /* Free cluster. */

    page = cluster->pages;
    n = pool->cluster_size >> pool->page_size_shift;

    do {
         nxt_queue_remove(&page->link);
         page++;
         n--;
    } while (n != 0);

    nxt_rbtree_delete(&pool->pages, &cluster->node);

    p = cluster->start;

    nxt_free(cluster);
    nxt_free(p);

    return NULL;
}


const nxt_mem_proto_t  nxt_mem_cache_proto = {
    (nxt_mem_proto_alloc_t) nxt_mem_cache_alloc,
    (nxt_mem_proto_free_t) nxt_mem_cache_free,
};

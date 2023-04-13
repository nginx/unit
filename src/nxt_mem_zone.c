
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


#define NXT_MEM_ZONE_PAGE_FREE      0
/*
 * A page was never allocated before so it should be filled with
 * junk on the first time allocation if memory debugging is enabled.
 */
#define NXT_MEM_ZONE_PAGE_FRESH     1

/* An entire page is currently used, no chunks inside the page. */
#define NXT_MEM_ZONE_PAGE_USED      2


typedef struct nxt_mem_zone_page_s  nxt_mem_zone_page_t;

struct nxt_mem_zone_page_s {
    /*
     * A size of page chunks if value is greater than or equal to 16.
     * Otherwise it is used to mark page state: NXT_MEM_ZONE_PAGE_FREE,
     * NXT_MEM_ZONE_PAGE_FRESH, and NXT_MEM_ZONE_PAGE_USED.
     */
    uint16_t               size;

    /* A number of free chunks of a chunked page. */
    uint16_t               chunks;

    union {
        /* A chunk bitmap if a number of chunks is lesser than 32. */
        uint8_t            map[4];
        /*
         * The count is a number of successive occupied pages in the first
         * page.  In the next occupied pages and in all free pages the count
         * is zero, because a number of successive free pages is stored in
         * free block size resided in beginning of the first free page.
         */
        uint32_t           count;
    } u;

    /* Used for slot list of pages with free chunks. */
    nxt_mem_zone_page_t    *next;

    /*
     * Used to link of all pages including free, chunked and occupied
     * pages to coalesce free pages.
     */
    nxt_queue_link_t       link;
};


typedef struct {
    uint32_t               size;
    uint32_t               chunks;
    uint32_t               start;
    uint32_t               map_size;
    nxt_mem_zone_page_t    *pages;
} nxt_mem_zone_slot_t;


typedef struct {
    NXT_RBTREE_NODE        (node);
    uint32_t               size;
} nxt_mem_zone_free_block_t;


struct nxt_mem_zone_s {
    nxt_thread_spinlock_t  lock;
    nxt_mem_zone_page_t    *pages;
    nxt_mem_zone_page_t    sentinel_page;
    nxt_rbtree_t           free_pages;

    uint32_t               page_size_shift;
    uint32_t               page_size_mask;
    uint32_t               max_chunk_size;
    uint32_t               small_bitmap_min_size;

    u_char                 *start;
    u_char                 *end;

    nxt_mem_zone_slot_t    slots[];
};


#define nxt_mem_zone_page_addr(zone, page)                                    \
    (void *) (zone->start + ((page - zone->pages) << zone->page_size_shift))


#define nxt_mem_zone_addr_page(zone, addr)                                    \
    &zone->pages[((u_char *) addr - zone->start) >> zone->page_size_shift]


#define nxt_mem_zone_page_is_free(page)                                       \
    (page->size < NXT_MEM_ZONE_PAGE_USED)


#define nxt_mem_zone_page_is_chunked(page)                                    \
    (page->size >= 16)


#define nxt_mem_zone_page_bitmap(zone, slot)                                  \
    (slot->size < zone->small_bitmap_min_size)


#define nxt_mem_zone_set_chunk_free(map, chunk)                               \
    map[chunk / 8] &= ~(0x80 >> (chunk & 7))


#define nxt_mem_zone_chunk_is_free(map, chunk)                                \
    ((map[chunk / 8] & (0x80 >> (chunk & 7))) == 0)


#define nxt_mem_zone_fresh_junk(p, size)                                      \
    nxt_memset((p), 0xA5, size)


#define nxt_mem_zone_free_junk(p, size)                                       \
    nxt_memset((p), 0x5A, size)


static uint32_t nxt_mem_zone_pages(u_char *start, size_t zone_size,
    nxt_uint_t page_size);
static void *nxt_mem_zone_slots_init(nxt_mem_zone_t *zone,
    nxt_uint_t page_size);
static void nxt_mem_zone_slot_init(nxt_mem_zone_slot_t *slot,
    nxt_uint_t page_size);
static intptr_t nxt_mem_zone_rbtree_compare(nxt_rbtree_node_t *node1,
    nxt_rbtree_node_t *node2);
static void *nxt_mem_zone_alloc_small(nxt_mem_zone_t *zone,
    nxt_mem_zone_slot_t *slot, size_t size);
static nxt_uint_t nxt_mem_zone_alloc_chunk(uint8_t *map, nxt_uint_t offset,
    nxt_uint_t size);
static void *nxt_mem_zone_alloc_large(nxt_mem_zone_t *zone, size_t alignment,
    size_t size);
static nxt_mem_zone_page_t *nxt_mem_zone_alloc_pages(nxt_mem_zone_t *zone,
    size_t alignment, uint32_t pages);
static nxt_mem_zone_free_block_t *
    nxt_mem_zone_find_free_block(nxt_mem_zone_t *zone, nxt_rbtree_node_t *node,
    uint32_t alignment, uint32_t pages);
static const char *nxt_mem_zone_free_chunk(nxt_mem_zone_t *zone,
    nxt_mem_zone_page_t *page, void *p);
static void nxt_mem_zone_free_pages(nxt_mem_zone_t *zone,
    nxt_mem_zone_page_t *page, nxt_uint_t count);


static nxt_log_moderation_t  nxt_mem_zone_log_moderation = {
    NXT_LOG_ALERT, 2, "mem_zone_alloc() failed, not enough memory",
    NXT_LOG_MODERATION
};


nxt_mem_zone_t *
nxt_mem_zone_init(u_char *start, size_t zone_size, nxt_uint_t page_size)
{
    uint32_t                   pages;
    nxt_uint_t                 n;
    nxt_mem_zone_t             *zone;
    nxt_mem_zone_page_t        *page;
    nxt_mem_zone_free_block_t  *block;

    if (nxt_slow_path((page_size & (page_size - 1)) != 0)) {
        nxt_thread_log_alert("mem zone page size must be a power of 2");
        return NULL;
    }

    pages = nxt_mem_zone_pages(start, zone_size, page_size);
    if (pages == 0) {
        return NULL;
    }

    zone = (nxt_mem_zone_t *) start;

    /* The function returns address after all slots. */
    page = nxt_mem_zone_slots_init(zone, page_size);

    zone->pages = page;

    for (n = 0; n < pages; n++) {
        page[n].size = NXT_MEM_ZONE_PAGE_FRESH;
    }

    /*
     * A special sentinel page entry marked as used does not correspond
     * to a real page.  The entry simplifies neighbour queue nodes check
     * in nxt_mem_zone_free_pages().
     */
    zone->sentinel_page.size = NXT_MEM_ZONE_PAGE_USED;
    nxt_queue_sentinel(&zone->sentinel_page.link);
    nxt_queue_insert_after(&zone->sentinel_page.link, &page->link);

    /* rbtree of free pages. */

    nxt_rbtree_init(&zone->free_pages, nxt_mem_zone_rbtree_compare);

    block = (nxt_mem_zone_free_block_t *) zone->start;
    block->size = pages;

    nxt_rbtree_insert(&zone->free_pages, &block->node);

    return zone;
}


static uint32_t
nxt_mem_zone_pages(u_char *start, size_t zone_size, nxt_uint_t page_size)
{
    u_char          *end;
    size_t          reserved;
    nxt_uint_t      n, pages, size, chunks, last;
    nxt_mem_zone_t  *zone;

    /*
     * Find all maximum chunk sizes which zone page can be split on
     * with minimum 16-byte step.
     */
    last = page_size / 16;
    n = 0;
    size = 32;

    do {
        chunks = page_size / size;

        if (last != chunks) {
            last = chunks;
            n++;
        }

        size += 16;

    } while (chunks > 1);

    /*
     * Find number of usable zone pages except zone bookkeeping data,
     * slots, and pages entries.
     */
    reserved = sizeof(nxt_mem_zone_t) + (n * sizeof(nxt_mem_zone_slot_t));

    end = nxt_trunc_ptr(start + zone_size, page_size);
    zone_size = end - start;

    pages = (zone_size - reserved) / (page_size + sizeof(nxt_mem_zone_page_t));

    if (reserved > zone_size || pages == 0) {
        nxt_thread_log_alert("mem zone size is too small: %uz", zone_size);
        return 0;
    }

    reserved += pages * sizeof(nxt_mem_zone_page_t);
    nxt_memzero(start, reserved);

    zone = (nxt_mem_zone_t *) start;

    zone->start = nxt_align_ptr(start + reserved, page_size);
    zone->end = end;

    nxt_thread_log_debug("mem zone pages: %uD, unused:%z", pages,
                         end - (zone->start + pages * page_size));

    /*
     * If a chunk size is lesser than zone->small_bitmap_min_size
     * bytes, a page's chunk bitmap is larger than 32 bits and the
     * bimap is placed at the start of the page.
     */
    zone->small_bitmap_min_size = page_size / 32;

    zone->page_size_mask = page_size - 1;
    zone->max_chunk_size = page_size / 2;

    n = zone->max_chunk_size;

    do {
        zone->page_size_shift++;
        n /= 2;
    } while (n != 0);

    return (uint32_t) pages;
}


static void *
nxt_mem_zone_slots_init(nxt_mem_zone_t *zone, nxt_uint_t page_size)
{
    nxt_uint_t           n, size, chunks;
    nxt_mem_zone_slot_t  *slot;

    slot = zone->slots;

    slot[0].chunks = page_size / 16;
    slot[0].size = 16;

    n = 0;
    size = 32;

    for ( ;; ) {
        chunks = page_size / size;

        if (slot[n].chunks != chunks) {

            nxt_mem_zone_slot_init(&slot[n], page_size);

            nxt_thread_log_debug(
                           "mem zone size:%uD chunks:%uD start:%uD map:%uD",
                           slot[n].size, slot[n].chunks + 1,
                           slot[n].start, slot[n].map_size);

            n++;

            if (chunks == 1) {
                return &slot[n];
            }
        }

        slot[n].chunks = chunks;
        slot[n].size = size;
        size += 16;
    }
}


static void
nxt_mem_zone_slot_init(nxt_mem_zone_slot_t *slot, nxt_uint_t page_size)
{
    /*
     * Calculate number of bytes required to store a chunk bitmap
     * and align it to 4 bytes.
     */
    slot->map_size = nxt_align_size(((slot->chunks + 7) / 8), 4);

    /* If chunk size is not a multiple of zone page size, there
     * is surplus space which can be used for the chunk's bitmap.
     */
    slot->start = page_size - slot->chunks * slot->size;

    /* slot->chunks should be one less than actual number of chunks. */
    slot->chunks--;

    if (slot->map_size > 4) {
        /* A page's chunks bitmap is placed at the start of the page. */

        if (slot->start < slot->map_size) {
            /*
             * There is no surplus space or the space is too
             * small for chunks bitmap, so use the first chunks.
             */
            if (slot->size < slot->map_size) {
                /* The first chunks are occupied by bitmap. */
                slot->chunks -= slot->map_size / slot->size;
                slot->start = nxt_align_size(slot->map_size, 16);

            } else {
                /* The first chunk is occupied by bitmap. */
                slot->chunks--;
                slot->start = slot->size;
            }
        }
    }
}


/*
 * Round up to the next highest power of 2.  The algorithm is
 * described in "Bit Twiddling Hacks" by Sean Eron Anderson.
 */

nxt_inline uint32_t
nxt_next_highest_power_of_two(uint32_t n)
{
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n++;

    return n;
}


static intptr_t
nxt_mem_zone_rbtree_compare(nxt_rbtree_node_t *node1, nxt_rbtree_node_t *node2)
{
    u_char                     *start1, *end1, *start2, *end2;
    uint32_t                   n, size, size1, size2;
    nxt_mem_zone_free_block_t  *block1, *block2;

    block1 = (nxt_mem_zone_free_block_t *) node1;
    block2 = (nxt_mem_zone_free_block_t *) node2;

    size1 = block1->size;
    size2 = block2->size;

    /*
     * This subtractions do not overflow if number of pages of a free
     * block is below 2^31-1.  This allows to use blocks up to 128G if
     * a zone page size is just 64 bytes.
     */
    n = size1 - size2;

    if (n != 0) {
        return n;
    }

    /*
     * Sort equally sized blocks by their capability to allocate memory with
     * alignment equal to the size rounded the previous higest power of 2.
     */

    /* Round the size to the previous higest power of two. */
    size = nxt_next_highest_power_of_two(size1) >> 1;

    /* Align the blocks' start and end to the rounded size. */
    start1 = nxt_align_ptr(block1, size);
    end1 = nxt_trunc_ptr((u_char *) block1 + size1, size);

    start2 = nxt_align_ptr(block2, size);
    end2 = nxt_trunc_ptr((u_char *) block2 + size2, size);

    return (end1 - start1) - (end2 - start2);
}


void *
nxt_mem_zone_zalloc(nxt_mem_zone_t *zone, size_t size)
{
    void  *p;

    p = nxt_mem_zone_align(zone, 1, size);

    if (nxt_fast_path(p != NULL)) {
        nxt_memzero(p, size);
    }

    return p;
}


void *
nxt_mem_zone_align(nxt_mem_zone_t *zone, size_t alignment, size_t size)
{
    void                 *p;
    nxt_mem_zone_slot_t  *slot;

    if (nxt_slow_path((alignment - 1) & alignment) != 0) {
        /* Alignment must be a power of 2. */
        return NULL;
    }

    if (size <= zone->max_chunk_size && alignment <= zone->max_chunk_size) {
        /* All chunks are aligned to 16. */

        if (alignment > 16) {
            /*
             * Chunks which size is power of 2 are aligned to the size.
             * So allocation size should be increased to the next highest
             * power of two.  This can waste memory, but a main consumer
             * of aligned allocations is lvlhsh which anyway allocates
             * memory with alignment equal to size.
             */
            size = nxt_next_highest_power_of_two(size);
            size = nxt_max(size, alignment);
        }

        /*
         * Find a zone slot with appropriate chunk size.
         * This operation can be performed without holding lock.
         */
        for (slot = zone->slots; slot->size < size; slot++) { /* void */ }

        nxt_thread_log_debug("mem zone alloc: @%uz:%uz chunk:%uD",
                             alignment, size, slot->size);

        nxt_thread_spin_lock(&zone->lock);

        p = nxt_mem_zone_alloc_small(zone, slot, size);

    } else {

        nxt_thread_log_debug("mem zone alloc: @%uz:%uz", alignment, size);

        nxt_thread_spin_lock(&zone->lock);

        p = nxt_mem_zone_alloc_large(zone, alignment, size);
    }

    nxt_thread_spin_unlock(&zone->lock);

    if (nxt_fast_path(p != NULL)) {
        nxt_thread_log_debug("mem zone alloc: %p", p);

    } else {
        nxt_log_alert_moderate(&nxt_mem_zone_log_moderation, nxt_thread_log(),
                    "nxt_mem_zone_alloc(%uz, %uz) failed, not enough memory",
                    alignment, size);
    }

    return p;
}


static void *
nxt_mem_zone_alloc_small(nxt_mem_zone_t *zone, nxt_mem_zone_slot_t *slot,
    size_t size)
{
    u_char               *p;
    uint8_t              *map;
    nxt_mem_zone_page_t  *page;

    page = slot->pages;

    if (nxt_fast_path(page != NULL)) {

        p = nxt_mem_zone_page_addr(zone, page);

        if (nxt_mem_zone_page_bitmap(zone, slot)) {
            /* A page's chunks bitmap is placed at the start of the page. */
            map = p;

        } else {
            map = page->u.map;
        }

        p += nxt_mem_zone_alloc_chunk(map, slot->start, slot->size);

        page->chunks--;

        if (page->chunks == 0) {
            /*
             * Remove full page from the zone slot list of pages with
             * free chunks.
             */
            slot->pages = page->next;
#if (NXT_DEBUG)
            page->next = NULL;
#endif
        }

        return p;
    }

    page = nxt_mem_zone_alloc_pages(zone, 1, 1);

    if (nxt_fast_path(page != NULL)) {

        slot->pages = page;

        page->size = slot->size;
        /* slot->chunks are already one less. */
        page->chunks = slot->chunks;
        page->u.count = 0;
        page->next = NULL;

        p = nxt_mem_zone_page_addr(zone, page);

        if (nxt_mem_zone_page_bitmap(zone, slot)) {
            /* A page's chunks bitmap is placed at the start of the page. */
            map = p;
            nxt_memzero(map, slot->map_size);

        } else {
            map = page->u.map;
        }

        /* Mark the first chunk as busy. */
        map[0] = 0x80;

        return p + slot->start;
    }

    return NULL;
}


static nxt_uint_t
nxt_mem_zone_alloc_chunk(uint8_t *map, nxt_uint_t offset, nxt_uint_t size)
{
    uint8_t     mask;
    nxt_uint_t  n;

    n = 0;

    /* The page must have at least one free chunk. */

    for ( ;; ) {
        /* The bitmap is always aligned to uint32_t. */

        if (*(uint32_t *) &map[n] != 0xFFFFFFFF) {

            do {
                if (map[n] != 0xFF) {

                    mask = 0x80;

                    do {
                        if ((map[n] & mask) == 0) {
                            /* The free chunk is found. */
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

            } while (n % 4 != 0);

        } else {
            /* Fast-forward: all 32 chunks are occupied. */
            offset += size * 32;
            n += 4;
        }
    }
}


static void *
nxt_mem_zone_alloc_large(nxt_mem_zone_t *zone, size_t alignment, size_t size)
{
    uint32_t             pages;
    nxt_mem_zone_page_t  *page;

    pages = (size + zone->page_size_mask) >> zone->page_size_shift;

    page = nxt_mem_zone_alloc_pages(zone, alignment, pages);

    if (nxt_fast_path(page != NULL)) {
        return nxt_mem_zone_page_addr(zone, page);
    }

    return NULL;
}


static nxt_mem_zone_page_t *
nxt_mem_zone_alloc_pages(nxt_mem_zone_t *zone, size_t alignment, uint32_t pages)
{
    u_char                     *p;
    size_t                     prev_size;
    uint32_t                   prev_pages, node_pages, next_pages;
    nxt_uint_t                 n;
    nxt_mem_zone_page_t        *prev_page, *page, *next_page;
    nxt_mem_zone_free_block_t  *block, *next_block;

    block = nxt_mem_zone_find_free_block(zone,
                                         nxt_rbtree_root(&zone->free_pages),
                                         alignment, pages);

    if (nxt_slow_path(block == NULL)) {
        return NULL;
    }

    node_pages = block->size;

    nxt_rbtree_delete(&zone->free_pages, &block->node);

    p = nxt_align_ptr(block, alignment);
    page = nxt_mem_zone_addr_page(zone, p);

    prev_size = p - (u_char *) block;

    if (prev_size != 0) {
        prev_pages = prev_size >> zone->page_size_shift;
        node_pages -= prev_pages;

        block->size = prev_pages;
        nxt_rbtree_insert(&zone->free_pages, &block->node);

        prev_page = nxt_mem_zone_addr_page(zone, block);
        nxt_queue_insert_after(&prev_page->link, &page->link);
    }

    next_pages = node_pages - pages;

    if (next_pages != 0) {
        next_page = &page[pages];
        next_block = nxt_mem_zone_page_addr(zone, next_page);
        next_block->size = next_pages;

        nxt_rbtree_insert(&zone->free_pages, &next_block->node);
        nxt_queue_insert_after(&page->link, &next_page->link);
    }

    /* Go through pages after all rbtree operations to not trash CPU cache. */

    page[0].u.count = pages;

    for (n = 0; n < pages; n++) {

        if (page[n].size == NXT_MEM_ZONE_PAGE_FRESH) {
            nxt_mem_zone_fresh_junk(nxt_mem_zone_page_addr(zone, &page[n]),
                                    zone->page_size_mask + 1);
        }

        page[n].size = NXT_MEM_ZONE_PAGE_USED;
    }

    return page;
}


/*
 * Free blocks are sorted by size and then if the sizes are equal
 * by aligned allocation capabilty.  The former criterion is just
 * comparison with a requested size and it can be used for iteractive
 * search.  The later criterion cannot be tested only by the requested
 * size and alignment, so recursive in-order tree traversal is required
 * to find a suitable free block.  nxt_mem_zone_find_free_block() uses
 * only recursive in-order tree traversal because anyway the slowest part
 * of the algorithm are CPU cache misses.  Besides the last tail recursive
 * call may be optimized by compiler into iteractive search.
 */

static nxt_mem_zone_free_block_t *
nxt_mem_zone_find_free_block(nxt_mem_zone_t *zone, nxt_rbtree_node_t *node,
    uint32_t alignment, uint32_t pages)
{
    u_char                     *aligned, *end;
    nxt_mem_zone_free_block_t  *block, *free_block;

    if (node == nxt_rbtree_sentinel(&zone->free_pages)) {
        return NULL;
    }

    block = (nxt_mem_zone_free_block_t *) node;

    if (pages <= block->size) {

        free_block = nxt_mem_zone_find_free_block(zone, block->node.left,
                                                  alignment, pages);
        if (free_block != NULL) {
            return free_block;
        }

        aligned = nxt_align_ptr(block, alignment);

        if (pages == block->size) {
            if (aligned == (u_char *) block) {
                /* Exact match. */
                return block;
            }

        } else {  /* pages < block->size */
            aligned += pages << zone->page_size_shift;
            end = nxt_pointer_to(block, block->size << zone->page_size_shift);

            if (aligned <= end) {
                return block;
            }
        }
    }

    return nxt_mem_zone_find_free_block(zone, block->node.right,
                                        alignment, pages);
}


void
nxt_mem_zone_free(nxt_mem_zone_t *zone, void *p)
{
    nxt_uint_t           count;
    const char           *err;
    nxt_mem_zone_page_t  *page;

    nxt_thread_log_debug("mem zone free: %p", p);

    if (nxt_fast_path(zone->start <= (u_char *) p
                      && (u_char *) p < zone->end))
    {
        page = nxt_mem_zone_addr_page(zone, p);

        nxt_thread_spin_lock(&zone->lock);

        if (nxt_mem_zone_page_is_chunked(page)) {
            err = nxt_mem_zone_free_chunk(zone, page, p);

        } else if (nxt_slow_path(nxt_mem_zone_page_is_free(page))) {
            err = "page is already free";

        } else if (nxt_slow_path((uintptr_t) p & zone->page_size_mask) != 0) {
            err = "invalid pointer to chunk";

        } else {
            count = page->u.count;

            if (nxt_fast_path(count != 0)) {
                nxt_mem_zone_free_junk(p, count * zone->page_size_mask + 1);
                nxt_mem_zone_free_pages(zone, page, count);
                err = NULL;

            } else {
                /* Not the first allocated page. */
                err = "pointer to wrong page";
            }
        }

        nxt_thread_spin_unlock(&zone->lock);

    } else {
        err = "pointer is out of zone";
    }

    if (nxt_slow_path(err != NULL)) {
        nxt_thread_log_alert("nxt_mem_zone_free(%p): %s", p, err);
    }
}


static const char *
nxt_mem_zone_free_chunk(nxt_mem_zone_t *zone, nxt_mem_zone_page_t *page,
    void *p)
{
    u_char               *map;
    uint32_t             size, offset, chunk;
    nxt_mem_zone_page_t  *pg, **ppg;
    nxt_mem_zone_slot_t  *slot;

    size = page->size;

    /* Find a zone slot with appropriate chunk size. */
    for (slot = zone->slots; slot->size < size; slot++) { /* void */ }

    offset = (uintptr_t) p & zone->page_size_mask;
    offset -= slot->start;

    chunk = offset / size;

    if (nxt_slow_path(offset != chunk * size)) {
        return "pointer to wrong chunk";
    }

    if (nxt_mem_zone_page_bitmap(zone, slot)) {
        /* A page's chunks bitmap is placed at the start of the page. */
        map = (u_char *) ((uintptr_t) p & ~((uintptr_t) zone->page_size_mask));

    } else {
        map = page->u.map;
    }

    if (nxt_mem_zone_chunk_is_free(map, chunk)) {
        return "chunk is already free";
    }

    nxt_mem_zone_set_chunk_free(map, chunk);

    nxt_mem_zone_free_junk(p, page->size);

    if (page->chunks == 0) {
        page->chunks = 1;

        /* Add the page to the head of slot list of pages with free chunks. */
        page->next = slot->pages;
        slot->pages = page;

    } else if (page->chunks != slot->chunks) {
        page->chunks++;

    } else {

        if (map != page->u.map) {
            nxt_mem_zone_free_junk(map, slot->map_size);
        }

        /*
         * All chunks are free, remove the page from the slot list of pages
         * with free chunks and add the page to the free pages tree.
         */
        ppg = &slot->pages;

        for (pg = slot->pages; pg != NULL; pg = pg->next) {

            if (pg == page) {
                *ppg = page->next;
                break;
            }

            ppg = &pg->next;
        }

        nxt_mem_zone_free_pages(zone, page, 1);
    }

    return NULL;
}


static void
nxt_mem_zone_free_pages(nxt_mem_zone_t *zone, nxt_mem_zone_page_t *page,
    nxt_uint_t count)
{
    nxt_mem_zone_page_t        *prev_page, *next_page;
    nxt_mem_zone_free_block_t  *block, *prev_block, *next_block;

    page->size = NXT_MEM_ZONE_PAGE_FREE;
    page->chunks = 0;
    page->u.count = 0;
    page->next = NULL;

    nxt_memzero(&page[1], (count - 1) * sizeof(nxt_mem_zone_page_t));

    next_page = nxt_queue_link_data(page->link.next, nxt_mem_zone_page_t, link);

    if (nxt_mem_zone_page_is_free(next_page)) {

        /* Coalesce with the next free pages. */

        nxt_queue_remove(&next_page->link);
        nxt_memzero(next_page, sizeof(nxt_mem_zone_page_t));

        next_block = nxt_mem_zone_page_addr(zone, next_page);
        count += next_block->size;
        nxt_rbtree_delete(&zone->free_pages, &next_block->node);
    }

    prev_page = nxt_queue_link_data(page->link.prev, nxt_mem_zone_page_t, link);

    if (nxt_mem_zone_page_is_free(prev_page)) {

        /* Coalesce with the previous free pages. */

        nxt_queue_remove(&page->link);

        prev_block = nxt_mem_zone_page_addr(zone, prev_page);
        count += prev_block->size;
        nxt_rbtree_delete(&zone->free_pages, &prev_block->node);

        prev_block->size = count;
        nxt_rbtree_insert(&zone->free_pages, &prev_block->node);

        return;
    }

    block = nxt_mem_zone_page_addr(zone, page);
    block->size = count;
    nxt_rbtree_insert(&zone->free_pages, &block->node);
}

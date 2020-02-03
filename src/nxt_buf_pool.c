
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


nxt_int_t
nxt_buf_pool_mem_alloc(nxt_buf_pool_t *bp, size_t size)
{
    nxt_buf_t  *b;

    b = bp->current;

    if (b != NULL && b->mem.free < b->mem.end) {
        return NXT_OK;
    }

    b = bp->free;

    if (b != NULL) {
        bp->current = b;
        bp->free = b->next;
        b->next = NULL;
        return NXT_OK;
    }

    if (bp->num >= bp->max) {
        return NXT_AGAIN;
    }

    if (size == 0 || size >= bp->size + bp->size / 4) {
        size = bp->size;
    }

    b = nxt_buf_mem_alloc(bp->mem_pool, size, bp->flags);

    if (nxt_fast_path(b != NULL)) {
        bp->current = b;
        bp->num++;
        return NXT_OK;
    }

    return NXT_ERROR;
}


nxt_int_t
nxt_buf_pool_file_alloc(nxt_buf_pool_t *bp, size_t size)
{
    nxt_buf_t  *b;

    b = bp->current;

    if (b != NULL && b->mem.free < b->mem.end) {
        return NXT_OK;
    }

    b = bp->free;

    if (b != NULL) {
        bp->current = b;
        bp->free = b->next;
        b->next = NULL;
        return NXT_OK;
    }

    if (bp->num >= bp->max) {
        return NXT_AGAIN;
    }

    if (size == 0 || size >= bp->size + bp->size / 4) {
        size = bp->size;
    }

    b = nxt_buf_file_alloc(bp->mem_pool, size, bp->flags);

    if (nxt_fast_path(b != NULL)) {
        bp->current = b;
        bp->num++;
        return NXT_OK;
    }

    return NXT_ERROR;
}


nxt_int_t
nxt_buf_pool_mmap_alloc(nxt_buf_pool_t *bp, size_t size)
{
    nxt_buf_t  *b;

    b = bp->current;

    if (b != NULL) {
        return NXT_OK;
    }

    b = bp->free;

    if (b != NULL) {
        bp->current = b;
        bp->free = b->next;
        b->next = NULL;
        return NXT_OK;
    }

    if (bp->num >= bp->max) {
        return NXT_AGAIN;
    }

    if (size == 0 || size >= bp->size + bp->size / 4) {
        size = bp->size;
    }

    b = nxt_buf_mmap_alloc(bp->mem_pool, size);

    if (nxt_fast_path(b != NULL)) {
        bp->mmap = 1;
        bp->current = b;
        bp->num++;
        return NXT_OK;
    }

    return NXT_ERROR;
}


void
nxt_buf_pool_free(nxt_buf_pool_t *bp, nxt_buf_t *b)
{
    size_t  size;

    nxt_thread_log_debug("buf pool free: %p %p", b, b->mem.start);

    size = nxt_buf_mem_size(&b->mem);

    if (bp->mmap) {
        nxt_mem_unmap(b->mem.start, &b->mmap, size);
    }

    if (bp->destroy) {

        if (b == bp->current) {
            bp->current = NULL;
        }

        nxt_buf_free(bp->mem_pool, b);

        return;
    }

    if (bp->mmap) {
        b->mem.pos = NULL;
        b->mem.free = NULL;
        nxt_buf_mem_set_size(&b->mem, size);

    } else {
        b->mem.pos = b->mem.start;
        b->mem.free = b->mem.start;
    }

    if (b != bp->current) {
        b->next = bp->free;
        bp->free = b;
    }
}


void
nxt_buf_pool_destroy(nxt_buf_pool_t *bp)
{
    nxt_buf_t  *b, *n;

    bp->destroy = 1;

    for (b = bp->free; b != NULL; b = n) {
        n = b->next;
        nxt_buf_free(bp->mem_pool, b);
    }

    bp->free = b; /* NULL */
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void nxt_buf_completion(nxt_task_t *task, void *obj, void *data);


nxt_buf_t *
nxt_buf_mem_alloc(nxt_mem_pool_t *mp, size_t size, nxt_uint_t flags)
{
    nxt_buf_t  *b;

    b = nxt_mem_cache_zalloc0(mp, NXT_BUF_MEM_SIZE);
    if (nxt_slow_path(b == NULL)) {
        return NULL;
    }

    b->data = mp;
    b->completion_handler = nxt_buf_completion;
    b->size = NXT_BUF_MEM_SIZE;

    if (size != 0) {
        b->mem.start = nxt_mem_buf(mp, &size, flags);
        if (nxt_slow_path(b->mem.start == NULL)) {
            return NULL;
        }

        b->mem.pos = b->mem.start;
        b->mem.free = b->mem.start;
        b->mem.end = b->mem.start + size;
    }

    return b;
}


nxt_buf_t *
nxt_buf_file_alloc(nxt_mem_pool_t *mp, size_t size, nxt_uint_t flags)
{
    nxt_buf_t  *b;

    b = nxt_mem_cache_zalloc0(mp, NXT_BUF_FILE_SIZE);
    if (nxt_slow_path(b == NULL)) {
        return NULL;
    }

    b->data = mp;
    b->completion_handler = nxt_buf_completion;
    b->size = NXT_BUF_FILE_SIZE;
    nxt_buf_set_file(b);

    if (size != 0) {
        b->mem.start = nxt_mem_buf(mp, &size, flags);
        if (nxt_slow_path(b->mem.start == NULL)) {
            return NULL;
        }

        b->mem.pos = b->mem.start;
        b->mem.free = b->mem.start;
        b->mem.end = b->mem.start + size;
    }

    return b;
}


nxt_buf_t *
nxt_buf_mmap_alloc(nxt_mem_pool_t *mp, size_t size)
{
    nxt_buf_t  *b;

    b = nxt_mem_cache_zalloc0(mp, NXT_BUF_MMAP_SIZE);

    if (nxt_fast_path(b != NULL)) {
        b->data = mp;
        b->completion_handler = nxt_buf_completion;
        b->size = NXT_BUF_MMAP_SIZE;

        nxt_buf_set_file(b);
        nxt_buf_set_mmap(b);
        nxt_buf_mem_set_size(&b->mem, size);
    }

    return b;
}


nxt_buf_t *
nxt_buf_sync_alloc(nxt_mem_pool_t *mp, nxt_uint_t flags)
{
    nxt_buf_t  *b;

    b = nxt_mem_cache_zalloc0(mp, NXT_BUF_SYNC_SIZE);

    if (nxt_fast_path(b != NULL)) {
        b->data = mp;
        b->completion_handler = nxt_buf_completion;
        b->size = NXT_BUF_SYNC_SIZE;

        nxt_buf_set_sync(b);
        b->is_nobuf = ((flags & NXT_BUF_SYNC_NOBUF) != 0);
        b->is_flush = ((flags & NXT_BUF_SYNC_FLUSH) != 0);
        b->is_last = ((flags & NXT_BUF_SYNC_LAST) != 0);
    }

    return b;
}


void
nxt_buf_chain_add(nxt_buf_t **head, nxt_buf_t *in)
{
    nxt_buf_t  *b, **prev;

    prev = head;

    for (b = *head; b != NULL; b = b->next) {
        prev = &b->next;
    }

    *prev = in;
}


size_t
nxt_buf_chain_length(nxt_buf_t *b)
{
    size_t  length;

    length = 0;

    while (b != NULL) {
        length += b->mem.free - b->mem.pos;
        b = b->next;
    }

    return length;
}


static void
nxt_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t       *b, *parent;
    nxt_mem_pool_t  *mp;

    b = obj;
    parent = data;

    nxt_debug(task, "buf completion: %p %p", b, b->mem.start);

    mp = b->data;
    nxt_buf_free(mp, b);

    if (parent != NULL) {
        nxt_debug(task, "parent retain:%uD", parent->retain);

        parent->retain--;

        if (parent->retain == 0) {
            parent->mem.pos = parent->mem.free;

            parent->completion_handler(task, parent, parent->parent);
        }
    }
}

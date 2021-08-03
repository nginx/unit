
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void nxt_buf_completion(nxt_task_t *task, void *obj, void *data);
static void nxt_buf_ts_completion(nxt_task_t *task, void *obj, void *data);


typedef struct {
    nxt_work_t          work;
    nxt_event_engine_t  *engine;
} nxt_buf_ts_t;


void
nxt_buf_mem_init(nxt_buf_t *b, void *start, size_t size)
{
    b->mem.start = start;
    b->mem.pos = start;
    b->mem.free = start;
    b->mem.end = nxt_pointer_to(start, size);
}


nxt_buf_t *
nxt_buf_mem_alloc(nxt_mp_t *mp, size_t size, nxt_uint_t flags)
{
    nxt_buf_t  *b;

    b = nxt_mp_alloc(mp, NXT_BUF_MEM_SIZE + size);
    if (nxt_slow_path(b == NULL)) {
        return NULL;
    }

    nxt_memzero(b, NXT_BUF_MEM_SIZE);

    b->data = mp;
    b->completion_handler = nxt_buf_completion;

    if (size != 0) {
        b->mem.start = nxt_pointer_to(b, NXT_BUF_MEM_SIZE);
        b->mem.pos = b->mem.start;
        b->mem.free = b->mem.start;
        b->mem.end = b->mem.start + size;
    }

    return b;
}


nxt_buf_t *
nxt_buf_mem_ts_alloc(nxt_task_t *task, nxt_mp_t *mp, size_t size)
{
    nxt_buf_t     *b;
    nxt_buf_ts_t  *ts;

    b = nxt_mp_alloc(mp, NXT_BUF_MEM_SIZE + sizeof(nxt_buf_ts_t) + size);
    if (nxt_slow_path(b == NULL)) {
        return NULL;
    }

    nxt_mp_retain(mp);

    nxt_memzero(b, NXT_BUF_MEM_SIZE + sizeof(nxt_buf_ts_t));

    b->data = mp;
    b->completion_handler = nxt_buf_ts_completion;
    b->is_ts = 1;

    if (size != 0) {
        b->mem.start = nxt_pointer_to(b, NXT_BUF_MEM_SIZE
                                         + sizeof(nxt_buf_ts_t));
        b->mem.pos = b->mem.start;
        b->mem.free = b->mem.start;
        b->mem.end = b->mem.start + size;
    }

    ts = nxt_pointer_to(b, NXT_BUF_MEM_SIZE);
    ts->engine = task->thread->engine;

    ts->work.handler = nxt_buf_ts_completion;
    ts->work.task = task;
    ts->work.obj = b;
    ts->work.data = b->parent;

    return b;
}


nxt_buf_t *
nxt_buf_file_alloc(nxt_mp_t *mp, size_t size, nxt_uint_t flags)
{
    nxt_buf_t  *b;

    b = nxt_mp_alloc(mp, NXT_BUF_FILE_SIZE + size);
    if (nxt_slow_path(b == NULL)) {
        return NULL;
    }

    nxt_memzero(b, NXT_BUF_FILE_SIZE);

    b->data = mp;
    b->completion_handler = nxt_buf_completion;
    nxt_buf_set_file(b);

    if (size != 0) {
        b->mem.start = nxt_pointer_to(b, NXT_BUF_FILE_SIZE);
        b->mem.pos = b->mem.start;
        b->mem.free = b->mem.start;
        b->mem.end = b->mem.start + size;
    }

    return b;
}


nxt_buf_t *
nxt_buf_mmap_alloc(nxt_mp_t *mp, size_t size)
{
    nxt_buf_t  *b;

    b = nxt_mp_zalloc(mp, NXT_BUF_MMAP_SIZE);

    if (nxt_fast_path(b != NULL)) {
        b->data = mp;
        b->completion_handler = nxt_buf_completion;

        nxt_buf_set_file(b);
        nxt_buf_set_mmap(b);
        nxt_buf_mem_set_size(&b->mem, size);
    }

    return b;
}


nxt_buf_t *
nxt_buf_sync_alloc(nxt_mp_t *mp, nxt_uint_t flags)
{
    nxt_buf_t  *b;

    b = nxt_mp_zalloc(mp, NXT_BUF_MEM_SIZE);

    if (nxt_fast_path(b != NULL)) {
        b->data = mp;
        b->completion_handler = nxt_buf_completion;

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
        if (!nxt_buf_is_sync(b)) {
            length += b->mem.free - b->mem.pos;
        }

        b = b->next;
    }

    return length;
}


static void
nxt_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_mp_t   *mp;
    nxt_buf_t  *b, *next, *parent;

    b = obj;

    nxt_debug(task, "buf completion: %p %p", b, b->mem.start);

    nxt_assert(data == b->parent);

    do {
        next = b->next;
        parent = b->parent;
        mp = b->data;

        nxt_mp_free(mp, b);

        nxt_buf_parent_completion(task, parent);

        b = next;
    } while (b != NULL);
}


void
nxt_buf_parent_completion(nxt_task_t *task, nxt_buf_t *parent)
{
    if (parent != NULL) {
        nxt_debug(task, "parent retain:%uD", parent->retain);

        parent->retain--;

        if (parent->retain == 0) {
            parent->mem.pos = parent->mem.free;

            parent->completion_handler(task, parent, parent->parent);
        }
    }
}


nxt_int_t
nxt_buf_ts_handle(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t     *b;
    nxt_buf_ts_t  *ts;

    b = obj;

    nxt_assert(b->is_ts != 0);

    ts = nxt_pointer_to(b, NXT_BUF_MEM_SIZE);

    if (ts->engine != task->thread->engine) {

        nxt_debug(task, "buf ts: %p current engine is %p, expected %p",
                  b, task->thread->engine, ts->engine);

        ts->work.handler = b->completion_handler;
        ts->work.obj = obj;
        ts->work.data = data;

        nxt_event_engine_post(ts->engine, &ts->work);

        return 1;
    }

    return 0;
}


static void
nxt_buf_ts_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_mp_t   *mp;
    nxt_buf_t  *b, *next, *parent;

    b = obj;

    if (nxt_buf_ts_handle(task, obj, data)) {
        return;
    }

    nxt_debug(task, "buf ts completion: %p %p", b, b->mem.start);

    nxt_assert(data == b->parent);

    do {
        next = b->next;
        parent = b->parent;
        mp = b->data;

        nxt_mp_free(mp, b);
        nxt_mp_release(mp);

        nxt_buf_parent_completion(task, parent);

        b = next;
    } while (b != NULL);
}


nxt_buf_t *
nxt_buf_make_plain(nxt_mp_t *mp, nxt_buf_t *src, size_t size)
{
    nxt_buf_t  *b, *i;

    if (nxt_slow_path(size == 0)) {
        for (i = src; i != NULL; i = i->next) {
            size += nxt_buf_used_size(i);
        }
    }

    b = nxt_buf_mem_alloc(mp, size, 0);

    if (nxt_slow_path(b == NULL)) {
        return NULL;
    }

    for (i = src; i != NULL; i = i->next) {
        if (nxt_slow_path(nxt_buf_mem_free_size(&b->mem)
                          < nxt_buf_used_size(i)))
        {
            break;
        }

        b->mem.free = nxt_cpymem(b->mem.free, i->mem.pos, nxt_buf_used_size(i));
    }

    return b;
}

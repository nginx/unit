
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * Available work items are crucial for overall engine operation, so
 * the items are preallocated in two chunks: cache and spare chunks.
 * By default each chunk preallocates 409 work items on two or four
 * CPU pages depending on platform.  If all items in a cache chunk are
 * exhausted then a spare chunk becomes a cache chunk, and a new spare
 * chunk is allocated.  This two-step allocation mitigates low memory
 * condition impact on work queue operation.  However, if both chunks
 * are exhausted then a thread will sleep in reliance on another thread
 * frees some memory.  However, this may lead to deadlock and probably
 * a process should be aborted.  This behaviour should be considered as
 * abort on program stack exhaustion.
 *
 * The cache and spare chunks initially are also allocated in two steps:
 * a spare chunk is allocated first, then it becomes the cache chunk and
 * a new spare chunk is allocated again.
 */

static void nxt_work_queue_allocate(nxt_work_queue_cache_t *cache);


/* It should be adjusted with the "work_queue_bucket_items" directive. */
static nxt_uint_t  nxt_work_queue_bucket_items = 409;


#if (NXT_DEBUG)

nxt_inline void
nxt_work_queue_thread_assert(nxt_work_queue_t *wq)
{
    nxt_tid_t     tid;
    nxt_thread_t  *thread;

    thread = nxt_thread();
    tid = nxt_thread_tid(thread);

    if (nxt_fast_path(wq->tid == tid)) {
        return;
    }

    if (nxt_slow_path(nxt_pid != wq->pid)) {
        wq->pid = nxt_pid;
        wq->tid = tid;

        return;
    }

    nxt_log_alert(thread->log, "work queue locked by thread %PT", wq->tid);
    nxt_abort();
}


void nxt_work_queue_thread_adopt(nxt_work_queue_t *wq)
{
    nxt_thread_t  *thread;

    thread = nxt_thread();

    wq->pid = nxt_pid;
    wq->tid = nxt_thread_tid(thread);
}


void
nxt_work_queue_name(nxt_work_queue_t *wq, const char *name)
{
    nxt_work_queue_thread_assert(wq);

    wq->name = name;
}

#else

#define nxt_work_queue_thread_assert(wq)

#endif


void
nxt_work_queue_cache_create(nxt_work_queue_cache_t *cache, size_t chunk_size)
{
    nxt_memzero(cache, sizeof(nxt_work_queue_cache_t));

    if (chunk_size == 0) {
        chunk_size = nxt_work_queue_bucket_items;
    }

    /* nxt_work_queue_chunk_t already has one work item. */
    cache->chunk_size = chunk_size - 1;

    while (cache->next == NULL) {
        nxt_work_queue_allocate(cache);
    }
}


void
nxt_work_queue_cache_destroy(nxt_work_queue_cache_t *cache)
{
    nxt_work_queue_chunk_t  *chunk, *next;

    for (chunk = cache->chunk; chunk; chunk = next) {
        next = chunk->next;
        nxt_free(chunk);
    }
}


static void
nxt_work_queue_allocate(nxt_work_queue_cache_t *cache)
{
    size_t                  size;
    nxt_uint_t              i, n;
    nxt_work_t              *work;
    nxt_work_queue_chunk_t  *chunk;

    n = cache->chunk_size;
    size = sizeof(nxt_work_queue_chunk_t) + n * sizeof(nxt_work_t);

    chunk = nxt_malloc(size);

    if (nxt_fast_path(chunk != NULL)) {

        chunk->next = cache->chunk;
        cache->chunk = chunk;
        work = &chunk->work;

        for (i = 0; i < n; i++) {
            work[i].next = &work[i + 1];
        }

        work[i].next = NULL;
        work++;

    } else if (cache->spare != NULL) {

        work = NULL;

    } else {
        return;
    }

    cache->next = cache->spare;
    cache->spare = work;
}


/* Add a work to a work queue tail. */

void
nxt_work_queue_add(nxt_work_queue_t *wq, nxt_work_handler_t handler,
    nxt_task_t *task, void *obj, void *data)
{
    nxt_work_t  *work;

    nxt_work_queue_thread_assert(wq);

    for ( ;; ) {
        work = wq->cache->next;

        if (nxt_fast_path(work != NULL)) {
            wq->cache->next = work->next;
            work->next = NULL;

            work->handler = handler;
            work->task = task;
            work->obj = obj;
            work->data = data;

            if (wq->tail != NULL) {
                wq->tail->next = work;

            } else {
                wq->head = work;
            }

            wq->tail = work;

            return;
        }

        nxt_work_queue_allocate(wq->cache);
    }
}


nxt_work_handler_t
nxt_work_queue_pop(nxt_work_queue_t *wq, nxt_task_t **task, void **obj,
    void **data)
{
    nxt_work_t  *work;

    nxt_work_queue_thread_assert(wq);

    work = wq->head;

    wq->head = work->next;

    if (work->next == NULL) {
        wq->tail = NULL;
    }

    *task = work->task;

    *obj = work->obj;
    nxt_prefetch(*obj);

    *data = work->data;
    nxt_prefetch(*data);

    work->next = wq->cache->next;
    wq->cache->next = work;

    return work->handler;
}


/* Add a work to a locked work queue tail. */

void
nxt_locked_work_queue_add(nxt_locked_work_queue_t *lwq, nxt_work_t *work)
{
    nxt_thread_spin_lock(&lwq->lock);

    if (lwq->tail != NULL) {
        lwq->tail->next = work;

    } else {
        lwq->head = work;
    }

    lwq->tail = work;

    nxt_thread_spin_unlock(&lwq->lock);
}


/* Pop a work from a locked work queue head. */

nxt_work_handler_t
nxt_locked_work_queue_pop(nxt_locked_work_queue_t *lwq, nxt_task_t **task,
    void **obj, void **data)
{
    nxt_work_t          *work;
    nxt_work_handler_t  handler;

    handler = NULL;

    nxt_thread_spin_lock(&lwq->lock);

    work = lwq->head;

    if (work != NULL) {
        *task = work->task;

        *obj = work->obj;
        nxt_prefetch(*obj);

        *data = work->data;
        nxt_prefetch(*data);

        lwq->head = work->next;

        if (work->next == NULL) {
            lwq->tail = NULL;
        }

        handler = work->handler;
    }

    nxt_thread_spin_unlock(&lwq->lock);

    return handler;
}


/* Move all works from a locked work queue to a usual work queue. */

void
nxt_locked_work_queue_move(nxt_thread_t *thr, nxt_locked_work_queue_t *lwq,
    nxt_work_queue_t *wq)
{
    nxt_work_t  *work;

    nxt_thread_spin_lock(&lwq->lock);

    work = lwq->head;

    lwq->head = NULL;
    lwq->tail = NULL;

    nxt_thread_spin_unlock(&lwq->lock);

    while (work != NULL) {
        work->task->thread = thr;

        nxt_work_queue_add(wq, work->handler, work->task,
                           work->obj, work->data);

        work = work->next;
    }
}

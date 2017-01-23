
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

static void nxt_work_queue_allocate(nxt_work_queue_cache_t *cache,
    nxt_thread_spinlock_t *lock);
static void nxt_work_queue_sleep(nxt_thread_spinlock_t *lock);
static nxt_work_queue_t *nxt_thread_current_work_queue(nxt_thread_t *thr);
static nxt_work_handler_t nxt_locked_work_queue_pop_work(
    nxt_locked_work_queue_t *lwq, nxt_task_t **task, void **obj, void **data);


/* It should be adjusted with the "work_queue_bucket_items" directive. */
static nxt_uint_t  nxt_work_queue_bucket_items = 409;


void
nxt_thread_work_queue_create(nxt_thread_t *thr, size_t chunk_size)
{
    nxt_memzero(&thr->work_queue, sizeof(nxt_thread_work_queue_t));

    nxt_work_queue_name(&thr->work_queue.main, "main");
    nxt_work_queue_name(&thr->work_queue.last, "last");

    if (chunk_size == 0) {
        chunk_size = nxt_work_queue_bucket_items;
    }

    /* nxt_work_queue_chunk_t already has one work item. */
    thr->work_queue.cache.chunk_size = chunk_size - 1;

    while (thr->work_queue.cache.next == NULL) {
        nxt_work_queue_allocate(&thr->work_queue.cache, NULL);
    }
}


void
nxt_thread_work_queue_destroy(nxt_thread_t *thr)
{
    nxt_work_queue_chunk_t  *chunk, *next;

    for (chunk = thr->work_queue.cache.chunk; chunk; chunk = next) {
        next = chunk->next;
        nxt_free(chunk);
    }
}


static void
nxt_work_queue_allocate(nxt_work_queue_cache_t *cache,
    nxt_thread_spinlock_t *lock)
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
        nxt_work_queue_sleep(lock);
        return;
    }

    cache->next = cache->spare;
    cache->spare = work;
}


static void
nxt_work_queue_sleep(nxt_thread_spinlock_t *lock)
{
    if (lock != NULL) {
        nxt_thread_spin_unlock(lock);
    }

    nxt_nanosleep(100 * 1000000);  /* 100ms */

    if (lock != NULL) {
        nxt_thread_spin_lock(lock);
    }
}


/* Add a work to a work queue tail. */

void
nxt_thread_work_queue_add(nxt_thread_t *thr, nxt_work_queue_t *wq,
    nxt_work_handler_t handler, nxt_task_t *task, void *obj, void *data)
{
    nxt_work_t  *work;

    nxt_work_queue_attach(thr, wq);

    for ( ;; ) {
        work = thr->work_queue.cache.next;

        if (nxt_fast_path(work != NULL)) {
            thr->work_queue.cache.next = work->next;
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

        nxt_work_queue_allocate(&thr->work_queue.cache, NULL);
    }
}


/* Push a work to a work queue head. */

void
nxt_thread_work_queue_push(nxt_thread_t *thr, nxt_work_queue_t *wq,
    nxt_work_handler_t handler, nxt_task_t *task, void *obj, void *data)
{
    nxt_work_t  *work;

    nxt_work_queue_attach(thr, wq);

    for ( ;; ) {
        work = thr->work_queue.cache.next;

        if (nxt_fast_path(work != NULL)) {
            thr->work_queue.cache.next = work->next;
            work->next = wq->head;

            work->handler = handler;
            work->obj = obj;
            work->data = data;

            wq->head = work;

            if (wq->tail == NULL) {
                wq->tail = work;
            }

            return;
        }

        nxt_work_queue_allocate(&thr->work_queue.cache, NULL);
    }
}


/* Attach a work queue to a thread work queue. */

void
nxt_work_queue_attach(nxt_thread_t *thr, nxt_work_queue_t *wq)
{
    if (wq->next == NULL && wq != thr->work_queue.tail) {

        if (thr->work_queue.tail != NULL) {
            thr->work_queue.tail->next = wq;

        } else {
            thr->work_queue.head = wq;
        }

        thr->work_queue.tail = wq;
    }
}


/* Pop a work from a thread work queue head. */

nxt_work_handler_t
nxt_thread_work_queue_pop(nxt_thread_t *thr, nxt_task_t **task, void **obj,
    void **data)
{
    nxt_work_t        *work;
    nxt_work_queue_t  *wq;

    wq = nxt_thread_current_work_queue(thr);

    if (wq != NULL) {

        work = wq->head;

        if (work != NULL) {
            wq->head = work->next;

            if (work->next == NULL) {
                wq->tail = NULL;
            }

            *task = work->task;
            *obj = work->obj;
            nxt_prefetch(*obj);
            *data = work->data;
            nxt_prefetch(*data);

            work->next = thr->work_queue.cache.next;
            thr->work_queue.cache.next = work;

#if (NXT_DEBUG)

            if (work->handler == NULL) {
                nxt_log_alert(thr->log, "null work handler");
                nxt_abort();
            }

#endif

            return work->handler;
        }
    }

    return NULL;
}


static nxt_work_queue_t *
nxt_thread_current_work_queue(nxt_thread_t *thr)
{
    nxt_work_queue_t  *wq, *next;

    for (wq = thr->work_queue.head; wq != NULL; wq = next) {

        if (wq->head != NULL) {
            nxt_log_debug(thr->log, "work queue: %s", wq->name);
            return wq;
        }

        /* Detach empty work queue. */
        next = wq->next;
        wq->next = NULL;
        thr->work_queue.head = next;
    }

    thr->work_queue.tail = NULL;

    return NULL;
}


/* Drop a work with specified data from a thread work queue. */

void
nxt_thread_work_queue_drop(nxt_thread_t *thr, void *data)
{
    nxt_work_t        *work, *prev, *next, **link;
    nxt_work_queue_t  *wq;

    for (wq = thr->work_queue.head; wq != NULL; wq = wq->next) {

        prev = NULL;
        link = &wq->head;

        for (work = wq->head; work != NULL; work = next) {

            next = work->next;

            if (data != work->obj) {
                prev = work;
                link = &work->next;

            } else {
                if (next == NULL) {
                    wq->tail = prev;
                }

                nxt_log_debug(thr->log, "work queue drop");

                *link = next;

                work->next = thr->work_queue.cache.next;
                thr->work_queue.cache.next = work;
            }
        }
    }
}


/* Add a work to the thread last work queue's tail. */

void
nxt_thread_last_work_queue_add(nxt_thread_t *thr, nxt_work_handler_t handler,
    void *obj, void *data)
{
    nxt_work_t  *work;

    for ( ;; ) {
        work = thr->work_queue.cache.next;

        if (nxt_fast_path(work != NULL)) {
            thr->work_queue.cache.next = work->next;
            work->next = NULL;

            work->handler = handler;
            work->obj = obj;
            work->data = data;

            if (thr->work_queue.last.tail != NULL) {
                thr->work_queue.last.tail->next = work;

            } else {
                thr->work_queue.last.head = work;
            }

            thr->work_queue.last.tail = work;

            return;
        }

        nxt_work_queue_allocate(&thr->work_queue.cache, NULL);
    }
}


/* Pop a work from the thread last work queue's head. */

nxt_work_handler_t
nxt_thread_last_work_queue_pop(nxt_thread_t *thr, nxt_task_t **task, void **obj,
    void **data)
{
    nxt_work_t  *work;

    work = thr->work_queue.last.head;

    if (work != NULL) {
        nxt_log_debug(thr->log, "work queue: %s", thr->work_queue.last.name);

        thr->work_queue.last.head = work->next;

        if (work->next == NULL) {
            thr->work_queue.last.tail = NULL;
        }

        *task = work->task;
        *obj = work->obj;
        nxt_prefetch(*obj);
        *data = work->data;
        nxt_prefetch(*data);

        work->next = thr->work_queue.cache.next;
        thr->work_queue.cache.next = work;

#if (NXT_DEBUG)

        if (work->handler == NULL) {
            nxt_log_alert(thr->log, "null work handler");
            nxt_abort();
        }

#endif

        return work->handler;
    }

    return NULL;
}


void
nxt_work_queue_destroy(nxt_work_queue_t *wq)
{
    nxt_thread_t      *thr;
    nxt_work_queue_t  *q;

    thr = nxt_thread();

    /* Detach from a thread work queue. */

    if (thr->work_queue.head == wq) {
        thr->work_queue.head = wq->next;
        q = NULL;
        goto found;
    }

    for (q = thr->work_queue.head; q != NULL; q = q->next) {
        if (q->next == wq) {
            q->next = wq->next;
            goto found;
        }
    }

    return;

found:

    if (thr->work_queue.tail == wq) {
        thr->work_queue.tail = q;
    }

    /* Move all queue's works to a thread work queue cache. */

    if (wq->tail != NULL) {
        wq->tail->next = thr->work_queue.cache.next;
    }

    if (wq->head != NULL) {
        thr->work_queue.cache.next = wq->head;
    }
}


/* Locked work queue operations. */

void
nxt_locked_work_queue_create(nxt_locked_work_queue_t *lwq, size_t chunk_size)
{
    nxt_memzero(lwq, sizeof(nxt_locked_work_queue_t));

    if (chunk_size == 0) {
        chunk_size = nxt_work_queue_bucket_items;
    }

    lwq->cache.chunk_size = chunk_size;

    while (lwq->cache.next == NULL) {
        nxt_work_queue_allocate(&lwq->cache, NULL);
    }
}


void
nxt_locked_work_queue_destroy(nxt_locked_work_queue_t *lwq)
{
    nxt_work_queue_chunk_t  *chunk, *next;

    for (chunk = lwq->cache.chunk; chunk; chunk = next) {
        next = chunk->next;
        nxt_free(chunk);
    }
}


/* Add a work to a locked work queue tail. */

void
nxt_locked_work_queue_add(nxt_locked_work_queue_t *lwq,
    nxt_work_handler_t handler, nxt_task_t *task, void *obj, void *data)
{
    nxt_work_t  *work;

    nxt_thread_spin_lock(&lwq->lock);

    for ( ;; ) {
        work = lwq->cache.next;

        if (nxt_fast_path(work != NULL)) {
            lwq->cache.next = work->next;

            work->next = NULL;
            work->handler = handler;
            work->task = task;
            work->obj = obj;
            work->data = data;

            if (lwq->tail != NULL) {
                lwq->tail->next = work;

            } else {
                lwq->head = work;
            }

            lwq->tail = work;

            break;
        }

        nxt_work_queue_allocate(&lwq->cache, &lwq->lock);
    }

    nxt_thread_spin_unlock(&lwq->lock);
}


/* Pop a work from a locked work queue head. */

nxt_work_handler_t
nxt_locked_work_queue_pop(nxt_locked_work_queue_t *lwq, nxt_task_t **task,
    void **obj, void **data)
{
    nxt_work_handler_t  handler;

    nxt_thread_spin_lock(&lwq->lock);

    handler = nxt_locked_work_queue_pop_work(lwq, task, obj, data);

    nxt_thread_spin_unlock(&lwq->lock);

    return handler;
}


static nxt_work_handler_t
nxt_locked_work_queue_pop_work(nxt_locked_work_queue_t *lwq, nxt_task_t **task,
    void **obj, void **data)
{
    nxt_work_t  *work;

    work = lwq->head;

    if (work == NULL) {
        return NULL;
    }

    *task = work->task;
    *obj = work->obj;
    nxt_prefetch(*obj);
    *data = work->data;
    nxt_prefetch(*data);

    lwq->head = work->next;

    if (work->next == NULL) {
        lwq->tail = NULL;
    }

    work->next = lwq->cache.next;
    lwq->cache.next = work;

    return work->handler;
}


/* Move all works from a locked work queue to a usual work queue. */

void
nxt_locked_work_queue_move(nxt_thread_t *thr, nxt_locked_work_queue_t *lwq,
    nxt_work_queue_t *wq)
{
    void                *obj, *data;
    nxt_task_t          *task;
    nxt_work_handler_t  handler;

    /* Locked work queue head can be tested without a lock. */

    if (nxt_fast_path(lwq->head == NULL)) {
        return;
    }

    nxt_thread_spin_lock(&lwq->lock);

    for ( ;; ) {
        handler = nxt_locked_work_queue_pop_work(lwq, &task, &obj, &data);

        if (handler == NULL) {
            break;
        }

        task->thread = thr;

        nxt_thread_work_queue_add(thr, wq, handler, task, obj, data);
    }

    nxt_thread_spin_unlock(&lwq->lock);
}

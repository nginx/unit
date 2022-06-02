
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_WORK_QUEUE_H_INCLUDED_
#define _NXT_WORK_QUEUE_H_INCLUDED_


typedef struct nxt_work_s  nxt_work_t;

struct nxt_task_s {
    nxt_thread_t  *thread;
    nxt_log_t     *log;
    uint32_t      ident;
    nxt_work_t    *next_work;

    /* TODO: exception_handler, prev/next task, subtasks. */
};


#define nxt_task_next_ident()                                                 \
    ((uint32_t) nxt_atomic_fetch_add(&nxt_task_ident, 1) & 0x3FFFFFFF)


/*
 * A work handler with just the obj and data arguments instead
 * of pointer to a possibly large a work struct allows to call
 * the handler not only via a work queue but also directly.
 * The only obj argument is enough for the most cases except the
 * source filters, so the data argument has been introduced and
 * is used where appropriate.
 */
//typedef void (*nxt_work_handler_t)(nxt_task_t *task, void *obj, void *data);


struct nxt_work_s {
    nxt_work_t                  *next;
    nxt_work_handler_t          handler;
    nxt_task_t                  *task;
    void                        *obj;
    void                        *data;
};


typedef struct nxt_work_queue_chunk_s  nxt_work_queue_chunk_t;

struct nxt_work_queue_chunk_s {
    nxt_work_queue_chunk_t      *next;
    nxt_work_t                  work;
};


typedef struct {
    nxt_work_t                  *next;
    nxt_work_t                  *spare;
    nxt_work_queue_chunk_t      *chunk;
    size_t                      chunk_size;
} nxt_work_queue_cache_t;


typedef struct nxt_work_queue_s  nxt_work_queue_t;

struct nxt_work_queue_s {
    nxt_work_t                  *head;
    nxt_work_t                  *tail;
    nxt_work_queue_cache_t      *cache;
#if (NXT_DEBUG)
    const char                  *name;
    int32_t                     pid;
    nxt_tid_t                   tid;
#endif
};


typedef struct {
    nxt_thread_spinlock_t       lock;
    nxt_work_t                  *head;
    nxt_work_t                  *tail;
    nxt_work_queue_cache_t      cache;
} nxt_locked_work_queue_t;


NXT_EXPORT void nxt_work_queue_cache_create(nxt_work_queue_cache_t *cache,
    size_t chunk_size);
NXT_EXPORT void nxt_work_queue_cache_destroy(nxt_work_queue_cache_t *cache);

NXT_EXPORT void nxt_work_queue_add(nxt_work_queue_t *wq,
    nxt_work_handler_t handler, nxt_task_t *task, void *obj, void *data);
NXT_EXPORT nxt_work_handler_t nxt_work_queue_pop(nxt_work_queue_t *wq,
    nxt_task_t **task, void **obj, void **data);


#define nxt_work_set(_work, _handler, _task, _obj, _data)                     \
    do {                                                                      \
        nxt_work_t  *work = _work;                                            \
                                                                              \
        work->handler = _handler;                                             \
        work->task = _task;                                                   \
        work->obj = _obj;                                                     \
        work->data = _data;                                                   \
    } while (0)

#if (NXT_DEBUG)

NXT_EXPORT void nxt_work_queue_name(nxt_work_queue_t *wq, const char *name);
NXT_EXPORT void nxt_work_queue_thread_adopt(nxt_work_queue_t *wq);

#else

#define nxt_work_queue_name(_wq, _name)

#define nxt_work_queue_thread_adopt(_wq)

#endif


NXT_EXPORT void nxt_locked_work_queue_add(nxt_locked_work_queue_t *lwq,
    nxt_work_t *work);
NXT_EXPORT nxt_work_handler_t nxt_locked_work_queue_pop(
    nxt_locked_work_queue_t *lwq, nxt_task_t **task, void **obj, void **data);
NXT_EXPORT void nxt_locked_work_queue_move(nxt_thread_t *thr,
    nxt_locked_work_queue_t *lwq, nxt_work_queue_t *wq);


#endif /* _NXT_WORK_QUEUE_H_INCLUDED_ */


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_WORK_QUEUE_H_INCLUDED_
#define _NXT_WORK_QUEUE_H_INCLUDED_


typedef struct nxt_work_s  nxt_work_t;

typedef struct {
     nxt_thread_t  *thread;
     nxt_log_t     *log;
     uint32_t      ident;
     nxt_work_t    *next_work;

     /* TODO: exception_handler, prev/next task, subtasks. */
} nxt_task_t;


#define nxt_task_next_ident()                                                 \
     ((uint32_t) nxt_atomic_fetch_add(&nxt_task_ident, 1) & 0x3fffffff)


/*
 * A work handler with just the obj and data arguments instead
 * of pointer to a possibly large a work struct allows to call
 * the handler not only via a work queue but also directly.
 * The only obj argument is enough for the most cases expect the
 * source filters, so the data argument has been introduced and
 * is used where appropriate.
 */
typedef void (*nxt_work_handler_t)(nxt_task_t *task, void *obj, void *data);


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
    nxt_work_queue_t            *next;
#if (NXT_DEBUG)
    const char                  *name;
#endif
};


typedef struct {
    nxt_work_queue_t            *head;
    nxt_work_queue_t            *tail;
    nxt_work_queue_t            main;
    nxt_work_queue_t            last;
    nxt_work_queue_cache_t      cache;
} nxt_thread_work_queue_t;


typedef struct {
    nxt_thread_spinlock_t       lock;
    nxt_work_t                  *head;
    nxt_work_t                  *tail;
    nxt_work_queue_cache_t      cache;
} nxt_locked_work_queue_t;


NXT_EXPORT void nxt_thread_work_queue_create(nxt_thread_t *thr,
    size_t chunk_size);
NXT_EXPORT void nxt_thread_work_queue_destroy(nxt_thread_t *thr);
NXT_EXPORT void nxt_thread_work_queue_add(nxt_thread_t *thr,
    nxt_work_queue_t *wq, nxt_work_handler_t handler, nxt_task_t *task,
    void *obj, void *data);
NXT_EXPORT void nxt_thread_work_queue_push(nxt_thread_t *thr,
    nxt_work_queue_t *wq, nxt_work_handler_t handler, nxt_task_t *task,
    void *obj, void *data);
NXT_EXPORT void nxt_work_queue_attach(nxt_thread_t *thr, nxt_work_queue_t *wq);
NXT_EXPORT nxt_work_handler_t nxt_thread_work_queue_pop(nxt_thread_t *thr,
    nxt_task_t **task, void **obj, void **data);
NXT_EXPORT void nxt_thread_work_queue_drop(nxt_thread_t *thr, void *data);


#define                                                                       \
nxt_thread_current_work_queue_add(thr, handler, task, obj, data)              \
    do {                                                                      \
        nxt_thread_t  *_thr = thr;                                            \
                                                                              \
        nxt_thread_work_queue_add(_thr, _thr->work_queue.head,                \
                                  handler, task, obj, data);                  \
    } while (0)


NXT_EXPORT void nxt_work_queue_destroy(nxt_work_queue_t *wq);


#if (NXT_DEBUG)

#define                                                                       \
nxt_work_queue_name(_wq, _name)                                               \
    (_wq)->name = _name

#else

#define                                                                       \
nxt_work_queue_name(_wq, _name)

#endif


NXT_EXPORT void nxt_thread_last_work_queue_add(nxt_thread_t *thr,
    nxt_work_handler_t handler, void *obj, void *data);
NXT_EXPORT nxt_work_handler_t nxt_thread_last_work_queue_pop(nxt_thread_t *thr,
    nxt_task_t **task, void **obj, void **data);


NXT_EXPORT void nxt_locked_work_queue_create(nxt_locked_work_queue_t *lwq,
    size_t chunk_size);
NXT_EXPORT void nxt_locked_work_queue_destroy(nxt_locked_work_queue_t *lwq);
NXT_EXPORT void nxt_locked_work_queue_add(nxt_locked_work_queue_t *lwq,
    nxt_work_handler_t handler, nxt_task_t *task, void *obj, void *data);
NXT_EXPORT nxt_work_handler_t nxt_locked_work_queue_pop(
    nxt_locked_work_queue_t *lwq, nxt_task_t **task, void **obj, void **data);
NXT_EXPORT void nxt_locked_work_queue_move(nxt_thread_t *thr,
    nxt_locked_work_queue_t *lwq, nxt_work_queue_t *wq);


#endif /* _NXT_WORK_QUEUE_H_INCLUDED_ */


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_SOURCE_H_INCLUDED_
#define _NXT_SOURCE_H_INCLUDED_


/*
 * A source handler should store a pointer to a passed source hook, but not
 * the hook's values themselves, because a source filter may change the values.
 */
typedef struct {
    void                *context;
    nxt_work_handler_t  filter;
} nxt_source_hook_t;


typedef void (*nxt_source_handler_t)(void *source_context,
    nxt_source_hook_t *query);


#define nxt_source_filter(thr, wq, task, next, out)                           \
    do {                                                                      \
        if (thr->engine->batch != 0) {                                        \
            nxt_thread_work_queue_add(thr, wq, nxt_source_filter_handler,     \
                                      task, next, out);                       \
                                                                              \
        } else {                                                              \
            (next)->filter(task, (next)->context, out);                       \
        }                                                                     \
                                                                              \
    } while (0)


NXT_EXPORT void nxt_source_filter_handler(nxt_task_t *task, void *obj,
    void *data);


#endif /* _NXT_SOURCE_H_INCLUDED_ */

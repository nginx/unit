
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIX_THREAD_POOL_H_INCLUDED_
#define _NXT_UNIX_THREAD_POOL_H_INCLUDED_


typedef void (*nxt_thread_pool_init_t)(void);


struct nxt_thread_pool_s {
    nxt_atomic_t             ready;
    nxt_atomic_t             waiting;
    nxt_atomic_t             threads;
    nxt_uint_t               max_threads;

    nxt_sem_t                sem;
    nxt_nsec_t               timeout;

    nxt_work_t               work;
    nxt_task_t               task;

    nxt_locked_work_queue_t  work_queue;

    nxt_thread_handle_t      main;

    nxt_event_engine_t       *engine;
    nxt_thread_pool_init_t   init;
    nxt_work_handler_t       exit;
};


NXT_EXPORT nxt_thread_pool_t *nxt_thread_pool_create(nxt_uint_t max_threads,
    nxt_nsec_t timeout, nxt_thread_pool_init_t init,
    nxt_event_engine_t *engine, nxt_work_handler_t exit);
NXT_EXPORT void nxt_thread_pool_destroy(nxt_thread_pool_t *tp);
NXT_EXPORT nxt_int_t nxt_thread_pool_post(nxt_thread_pool_t *tp,
    nxt_work_t *work);


#endif /* _NXT_UNIX_THREAD_POOL_H_INCLUDED_ */

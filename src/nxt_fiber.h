
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_FIBER_H_INCLUDED_
#define _NXT_FIBER_H_INCLUDED_


typedef struct nxt_fiber_main_s   nxt_fiber_main_t;
typedef void (*nxt_fiber_start_t)(void *data);


typedef uint32_t            nxt_fid_t;
#define nxt_fiber_id(f)     (f)->fid;


typedef struct nxt_fiber_s  nxt_fiber_t;

struct nxt_fiber_s {
    jmp_buf                 jmp;
    nxt_fid_t               fid;
    nxt_fiber_start_t       start;
    void                    *data;
    char                    *stack;
    size_t                  stack_size;
    nxt_err_t               err;

    nxt_task_t              task;

    nxt_fiber_main_t        *main;
    nxt_fiber_t             *next;

    nxt_timer_t             timer;
};


struct nxt_fiber_main_s {
    nxt_fiber_t             fiber;
    nxt_fiber_t             *idle;
    nxt_event_engine_t      *engine;
    size_t                  stack_size;
    nxt_fid_t               fid;
};


nxt_fiber_main_t *nxt_fiber_main_create(nxt_event_engine_t *engine);
nxt_int_t nxt_fiber_create(nxt_fiber_start_t start, void *data, size_t stack);
void nxt_fiber_yield(nxt_task_t *task);
void nxt_fiber_sleep(nxt_task_t *task, nxt_msec_t timeout);
void nxt_fiber_wait(nxt_task_t *task);
void nxt_fiber_exit(nxt_task_t *task, nxt_fiber_t *next, void *data);
NXT_EXPORT nxt_fiber_t *nxt_fiber_self(nxt_thread_t *thr);


#endif /* _NXT_FIBER_H_INCLUDED_ */

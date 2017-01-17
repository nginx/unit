
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_EVENT_ENGINE_H_INCLUDED_
#define _NXT_EVENT_ENGINE_H_INCLUDED_


#define NXT_ENGINE_FIBERS      1


typedef struct {
    nxt_fd_t                   fds[2];
    nxt_event_fd_t             event;
} nxt_event_engine_pipe_t;


struct nxt_event_engine_s {
    const nxt_event_set_ops_t  *event;
    nxt_event_set_t            *event_set;

    nxt_event_timers_t         timers;

    /* The engine ID, the main engine has ID 0. */
    uint32_t                   id;

    /*
     * A pipe to pass event signals to the engine, if the engine's
     * underlying event facility does not support user events.
     */
    nxt_event_engine_pipe_t    *pipe;

    nxt_work_queue_t           accept_work_queue;
    nxt_work_queue_t           read_work_queue;
    nxt_work_queue_t           socket_work_queue;
    nxt_work_queue_t           connect_work_queue;
    nxt_work_queue_t           write_work_queue;
    nxt_work_queue_t           shutdown_work_queue;
    nxt_work_queue_t           close_work_queue;

    nxt_locked_work_queue_t    work_queue;

    nxt_event_signals_t        *signals;

    nxt_fiber_main_t           *fibers;

    uint8_t                    shutdown;  /* 1 bit */

    uint32_t                   batch;
    uint32_t                   connections;
    uint32_t                   max_connections;

    nxt_queue_t                listen_connections;
    nxt_queue_t                idle_connections;
};


NXT_EXPORT nxt_event_engine_t *nxt_event_engine_create(nxt_thread_t *thr,
    const nxt_event_set_ops_t *event_set, const nxt_event_sig_t *signals,
    nxt_uint_t flags, nxt_uint_t batch);
NXT_EXPORT nxt_int_t nxt_event_engine_change(nxt_thread_t *thr,
    const nxt_event_set_ops_t *event_set, nxt_uint_t batch);
NXT_EXPORT void nxt_event_engine_free(nxt_event_engine_t *engine);
NXT_EXPORT void nxt_event_engine_start(nxt_event_engine_t *engine);

NXT_EXPORT void nxt_event_engine_post(nxt_event_engine_t *engine,
    nxt_work_handler_t handler, void *obj, void *data, nxt_log_t *log);
NXT_EXPORT void nxt_event_engine_signal(nxt_event_engine_t *engine,
    nxt_uint_t signo);


nxt_inline nxt_event_engine_t *
nxt_thread_event_engine(void)
{
    nxt_thread_t  *thr;

    thr = nxt_thread();
    return thr->engine;
}


nxt_inline nxt_work_queue_t *
nxt_thread_main_work_queue(void)
{
    nxt_thread_t  *thr;

    thr = nxt_thread();
    return &thr->work_queue.main;
}


#endif /* _NXT_EVENT_ENGINE_H_INCLUDED_ */


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_SIGNAL_H_INCLUDED_
#define _NXT_SIGNAL_H_INCLUDED_


struct nxt_sig_event_s {
    int                         signo;
    nxt_work_handler_t          handler;
    const char                  *name;
};

#define nxt_event_signal(sig, handler)                                        \
    { sig, handler, #sig }

#define nxt_event_signal_end                                                  \
    { 0, NULL, NULL }


typedef struct {
    /* Used by epoll and eventport. */
    nxt_work_handler_t          handler;

    const nxt_sig_event_t       *sigev;
    sigset_t                    sigmask;

    /* Used by the signal thread. */
    nxt_pid_t                   process;
    nxt_thread_handle_t         thread;
} nxt_event_signals_t;


nxt_event_signals_t *nxt_event_engine_signals(const nxt_sig_event_t *sigev);

#define nxt_event_engine_signals_start(engine)                                \
    nxt_signal_thread_start(engine)

#define nxt_event_engine_signals_stop(engine)                                 \
    nxt_signal_thread_stop(engine)


NXT_EXPORT nxt_int_t nxt_signal_thread_start(nxt_event_engine_t *engine);
NXT_EXPORT void nxt_signal_thread_stop(nxt_event_engine_t *engine);


#endif /* _NXT_SIGNAL_H_INCLUDED_ */

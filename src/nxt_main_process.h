
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_MAIN_PROCESS_H_INCLUDED_
#define _NXT_MAIN_PROCESS_H_INCLUDED_


nxt_int_t nxt_main_process_start(nxt_thread_t *thr, nxt_task_t *task,
    nxt_runtime_t *runtime);


NXT_EXPORT extern nxt_uint_t                nxt_conf_ver;
NXT_EXPORT extern const nxt_process_init_t  nxt_discovery_process;
NXT_EXPORT extern const nxt_process_init_t  nxt_controller_process;
NXT_EXPORT extern const nxt_process_init_t  nxt_router_process;
NXT_EXPORT extern const nxt_process_init_t  nxt_proto_process;
NXT_EXPORT extern const nxt_process_init_t  nxt_app_process;

extern const nxt_sig_event_t  nxt_main_process_signals[];
extern const nxt_sig_event_t  nxt_process_signals[];


#endif /* _NXT_MAIN_PROCESS_H_INCLUDED_ */

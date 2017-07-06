
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_MASTER_PROCESS_H_INCLUDED_
#define _NXT_MASTER_PROCESS_H_INCLUDED_


nxt_int_t nxt_master_process_start(nxt_thread_t *thr, nxt_task_t *task,
    nxt_runtime_t *runtime);
void nxt_master_stop_worker_processes(nxt_task_t *task, nxt_runtime_t *runtime);

nxt_int_t nxt_controller_start(nxt_task_t *task, nxt_runtime_t *rt);
nxt_int_t nxt_router_start(nxt_task_t *task, nxt_runtime_t *rt);


extern nxt_port_handler_t  nxt_worker_process_port_handlers[];
extern nxt_port_handler_t  nxt_app_process_port_handlers[];
extern nxt_port_handler_t  nxt_router_process_port_handlers[];
extern const nxt_sig_event_t  nxt_master_process_signals[];
extern const nxt_sig_event_t  nxt_worker_process_signals[];


#endif /* _NXT_MASTER_PROCESS_H_INCLUDED_ */

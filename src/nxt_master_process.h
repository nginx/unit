
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIX_MASTER_PROCESS_H_INCLUDED_
#define _NXT_UNIX_MASTER_PROCESS_H_INCLUDED_


nxt_int_t nxt_master_process_start(nxt_thread_t *thr, nxt_task_t *task,
    nxt_cycle_t *cycle);
void nxt_master_stop_worker_processes(nxt_task_t *task, nxt_cycle_t *cycle);
void nxt_worker_process_start(void *data);


extern const nxt_sig_event_t  nxt_master_process_signals[];


#endif /* _NXT_UNIX_MASTER_PROCESS_H_INCLUDED_ */

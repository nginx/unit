
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_MAIN_PROCESS_H_INCLUDED_
#define _NXT_MAIN_PROCESS_H_INCLUDED_


typedef enum {
    NXT_SOCKET_ERROR_SYSTEM = 0,
    NXT_SOCKET_ERROR_NOINET6,
    NXT_SOCKET_ERROR_PORT,
    NXT_SOCKET_ERROR_INUSE,
    NXT_SOCKET_ERROR_NOADDR,
    NXT_SOCKET_ERROR_ACCESS,
    NXT_SOCKET_ERROR_PATH,
} nxt_socket_error_t;


typedef struct {
    nxt_str_t    conf;
#if (NXT_TLS)
    nxt_array_t  *certs;
#endif
} nxt_controller_init_t;


nxt_int_t nxt_main_process_start(nxt_thread_t *thr, nxt_task_t *task,
    nxt_runtime_t *runtime);
void nxt_main_stop_all_processes(nxt_task_t *task, nxt_runtime_t *runtime);

nxt_int_t nxt_controller_start(nxt_task_t *task, void *data);
nxt_int_t nxt_router_start(nxt_task_t *task, void *data);
nxt_int_t nxt_discovery_start(nxt_task_t *task, void *data);
nxt_int_t nxt_app_start(nxt_task_t *task, void *data);


extern const nxt_sig_event_t  nxt_main_process_signals[];
extern const nxt_sig_event_t  nxt_worker_process_signals[];


#endif /* _NXT_MAIN_PROCESS_H_INCLUDED_ */

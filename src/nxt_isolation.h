/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_ISOLATION_H_INCLUDED_
#define _NXT_ISOLATION_H_INCLUDED_


nxt_int_t nxt_isolation_main_prefork(nxt_task_t *task, nxt_process_t *process,
    nxt_mp_t *mp);

#if (NXT_HAVE_ISOLATION_ROOTFS)
nxt_int_t nxt_isolation_prepare_rootfs(nxt_task_t *task,
    nxt_process_t *process);
nxt_int_t nxt_isolation_change_root(nxt_task_t *task, nxt_process_t *process);
#endif

#endif /* _NXT_ISOLATION_H_INCLUDED_ */

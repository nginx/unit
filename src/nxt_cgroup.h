/*
 * Copyright (C) Andrew Clayton
 * Copyright (C) F5, Inc.
 */

#ifndef _NXT_CGROUP_H_INCLUDED_
#define _NXT_CGROUP_H_INCLUDED_


nxt_int_t nxt_cgroup_proc_add(nxt_task_t *task, nxt_process_t *process);
void nxt_cgroup_cleanup(nxt_task_t *task, const nxt_process_t *process);


#endif /* _NXT_CGROUP_H_INCLUDED_ */

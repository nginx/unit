/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_CLONE_INCLUDED_
#define _NXT_CLONE_INCLUDED_


pid_t nxt_clone(nxt_int_t flags);

#if (NXT_HAVE_CLONE_NEWUSER)
nxt_int_t nxt_clone_proc_map(nxt_task_t *task, pid_t pid,
        nxt_process_clone_t *clone);
#endif

#endif /* _NXT_CLONE_INCLUDED_ */

#ifndef _NXT_CLONE_INCLUDED_
#define _NXT_CLONE_INCLUDED_

#ifdef NXT_LINUX

#endif

/**
 * Limit values obtained from `man user_namespaces`
 */
#ifdef NXT_LINUX

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
#define NXT_CLONE_MAX_UID_LINES 340
#else
#define NXT_CLONE_MAX_UID_LINES 5
#endif

#else 
#define NXT_CLONE_MAX_UID_LINES 5
#endif

#if (NXT_HAVE_CLONE)
pid_t nxt_clone(nxt_int_t flags);
#endif

#if (NXT_HAVE_CLONE_NEWUSER)
nxt_int_t nxt_clone_proc_map(nxt_task_t *task, pid_t pid, 
        nxt_process_clone_t *clone);
#endif

#endif
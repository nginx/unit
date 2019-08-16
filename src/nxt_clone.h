#ifndef _NXT_CLONE_INCLUDED_
#define _NXT_CLONE_INCLUDED_

#if (NXT_HAVE_CLONE)
pid_t nxt_clone(nxt_int_t flags);
#endif

#if (NXT_HAVE_CLONE_NEWUSER)

nxt_int_t nxt_clone_proc_setgroups(nxt_task_t *task, 
        pid_t child_pid, const char *str);
nxt_int_t nxt_clone_proc_map(nxt_task_t *task, pid_t pid);
nxt_int_t nxt_clone_proc_map_set(nxt_task_t *task, const char *mapfile, 
        pid_t pid, char *mapinfo);

#endif

#endif
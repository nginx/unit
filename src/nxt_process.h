
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIX_PROCESS_H_INCLUDED_
#define _NXT_UNIX_PROCESS_H_INCLUDED_


typedef pid_t  nxt_pid_t;


#define                                                                       \
nxt_sched_yield()                                                             \
    sched_yield()


#define                                                                       \
nxt_process_id()                                                              \
    nxt_pid


/*
 * Solaris declares abort() as __NORETURN,
 * raise(SIGABRT) is mostly the same.
 */

#define                                                                       \
nxt_abort()                                                                   \
    (void) raise(SIGABRT)


typedef void (*nxt_process_start_t)(void *data);

NXT_EXPORT nxt_pid_t nxt_process_create(nxt_process_start_t start, void *data,
    const char *name);
NXT_EXPORT nxt_pid_t nxt_process_execute(char *name, char **argv, char **envp);
NXT_EXPORT nxt_int_t nxt_process_daemon(void);
NXT_EXPORT void nxt_nanosleep(nxt_nsec_t ns);

NXT_EXPORT void nxt_process_arguments(char **orig_argv, char ***orig_envp);


#if (NXT_HAVE_SETPROCTITLE)

#define                                                                       \
nxt_process_title(title)                                                      \
    setproctitle("%s", title)

#elif (NXT_LINUX || NXT_SOLARIS || NXT_MACOSX)

#define NXT_SETPROCTITLE_ARGV  1
NXT_EXPORT void nxt_process_title(const char *title);

#else

#define                                                                       \
nxt_process_title(title)

#endif


NXT_EXPORT extern nxt_pid_t  nxt_pid;
NXT_EXPORT extern nxt_pid_t  nxt_ppid;
NXT_EXPORT extern char       **nxt_process_argv;
NXT_EXPORT extern char       ***nxt_process_environ;


typedef uid_t                nxt_uid_t;
typedef gid_t                nxt_gid_t;


typedef struct {
    const char               *user;
    nxt_uid_t                uid;
    nxt_gid_t                base_gid;
    nxt_uint_t               ngroups;
    nxt_gid_t                *gids;
} nxt_user_cred_t;


NXT_EXPORT nxt_int_t nxt_user_cred_get(nxt_user_cred_t *uc, const char *group);
NXT_EXPORT nxt_int_t nxt_user_cred_set(nxt_user_cred_t *uc);


#endif /* _NXT_UNIX_PROCESS_H_INCLUDED_ */

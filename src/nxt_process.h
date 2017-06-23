
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PROCESS_H_INCLUDED_
#define _NXT_PROCESS_H_INCLUDED_


typedef enum {
    NXT_PROCESS_SINGLE = 0,
    NXT_PROCESS_MASTER,
    NXT_PROCESS_CONTROLLER,
    NXT_PROCESS_ROUTER,
    NXT_PROCESS_WORKER,
} nxt_process_type_t;


typedef pid_t            nxt_pid_t;
typedef uid_t            nxt_uid_t;
typedef gid_t            nxt_gid_t;


typedef struct {
    const char           *user;
    nxt_uid_t            uid;
    nxt_gid_t            base_gid;
    nxt_uint_t           ngroups;
    nxt_gid_t            *gids;
} nxt_user_cred_t;

typedef struct nxt_process_init_s  nxt_process_init_t;
typedef nxt_int_t (*nxt_process_star_t)(nxt_task_t *task, nxt_runtime_t *rt);


struct nxt_process_init_s {
    nxt_process_star_t     start;
    const char             *name;
    nxt_user_cred_t        *user_cred;

    nxt_port_t             *port;
    nxt_port_t             *master_port;
    nxt_port_handler_t     *port_handlers;
    const nxt_sig_event_t  *signals;

    nxt_process_type_t     type:8;   /* 3 bits */
};


typedef struct {
    nxt_mp_t            *mem_pool;

    nxt_pid_t           pid;
    nxt_queue_t         ports;      /* of nxt_port_t */
    nxt_port_id_t       last_port_id;

    nxt_process_init_t  *init;
    nxt_array_t         *incoming;  /* of nxt_mmap_t */
    nxt_array_t         *outgoing;  /* of nxt_mmap_t */
} nxt_process_t;


NXT_EXPORT nxt_pid_t nxt_process_create(nxt_task_t *task,
    nxt_process_t *process);
NXT_EXPORT nxt_pid_t nxt_process_execute(nxt_task_t *task, char *name,
    char **argv, char **envp);
NXT_EXPORT nxt_int_t nxt_process_daemon(nxt_task_t *task);
NXT_EXPORT void nxt_nanosleep(nxt_nsec_t ns);

NXT_EXPORT void nxt_process_arguments(nxt_task_t *task, char **orig_argv,
    char ***orig_envp);

NXT_EXPORT nxt_port_t * nxt_process_port_new(nxt_process_t *process);

#define nxt_process_port_remove(port)                                         \
    nxt_queue_remove(&port->link)

#define nxt_process_port_first(process)                                       \
    nxt_queue_link_data(nxt_queue_first(&process->ports), nxt_port_t, link)

#define nxt_process_port_add(process, port)                                   \
    nxt_queue_insert_tail(&process->ports, &port->link)

#define nxt_process_port_each(process, port)                                   \
    nxt_queue_each(port, &process->ports, nxt_port_t, link)

#define nxt_process_port_loop                                                 \
    nxt_queue_loop

#if (NXT_HAVE_SETPROCTITLE)

#define nxt_process_title(task, fmt, ...)                                     \
    setproctitle(fmt, __VA_ARGS__)

#elif (NXT_LINUX || NXT_SOLARIS || NXT_MACOSX)

#define NXT_SETPROCTITLE_ARGV  1
NXT_EXPORT void nxt_process_title(nxt_task_t *task, const char *fmt, ...);

#endif


#define nxt_sched_yield()                                                     \
    sched_yield()

/*
 * Solaris declares abort() as __NORETURN,
 * raise(SIGABRT) is mostly the same.
 */

#define nxt_abort()                                                           \
    (void) raise(SIGABRT)

NXT_EXPORT nxt_int_t nxt_user_cred_get(nxt_task_t *task, nxt_user_cred_t *uc,
    const char *group);
NXT_EXPORT nxt_int_t nxt_user_cred_set(nxt_task_t *task, nxt_user_cred_t *uc);

NXT_EXPORT extern nxt_pid_t  nxt_pid;
NXT_EXPORT extern nxt_pid_t  nxt_ppid;
NXT_EXPORT extern char       **nxt_process_argv;
NXT_EXPORT extern char       ***nxt_process_environ;


#endif /* _NXT_PROCESS_H_INCLUDED_ */


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PROCESS_H_INCLUDED_
#define _NXT_PROCESS_H_INCLUDED_

#if (NXT_HAVE_LINUX_NS)
#include <unistd.h>
#include <nxt_clone.h>
#endif


typedef pid_t            nxt_pid_t;


typedef struct nxt_common_app_conf_s nxt_common_app_conf_t;


typedef struct {
    nxt_runtime_t              *rt;
} nxt_discovery_init_t;


typedef struct {
    nxt_str_t                  conf;
#if (NXT_TLS)
    nxt_array_t                *certs;
#endif
#if (NXT_HAVE_NJS)
    nxt_array_t                *scripts;
#endif
} nxt_controller_init_t;


typedef union {
    void                       *discovery;
    nxt_controller_init_t      controller;
    void                       *router;
    nxt_common_app_conf_t      *app;
} nxt_process_data_t;


typedef enum {
    NXT_PROCESS_STATE_CREATING = 0,
    NXT_PROCESS_STATE_CREATED,
    NXT_PROCESS_STATE_READY,
} nxt_process_state_t;


typedef struct nxt_port_mmap_s  nxt_port_mmap_t;
typedef struct nxt_process_s    nxt_process_t;
typedef struct nxt_cgroup_s     nxt_cgroup_t;
typedef void (*nxt_isolation_cleanup_t)(nxt_task_t *task,
    nxt_process_t *process);
typedef void (*nxt_cgroup_cleanup_t)(nxt_task_t *task,
    const nxt_process_t *process);


typedef struct {
    nxt_thread_mutex_t  mutex;
    uint32_t            size;
    uint32_t            cap;
    nxt_port_mmap_t     *elts;
} nxt_port_mmaps_t;


typedef struct {
    uint8_t             language_deps;      /* 1-bit */
    uint8_t             tmpfs;              /* 1-bit */
    uint8_t             procfs;             /* 1-bit */
} nxt_process_automount_t;


struct nxt_cgroup_s {
    char  *path;
};


typedef struct {
    u_char                   *rootfs;
    nxt_process_automount_t  automount;
    nxt_array_t              *mounts;     /* of nxt_mount_t */

    nxt_isolation_cleanup_t  cleanup;

    nxt_cgroup_cleanup_t     cgroup_cleanup;
#if (NXT_HAVE_CGROUP)
    nxt_cgroup_t             cgroup;
#endif

#if (NXT_HAVE_LINUX_NS)
    nxt_clone_t              clone;
#endif

#if (NXT_HAVE_PR_SET_NO_NEW_PRIVS)
    uint8_t                  new_privs;   /* 1 bit */
#endif
} nxt_process_isolation_t;


struct nxt_process_s {
    nxt_pid_t                pid;
    nxt_queue_t              ports;      /* of nxt_port_t.link */
    nxt_process_state_t      state;
    nxt_bool_t               registered;
    nxt_int_t                use_count;

    nxt_port_mmaps_t         incoming;


    nxt_pid_t                isolated_pid;
    const char               *name;
    nxt_port_t               *parent_port;

    uint32_t                 stream;

    nxt_mp_t                 *mem_pool;
    nxt_credential_t         *user_cred;

    nxt_queue_t              children;   /* of nxt_process_t.link */
    nxt_queue_link_t         link;       /* for nxt_process_t.children */

    nxt_process_data_t       data;

    nxt_process_isolation_t  isolation;
};


typedef nxt_int_t (*nxt_process_prefork_t)(nxt_task_t *task,
    nxt_process_t *process, nxt_mp_t *mp);
typedef nxt_int_t (*nxt_process_postfork_t)(nxt_task_t *task,
    nxt_process_t *process, nxt_mp_t *mp);
typedef nxt_int_t (*nxt_process_setup_t)(nxt_task_t *task,
    nxt_process_t *process);
typedef nxt_int_t (*nxt_process_start_t)(nxt_task_t *task,
    nxt_process_data_t *data);


typedef struct {
    const char                 *name;
    nxt_process_type_t         type;

    nxt_process_prefork_t      prefork;

    nxt_process_setup_t        setup;
    nxt_process_start_t        start;

    uint8_t                    restart; /* 1-bit */

    const nxt_port_handlers_t  *port_handlers;
    const nxt_sig_event_t      *signals;

    nxt_queue_t                *siblings;
} nxt_process_init_t;


extern uint8_t  nxt_proc_keep_matrix[NXT_PROCESS_MAX][NXT_PROCESS_MAX];
extern uint8_t  nxt_proc_send_matrix[NXT_PROCESS_MAX][NXT_PROCESS_MAX];
extern uint8_t  nxt_proc_remove_notify_matrix[NXT_PROCESS_MAX][NXT_PROCESS_MAX];

NXT_EXPORT nxt_pid_t nxt_process_execute(nxt_task_t *task, char *name,
    char **argv, char **envp);
NXT_EXPORT nxt_int_t nxt_process_daemon(nxt_task_t *task);
NXT_EXPORT void nxt_nanosleep(nxt_nsec_t ns);

NXT_EXPORT void nxt_process_arguments(nxt_task_t *task, char **orig_argv,
    char ***orig_envp);

#define nxt_process_init(process)                                             \
    (nxt_pointer_to(process, sizeof(nxt_process_t)))

#define nxt_process_port_remove(port)                                         \
    nxt_queue_remove(&port->link)

#define nxt_process_port_first(process)                                       \
    nxt_queue_link_data(nxt_queue_first(&process->ports), nxt_port_t, link)

NXT_EXPORT void nxt_process_port_add(nxt_task_t *task, nxt_process_t *process,
    nxt_port_t *port);

#define nxt_process_port_each(process, port)                                   \
    nxt_queue_each(port, &process->ports, nxt_port_t, link)

#define nxt_process_port_loop                                                 \
    nxt_queue_loop

nxt_process_t *nxt_process_new(nxt_runtime_t *rt);
void nxt_process_use(nxt_task_t *task, nxt_process_t *process, int i);
nxt_int_t nxt_process_init_start(nxt_task_t *task, nxt_process_init_t init);
nxt_int_t nxt_process_start(nxt_task_t *task, nxt_process_t *process);
nxt_process_type_t nxt_process_type(nxt_process_t *process);

void nxt_process_use(nxt_task_t *task, nxt_process_t *process, int i);

void nxt_process_close_ports(nxt_task_t *task, nxt_process_t *process);

void nxt_process_quit(nxt_task_t *task, nxt_uint_t exit_status);
void nxt_signal_quit_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);

nxt_int_t nxt_process_core_setup(nxt_task_t *task, nxt_process_t *process);
nxt_int_t nxt_process_creds_set(nxt_task_t *task, nxt_process_t *process,
    nxt_str_t *user, nxt_str_t *group);
nxt_int_t nxt_process_apply_creds(nxt_task_t *task, nxt_process_t *process);

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


NXT_EXPORT extern nxt_pid_t  nxt_pid;
NXT_EXPORT extern nxt_pid_t  nxt_ppid;
NXT_EXPORT extern nxt_uid_t  nxt_euid;
NXT_EXPORT extern nxt_gid_t  nxt_egid;
NXT_EXPORT extern char       **nxt_process_argv;
NXT_EXPORT extern char       ***nxt_process_environ;


#endif /* _NXT_PROCESS_H_INCLUDED_ */


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_RUNTIME_H_INCLUDED_
#define _NXT_RUNTIME_H_INCLUDED_


typedef void (*nxt_runtime_cont_t)(nxt_task_t *task, nxt_uint_t status);


struct nxt_runtime_s {
    nxt_mp_t               *mem_pool;

    nxt_array_t            *inherited_sockets;  /* of nxt_listen_socket_t */
    nxt_array_t            *listen_sockets;     /* of nxt_listen_socket_t */

    nxt_array_t            *services;           /* of nxt_service_t */
    nxt_array_t            *languages;          /* of nxt_app_lang_module_t */
    void                   *data;

    nxt_runtime_cont_t     start;

    nxt_str_t              hostname;

    nxt_file_name_t        *pid_file;

#if (NXT_TLS)
    const nxt_tls_lib_t    *tls;
#endif

    nxt_array_t            *thread_pools;       /* of nxt_thread_pool_t */
    nxt_runtime_cont_t     continuation;

    nxt_process_t          *mprocess;
    size_t                 nprocesses;
    nxt_thread_mutex_t     processes_mutex;
    nxt_lvlhsh_t           processes;           /* of nxt_process_t */

    nxt_port_t             *port_by_type[NXT_PROCESS_MAX];
    nxt_lvlhsh_t           ports;               /* of nxt_port_t */

    nxt_list_t             *log_files;          /* of nxt_file_t */

    uint32_t               last_engine_id;

    nxt_process_type_t     type;

    nxt_timer_t            timer;

    uint8_t                daemon;
    uint8_t                batch;
    uint8_t                status;

    const char             *engine;
    uint32_t               engine_connections;
    uint32_t               auxiliary_threads;
    nxt_user_cred_t        user_cred;
    const char             *group;
    const char             *pid;
    const char             *log;
    const char             *modules;
    const char             *state;
    const char             *conf;
    const char             *conf_tmp;
    const char             *control;

    nxt_str_t              certs;

    nxt_queue_t            engines;            /* of nxt_event_engine_t */

    nxt_sockaddr_t         *controller_listen;
    nxt_listen_socket_t    *controller_socket;
};



typedef nxt_int_t (*nxt_module_init_t)(nxt_thread_t *thr, nxt_runtime_t *rt);


nxt_int_t nxt_runtime_create(nxt_task_t *task);
void nxt_runtime_quit(nxt_task_t *task, nxt_uint_t status);

void nxt_runtime_event_engine_free(nxt_runtime_t *rt);

nxt_int_t nxt_runtime_thread_pool_create(nxt_thread_t *thr, nxt_runtime_t *rt,
    nxt_uint_t max_threads, nxt_nsec_t timeout);


nxt_process_t *nxt_runtime_process_new(nxt_runtime_t *rt);

nxt_process_t *nxt_runtime_process_get(nxt_runtime_t *rt, nxt_pid_t pid);

void nxt_runtime_process_add(nxt_task_t *task, nxt_process_t *process);

nxt_process_t *nxt_runtime_process_find(nxt_runtime_t *rt, nxt_pid_t pid);

void nxt_process_use(nxt_task_t *task, nxt_process_t *process, int i);

nxt_process_t *nxt_runtime_process_first(nxt_runtime_t *rt,
    nxt_lvlhsh_each_t *lhe);

#define nxt_runtime_process_next(rt, lhe)                                     \
    nxt_lvlhsh_each(&rt->processes, lhe)


void nxt_runtime_port_add(nxt_task_t *task, nxt_port_t *port);

void nxt_runtime_port_remove(nxt_task_t *task, nxt_port_t *port);

NXT_EXPORT nxt_port_t *nxt_runtime_port_find(nxt_runtime_t *rt, nxt_pid_t pid,
    nxt_port_id_t port_id);


/* STUB */
nxt_int_t nxt_runtime_controller_socket(nxt_task_t *task, nxt_runtime_t *rt);

nxt_str_t *nxt_current_directory(nxt_mp_t *mp);

nxt_listen_socket_t *nxt_runtime_listen_socket_add(nxt_runtime_t *rt,
    nxt_sockaddr_t *sa);
nxt_int_t nxt_runtime_listen_sockets_create(nxt_task_t *task,
    nxt_runtime_t *rt);
nxt_int_t nxt_runtime_listen_sockets_enable(nxt_task_t *task,
    nxt_runtime_t *rt);
nxt_file_t *nxt_runtime_log_file_add(nxt_runtime_t *rt, nxt_str_t *name);

/* STUB */
void nxt_cdecl nxt_log_time_handler(nxt_uint_t level, nxt_log_t *log,
    const char *fmt, ...);

void nxt_stream_connection_init(nxt_task_t *task, void *obj, void *data);


#define nxt_runtime_process_each(rt, process)                                 \
    do {                                                                      \
        nxt_lvlhsh_each_t  _lhe;                                              \
        nxt_process_t      *_nxt;                                             \
                                                                              \
        for (process = nxt_runtime_process_first(rt, &_lhe);                  \
             process != NULL;                                                 \
             process = _nxt) {                                                \
                                                                              \
            _nxt = nxt_runtime_process_next(rt, &_lhe);                       \

#define nxt_runtime_process_loop                                              \
        }                                                                     \
    } while(0)


extern nxt_module_init_t  nxt_init_modules[];
extern nxt_uint_t         nxt_init_modules_n;


#endif /* _NXT_RUNTIME_H_INCLIDED_ */

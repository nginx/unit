
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_CYCLE_H_INCLUDED_
#define _NXT_CYCLE_H_INCLUDED_


typedef enum {
    NXT_PROCESS_SINGLE = 0,
    NXT_PROCESS_MASTER,
    NXT_PROCESS_WORKER,
} nxt_process_type_e;


typedef struct nxt_cycle_s  nxt_cycle_t;
typedef void (*nxt_cycle_cont_t)(nxt_thread_t *thr, nxt_cycle_t *cycle);


struct nxt_cycle_s {
    nxt_mem_pool_t         *mem_pool;

    nxt_cycle_t            *previous;

    nxt_array_t            *inherited_sockets;  /* of nxt_listen_socket_t */
    nxt_array_t            *listen_sockets;     /* of nxt_listen_socket_t */

    nxt_array_t            *services;           /* of nxt_service_t */
    nxt_array_t            *engines;            /* of nxt_event_engine_t */

    nxt_cycle_cont_t       start;

    nxt_str_t              *config_name;

    nxt_str_t              *conf_prefix;
    nxt_str_t              *prefix;

    nxt_str_t              hostname;

    nxt_file_name_t        *pid_file;
    nxt_file_name_t        *oldbin_file;
    nxt_pid_t              new_binary;

#if (NXT_THREADS)
    nxt_array_t            *thread_pools;       /* of nxt_thread_pool_t */
    nxt_cycle_cont_t       continuation;
#endif

    nxt_array_t            *processes;          /* of nxt_process_chan_t */

    nxt_list_t             *log_files;          /* of nxt_file_t */

    nxt_array_t            *shm_zones;          /* of nxt_cycle_shm_zone_t */

    uint32_t               process_generation;
    uint32_t               current_process;
    uint32_t               last_engine_id;

    nxt_process_type_e     type;

    uint8_t                test_config;         /* 1 bit */
    uint8_t                reconfiguring;       /* 1 bit */

    void                   **core_ctx;

    nxt_event_timer_t      timer;

    uint8_t                daemon;
    uint8_t                batch;
    uint8_t                master_process;
    const char             *engine;
    uint32_t               engine_connections;
    uint32_t               worker_processes;
    uint32_t               auxiliary_threads;
    nxt_user_cred_t        user_cred;
    const char             *group;
    const char             *pid;
    const char             *error_log;
    nxt_sockaddr_t         *listen;
};


typedef struct {
    void                   *addr;
    size_t                 size;
    nxt_uint_t             page_size;
    nxt_str_t              name;
} nxt_cycle_shm_zone_t;



typedef nxt_int_t (*nxt_module_init_t)(nxt_thread_t *thr, nxt_cycle_t *cycle);


nxt_thread_extern_data(nxt_cycle_t *, nxt_thread_cycle_data);


nxt_inline void
nxt_thread_cycle_set(nxt_cycle_t *cycle)
{
    nxt_cycle_t  **p;

    p = nxt_thread_get_data(nxt_thread_cycle_data);

    *p = cycle;
}


nxt_inline nxt_cycle_t *
nxt_thread_cycle(void)
{
    nxt_cycle_t  **p;

    p = nxt_thread_get_data(nxt_thread_cycle_data);

    return *p;
}


nxt_int_t nxt_cycle_create(nxt_thread_t *thr, nxt_cycle_t *previous,
    nxt_cycle_cont_t start, nxt_str_t *config_name, nxt_bool_t test_config);
void nxt_cycle_quit(nxt_thread_t *thr, nxt_cycle_t *cycle);

void nxt_cycle_event_engine_free(nxt_cycle_t *cycle);

#if (NXT_THREADS)
nxt_int_t nxt_cycle_thread_pool_create(nxt_thread_t *thr, nxt_cycle_t *cycle,
    nxt_uint_t max_threads, nxt_nsec_t timeout);
#endif

/* STUB */
nxt_str_t *nxt_current_directory(nxt_mem_pool_t *mp);

nxt_int_t nxt_cycle_pid_file_create(nxt_file_name_t *pid_file, nxt_bool_t test);

nxt_listen_socket_t *nxt_cycle_listen_socket_add(nxt_cycle_t *cycle,
    nxt_sockaddr_t *sa);
nxt_int_t nxt_cycle_listen_sockets_enable(nxt_thread_t *thr,
    nxt_cycle_t *cycle);
nxt_file_t *nxt_cycle_log_file_add(nxt_cycle_t *cycle, nxt_str_t *name);

nxt_int_t nxt_cycle_shm_zone_add(nxt_cycle_t *cycle, nxt_str_t *name,
    size_t size, nxt_uint_t page_size);

/* STUB */
void nxt_cdecl nxt_log_time_handler(nxt_uint_t level, nxt_log_t *log,
    const char *fmt, ...);

nxt_int_t nxt_app_start(nxt_cycle_t *cycle);


extern nxt_module_init_t  nxt_init_modules[];
extern nxt_uint_t         nxt_init_modules_n;


#endif /* _NXT_CYCLE_H_INCLIDED_ */

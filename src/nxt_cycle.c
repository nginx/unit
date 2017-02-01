
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_cycle.h>
#include <nxt_process_chan.h>
#include <nxt_master_process.h>


static nxt_int_t nxt_cycle_inherited_listen_sockets(nxt_thread_t *thr,
    nxt_cycle_t *cycle);
static nxt_int_t nxt_cycle_systemd_listen_sockets(nxt_thread_t *thr,
    nxt_cycle_t *cycle);
static nxt_int_t nxt_cycle_event_engines(nxt_thread_t *thr, nxt_cycle_t *cycle);
static nxt_int_t nxt_cycle_processes(nxt_cycle_t *cycle);
static nxt_int_t nxt_cycle_thread_pools(nxt_thread_t *thr, nxt_cycle_t *cycle);
static void nxt_cycle_start(nxt_task_t *task, void *obj, void *data);
static void nxt_cycle_initial_start(nxt_task_t *task, nxt_cycle_t *cycle);
static void nxt_single_process_start(nxt_thread_t *thr, nxt_task_t *task,
    nxt_cycle_t *cycle);
static void nxt_cycle_close_idle_connections(nxt_thread_t *thr, nxt_task_t *task);
static void nxt_cycle_exit(nxt_task_t *task, void *obj, void *data);
static nxt_int_t nxt_cycle_event_engine_change(nxt_thread_t *thr,
    nxt_task_t *task, nxt_cycle_t *cycle);
static nxt_int_t nxt_cycle_conf_init(nxt_thread_t *thr, nxt_cycle_t *cycle);
static nxt_int_t nxt_cycle_conf_read_cmd(nxt_thread_t *thr, nxt_cycle_t *cycle);
static nxt_sockaddr_t *nxt_cycle_sockaddr_parse(nxt_str_t *addr,
    nxt_mem_pool_t *mp, nxt_log_t *log);
static nxt_sockaddr_t *nxt_cycle_sockaddr_unix_parse(nxt_str_t *addr,
    nxt_mem_pool_t *mp, nxt_log_t *log);
static nxt_sockaddr_t *nxt_cycle_sockaddr_inet6_parse(nxt_str_t *addr,
    nxt_mem_pool_t *mp, nxt_log_t *log);
static nxt_sockaddr_t *nxt_cycle_sockaddr_inet_parse(nxt_str_t *addr,
    nxt_mem_pool_t *mp, nxt_log_t *log);
static nxt_int_t nxt_cycle_conf_apply(nxt_thread_t *thr, nxt_task_t *task,
    nxt_cycle_t *cycle);
static nxt_int_t nxt_cycle_listen_socket(nxt_cycle_t *cycle);
static nxt_int_t nxt_cycle_hostname(nxt_thread_t *thr, nxt_cycle_t *cycle);
static nxt_int_t nxt_cycle_log_files_init(nxt_cycle_t *cycle);
static nxt_int_t nxt_cycle_log_files_create(nxt_cycle_t *cycle);
static nxt_int_t nxt_cycle_listen_sockets_create(nxt_cycle_t *cycle);
static void nxt_cycle_listen_sockets_close(nxt_cycle_t *cycle);
static void nxt_cycle_pid_file_delete(nxt_cycle_t *cycle);
static nxt_int_t nxt_cycle_shm_zones_enable(nxt_cycle_t *cycle);
static nxt_int_t nxt_cycle_shm_zone_create(nxt_cycle_shm_zone_t *shm_zone);

#if (NXT_THREADS)
static void nxt_cycle_thread_pool_destroy(nxt_thread_t *thr,
    nxt_task_t *task, nxt_cycle_t *cycle, nxt_cycle_cont_t cont);
#endif


nxt_thread_declare_data(nxt_cycle_t *, nxt_thread_cycle_data);


nxt_int_t
nxt_cycle_create(nxt_thread_t *thr, nxt_task_t *task, nxt_cycle_t *previous,
    nxt_cycle_cont_t start)
{
    nxt_int_t           ret;
    nxt_cycle_t         *cycle;
    nxt_array_t         *listen_sockets;
    nxt_mem_pool_t      *mp;
    static nxt_str_t    upstream_zone = nxt_string("upstream_zone");

    mp = nxt_mem_pool_create(1024);

    if (nxt_slow_path(mp == NULL)) {
        return NXT_ERROR;
    }

    /* This alloction cannot fail. */
    cycle = nxt_mem_zalloc(mp, sizeof(nxt_cycle_t));

    cycle->mem_pool = mp;
    cycle->previous = previous;

    if (previous == NULL) {
        cycle->prefix = nxt_current_directory(mp);

    } else {
        cycle->type = previous->type;
        cycle->prefix = nxt_str_dup(mp, NULL, previous->prefix);
    }

    if (nxt_slow_path(cycle->prefix == NULL)) {
        goto fail;
    }

    cycle->conf_prefix = cycle->prefix;

    cycle->services = nxt_services_init(mp);
    if (nxt_slow_path(cycle->services == NULL)) {
        goto fail;
    }

    listen_sockets = nxt_array_create(mp, 1, sizeof(nxt_listen_socket_t));
    if (nxt_slow_path(listen_sockets == NULL)) {
        goto fail;
    }

    cycle->listen_sockets = listen_sockets;

    if (previous == NULL) {
        ret = nxt_cycle_inherited_listen_sockets(thr, cycle);
        if (nxt_slow_path(ret != NXT_OK)) {
            goto fail;
        }
    }

    if (nxt_slow_path(nxt_cycle_hostname(thr, cycle) != NXT_OK)) {
        goto fail;
    }

    if (nxt_slow_path(nxt_cycle_log_files_init(cycle) != NXT_OK)) {
        goto fail;
    }

    if (nxt_slow_path(nxt_cycle_event_engines(thr, cycle) != NXT_OK)) {
        goto fail;
    }

    if (nxt_slow_path(nxt_cycle_processes(cycle) != NXT_OK)) {
        goto fail;
    }

    if (nxt_slow_path(nxt_cycle_thread_pools(thr, cycle) != NXT_OK)) {
        goto fail;
    }

    ret = nxt_cycle_shm_zone_add(cycle, &upstream_zone, 1024 * 1024, 8192);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    /* Cycle shm zones array is created on demand. */

    if (previous != NULL) {
        previous->reconfiguring = 1;
        cycle->start = start;

    } else {
        nxt_thread_init_data(nxt_thread_cycle_data);
        nxt_thread_cycle_set(cycle);

        cycle->start = nxt_cycle_initial_start;
    }

    nxt_log_debug(thr->log, "new cycle: %p", cycle);

    nxt_work_queue_add(&thr->engine->fast_work_queue, nxt_cycle_start,
                       task, cycle, NULL);

    return NXT_OK;

fail:

    nxt_mem_pool_destroy(mp);

    return NXT_ERROR;
}


static nxt_int_t
nxt_cycle_inherited_listen_sockets(nxt_thread_t *thr, nxt_cycle_t *cycle)
{
    u_char               *v, *p;
    nxt_int_t            type;
    nxt_array_t          *inherited_sockets;
    nxt_socket_t         s;
    nxt_listen_socket_t  *ls;

    v = (u_char *) getenv("NGINX");

    if (v == NULL) {
        return nxt_cycle_systemd_listen_sockets(thr, cycle);
    }

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "using inherited listen sockets: %s", v);

    inherited_sockets = nxt_array_create(cycle->mem_pool,
                                         1, sizeof(nxt_listen_socket_t));
    if (inherited_sockets == NULL) {
        return NXT_ERROR;
    }

    cycle->inherited_sockets = inherited_sockets;

    for (p = v; *p != '\0'; p++) {

        if (*p == ';') {
            s = nxt_int_parse(v, p - v);

            if (nxt_slow_path(s < 0)) {
                nxt_log_emerg(thr->log, "invalid socket number "
                              "\"%s\" in NGINX environment variable, "
                              "ignoring the rest of the variable", v);
                return NXT_ERROR;
            }

            v = p + 1;

            ls = nxt_array_zero_add(inherited_sockets);
            if (nxt_slow_path(ls == NULL)) {
                return NXT_ERROR;
            }

            ls->socket = s;

            ls->sockaddr = nxt_getsockname(cycle->mem_pool, s);
            if (nxt_slow_path(ls->sockaddr == NULL)) {
                return NXT_ERROR;
            }

            type = nxt_socket_getsockopt(s, SOL_SOCKET, SO_TYPE);
            if (nxt_slow_path(type == -1)) {
                return NXT_ERROR;
            }

            ls->sockaddr->type = (uint16_t) type;
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_cycle_systemd_listen_sockets(nxt_thread_t *thr, nxt_cycle_t *cycle)
{
    u_char               *nfd, *pid;
    nxt_int_t            n;
    nxt_array_t          *inherited_sockets;
    nxt_socket_t         s;
    nxt_listen_socket_t  *ls;

    /*
     * Number of listening sockets passed.  The socket
     * descriptors start from number 3 and are sequential.
     */
    nfd = (u_char *) getenv("LISTEN_FDS");
    if (nfd == NULL) {
        return NXT_OK;
    }

    /* The pid of the service process. */
    pid = (u_char *) getenv("LISTEN_PID");
    if (pid == NULL) {
        return NXT_OK;
    }

    n = nxt_int_parse(nfd, nxt_strlen(nfd));
    if (n < 0) {
        return NXT_OK;
    }

    if (nxt_pid != nxt_int_parse(pid, nxt_strlen(pid))) {
        return NXT_OK;
    }

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "using %s systemd listen sockets", n);

    inherited_sockets = nxt_array_create(cycle->mem_pool,
                                         n, sizeof(nxt_listen_socket_t));
    if (inherited_sockets == NULL) {
        return NXT_ERROR;
    }

    cycle->inherited_sockets = inherited_sockets;

    for (s = 3; s < n; s++) {
        ls = nxt_array_zero_add(inherited_sockets);
        if (nxt_slow_path(ls == NULL)) {
            return NXT_ERROR;
        }

        ls->socket = s;

        ls->sockaddr = nxt_getsockname(cycle->mem_pool, s);
        if (nxt_slow_path(ls->sockaddr == NULL)) {
            return NXT_ERROR;
        }

        ls->sockaddr->type = SOCK_STREAM;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_cycle_event_engines(nxt_thread_t *thr, nxt_cycle_t *cycle)
{
    nxt_event_engine_t         *engine, **e, **engines;
    const nxt_event_set_ops_t  *event_set;

    cycle->engines = nxt_array_create(cycle->mem_pool, 1,
                                      sizeof(nxt_event_engine_t *));

    if (nxt_slow_path(cycle->engines == NULL)) {
        return NXT_ERROR;
    }

    e = nxt_array_add(cycle->engines);
    if (nxt_slow_path(e == NULL)) {
        return NXT_ERROR;
    }

    if (cycle->previous != NULL) {
        /* Event engines are not allocated in memory pool. */
        engines = cycle->previous->engines->elts;
        *e = engines[0];

    } else {
        event_set = nxt_service_get(cycle->services, "engine", NULL);

        if (nxt_slow_path(event_set == NULL)) {
            /* TODO: log */
            return NXT_ERROR;
        }

        engine = nxt_event_engine_create(thr, event_set,
                                         nxt_master_process_signals, 0, 0);

        if (nxt_slow_path(engine == NULL)) {
            return NXT_ERROR;
        }

        engine->id = cycle->last_engine_id++;
        *e = engine;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_cycle_processes(nxt_cycle_t *cycle)
{
    nxt_uint_t          n;
    nxt_process_chan_t  *proc, *prev;

    /*
     * Preallocate double number of previous cycle
     * process slots or 2 process slots for initial cycle.
     */
    n = (cycle->previous != NULL) ? cycle->previous->processes->nelts : 1;

    cycle->processes = nxt_array_create(cycle->mem_pool, 2 * n,
                                        sizeof(nxt_process_chan_t));

    if (nxt_slow_path(cycle->processes == NULL)) {
        return NXT_ERROR;
    }

    if (cycle->previous != NULL) {
        cycle->process_generation = cycle->previous->process_generation;

        prev = cycle->previous->processes->elts;

        while (n != 0) {
            proc = nxt_array_add(cycle->processes);
            if (nxt_slow_path(proc == NULL)) {
                return NXT_ERROR;
            }

            *proc = *prev++;
            n--;
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_cycle_thread_pools(nxt_thread_t *thr, nxt_cycle_t *cycle)
{
#if (NXT_THREADS)
    nxt_int_t    ret;
    nxt_array_t  *thread_pools;

    thread_pools = nxt_array_create(cycle->mem_pool, 1,
                                    sizeof(nxt_thread_pool_t *));

    if (nxt_slow_path(thread_pools == NULL)) {
        return NXT_ERROR;
    }

    cycle->thread_pools = thread_pools;

    ret = nxt_cycle_thread_pool_create(thr, cycle, 2, 60000 * 1000000LL);

    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

#endif

    return NXT_OK;
}


static void
nxt_cycle_start(nxt_task_t *task, void *obj, void *data)
{
    nxt_uint_t   i;
    nxt_cycle_t  *cycle;

    cycle = obj;

    nxt_debug(task, "cycle conf done");

    nxt_mem_pool_debug_lock(cycle->mem_pool, nxt_thread_tid(task->thread));

    task->thread->log->ctx_handler = NULL;
    task->thread->log->ctx = NULL;

    if (nxt_cycle_conf_init(task->thread, cycle) != NXT_OK) {
        goto fail;
    }

    for (i = 0; i < nxt_init_modules_n; i++) {
        if (nxt_init_modules[i](task->thread, cycle) != NXT_OK) {
            goto fail;
        }
    }

    if (nxt_cycle_conf_apply(task->thread, task, cycle) != NXT_OK) {
        goto fail;
    }

    nxt_thread_cycle_set(cycle);

#if (NXT_THREADS)

    /*
     * Thread pools should be destroyed before starting worker
     * processes, because thread pool semaphores will stick in
     * locked state in new processes after fork().
     */
    nxt_cycle_thread_pool_destroy(task->thread, task, cycle, cycle->start);

#else

    cycle->start(task->thread, cycle);

#endif

    return;

fail:

    nxt_cycle_quit(task, cycle);
}


static void
nxt_cycle_initial_start(nxt_task_t *task, nxt_cycle_t *cycle)
{
    nxt_int_t                  ret;
    nxt_thread_t               *thr;
    const nxt_event_set_ops_t  *event_set;

    thr = task->thread;

    if (cycle->inherited_sockets == NULL && cycle->daemon) {

        if (nxt_process_daemon() != NXT_OK) {
            goto fail;
        }

        /*
         * An event engine should be updated after fork()
         * even if an event facility was not changed because:
         * 1) inherited kqueue descriptor is invalid,
         * 2) the signal thread is not inherited.
         */
        event_set = nxt_service_get(cycle->services, "engine", cycle->engine);
        if (event_set == NULL) {
            goto fail;
        }

        ret = nxt_event_engine_change(thr, task, event_set, cycle->batch);
        if (ret != NXT_OK) {
            goto fail;
        }
    }

    ret = nxt_cycle_pid_file_create(cycle->pid_file, cycle->test_config);
    if (ret != NXT_OK) {
        goto fail;
    }

    if (nxt_cycle_event_engine_change(thr, task, cycle) != NXT_OK) {
        goto fail;
    }

    thr->engine->max_connections = cycle->engine_connections;

    if (cycle->master_process) {
        if (nxt_master_process_start(thr, task, cycle) != NXT_ERROR) {
            return;
        }

    } else {
        nxt_single_process_start(thr, task, cycle);
        return;
    }

fail:

    nxt_cycle_quit(task, cycle);
}


static void
nxt_single_process_start(nxt_thread_t *thr, nxt_task_t *task,
    nxt_cycle_t *cycle)
{
#if (NXT_THREADS)
    nxt_int_t  ret;

    ret = nxt_cycle_thread_pool_create(thr, cycle, cycle->auxiliary_threads,
                                       60000 * 1000000LL);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_cycle_quit(task, cycle);
        return;
    }

#endif

    cycle->type = NXT_PROCESS_SINGLE;

    nxt_cycle_listen_sockets_enable(task, cycle);

    return;
}


void
nxt_cycle_quit(nxt_task_t *task, nxt_cycle_t *cycle)
{
    nxt_bool_t    done;
    nxt_thread_t  *thr;

    thr = task->thread;

    nxt_debug(task, "exiting");

    if (cycle == NULL) {
        cycle = nxt_thread_cycle();
    }

    done = 1;

    if (!thr->engine->shutdown) {
        thr->engine->shutdown = 1;

#if (NXT_THREADS)

        if (!nxt_array_is_empty(cycle->thread_pools)) {
            nxt_cycle_thread_pool_destroy(thr, task, cycle, nxt_cycle_quit);
            done = 0;
        }

#endif

        if (!cycle->test_config && cycle->type == NXT_PROCESS_MASTER) {
            nxt_master_stop_worker_processes(task, cycle);
            done = 0;
        }
    }

    nxt_cycle_close_idle_connections(thr, task);

    if (done) {
        nxt_work_queue_add(&thr->engine->fast_work_queue, nxt_cycle_exit,
                           task, cycle, NULL);
    }
}


static void
nxt_cycle_close_idle_connections(nxt_thread_t *thr, nxt_task_t *task)
{
    nxt_queue_t       *idle;
    nxt_queue_link_t  *link, *next;
    nxt_event_conn_t  *c;

    nxt_log_debug(thr->log, "close idle connections");

    idle = &thr->engine->idle_connections;

    for (link = nxt_queue_head(idle);
         link != nxt_queue_tail(idle);
         link = next)
    {
        next = nxt_queue_next(link);
        c = nxt_queue_link_data(link, nxt_event_conn_t, link);

        if (!c->socket.read_ready) {
            nxt_queue_remove(link);
            nxt_event_conn_close(task, c);
        }
    }
}


static void
nxt_cycle_exit(nxt_task_t *task, void *obj, void *data)
{
    nxt_cycle_t  *cycle;

    cycle = obj;

#if (NXT_THREADS)

    nxt_debug(task, "thread pools: %d", cycle->thread_pools->nelts);

    if (!nxt_array_is_empty(cycle->thread_pools)) {
        return;
    }

#endif

    if (cycle->type <= NXT_PROCESS_MASTER) {
        nxt_cycle_pid_file_delete(cycle);
    }

    if (!task->thread->engine->event->signal_support) {
        nxt_event_engine_signals_stop(task->thread->engine);
    }

    nxt_debug(task, "exit");

    exit(0);
    nxt_unreachable();
}


static nxt_int_t
nxt_cycle_event_engine_change(nxt_thread_t *thr, nxt_task_t *task,
    nxt_cycle_t *cycle)
{
    const nxt_event_set_ops_t  *event_set;

    if (thr->engine->batch == cycle->batch
        && nxt_strcmp(thr->engine->event->name, cycle->engine) == 0)
    {
        return NXT_OK;
    }

    event_set = nxt_service_get(cycle->services, "engine", cycle->engine);
    if (event_set != NULL) {
        return nxt_event_engine_change(thr, task, event_set, cycle->batch);
    }

    return NXT_ERROR;
}


void
nxt_cycle_event_engine_free(nxt_cycle_t *cycle)
{
    nxt_event_engine_t      *engine, **engines;

    engines = cycle->engines->elts;
    engine = engines[0];
    nxt_array_remove(cycle->engines, &engines[0]);

    nxt_event_engine_free(engine);
}


#if (NXT_THREADS)

static void nxt_cycle_thread_pool_init(void);
static void nxt_cycle_thread_pool_exit(nxt_task_t *task, void *obj, void *data);


nxt_int_t
nxt_cycle_thread_pool_create(nxt_thread_t *thr, nxt_cycle_t *cycle,
    nxt_uint_t max_threads, nxt_nsec_t timeout)
{
    nxt_thread_pool_t   *thread_pool, **tp;

    tp = nxt_array_add(cycle->thread_pools);
    if (tp == NULL) {
        return NXT_ERROR;
    }

    thread_pool = nxt_thread_pool_create(max_threads, timeout,
                                         nxt_cycle_thread_pool_init,
                                         thr->engine,
                                         nxt_cycle_thread_pool_exit);

    if (nxt_fast_path(thread_pool != NULL)) {
        *tp = thread_pool;
    }

    return NXT_OK;
}


static void
nxt_cycle_thread_pool_destroy(nxt_thread_t *thr, nxt_task_t *task,
    nxt_cycle_t *cycle, nxt_cycle_cont_t cont)
{
    nxt_uint_t         n;
    nxt_thread_pool_t  **tp;

    cycle->continuation = cont;

    n = cycle->thread_pools->nelts;

    if (n == 0) {
        cont(task, cycle);
        return;
    }

    tp = cycle->thread_pools->elts;

    do {
        nxt_thread_pool_destroy(*tp);

        tp++;
        n--;
    } while (n != 0);
}


static void
nxt_cycle_thread_pool_init(void)
{
#if (NXT_REGEX)
    nxt_regex_init(0);
#endif
}


static void
nxt_cycle_thread_pool_exit(nxt_task_t *task, void *obj, void *data)
{
    nxt_uint_t           i, n;
    nxt_cycle_t          *cycle;
    nxt_thread_pool_t    *tp, **thread_pools;
    nxt_thread_handle_t  handle;

    tp = obj;

    if (data != NULL) {
        handle = (nxt_thread_handle_t) (uintptr_t) data;
        nxt_thread_wait(handle);
    }

    cycle = nxt_thread_cycle();

    thread_pools = cycle->thread_pools->elts;
    n = cycle->thread_pools->nelts;

    nxt_debug(task, "thread pools: %ui, cycle %p", n, cycle);

    for (i = 0; i < n; i++) {

        if (tp == thread_pools[i]) {
            nxt_array_remove(cycle->thread_pools, &thread_pools[i]);

            if (n == 1) {
                /* The last thread pool. */
                cycle->continuation(task, cycle);
            }

            return;
        }
    }
}

#endif


static nxt_int_t
nxt_cycle_conf_init(nxt_thread_t *thr, nxt_cycle_t *cycle)
{
    nxt_int_t                  ret;
    nxt_str_t                  *prefix;
    nxt_file_t                 *file;
    nxt_file_name_str_t        file_name;
    const nxt_event_set_ops_t  *event_set;

    cycle->daemon = 1;
    cycle->master_process = 1;
    cycle->engine_connections = 256;
    cycle->worker_processes = 1;
    cycle->auxiliary_threads = 2;
    cycle->user_cred.user = "nobody";
    cycle->group = NULL;
    cycle->pid = "nginext.pid";
    cycle->error_log = "error.log";

    if (nxt_cycle_conf_read_cmd(thr, cycle) != NXT_OK) {
        return NXT_ERROR;
    }

    if (nxt_user_cred_get(&cycle->user_cred, cycle->group) != NXT_OK) {
        return NXT_ERROR;
    }

    /* An engine's parameters. */

    event_set = nxt_service_get(cycle->services, "engine", cycle->engine);
    if (event_set == NULL) {
        return NXT_ERROR;
    }

    cycle->engine = event_set->name;

    prefix = nxt_file_name_is_absolute(cycle->pid) ? NULL : cycle->prefix;

    ret = nxt_file_name_create(cycle->mem_pool, &file_name, "%V%s%Z",
                               prefix, cycle->pid);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    cycle->pid_file = file_name.start;

    prefix = nxt_file_name_is_absolute(cycle->error_log) ? NULL : cycle->prefix;

    ret = nxt_file_name_create(cycle->mem_pool, &file_name, "%V%s%Z",
                               prefix, cycle->error_log);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    file = nxt_list_first(cycle->log_files);
    file->name = file_name.start;

    return NXT_OK;
}


static nxt_int_t
nxt_cycle_conf_read_cmd(nxt_thread_t *thr, nxt_cycle_t *cycle)
{
    char            *p, **argv;
    nxt_int_t       n;
    nxt_str_t       addr;
    nxt_sockaddr_t  *sa;

    argv = nxt_process_argv;

    while (*argv != NULL) {
        p = *argv++;

        if (nxt_strcmp(p, "--listen") == 0) {
            if (*argv == NULL) {
                nxt_log_emerg(thr->log, "no argument for option \"--listen\"");
                return NXT_ERROR;
            }

            p = *argv++;

            addr.length = nxt_strlen(p);
            addr.start = (u_char *) p;

            sa = nxt_cycle_sockaddr_parse(&addr, cycle->mem_pool, thr->log);

            if (sa == NULL) {
                return NXT_ERROR;
            }

            cycle->listen = sa;

            continue;
        }

        if (nxt_strcmp(p, "--workers") == 0) {
            if (*argv == NULL) {
                nxt_log_emerg(thr->log, "no argument for option \"--workers\"");
                return NXT_ERROR;
            }

            p = *argv++;
            n = nxt_int_parse((u_char *) p, nxt_strlen(p));

            if (n < 1) {
                nxt_log_emerg(thr->log, "invalid number of workers: \"%s\"", p);
                return NXT_ERROR;
            }

            cycle->worker_processes = n;

            continue;
        }

        if (nxt_strcmp(p, "--user") == 0) {
            if (*argv == NULL) {
                nxt_log_emerg(thr->log, "no argument for option \"--user\"");
                return NXT_ERROR;
            }

            p = *argv++;

            cycle->user_cred.user = p;

            continue;
        }

        if (nxt_strcmp(p, "--group") == 0) {
            if (*argv == NULL) {
                nxt_log_emerg(thr->log, "no argument for option \"--group\"");
                return NXT_ERROR;
            }

            p = *argv++;

            cycle->group = p;

            continue;
        }

        if (nxt_strcmp(p, "--pid") == 0) {
            if (*argv == NULL) {
                nxt_log_emerg(thr->log, "no argument for option \"--pid\"");
                return NXT_ERROR;
            }

            p = *argv++;

            cycle->pid = p;

            continue;
        }

        if (nxt_strcmp(p, "--log") == 0) {
            if (*argv == NULL) {
                nxt_log_emerg(thr->log, "no argument for option \"--log\"");
                return NXT_ERROR;
            }

            p = *argv++;

            cycle->error_log = p;

            continue;
        }

        if (nxt_strcmp(p, "--no-daemonize") == 0) {
            cycle->daemon = 0;
            continue;
        }
    }

    return NXT_OK;
}


static nxt_sockaddr_t *
nxt_cycle_sockaddr_parse(nxt_str_t *addr, nxt_mem_pool_t *mp, nxt_log_t *log)
{
    u_char  *p;
    size_t  length;

    length = addr->length;
    p = addr->start;

    if (length >= 5 && nxt_memcmp(p, (u_char *) "unix:", 5) == 0) {
        return nxt_cycle_sockaddr_unix_parse(addr, mp, log);
    }

    if (length != 0 && *p == '[') {
        return nxt_cycle_sockaddr_inet6_parse(addr, mp, log);
    }

    return nxt_cycle_sockaddr_inet_parse(addr, mp, log);
}


static nxt_sockaddr_t *
nxt_cycle_sockaddr_unix_parse(nxt_str_t *addr, nxt_mem_pool_t *mp,
    nxt_log_t *log)
{
#if (NXT_HAVE_UNIX_DOMAIN)
    u_char          *p;
    size_t          length, socklen;
    nxt_sockaddr_t  *sa;

    /*
     * Actual sockaddr_un length can be lesser or even larger than defined
     * struct sockaddr_un length (see comment in unix/nxt_socket.h).  So
     * limit maximum Unix domain socket address length by defined sun_path[]
     * length because some OSes accept addresses twice larger than defined
     * struct sockaddr_un.  Also reserve space for a trailing zero to avoid
     * ambiguity, since many OSes accept Unix domain socket addresses
     * without a trailing zero.
     */
    const size_t max_len = sizeof(struct sockaddr_un)
                           - offsetof(struct sockaddr_un, sun_path) - 1;

    /* cutting "unix:" */
    length = addr->length - 5;
    p = addr->start + 5;

    if (length == 0) {
        nxt_log_emerg(log, "unix domain socket \"%V\" name is invalid", addr);
        return NULL;
    }

    if (length > max_len) {
        nxt_log_emerg(log, "unix domain socket \"%V\" name is too long", addr);
        return NULL;
    }

    socklen = offsetof(struct sockaddr_un, sun_path) + length + 1;

#if (NXT_LINUX)

    /*
     * Linux unix(7):
     *
     *   abstract: an abstract socket address is distinguished by the fact
     *   that sun_path[0] is a null byte ('\0').  The socket's address in
     *   this namespace is given by the additional bytes in sun_path that
     *   are covered by the specified length of the address structure.
     *   (Null bytes in the name have no special significance.)
     */
    if (p[0] == '@') {
        p[0] = '\0';
        socklen--;
    }

#endif

    sa = nxt_sockaddr_alloc(mp, socklen);

    if (nxt_slow_path(sa == NULL)) {
        return NULL;
    }

    sa->type = SOCK_STREAM;

    sa->u.sockaddr_un.sun_family = AF_UNIX;
    nxt_memcpy(sa->u.sockaddr_un.sun_path, p, length);

    return sa;

#else  /* !(NXT_HAVE_UNIX_DOMAIN) */

    nxt_log_emerg(log, "unix domain socket \"%V\" is not supported", addr);

    return NULL;

#endif
}


static nxt_sockaddr_t *
nxt_cycle_sockaddr_inet6_parse(nxt_str_t *addr, nxt_mem_pool_t *mp,
    nxt_log_t *log)
{
#if (NXT_INET6)
    u_char           *p, *addr, *addr_end;
    size_t           length;
    nxt_int_t        port;
    nxt_mem_pool_t   *mp;
    nxt_sockaddr_t   *sa;
    struct in6_addr  *in6_addr;

    length = addr->length - 1;
    p = addr->start + 1;

    addr_end = nxt_memchr(p, ']', length);

    if (addr_end == NULL) {
        goto invalid_address;
    }

    sa = nxt_sockaddr_alloc(mp, sizeof(struct sockaddr_in6));

    if (nxt_slow_path(sa == NULL)) {
        return NULL;
    }

    in6_addr = &sa->u.sockaddr_in6.sin6_addr;

    if (nxt_inet6_addr(in6_addr, p, addr_end - p) != NXT_OK) {
        goto invalid_address;
    }

    p = addr_end + 1;
    length = (p + length) - p;

    if (length == 0) {
        goto found;
    }

    if (*p == ':') {
        port = nxt_int_parse(p + 1, length - 1);

        if (port >= 1 && port <= 65535) {
            goto found;
        }
    }

    nxt_log_emerg(log, "invalid port in \"%V\"", addr);

    return NULL;

found:

    sa->type = SOCK_STREAM;

    sa->u.sockaddr_in6.sin6_family = AF_INET6;
    sa->u.sockaddr_in6.sin6_port = htons((in_port_t) port);

    return sa;

invalid_address:

    nxt_log_emerg(log, "invalid IPv6 address in \"%V\"", addr);

    return NULL;

#else

    nxt_log_emerg(log, "IPv6 socket \"%V\" is not supported", addr);

    return NULL;

#endif
}


static nxt_sockaddr_t *
nxt_cycle_sockaddr_inet_parse(nxt_str_t *addr, nxt_mem_pool_t *mp,
    nxt_log_t *log)
{
    u_char          *p, *ip;
    size_t          length;
    in_addr_t       s_addr;
    nxt_int_t       port;
    nxt_sockaddr_t  *sa;

    s_addr = INADDR_ANY;

    length = addr->length;
    ip = addr->start;

    p = nxt_memchr(ip, ':', length);

    if (p == NULL) {

        /* single value port, or address */

        port = nxt_int_parse(ip, length);

        if (port > 0) {
            /* "*:XX" */

            if (port < 1 || port > 65535) {
                goto invalid_port;
            }

        } else {
            /* "x.x.x.x" */

            s_addr = nxt_inet_addr(ip, length);

            if (s_addr == INADDR_NONE) {
                goto invalid_port;
            }

            port = 8080;
        }

    } else {

        /* x.x.x.x:XX */

        p++;
        length = (ip + length) - p;
        port = nxt_int_parse(p, length);

        if (port < 1 || port > 65535) {
            goto invalid_port;
        }

        length = (p - 1) - ip;

        if (length != 1 || ip[0] != '*') {
            s_addr = nxt_inet_addr(ip, length);

            if (s_addr == INADDR_NONE) {
                goto invalid_addr;
            }

            /* "x.x.x.x:XX" */
        }
    }

    sa = nxt_sockaddr_alloc(mp, sizeof(struct sockaddr_in));

    if (nxt_slow_path(sa == NULL)) {
        return NULL;
    }

    sa->type = SOCK_STREAM;

    sa->u.sockaddr_in.sin_family = AF_INET;
    sa->u.sockaddr_in.sin_port = htons((in_port_t) port);
    sa->u.sockaddr_in.sin_addr.s_addr = s_addr;

    return sa;

invalid_port:

    nxt_log_emerg(log, "invalid port in \"%V\"", addr);

    return NULL;

invalid_addr:

    nxt_log_emerg(log, "invalid address in \"%V\"", addr);

    return NULL;
}


static nxt_int_t
nxt_cycle_conf_apply(nxt_thread_t *thr, nxt_task_t *task, nxt_cycle_t *cycle)
{
    if (nxt_cycle_log_files_create(cycle) != NXT_OK) {
        return NXT_ERROR;
    }

    if (nxt_cycle_listen_socket(cycle) != NXT_OK) {
        return NXT_ERROR;
    }

    if (nxt_cycle_event_engine_change(thr, task, cycle) != NXT_OK) {
        return NXT_ERROR;
    }

    if (nxt_cycle_listen_sockets_create(cycle) != NXT_OK) {
        return NXT_ERROR;
    }

    if (nxt_cycle_shm_zones_enable(cycle) != NXT_OK) {
        return NXT_ERROR;
    }

    nxt_cycle_listen_sockets_close(cycle);

    return NXT_OK;
}


static nxt_int_t
nxt_cycle_listen_socket(nxt_cycle_t *cycle)
{
    nxt_sockaddr_t       *sa;
//    nxt_work_queue_t     *wq;
    nxt_listen_socket_t  *ls;

    if (cycle->listen == NULL) {
        sa = nxt_sockaddr_alloc(cycle->mem_pool, sizeof(struct sockaddr_in));
        if (sa == NULL) {
            return NXT_ERROR;
        }

        sa->type = SOCK_STREAM;
        sa->u.sockaddr_in.sin_family = AF_INET;
        sa->u.sockaddr_in.sin_port = htons(8080);

        cycle->listen = sa;
    }

    if (nxt_sockaddr_text(cycle->mem_pool, cycle->listen, 1) != NXT_OK) {
        return NXT_ERROR;
    }

    ls = nxt_cycle_listen_socket_add(cycle, cycle->listen);
    if (ls == NULL) {
        return NXT_ERROR;
    }

    ls->read_after_accept = 1;

#if 0
    ls->flags = NXT_NONBLOCK;

    /* STUB */
    wq = nxt_mem_zalloc(cf->mem_pool, sizeof(nxt_work_queue_t));
    if (wq == NULL) {
        return NXT_ERROR;
    }
    nxt_work_queue_name(wq, "listen");
    /**/

    ls->work_queue = wq;
    ls->handler = nxt_stream_connection_init;

    /*
     * Connection memory pool chunk size is tunned to
     * allocate the most data in one mem_pool chunk.
     */
    ls->mem_pool_size = nxt_listen_socket_pool_min_size(ls)
                        + sizeof(nxt_event_conn_proxy_t)
                        + sizeof(nxt_event_conn_t)
                        + 4 * sizeof(nxt_buf_t);
#endif

    return NXT_OK;
}


nxt_listen_socket_t *
nxt_cycle_listen_socket_add(nxt_cycle_t *cycle, nxt_sockaddr_t *sa)
{
    nxt_mem_pool_t       *mp;
    nxt_listen_socket_t  *ls;

    ls = nxt_array_zero_add(cycle->listen_sockets);
    if (ls == NULL) {
        return NULL;
    }

    mp = cycle->mem_pool;

    ls->sockaddr = nxt_sockaddr_create(mp, &sa->u.sockaddr, nxt_socklen(sa));
    if (ls->sockaddr == NULL) {
        return NULL;
    }

    ls->sockaddr->type = sa->type;

    if (nxt_sockaddr_text(mp, ls->sockaddr, 1) != NXT_OK) {
        return NULL;
    }

    ls->socket = -1;
    ls->backlog = NXT_LISTEN_BACKLOG;

    return ls;
}


static nxt_int_t
nxt_cycle_hostname(nxt_thread_t *thr, nxt_cycle_t *cycle)
{
    size_t  length;
    char    hostname[NXT_MAXHOSTNAMELEN + 1];

    if (gethostname(hostname, NXT_MAXHOSTNAMELEN) != 0) {
        nxt_log_emerg(thr->log, "gethostname() failed %E", nxt_errno);
        return NXT_ERROR;
    }

    /*
     * Linux gethostname(2):
     *
     *    If the null-terminated hostname is too large to fit,
     *    then the name is truncated, and no error is returned.
     *
     * For this reason an additional byte is reserved in the buffer.
     */
    hostname[NXT_MAXHOSTNAMELEN] = '\0';

    length = nxt_strlen(hostname);
    cycle->hostname.length = length;

    cycle->hostname.start = nxt_mem_nalloc(cycle->mem_pool, length);

    if (cycle->hostname.start != NULL) {
        nxt_memcpy_lowcase(cycle->hostname.start, (u_char *) hostname, length);
        return NXT_OK;
    }

    return NXT_ERROR;
}


static nxt_int_t
nxt_cycle_log_files_init(nxt_cycle_t *cycle)
{
    nxt_uint_t  n;
    nxt_file_t  *file;
    nxt_list_t  *log_files;

    n = (cycle->previous != NULL) ? nxt_list_nelts(cycle->previous->log_files):
                                    1;

    log_files = nxt_list_create(cycle->mem_pool, n, sizeof(nxt_file_t));

    if (nxt_fast_path(log_files != NULL)) {
        cycle->log_files = log_files;

        /* Preallocate the main error_log.  This allocation cannot fail. */
        file = nxt_list_zero_add(log_files);

        file->fd = NXT_FILE_INVALID;
        file->log_level = NXT_LOG_CRIT;

        return NXT_OK;
    }

    return NXT_ERROR;
}


nxt_file_t *
nxt_cycle_log_file_add(nxt_cycle_t *cycle, nxt_str_t *name)
{
    nxt_int_t            ret;
    nxt_str_t            *prefix;
    nxt_file_t           *file;
    nxt_file_name_str_t  file_name;

    prefix = nxt_file_name_is_absolute(name->start) ? NULL : cycle->prefix;

    ret = nxt_file_name_create(cycle->mem_pool, &file_name, "%V%V%Z",
                               prefix, name);

    if (nxt_slow_path(ret != NXT_OK)) {
        return NULL;
    }

    nxt_list_each(file, cycle->log_files) {

        /* STUB: hardecoded case sensitive/insensitive. */

        if (file->name != NULL
            && nxt_file_name_eq(file->name, file_name.start))
        {
            return file;
        }

    } nxt_list_loop;

    file = nxt_list_zero_add(cycle->log_files);

    if (nxt_slow_path(file == NULL)) {
        return NULL;
    }

    file->fd = NXT_FILE_INVALID;
    file->log_level = NXT_LOG_CRIT;
    file->name = file_name.start;

    return file;
}


static nxt_int_t
nxt_cycle_log_files_create(nxt_cycle_t *cycle)
{
    nxt_int_t   ret;
    nxt_file_t  *file;

    nxt_list_each(file, cycle->log_files) {

        ret = nxt_file_open(file, NXT_FILE_APPEND, NXT_FILE_CREATE_OR_OPEN,
                            NXT_FILE_OWNER_ACCESS);

        if (ret != NXT_OK) {
            return NXT_ERROR;
        }

    } nxt_list_loop;

    file = nxt_list_first(cycle->log_files);

    return nxt_file_stderr(file);
}


static nxt_int_t
nxt_cycle_listen_sockets_create(nxt_cycle_t *cycle)
{
    nxt_uint_t           c, p, ncurr, nprev;
    nxt_listen_socket_t  *curr, *prev;

    curr = cycle->listen_sockets->elts;
    ncurr = cycle->listen_sockets->nelts;

    if (cycle->previous != NULL) {
        prev = cycle->previous->listen_sockets->elts;
        nprev = cycle->previous->listen_sockets->nelts;

    } else if (cycle->inherited_sockets != NULL) {
        prev = cycle->inherited_sockets->elts;
        nprev = cycle->inherited_sockets->nelts;

    } else {
        prev = NULL;
        nprev = 0;
    }

    for (c = 0; c < ncurr; c++) {

        for (p = 0; p < nprev; p++) {

            if (nxt_sockaddr_cmp(curr[c].sockaddr, prev[p].sockaddr)) {

                if (nxt_listen_socket_update(&curr[c], &prev[p]) != NXT_OK) {
                    return NXT_ERROR;
                }

                goto next;
            }
        }

        if (nxt_listen_socket_create(&curr[c], cycle->test_config) != NXT_OK) {
            return NXT_ERROR;
        }

    next:

        continue;
    }

    return NXT_OK;
}


static void
nxt_cycle_listen_sockets_close(nxt_cycle_t *cycle)
{
    nxt_uint_t           p, c, nprev, ncurr;
    nxt_listen_socket_t  *curr, *prev;

    if (cycle->previous == NULL) {
        return;
    }

    prev = cycle->previous->listen_sockets->elts;
    nprev = cycle->previous->listen_sockets->nelts;

    curr = cycle->listen_sockets->elts;
    ncurr = cycle->listen_sockets->nelts;

    for (p = 0; p < nprev; p++) {

        for (c = 0; c < ncurr; c++) {
            if (nxt_sockaddr_cmp(prev[p].sockaddr, curr[c].sockaddr)) {
                goto next;
            }
        }

        nxt_socket_close(prev[p].socket);

    next:

        continue;
    }

    return;
}


nxt_int_t
nxt_cycle_listen_sockets_enable(nxt_task_t *task, nxt_cycle_t *cycle)
{
    nxt_uint_t           i, n;
    nxt_listen_socket_t  *ls;

    ls = cycle->listen_sockets->elts;
    n = cycle->listen_sockets->nelts;

    for (i = 0; i < n; i++) {
        if (nxt_event_conn_listen(task, &ls[i]) != NXT_OK) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


nxt_str_t *
nxt_current_directory(nxt_mem_pool_t *mp)
{
    size_t     length;
    u_char     *p;
    nxt_str_t  *name;
    char       buf[NXT_MAX_PATH_LEN];

    length = nxt_dir_current(buf, NXT_MAX_PATH_LEN);

    if (nxt_fast_path(length != 0)) {
        name = nxt_str_alloc(mp, length + 1);

        if (nxt_fast_path(name != NULL)) {
            p = nxt_cpymem(name->start, buf, length);
            *p = '/';

            return name;
        }
    }

    return NULL;
}


nxt_int_t
nxt_cycle_pid_file_create(nxt_file_name_t *pid_file, nxt_bool_t test)
{
    ssize_t     length;
    nxt_int_t   n;
    nxt_uint_t  create;
    nxt_file_t  file;
    u_char      pid[NXT_INT64_T_LEN + NXT_LINEFEED_SIZE];

    nxt_memzero(&file, sizeof(nxt_file_t));

    file.name = pid_file;

    create = test ? NXT_FILE_CREATE_OR_OPEN : NXT_FILE_TRUNCATE;

    n = nxt_file_open(&file, NXT_FILE_WRONLY, create, NXT_FILE_DEFAULT_ACCESS);

    if (n != NXT_OK) {
        return NXT_ERROR;
    }

    if (!test) {
        length = nxt_sprintf(pid, pid + sizeof(pid), "%PI%n", nxt_pid) - pid;

        if (nxt_file_write(&file, pid, length, 0) != length) {
            return NXT_ERROR;
        }
    }

    nxt_file_close(&file);

    return NXT_OK;
}


static void
nxt_cycle_pid_file_delete(nxt_cycle_t *cycle)
{
    nxt_file_name_t  *pid_file;

    if (!cycle->test_config) {
        pid_file = (cycle->new_binary != 0) ? cycle->oldbin_file:
                                              cycle->pid_file;
        if (pid_file != NULL) {
            nxt_file_delete(pid_file);
        }
    }
}


nxt_int_t
nxt_cycle_shm_zone_add(nxt_cycle_t *cycle, nxt_str_t *name, size_t size,
    nxt_uint_t page_size)
{
    nxt_cycle_shm_zone_t  *shm_zone;

    if (cycle->shm_zones == NULL) {
        cycle->shm_zones = nxt_array_create(cycle->mem_pool, 1,
                                            sizeof(nxt_cycle_shm_zone_t));
        if (cycle->shm_zones == NULL) {
            return NXT_ERROR;
        }
    }

    shm_zone = nxt_array_add(cycle->shm_zones);

    if (shm_zone != NULL) {
        shm_zone->size = size;
        shm_zone->page_size = page_size;
        shm_zone->name = *name;

        return NXT_OK;
    }

    return NXT_ERROR;
}


static nxt_int_t
nxt_cycle_shm_zones_enable(nxt_cycle_t *cycle)
{
    nxt_uint_t            i, n;
    nxt_cycle_shm_zone_t  *shm_zone;

    if (cycle->shm_zones != NULL) {
        shm_zone = cycle->shm_zones->elts;
        n = cycle->shm_zones->nelts;

        for (i = 0; i < n; i++) {
            if (nxt_cycle_shm_zone_create(&shm_zone[i]) != NXT_OK) {
                return NXT_ERROR;
            }
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_cycle_shm_zone_create(nxt_cycle_shm_zone_t *shm_zone)
{
    nxt_mem_zone_t  *zone;

    /*
     * Unix-only code because Windows ASLR maps shared memory segments at
     * different addresses in different processes.  Unix ASLR does not affect
     * this because all shared memory segments are inherited during fork().
     */

    shm_zone->addr = nxt_mem_mmap(NULL, shm_zone->size,
                                  NXT_MEM_MAP_READ | NXT_MEM_MAP_WRITE,
                                  NXT_MEM_MAP_SHARED, NXT_FILE_INVALID, 0);

    if (shm_zone->addr != NXT_MEM_MAP_FAILED) {

        zone = nxt_mem_zone_init(shm_zone->addr, shm_zone->size,
                                 shm_zone->page_size);
        if (zone != NULL) {
            return NXT_OK;
        }

        nxt_mem_munmap(shm_zone->addr, shm_zone->size);
    }

    return NXT_ERROR;
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_port.h>
#include <nxt_master_process.h>


static nxt_int_t nxt_master_process_port_create(nxt_task_t *task,
    nxt_runtime_t *rt);
static void nxt_master_process_title(nxt_task_t *task);
static nxt_int_t nxt_master_start_controller_process(nxt_task_t *task,
    nxt_runtime_t *rt);
static nxt_int_t nxt_master_start_router_process(nxt_task_t *task,
    nxt_runtime_t *rt);
static nxt_int_t nxt_master_start_worker_processes(nxt_task_t *task,
    nxt_runtime_t *rt);
static nxt_int_t nxt_master_create_worker_process(nxt_task_t *task,
    nxt_runtime_t *rt, nxt_process_init_t *init);
static void nxt_master_process_sigterm_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_master_process_sigquit_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_master_process_sigusr1_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_master_process_sigchld_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_master_cleanup_worker_process(nxt_task_t *task, nxt_pid_t pid);


const nxt_sig_event_t  nxt_master_process_signals[] = {
    nxt_event_signal(SIGINT,  nxt_master_process_sigterm_handler),
    nxt_event_signal(SIGQUIT, nxt_master_process_sigquit_handler),
    nxt_event_signal(SIGTERM, nxt_master_process_sigterm_handler),
    nxt_event_signal(SIGCHLD, nxt_master_process_sigchld_handler),
    nxt_event_signal(SIGUSR1, nxt_master_process_sigusr1_handler),
    nxt_event_signal_end,
};


static nxt_bool_t  nxt_exiting;


nxt_int_t
nxt_master_process_start(nxt_thread_t *thr, nxt_task_t *task,
    nxt_runtime_t *rt)
{
    nxt_int_t  ret;

    rt->types |= (1U << NXT_PROCESS_MASTER);

    if (nxt_master_process_port_create(task, rt) != NXT_OK) {
        return NXT_ERROR;
    }

    nxt_master_process_title(task);

    ret = nxt_master_start_controller_process(task, rt);
    if (ret != NXT_OK) {
        return ret;
    }

    ret = nxt_master_start_router_process(task, rt);
    if (ret != NXT_OK) {
        return ret;
    }

    return nxt_master_start_worker_processes(task, rt);
}


static nxt_int_t
nxt_master_process_port_create(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_int_t      ret;
    nxt_port_t     *port;
    nxt_process_t  *process;

    process = nxt_runtime_process_get(rt, nxt_pid);
    if (nxt_slow_path(process == NULL)) {
        return NXT_ERROR;
    }

    port = nxt_process_port_new(process);
    if (nxt_slow_path(port == NULL)) {
        return NXT_ERROR;
    }

    ret = nxt_port_socket_init(task, port, 0);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    port->engine = 0;
    port->type = NXT_PROCESS_MASTER;

    nxt_runtime_port_add(rt, port);

    /*
     * A master process port.  A write port is not closed
     * since it should be inherited by worker processes.
     */
    nxt_port_read_enable(task, port);

    return NXT_OK;
}


static void
nxt_master_process_title(nxt_task_t *task)
{
    u_char      *p, *end;
    nxt_uint_t  i;
    u_char      title[2048];

    end = title + sizeof(title);

    p = nxt_sprintf(title, end, "nginext: master process %s",
                    nxt_process_argv[0]);

    for (i = 1; nxt_process_argv[i] != NULL; i++) {
        p = nxt_sprintf(p, end, " %s", nxt_process_argv[i]);
    }

    *p = '\0';

    nxt_process_title(task, "%s", (char *) title);
}


static nxt_int_t
nxt_master_start_controller_process(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_process_init_t  *init;

    init = nxt_mp_get(rt->mem_pool, sizeof(nxt_process_init_t));
    if (nxt_slow_path(init == NULL)) {
        return NXT_ERROR;
    }

    init->start = nxt_controller_start;
    init->name = "controller process";
    init->user_cred = &rt->user_cred;
    init->port_handlers = nxt_worker_process_port_handlers;
    init->signals = nxt_worker_process_signals;
    init->type = NXT_PROCESS_CONTROLLER;

    return nxt_master_create_worker_process(task, rt, init);
}


static nxt_int_t
nxt_master_start_router_process(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_process_init_t  *init;

    init = nxt_mp_get(rt->mem_pool, sizeof(nxt_process_init_t));
    if (nxt_slow_path(init == NULL)) {
        return NXT_ERROR;
    }

    init->start = nxt_router_start;
    init->name = "router process";
    init->user_cred = &rt->user_cred;
    init->port_handlers = nxt_router_process_port_handlers;
    init->signals = nxt_worker_process_signals;
    init->type = NXT_PROCESS_ROUTER;

    return nxt_master_create_worker_process(task, rt, init);
}


static nxt_int_t
nxt_master_start_worker_processes(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_int_t           ret;
    nxt_uint_t          n;
    nxt_process_init_t  *init;

    init = nxt_mp_get(rt->mem_pool, sizeof(nxt_process_init_t));
    if (nxt_slow_path(init == NULL)) {
        return NXT_ERROR;
    }

    init->start = nxt_app_start;
    init->name = "worker process";
    init->user_cred = &rt->user_cred;
    init->port_handlers = nxt_app_process_port_handlers;
    init->signals = nxt_worker_process_signals;
    init->type = NXT_PROCESS_WORKER;

    n = rt->worker_processes;

    while (n-- != 0) {
        ret = nxt_master_create_worker_process(task, rt, init);

        if (ret != NXT_OK) {
            return ret;
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_master_create_worker_process(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_process_init_t *init)
{
    nxt_int_t      ret;
    nxt_pid_t      pid;
    nxt_port_t     *port;
    nxt_process_t  *process, *master_process;

    /*
     * TODO: remove process, init, ports from array on memory and fork failures.
     */

    process = nxt_runtime_process_new(rt);
    if (nxt_slow_path(process == NULL)) {
        return NXT_ERROR;
    }

    process->init = init;
    master_process = rt->mprocess;
    init->master_port = nxt_process_port_first(master_process);

    port = nxt_process_port_new(process);
    if (nxt_slow_path(port == NULL)) {
        return NXT_ERROR;
    }

    init->port = port;

    ret = nxt_port_socket_init(task, port, 0);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    port->engine = 0;
    port->type = init->type;

    pid = nxt_process_create(task, process);

    switch (pid) {

    case -1:
        return NXT_ERROR;

    case 0:
        /* A worker process, return to the event engine work queue loop. */
        return NXT_AGAIN;

    default:
        /* The master process created a new process. */

        nxt_port_read_close(port);
        nxt_port_write_enable(task, port);

        nxt_port_send_new_port(task, rt, port);
        return NXT_OK;
    }
}


void
nxt_master_stop_worker_processes(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_port_t     *port;
    nxt_process_t  *process;

    nxt_runtime_process_each(rt, process)
    {
        if (nxt_pid != process->pid) {
            process->init = NULL;

            nxt_process_port_each(process, port) {

                (void) nxt_port_socket_write(task, port, NXT_PORT_MSG_QUIT,
                                             -1, 0, 0, NULL);

            } nxt_process_port_loop;
        }
    }
    nxt_runtime_process_loop;
}



static void
nxt_master_process_sigterm_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_debug(task, "sigterm handler signo:%d (%s)",
              (int) (uintptr_t) obj, data);

    /* TODO: fast exit. */

    nxt_exiting = 1;

    nxt_runtime_quit(task);
}


static void
nxt_master_process_sigquit_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_debug(task, "sigquit handler signo:%d (%s)",
              (int) (uintptr_t) obj, data);

    /* TODO: graceful exit. */

    nxt_exiting = 1;

    nxt_runtime_quit(task);
}


static void
nxt_master_process_sigusr1_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_mp_t        *mp;
    nxt_int_t       ret;
    nxt_uint_t      n;
    nxt_file_t      *file, *new_file;
    nxt_runtime_t   *rt;
    nxt_array_t     *new_files;

    nxt_log(task, NXT_LOG_NOTICE, "signal %d (%s) recevied, %s",
            (int) (uintptr_t) obj, data, "log files rotation");

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (mp == NULL) {
        return;
    }

    rt = task->thread->runtime;

    n = nxt_list_nelts(rt->log_files);

    new_files = nxt_array_create(mp, n, sizeof(nxt_file_t));
    if (new_files == NULL) {
        nxt_mp_destroy(mp);
        return;
    }

    nxt_list_each(file, rt->log_files) {

        /* This allocation cannot fail. */
        new_file = nxt_array_add(new_files);

        new_file->name = file->name;
        new_file->fd = NXT_FILE_INVALID;
        new_file->log_level = NXT_LOG_CRIT;

        ret = nxt_file_open(task, new_file, O_WRONLY | O_APPEND, O_CREAT,
                            NXT_FILE_OWNER_ACCESS);

        if (ret != NXT_OK) {
            goto fail;
        }

    } nxt_list_loop;

    new_file = new_files->elts;

    ret = nxt_file_stderr(&new_file[0]);

    if (ret == NXT_OK) {
        n = 0;

        nxt_list_each(file, rt->log_files) {

            nxt_port_change_log_file(task, rt, n, new_file[n].fd);
            /*
             * The old log file descriptor must be closed at the moment
             * when no other threads use it.  dup2() allows to use the
             * old file descriptor for new log file.  This change is
             * performed atomically in the kernel.
             */
            (void) nxt_file_redirect(file, new_file[n].fd);

            n++;

        } nxt_list_loop;

        nxt_mp_destroy(mp);
        return;
   }

fail:

    new_file = new_files->elts;
    n = new_files->nelts;

    while (n != 0) {
        if (new_file->fd != NXT_FILE_INVALID) {
            nxt_file_close(task, new_file);
        }

        new_file++;
        n--;
    }

    nxt_mp_destroy(mp);
}


static void
nxt_master_process_sigchld_handler(nxt_task_t *task, void *obj, void *data)
{
    int                    status;
    nxt_err_t              err;
    nxt_pid_t              pid;

    nxt_debug(task, "sigchld handler signo:%d (%s)",
              (int) (uintptr_t) obj, data);

    for ( ;; ) {
        pid = waitpid(-1, &status, WNOHANG);

        if (pid == -1) {

            switch (err = nxt_errno) {

            case NXT_ECHILD:
                return;

            case NXT_EINTR:
                continue;

            default:
                nxt_log(task, NXT_LOG_CRIT, "waitpid() failed: %E", err);
                return;
            }
        }

        nxt_debug(task, "waitpid(): %PI", pid);

        if (pid == 0) {
            return;
        }

        if (WTERMSIG(status)) {
#ifdef WCOREDUMP
            nxt_log(task, NXT_LOG_CRIT, "process %PI exited on signal %d%s",
                    pid, WTERMSIG(status),
                    WCOREDUMP(status) ? " (core dumped)" : "");
#else
            nxt_log(task, NXT_LOG_CRIT, "process %PI exited on signal %d",
                    pid, WTERMSIG(status));
#endif

        } else {
            nxt_trace(task, "process %PI exited with code %d",
                      pid, WEXITSTATUS(status));
        }

        nxt_master_cleanup_worker_process(task, pid);
    }
}


static void
nxt_master_cleanup_worker_process(nxt_task_t *task, nxt_pid_t pid)
{
    nxt_port_t          *port;
    nxt_runtime_t       *rt;
    nxt_process_t       *process;
    nxt_process_init_t  *init;

    rt = task->thread->runtime;

    process = nxt_runtime_process_find(rt, pid);

    if (process) {
        init = process->init;

        nxt_runtime_process_remove(rt, process);

        if (!nxt_exiting) {
            nxt_runtime_process_each(rt, process)
            {
                if (process->pid == nxt_pid) {
                    continue;
                }

                port = nxt_process_port_first(process);

                nxt_port_socket_write(task, port, NXT_PORT_MSG_REMOVE_PID,
                                      -1, pid, 0, NULL);
            }
            nxt_runtime_process_loop;
        }

        if (nxt_exiting) {

            if (rt->nprocesses == 2) {
                nxt_runtime_quit(task);
            }

        } else if (init != NULL) {
            (void) nxt_master_create_worker_process(task, rt, init);
        }
    }
}

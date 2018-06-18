
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_port.h>
#include <nxt_main_process.h>
#include <nxt_router.h>


static void nxt_worker_process_quit(nxt_task_t *task);
static void nxt_worker_process_signal_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_worker_process_sigterm_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_worker_process_sigquit_handler(nxt_task_t *task, void *obj,
    void *data);


nxt_port_handlers_t  nxt_app_process_port_handlers = {
    .quit         = nxt_app_quit_handler,
    .new_port     = nxt_port_new_port_handler,
    .change_file  = nxt_port_change_log_file_handler,
    .mmap         = nxt_port_mmap_handler,
    .data         = nxt_app_data_handler,
    .remove_pid   = nxt_port_remove_pid_handler,
};


nxt_port_handlers_t  nxt_discovery_process_port_handlers = {
    .quit         = nxt_worker_process_quit_handler,
    .new_port     = nxt_port_new_port_handler,
    .change_file  = nxt_port_change_log_file_handler,
    .mmap         = nxt_port_mmap_handler,
    .data         = nxt_port_data_handler,
    .remove_pid   = nxt_port_remove_pid_handler,
    .rpc_ready    = nxt_port_rpc_handler,
    .rpc_error    = nxt_port_rpc_handler,
};


const nxt_sig_event_t  nxt_worker_process_signals[] = {
    nxt_event_signal(SIGHUP,  nxt_worker_process_signal_handler),
    nxt_event_signal(SIGINT,  nxt_worker_process_sigterm_handler),
    nxt_event_signal(SIGQUIT, nxt_worker_process_sigterm_handler),
    nxt_event_signal(SIGTERM, nxt_worker_process_sigquit_handler),
    nxt_event_signal(SIGCHLD, nxt_worker_process_signal_handler),
    nxt_event_signal(SIGUSR1, nxt_worker_process_signal_handler),
    nxt_event_signal(SIGUSR2, nxt_worker_process_signal_handler),
    nxt_event_signal_end,
};


static void
nxt_worker_process_quit(nxt_task_t *task)
{
    nxt_uint_t           n;
    nxt_queue_t          *listen;
    nxt_runtime_t        *rt;
    nxt_queue_link_t     *link, *next;
    nxt_listen_event_t   *lev;
    nxt_listen_socket_t  *ls;

    rt = task->thread->runtime;

    nxt_debug(task, "close listen connections");

    listen = &task->thread->engine->listen_connections;

    for (link = nxt_queue_first(listen);
         link != nxt_queue_tail(listen);
         link = next)
    {
        next = nxt_queue_next(link);
        lev = nxt_queue_link_data(link, nxt_listen_event_t, link);
        nxt_queue_remove(link);

        nxt_fd_event_close(task->thread->engine, &lev->socket);
    }

    if (rt->listen_sockets != NULL) {

        ls = rt->listen_sockets->elts;
        n = rt->listen_sockets->nelts;

        while (n != 0) {
            nxt_socket_close(task, ls->socket);
            ls->socket = -1;

            ls++;
            n--;
        }

        rt->listen_sockets->nelts = 0;
    }

    nxt_runtime_quit(task, 0);
}


static void
nxt_worker_process_signal_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_trace(task, "signal signo:%d (%s) recevied, ignored",
              (int) (uintptr_t) obj, data);
}


void
nxt_worker_process_quit_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_worker_process_quit(task);
}


static void
nxt_worker_process_sigterm_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_debug(task, "sigterm handler signo:%d (%s)",
              (int) (uintptr_t) obj, data);

    /* A fast exit. */

    nxt_runtime_quit(task, 0);
}


static void
nxt_worker_process_sigquit_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_debug(task, "sigquit handler signo:%d (%s)",
              (int) (uintptr_t) obj, data);

    /* A graceful exit. */

    nxt_worker_process_quit(task);
}

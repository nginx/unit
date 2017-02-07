
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_cycle.h>
#include <nxt_port.h>
#include <nxt_master_process.h>


static void nxt_worker_process_quit(nxt_task_t *task);
static void nxt_worker_process_quit_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
static void nxt_worker_process_signal_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_worker_process_sigterm_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_worker_process_sigquit_handler(nxt_task_t *task, void *obj,
    void *data);


static nxt_process_port_handler_t  nxt_worker_process_port_handlers[] = {
    nxt_worker_process_quit_handler,
    nxt_process_port_new_handler,
    nxt_process_port_change_log_file_handler,
    nxt_process_port_data_handler,
};


static const nxt_sig_event_t  nxt_worker_process_signals[] = {
    nxt_event_signal(SIGHUP,  nxt_worker_process_signal_handler),
    nxt_event_signal(SIGINT,  nxt_worker_process_sigterm_handler),
    nxt_event_signal(SIGQUIT, nxt_worker_process_sigterm_handler),
    nxt_event_signal(SIGTERM, nxt_worker_process_sigquit_handler),
    nxt_event_signal(SIGCHLD, nxt_worker_process_signal_handler),
    nxt_event_signal(SIGUSR1, nxt_worker_process_signal_handler),
    nxt_event_signal(SIGUSR1, nxt_worker_process_signal_handler),
    nxt_event_signal_end,
};


void
nxt_worker_process_start(void *data)
{
    nxt_int_t                    n;
    nxt_cycle_t                  *cycle;
    nxt_thread_t                 *thr;
    nxt_process_port_t           *proc;
    const nxt_event_interface_t  *interface;

    cycle = data;

    nxt_thread_init_data(nxt_thread_cycle_data);
    nxt_thread_cycle_set(cycle);

    thr = nxt_thread();

    nxt_log_error(NXT_LOG_INFO, thr->log, "worker process");

    nxt_process_title("nginext: worker process");

    cycle->type = NXT_PROCESS_WORKER;

    nxt_random_init(&nxt_random_data);

    if (getuid() == 0) {
        /* Super-user. */

        n = nxt_user_cred_set(&cycle->user_cred);
        if (n != NXT_OK) {
            goto fail;
        }
    }

    /* Update inherited master process event engine and signals processing. */
    thr->engine->signals->sigev = nxt_worker_process_signals;

    interface = nxt_service_get(cycle->services, "engine", cycle->engine);
    if (interface == NULL) {
        goto fail;
    }

    if (nxt_event_engine_change(thr, &nxt_main_task, interface, cycle->batch) != NXT_OK) {
        goto fail;
    }

#if 0
    if (nxt_cycle_listen_sockets_enable(thr, cycle) != NXT_OK) {
        goto fail;
    }
#endif

    proc = cycle->processes->elts;

    /* A master process port. */
    nxt_port_read_close(proc[0].port);
    nxt_port_write_enable(&nxt_main_task, proc[0].port);

    /* A worker process port. */
    nxt_process_port_create(thr, &proc[cycle->current_process],
                            nxt_worker_process_port_handlers);

#if (NXT_THREADS)
    {
        nxt_int_t  ret;

        ret = nxt_cycle_thread_pool_create(thr, cycle, cycle->auxiliary_threads,
                                           60000 * 1000000LL);

        if (nxt_slow_path(ret != NXT_OK)) {
            goto fail;
        }
    }

    nxt_app_start(cycle);
#endif

    return;

fail:

    exit(1);
    nxt_unreachable();
}


static void
nxt_worker_process_quit(nxt_task_t *task)
{
    nxt_uint_t               n;
    nxt_cycle_t              *cycle;
    nxt_queue_t              *listen;
    nxt_queue_link_t         *link, *next;
    nxt_listen_socket_t      *ls;
    nxt_event_conn_listen_t  *cls;

    cycle = nxt_thread_cycle();

    nxt_debug(task, "close listen connections");

    listen = &task->thread->engine->listen_connections;

    for (link = nxt_queue_first(listen);
         link != nxt_queue_tail(listen);
         link = next)
    {
        next = nxt_queue_next(link);
        cls = nxt_queue_link_data(link, nxt_event_conn_listen_t, link);
        nxt_queue_remove(link);

        nxt_fd_event_close(task->thread->engine, &cls->socket);
    }

    if (cycle->listen_sockets != NULL) {

        ls = cycle->listen_sockets->elts;
        n = cycle->listen_sockets->nelts;

        while (n != 0) {
            nxt_socket_close(ls->socket);
            ls->socket = -1;

            ls++;
            n--;
        }

        cycle->listen_sockets->nelts = 0;
    }

    nxt_cycle_quit(task, cycle);
}


static void
nxt_worker_process_signal_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_trace(task, "signal signo:%d (%s) recevied, ignored",
              (int) (uintptr_t) obj, data);
}


static void
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

    nxt_cycle_quit(task, NULL);
}


static void
nxt_worker_process_sigquit_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_debug(task, "sigquit handler signo:%d (%s)",
              (int) (uintptr_t) obj, data);

    /* A graceful exit. */

    nxt_worker_process_quit(task);
}

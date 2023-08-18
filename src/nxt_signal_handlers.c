
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_port.h>
#include <nxt_main_process.h>
#include <nxt_router.h>


static void nxt_signal_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_signal_sigterm_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_signal_sigquit_handler(nxt_task_t *task, void *obj, void *data);


const nxt_sig_event_t  nxt_process_signals[] = {
    nxt_event_signal(SIGHUP,  nxt_signal_handler),
    nxt_event_signal(SIGINT,  nxt_signal_sigterm_handler),
    nxt_event_signal(SIGQUIT, nxt_signal_sigquit_handler),
    nxt_event_signal(SIGTERM, nxt_signal_sigterm_handler),
    nxt_event_signal(SIGCHLD, nxt_signal_handler),
    nxt_event_signal(SIGUSR1, nxt_signal_handler),
    nxt_event_signal(SIGUSR2, nxt_signal_handler),
    nxt_event_signal_end,
};


static void
nxt_signal_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_trace(task, "signal signo:%d (%s) received, ignored",
              (int) (uintptr_t) obj, data);
}


void
nxt_signal_quit_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_process_quit(task, 0);
}


static void
nxt_signal_sigterm_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_debug(task, "sigterm handler signo:%d (%s)",
              (int) (uintptr_t) obj, data);

    /* A fast exit. */

    nxt_runtime_quit(task, 0);
}


static void
nxt_signal_sigquit_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_debug(task, "sigquit handler signo:%d (%s)",
              (int) (uintptr_t) obj, data);

    /* A graceful exit. */

    nxt_process_quit(task, 0);
}

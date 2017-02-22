
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_cycle.h>
#include <nxt_port.h>


static void nxt_process_port_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
static void nxt_process_new_port_buf_completion(nxt_task_t *task, void *obj,
    void *data);


void
nxt_process_port_create(nxt_thread_t *thr, nxt_process_port_t *proc,
    nxt_process_port_handler_t *handlers)
{
    proc->pid = nxt_pid;
    proc->engine = thr->engine->id;
    proc->port->handler = nxt_process_port_handler;
    proc->port->data = handlers;

    nxt_port_write_close(proc->port);
    nxt_port_read_enable(&thr->engine->task, proc->port);
}


void
nxt_process_port_write(nxt_task_t *task, nxt_cycle_t *cycle, nxt_uint_t type,
    nxt_fd_t fd, uint32_t stream, nxt_buf_t *b)
{
    nxt_uint_t          i, n;
    nxt_process_port_t  *proc;

    proc = cycle->processes->elts;
    n = cycle->processes->nelts;

    for (i = 0; i < n; i++) {
        if (nxt_pid != proc[i].pid) {
            (void) nxt_port_write(task, proc[i].port, type, fd, stream, b);
        }
    }
}


static void
nxt_process_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_process_port_handler_t  *handlers;

    if (nxt_fast_path(msg->type <= NXT_PORT_MSG_MAX)) {

        nxt_debug(task, "port %d: message type:%uD",
                  msg->port->socket.fd, msg->type);

        handlers = msg->port->data;
        handlers[msg->type](task, msg);

        return;
    }

    nxt_log(task, NXT_LOG_CRIT, "port %d: unknown message type:%uD",
            msg->port->socket.fd, msg->type);
}


void
nxt_process_port_quit_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_cycle_quit(task, NULL);
}


void
nxt_process_new_port(nxt_task_t *task, nxt_cycle_t *cycle,
    nxt_process_port_t *proc)
{
    nxt_buf_t                *b;
    nxt_uint_t               i, n;
    nxt_process_port_t       *p;
    nxt_proc_msg_new_port_t  *new_port;

    n = cycle->processes->nelts;
    if (n == 0) {
        return;
    }

    nxt_thread_log_debug("new port %d for process %PI engine %uD",
                         proc->port->socket.fd, proc->pid, proc->engine);

    p = cycle->processes->elts;

    for (i = 0; i < n; i++) {

        if (proc->pid == p[i].pid || nxt_pid == p[i].pid || p[i].engine != 0) {
            continue;
        }

        b = nxt_buf_mem_alloc(p[i].port->mem_pool,
                              sizeof(nxt_process_port_data_t), 0);

        if (nxt_slow_path(b == NULL)) {
            continue;
        }

        b->data = p[i].port;
        b->completion_handler = nxt_process_new_port_buf_completion;
        b->mem.free += sizeof(nxt_proc_msg_new_port_t);
        new_port = (nxt_proc_msg_new_port_t *) b->mem.pos;

        new_port->pid = proc->pid;
        new_port->engine = proc->engine;
        new_port->max_size = p[i].port->max_size;
        new_port->max_share = p[i].port->max_share;

        (void) nxt_port_write(task, p[i].port, NXT_PORT_MSG_NEW_PORT,
                              proc->port->socket.fd, 0, b);
    }
}


static void
nxt_process_new_port_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t   *b;
    nxt_port_t  *port;

    b = obj;
    port = b->data;

    /* TODO: b->mem.pos */

    nxt_buf_free(port->mem_pool, b);
}


void
nxt_process_port_new_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_port_t               *port;
    nxt_cycle_t              *cycle;
    nxt_process_port_t       *proc;
    nxt_proc_msg_new_port_t  *new_port;

    cycle = nxt_thread_cycle();

    proc = nxt_array_add(cycle->processes);
    if (nxt_slow_path(proc == NULL)) {
        return;
    }

    port = nxt_port_alloc(task);
    if (nxt_slow_path(port == NULL)) {
        return;
    }

    proc->port = port;

    new_port = (nxt_proc_msg_new_port_t *) msg->buf->mem.pos;
    msg->buf->mem.pos = msg->buf->mem.free;

    nxt_debug(task, "new port %d received for process %PI engine %uD",
              msg->fd, new_port->pid, new_port->engine);

    proc->pid = new_port->pid;
    proc->engine = new_port->engine;
    port->pair[1] = msg->fd;
    port->max_size = new_port->max_size;
    port->max_share = new_port->max_share;

    /* A read port is not passed at all. */
    nxt_port_write_enable(task, port);
}


void
nxt_process_port_change_log_file(nxt_task_t *task, nxt_cycle_t *cycle,
    nxt_uint_t slot, nxt_fd_t fd)
{
    nxt_buf_t           *b;
    nxt_uint_t          i, n;
    nxt_process_port_t  *p;

    n = cycle->processes->nelts;
    if (n == 0) {
        return;
    }

    nxt_thread_log_debug("change log file #%ui fd:%FD", slot, fd);

    p = cycle->processes->elts;

    /* p[0] is master process. */

    for (i = 1; i < n; i++) {
        b = nxt_buf_mem_alloc(p[i].port->mem_pool,
                              sizeof(nxt_process_port_data_t), 0);

        if (nxt_slow_path(b == NULL)) {
            continue;
        }

        *(nxt_uint_t *) b->mem.pos = slot;
        b->mem.free += sizeof(nxt_uint_t);

        (void) nxt_port_write(task, p[i].port, NXT_PORT_MSG_PORTGE_FILE,
                              fd, 0, b);
    }
}


void
nxt_process_port_change_log_file_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg)
{
    nxt_buf_t    *b;
    nxt_uint_t   slot;
    nxt_file_t   *log_file;
    nxt_cycle_t  *cycle;

    cycle = nxt_thread_cycle();

    b = msg->buf;
    slot = *(nxt_uint_t *) b->mem.pos;

    log_file = nxt_list_elt(cycle->log_files, slot);

    nxt_debug(task, "change log file %FD:%FD", msg->fd, log_file->fd);

    /*
     * The old log file descriptor must be closed at the moment when no
     * other threads use it.  dup2() allows to use the old file descriptor
     * for new log file.  This change is performed atomically in the kernel.
     */
    if (nxt_file_redirect(log_file, msg->fd) == NXT_OK) {

        if (slot == 0) {
            (void) nxt_file_stderr(log_file);
        }
    }
}


void
nxt_process_port_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_buf_t  *b;

    b = msg->buf;

    nxt_debug(task, "data: %*s", b->mem.free - b->mem.pos, b->mem.pos);

    b->mem.pos = b->mem.free;
}


void
nxt_process_port_empty_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_debug(task, "port empty handler");
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_port.h>


static void nxt_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
static void nxt_port_new_port_buf_completion(nxt_task_t *task, void *obj,
    void *data);


void
nxt_port_create(nxt_thread_t *thread, nxt_port_t *port,
    nxt_port_handler_t *handlers)
{
    port->pid = nxt_pid;
    port->engine = thread->engine->id;
    port->handler = nxt_port_handler;
    port->data = handlers;

    nxt_port_write_close(port);
    nxt_port_read_enable(&thread->engine->task, port);
}


void
nxt_port_write(nxt_task_t *task, nxt_runtime_t *rt, nxt_uint_t type,
    nxt_fd_t fd, uint32_t stream, nxt_buf_t *b)
{
    nxt_uint_t     i, n, nprocesses, nports;
    nxt_port_t     *port;
    nxt_process_t  *process;

    process = rt->processes->elts;
    nprocesses = rt->processes->nelts;

    for (i = 0; i < nprocesses; i++) {

        if (nxt_pid != process[i].pid) {
            port = process[i].ports->elts;
            nports = process[i].ports->nelts;

            for (n = 0; n < nports; n++) {
                (void) nxt_port_socket_write(task, &port[n], type,
                                             fd, stream, b);
            }
        }
    }
}


static void
nxt_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_port_handler_t  *handlers;

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
nxt_port_quit_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_runtime_quit(task);
}


void
nxt_port_send_new_port(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_port_t *new_port)
{
    nxt_buf_t                *b;
    nxt_uint_t               i, n;
    nxt_port_t               *port;
    nxt_process_t            *process;
    nxt_port_msg_new_port_t  *msg;

    n = rt->processes->nelts;
    if (n == 0) {
        return;
    }

    nxt_debug(task, "new port %d for process %PI engine %uD",
              new_port->socket.fd, new_port->pid, new_port->engine);

    process = rt->processes->elts;

    for (i = 0; i < n; i++) {

        if (process[i].pid == new_port->pid || process[i].pid == nxt_pid) {
            continue;
        }

        port = process[i].ports->elts;

        b = nxt_buf_mem_alloc(port->mem_pool, sizeof(nxt_port_data_t), 0);

        if (nxt_slow_path(b == NULL)) {
            continue;
        }

        b->data = port;
        b->completion_handler = nxt_port_new_port_buf_completion;
        b->mem.free += sizeof(nxt_port_msg_new_port_t);
        msg = (nxt_port_msg_new_port_t *) b->mem.pos;

        msg->pid = new_port->pid;
        msg->engine = new_port->engine;
        msg->max_size = port->max_size;
        msg->max_share = port->max_share;

        (void) nxt_port_socket_write(task, port, NXT_PORT_MSG_NEW_PORT,
                                     new_port->socket.fd, 0, b);
    }
}


static void
nxt_port_new_port_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t   *b;
    nxt_port_t  *port;

    b = obj;
    port = b->data;

    /* TODO: b->mem.pos */

    nxt_buf_free(port->mem_pool, b);
}


void
nxt_port_new_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_port_t               *port;
    nxt_process_t            *process;
    nxt_runtime_t            *rt;
    nxt_mem_pool_t           *mp;
    nxt_port_msg_new_port_t  *new_port_msg;

    rt = task->thread->runtime;

    process = nxt_runtime_new_process(rt);
    if (nxt_slow_path(process == NULL)) {
        return;
    }

    port = nxt_array_zero_add(process->ports);
    if (nxt_slow_path(port == NULL)) {
        return;
    }

    mp = nxt_mem_pool_create(1024);
    if (nxt_slow_path(mp == NULL)) {
        return;
    }

    port->mem_pool = mp;

    new_port_msg = (nxt_port_msg_new_port_t *) msg->buf->mem.pos;
    msg->buf->mem.pos = msg->buf->mem.free;

    nxt_debug(task, "new port %d received for process %PI engine %uD",
              msg->fd, new_port_msg->pid, new_port_msg->engine);

    process->pid = new_port_msg->pid;

    port->pid = new_port_msg->pid;
    port->engine = new_port_msg->engine;
    port->pair[0] = -1;
    port->pair[1] = msg->fd;
    port->max_size = new_port_msg->max_size;
    port->max_share = new_port_msg->max_share;

    nxt_queue_init(&port->messages);

    port->socket.task = task;

    nxt_port_write_enable(task, port);
}


void
nxt_port_change_log_file(nxt_task_t *task, nxt_runtime_t *rt, nxt_uint_t slot,
    nxt_fd_t fd)
{
    nxt_buf_t      *b;
    nxt_uint_t     i, n;
    nxt_port_t     *port;
    nxt_process_t  *process;

    n = rt->processes->nelts;
    if (n == 0) {
        return;
    }

    nxt_debug(task, "change log file #%ui fd:%FD", slot, fd);

    process = rt->processes->elts;

    /* process[0] is master process. */

    for (i = 1; i < n; i++) {
        port = process[i].ports->elts;

        b = nxt_buf_mem_alloc(port->mem_pool, sizeof(nxt_port_data_t), 0);
        if (nxt_slow_path(b == NULL)) {
            continue;
        }

        *(nxt_uint_t *) b->mem.pos = slot;
        b->mem.free += sizeof(nxt_uint_t);

        (void) nxt_port_socket_write(task, port, NXT_PORT_MSG_CHANGE_FILE,
                                     fd, 0, b);
    }
}


void
nxt_port_change_log_file_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_buf_t      *b;
    nxt_uint_t     slot;
    nxt_file_t     *log_file;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;

    b = msg->buf;
    slot = *(nxt_uint_t *) b->mem.pos;

    log_file = nxt_list_elt(rt->log_files, slot);

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
nxt_port_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_buf_t  *b;

    b = msg->buf;

    nxt_debug(task, "data: %*s", b->mem.free - b->mem.pos, b->mem.pos);

    b->mem.pos = b->mem.free;
}


void
nxt_port_empty_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_debug(task, "port empty handler");
}

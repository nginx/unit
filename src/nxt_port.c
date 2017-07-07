
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_port.h>


static void nxt_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);


void
nxt_port_create(nxt_task_t *task, nxt_port_t *port,
    nxt_port_handler_t *handlers)
{
    port->pid = nxt_pid;
    port->engine = task->thread->engine->id;
    port->handler = nxt_port_handler;
    port->data = handlers;

    nxt_port_read_enable(task, port);
}


void
nxt_port_write(nxt_task_t *task, nxt_runtime_t *rt, nxt_uint_t type,
    nxt_fd_t fd, uint32_t stream, nxt_buf_t *b)
{
    nxt_port_t     *port;
    nxt_process_t  *process;

    nxt_runtime_process_each(rt, process)
    {
        if (nxt_pid != process->pid) {
            nxt_process_port_each(process, port) {

                (void) nxt_port_socket_write(task, port, type,
                                             fd, stream, 0, b);

            } nxt_process_port_loop;
        }
    }
    nxt_runtime_process_loop;
}


static void
nxt_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_port_handler_t  *handlers;

    if (nxt_fast_path(msg->port_msg.type < NXT_PORT_MSG_MAX)) {

        nxt_debug(task, "port %d: message type:%uD",
                  msg->port->socket.fd, msg->port_msg.type);

        handlers = msg->port->data;
        handlers[msg->port_msg.type](task, msg);

        return;
    }

    nxt_log(task, NXT_LOG_CRIT, "port %d: unknown message type:%uD",
            msg->port->socket.fd, msg->port_msg.type);
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
    nxt_process_t  *process;

    nxt_debug(task, "new port %d for process %PI engine %uD",
              new_port->pair[1], new_port->pid, new_port->engine);

    nxt_runtime_process_each(rt, process)
    {
        if (process->pid == new_port->pid || process->pid == nxt_pid) {
            continue;
        }

        (void) nxt_port_send_port(task, nxt_process_port_first(process),
                                  new_port);
    }
    nxt_runtime_process_loop;
}


nxt_int_t
nxt_port_send_port(nxt_task_t *task, nxt_port_t *port, nxt_port_t *new_port)
{
    nxt_buf_t                *b;
    nxt_port_msg_new_port_t  *msg;

    b = nxt_buf_mem_ts_alloc(task, port->mem_pool, sizeof(nxt_port_data_t));
    if (nxt_slow_path(b == NULL)) {
        return NXT_ERROR;
    }

    nxt_debug(task, "send port %FD to process %PI",
              new_port->pair[1], port->pid);

    b->mem.free += sizeof(nxt_port_msg_new_port_t);
    msg = (nxt_port_msg_new_port_t *) b->mem.pos;

    msg->id = new_port->id;
    msg->pid = new_port->pid;
    msg->engine = new_port->engine;
    msg->max_size = port->max_size;
    msg->max_share = port->max_share;
    msg->type = new_port->type;

    return nxt_port_socket_write(task, port, NXT_PORT_MSG_NEW_PORT,
                                 new_port->pair[1], 0, 0, b);
}


void
nxt_port_new_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_mp_t                 *mp;
    nxt_port_t               *port;
    nxt_process_t            *process;
    nxt_runtime_t            *rt;
    nxt_port_msg_new_port_t  *new_port_msg;

    rt = task->thread->runtime;

    new_port_msg = (nxt_port_msg_new_port_t *) msg->buf->mem.pos;
    msg->buf->mem.pos = msg->buf->mem.free;

    process = nxt_runtime_process_get(rt, new_port_msg->pid);
    if (nxt_slow_path(process == NULL)) {
        return;
    }

    port = nxt_process_port_new(process);
    if (nxt_slow_path(port == NULL)) {
        return;
    }

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (nxt_slow_path(mp == NULL)) {
        return;
    }

    port->mem_pool = mp;

    nxt_debug(task, "new port %d received for process %PI engine %uD",
              msg->fd, new_port_msg->pid, new_port_msg->engine);

    port->id = new_port_msg->id;
    port->engine = new_port_msg->engine;
    port->pair[0] = -1;
    port->pair[1] = msg->fd;
    port->max_size = new_port_msg->max_size;
    port->max_share = new_port_msg->max_share;
    port->type = new_port_msg->type;

    nxt_queue_init(&port->messages);

    port->socket.task = task;

    nxt_runtime_port_add(rt, port);

    nxt_port_write_enable(task, port);
}


void
nxt_port_mmap_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_runtime_t  *rt;
    nxt_process_t  *process;

    rt = task->thread->runtime;

    if (nxt_slow_path(msg->fd == -1)) {
        nxt_log(task, NXT_LOG_WARN, "invalid fd passed with mmap message");

        return;
    }

    process = nxt_runtime_process_get(rt, msg->port_msg.pid);
    if (nxt_slow_path(process == NULL)) {
        nxt_log(task, NXT_LOG_WARN, "failed to get process #%PI",
                msg->port_msg.pid);

        goto fail_close;
    }

    nxt_port_incoming_port_mmap(task, process, msg->fd);

fail_close:

    close(msg->fd);
}


void
nxt_port_change_log_file(nxt_task_t *task, nxt_runtime_t *rt, nxt_uint_t slot,
    nxt_fd_t fd)
{
    nxt_buf_t      *b;
    nxt_port_t     *port;
    nxt_process_t  *process;

    nxt_debug(task, "change log file #%ui fd:%FD", slot, fd);

    nxt_runtime_process_each(rt, process)
    {
        if (nxt_pid == process->pid) {
            continue;
        }

        port = nxt_process_port_first(process);

        b = nxt_buf_mem_alloc(port->mem_pool, sizeof(nxt_port_data_t), 0);
        if (nxt_slow_path(b == NULL)) {
            continue;
        }

        *(nxt_uint_t *) b->mem.pos = slot;
        b->mem.free += sizeof(nxt_uint_t);

        (void) nxt_port_socket_write(task, port, NXT_PORT_MSG_CHANGE_FILE,
                                     fd, 0, 0, b);
    }
    nxt_runtime_process_loop;
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
    size_t     dump_size;
    nxt_buf_t  *b;

    b = msg->buf;
    dump_size = b->mem.free - b->mem.pos;

    if (dump_size > 300) {
        dump_size = 300;
    }

    nxt_debug(task, "data: %*s", dump_size, b->mem.pos);

    b->mem.pos = b->mem.free;
}


void
nxt_port_remove_pid_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_pid_t           pid;
    nxt_runtime_t       *rt;
    nxt_process_t       *process;

    nxt_debug(task, "port remove pid handler");

    rt = task->thread->runtime;
    pid = msg->port_msg.stream;

    process = nxt_runtime_process_find(rt, pid);

    if (process) {
        nxt_runtime_process_remove(rt, process);
    }
}


void
nxt_port_empty_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_debug(task, "port empty handler");
}

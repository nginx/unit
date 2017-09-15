
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_port.h>
#include <nxt_router.h>


static void nxt_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);

static nxt_atomic_uint_t nxt_port_last_id = 1;


static void
nxt_port_mp_cleanup(nxt_task_t *task, void *obj, void *data)
{
    nxt_mp_t    *mp;
    nxt_port_t  *port;

    port = obj;
    mp = data;

    nxt_assert(port->pair[0] == -1);
    nxt_assert(port->pair[1] == -1);

    nxt_assert(port->app_stream == 0);
    nxt_assert(port->app_link.next == NULL);

    nxt_assert(nxt_queue_is_empty(&port->messages));
    nxt_assert(nxt_lvlhsh_is_empty(&port->rpc_streams));
    nxt_assert(nxt_lvlhsh_is_empty(&port->rpc_peers));

    nxt_mp_free(mp, port);
}


nxt_port_t *
nxt_port_new(nxt_task_t *task, nxt_port_id_t id, nxt_pid_t pid,
    nxt_process_type_t type)
{
    nxt_mp_t    *mp;
    nxt_port_t  *port;

    mp = nxt_mp_create(1024, 128, 256, 32);

    if (nxt_slow_path(mp == NULL)) {
        return NULL;
    }

    port = nxt_mp_zalloc(mp, sizeof(nxt_port_t));

    if (nxt_fast_path(port != NULL)) {
        port->id = id;
        port->pid = pid;
        port->type = type;
        port->mem_pool = mp;

        nxt_mp_cleanup(mp, nxt_port_mp_cleanup, task, port, mp);

        nxt_queue_init(&port->messages);

    } else {
        nxt_mp_destroy(mp);
    }

    nxt_thread_log_debug("port %p %d:%d new, type %d", port, pid, id, type);

    return port;
}


nxt_bool_t
nxt_port_release(nxt_port_t *port)
{
    nxt_thread_log_debug("port %p %d:%d release, type %d", port, port->pid,
                         port->id, port->type);

    if (port->pair[0] != -1) {
        nxt_fd_close(port->pair[0]);
        port->pair[0] = -1;
    }

    if (port->pair[1] != -1) {
        nxt_fd_close(port->pair[1]);
        port->pair[1] = -1;
    }

    if (port->type == NXT_PROCESS_WORKER) {
        if (nxt_router_app_remove_port(port) == 0) {
            return 0;
        }
    }

    if (port->link.next != NULL) {
        nxt_process_port_remove(port);
    }

    nxt_mp_release(port->mem_pool, NULL);

    return 1;
}


nxt_port_id_t
nxt_port_get_next_id()
{
    return nxt_atomic_fetch_add(&nxt_port_last_id, 1);
}


void
nxt_port_reset_next_id()
{
    nxt_port_last_id = 1;
}


void
nxt_port_enable(nxt_task_t *task, nxt_port_t *port,
    nxt_port_handlers_t *handlers)
{
    port->pid = nxt_pid;
    port->handler = nxt_port_handler;
    port->data = (nxt_port_handler_t *) (handlers);

    nxt_port_read_enable(task, port);
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
    nxt_port_t *new_port, uint32_t stream)
{
    nxt_port_t     *port;
    nxt_process_t  *process;

    nxt_debug(task, "new port %d for process %PI",
              new_port->pair[1], new_port->pid);

    nxt_runtime_process_each(rt, process) {

        if (process->pid == new_port->pid || process->pid == nxt_pid) {
            continue;
        }

        port = nxt_process_port_first(process);

        if (port->type == NXT_PROCESS_MAIN
            || port->type == NXT_PROCESS_CONTROLLER
            || port->type == NXT_PROCESS_ROUTER)
        {
            (void) nxt_port_send_port(task, port, new_port, stream);
        }

    } nxt_runtime_process_loop;
}


nxt_int_t
nxt_port_send_port(nxt_task_t *task, nxt_port_t *port, nxt_port_t *new_port,
    uint32_t stream)
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
    msg->max_size = port->max_size;
    msg->max_share = port->max_share;
    msg->type = new_port->type;

    return nxt_port_socket_write(task, port, NXT_PORT_MSG_NEW_PORT,
                                 new_port->pair[1], stream, 0, b);
}


void
nxt_port_new_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_port_t               *port;
    nxt_process_t            *process;
    nxt_runtime_t            *rt;
    nxt_port_msg_new_port_t  *new_port_msg;

    rt = task->thread->runtime;

    new_port_msg = (nxt_port_msg_new_port_t *) msg->buf->mem.pos;

    nxt_debug(task, "new port %d received for process %PI:%d",
              msg->fd, new_port_msg->pid, new_port_msg->id);

    port = nxt_runtime_port_find(rt, new_port_msg->pid, new_port_msg->id);
    if (port != NULL) {
        nxt_debug(task, "port %PI:%d already exists", new_port_msg->pid,
              new_port_msg->id);

        nxt_fd_close(msg->fd);
        msg->fd = -1;
        return;
    }

    process = nxt_runtime_process_get(rt, new_port_msg->pid);
    if (nxt_slow_path(process == NULL)) {
        return;
    }

    port = nxt_port_new(task, new_port_msg->id, new_port_msg->pid,
                        new_port_msg->type);
    if (nxt_slow_path(port == NULL)) {
        return;
    }

    nxt_process_port_add(task, process, port);

    port->pair[0] = -1;
    port->pair[1] = msg->fd;
    port->max_size = new_port_msg->max_size;
    port->max_share = new_port_msg->max_share;

    port->socket.task = task;

    nxt_runtime_port_add(rt, port);

    nxt_port_write_enable(task, port);

    msg->new_port = port;
}


void
nxt_port_process_ready_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_port_t     *port;
    nxt_process_t  *process;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;

    nxt_assert(nxt_runtime_is_main(rt));

    process = nxt_runtime_process_get(rt, msg->port_msg.pid);
    if (nxt_slow_path(process == NULL)) {
        return;
    }

    process->ready = 1;

    port = nxt_process_port_first(process);
    if (nxt_slow_path(port == NULL)) {
        return;
    }

    nxt_debug(task, "process %PI ready", msg->port_msg.pid);

    nxt_port_send_new_port(task, rt, port, msg->port_msg.stream);
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

    process = nxt_runtime_process_find(rt, msg->port_msg.pid);
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

    nxt_runtime_process_each(rt, process) {

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

    } nxt_runtime_process_loop;
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
}


void
nxt_port_remove_pid_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_buf_t           *buf;
    nxt_pid_t           pid;
    nxt_runtime_t       *rt;
    nxt_process_t       *process;

    buf = msg->buf;

    nxt_assert(nxt_buf_used_size(buf) == sizeof(pid));

    nxt_memcpy(&pid, buf->mem.pos, sizeof(pid));

    nxt_debug(task, "port remove pid %PI handler", pid);

    rt = task->thread->runtime;

    nxt_port_rpc_remove_peer(task, msg->port, pid);

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

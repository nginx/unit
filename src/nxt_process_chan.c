
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_cycle.h>
#include <nxt_process_chan.h>


static void nxt_process_chan_handler(nxt_thread_t *thr,
    nxt_chan_recv_msg_t *msg);
static void nxt_process_new_chan_buf_completion(nxt_thread_t *thr, void *obj,
    void *data);


void
nxt_process_chan_create(nxt_thread_t *thr, nxt_process_chan_t *proc,
    nxt_process_chan_handler_t *handlers)
{
    proc->pid = nxt_pid;
    proc->engine = thr->engine->id;
    proc->chan->handler = nxt_process_chan_handler;
    proc->chan->data = handlers;

    nxt_chan_write_close(proc->chan);
    nxt_chan_read_enable(thr, proc->chan);
}


void
nxt_process_chan_write(nxt_cycle_t *cycle, nxt_uint_t type, nxt_fd_t fd,
    uint32_t stream, nxt_buf_t *b)
{
    nxt_uint_t          i, n;
    nxt_process_chan_t  *proc;

    proc = cycle->processes->elts;
    n = cycle->processes->nelts;

    for (i = 0; i < n; i++) {
        if (nxt_pid != proc[i].pid) {
            (void) nxt_chan_write(proc[i].chan, type, fd, stream, b);
        }
    }
}


static void
nxt_process_chan_handler(nxt_thread_t *thr, nxt_chan_recv_msg_t *msg)
{
    nxt_process_chan_handler_t  *handlers;

    if (nxt_fast_path(msg->type <= NXT_CHAN_MSG_MAX)) {

        nxt_log_debug(thr->log, "chan %d: message type:%uD",
                      msg->chan->socket.fd, msg->type);

        handlers = msg->chan->data;
        handlers[msg->type](thr, msg);

        return;
    }

    nxt_log_alert(thr->log, "chan %d: unknown message type:%uD",
                  msg->chan->socket.fd, msg->type);
}


void
nxt_process_chan_quit_handler(nxt_thread_t *thr, nxt_chan_recv_msg_t *msg)
{
    nxt_cycle_quit(thr, NULL);
}


void
nxt_process_new_chan(nxt_cycle_t *cycle, nxt_process_chan_t *proc)
{
    nxt_buf_t                *b;
    nxt_uint_t               i, n;
    nxt_process_chan_t       *p;
    nxt_proc_msg_new_chan_t  *new_chan;

    n = cycle->processes->nelts;
    if (n == 0) {
        return;
    }

    nxt_thread_log_debug("new chan %d for process %PI engine %uD",
                         proc->chan->socket.fd, proc->pid, proc->engine);

    p = cycle->processes->elts;

    for (i = 0; i < n; i++) {

        if (proc->pid == p[i].pid || nxt_pid == p[i].pid || p[i].engine != 0) {
            continue;
        }

        b = nxt_buf_mem_alloc(p[i].chan->mem_pool,
                              sizeof(nxt_process_chan_data_t), 0);

        if (nxt_slow_path(b == NULL)) {
            continue;
        }

        b->data = p[i].chan;
        b->completion_handler = nxt_process_new_chan_buf_completion;
        b->mem.free += sizeof(nxt_proc_msg_new_chan_t);
        new_chan = (nxt_proc_msg_new_chan_t *) b->mem.pos;

        new_chan->pid = proc->pid;
        new_chan->engine = proc->engine;
        new_chan->max_size = p[i].chan->max_size;
        new_chan->max_share = p[i].chan->max_share;

        (void) nxt_chan_write(p[i].chan, NXT_CHAN_MSG_NEW_CHAN,
                              proc->chan->socket.fd, 0, b);
    }
}


static void
nxt_process_new_chan_buf_completion(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_buf_t   *b;
    nxt_chan_t  *chan;

    b = obj;
    chan = b->data;

    /* TODO: b->mem.pos */

    nxt_buf_free(chan->mem_pool, b);
}


void
nxt_process_chan_new_handler(nxt_thread_t *thr, nxt_chan_recv_msg_t *msg)
{
    nxt_chan_t               *chan;
    nxt_cycle_t              *cycle;
    nxt_process_chan_t       *proc;
    nxt_proc_msg_new_chan_t  *new_chan;

    cycle = nxt_thread_cycle();

    proc = nxt_array_add(cycle->processes);
    if (nxt_slow_path(proc == NULL)) {
        return;
    }

    chan = nxt_chan_alloc();
    if (nxt_slow_path(chan == NULL)) {
        return;
    }

    proc->chan = chan;

    new_chan = (nxt_proc_msg_new_chan_t *) msg->buf->mem.pos;
    msg->buf->mem.pos = msg->buf->mem.free;

    nxt_log_debug(thr->log, "new chan %d received for process %PI engine %uD",
                  msg->fd, new_chan->pid, new_chan->engine);

    proc->pid = new_chan->pid;
    proc->engine = new_chan->engine;
    chan->pair[1] = msg->fd;
    chan->max_size = new_chan->max_size;
    chan->max_share = new_chan->max_share;

    /* A read chan is not passed at all. */
    nxt_chan_write_enable(thr, chan);
}


void
nxt_process_chan_change_log_file(nxt_cycle_t *cycle, nxt_uint_t slot,
    nxt_fd_t fd)
{
    nxt_buf_t           *b;
    nxt_uint_t          i, n;
    nxt_process_chan_t  *p;

    n = cycle->processes->nelts;
    if (n == 0) {
        return;
    }

    nxt_thread_log_debug("change log file #%ui fd:%FD", slot, fd);

    p = cycle->processes->elts;

    /* p[0] is master process. */

    for (i = 1; i < n; i++) {
        b = nxt_buf_mem_alloc(p[i].chan->mem_pool,
                              sizeof(nxt_process_chan_data_t), 0);

        if (nxt_slow_path(b == NULL)) {
            continue;
        }

        *(nxt_uint_t *) b->mem.pos = slot;
        b->mem.free += sizeof(nxt_uint_t);

        (void) nxt_chan_write(p[i].chan, NXT_CHAN_MSG_CHANGE_FILE, fd, 0, b);
    }
}


void
nxt_process_chan_change_log_file_handler(nxt_thread_t *thr,
    nxt_chan_recv_msg_t *msg)
{
    nxt_buf_t    *b;
    nxt_uint_t   slot;
    nxt_file_t   *log_file;
    nxt_cycle_t  *cycle;

    cycle = nxt_thread_cycle();

    b = msg->buf;
    slot = *(nxt_uint_t *) b->mem.pos;

    log_file = nxt_list_elt(cycle->log_files, slot);

    nxt_log_debug(thr->log, "change log file %FD:%FD", msg->fd, log_file->fd);

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
nxt_process_chan_data_handler(nxt_thread_t *thr, nxt_chan_recv_msg_t *msg)
{
    nxt_buf_t  *b;

    b = msg->buf;

    nxt_log_debug(thr->log, "data: %*s", b->mem.free - b->mem.pos, b->mem.pos);

    b->mem.pos = b->mem.free;
}


void
nxt_process_chan_empty_handler(nxt_thread_t *thr, nxt_chan_recv_msg_t *msg)
{
    nxt_log_debug(thr->log, "chan empty handler");
}

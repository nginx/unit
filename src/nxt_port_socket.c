
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void nxt_port_write_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_port_read_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_port_read_msg_process(nxt_task_t *task, nxt_port_t *port,
    nxt_port_msg_t *msg, nxt_fd_t fd, nxt_buf_t *b, size_t size);
static nxt_buf_t *nxt_port_buf_alloc(nxt_port_t *port);
static void nxt_port_buf_free(nxt_port_t *port, nxt_buf_t *b);
static void nxt_port_error_handler(nxt_task_t *task, void *obj, void *data);


nxt_int_t
nxt_port_socket_init(nxt_task_t *task, nxt_port_t *port, size_t max_size)
{
    nxt_int_t       sndbuf, rcvbuf, size;
    nxt_socket_t    snd, rcv;
    nxt_mem_pool_t  *mp;

    port->socket.task = task;

    port->pair[0] = -1;
    port->pair[1] = -1;

    nxt_queue_init(&port->messages);

    mp = nxt_mem_pool_create(1024);
    if (nxt_slow_path(mp == NULL)) {
        return NXT_ERROR;
    }

    port->mem_pool = mp;

    if (nxt_slow_path(nxt_socketpair_create(task, port->pair) != NXT_OK)) {
        goto socketpair_fail;
    }

    snd = port->pair[1];

    sndbuf = nxt_socket_getsockopt(task, snd, SOL_SOCKET, SO_SNDBUF);
    if (nxt_slow_path(sndbuf < 0)) {
        goto getsockopt_fail;
    }

    rcv = port->pair[0];

    rcvbuf = nxt_socket_getsockopt(task, rcv, SOL_SOCKET, SO_RCVBUF);
    if (nxt_slow_path(rcvbuf < 0)) {
        goto getsockopt_fail;
    }

    if (max_size == 0) {
        max_size = 16 * 1024;
    }

    if ((size_t) sndbuf < max_size) {
        /*
         * On Unix domain sockets
         *   Linux uses 224K on both send and receive directions;
         *   FreeBSD, MacOSX, NetBSD, and OpenBSD use 2K buffer size
         *   on send direction and 4K buffer size on receive direction;
         *   Solaris uses 16K on send direction and 5K on receive direction.
         */
        (void) nxt_socket_setsockopt(task, snd, SOL_SOCKET, SO_SNDBUF,
                                     max_size);

        sndbuf = nxt_socket_getsockopt(task, snd, SOL_SOCKET, SO_SNDBUF);
        if (nxt_slow_path(sndbuf < 0)) {
            goto getsockopt_fail;
        }

        size = sndbuf * 4;

        if (rcvbuf < size) {
            (void) nxt_socket_setsockopt(task, rcv, SOL_SOCKET, SO_RCVBUF,
                                         size);

            rcvbuf = nxt_socket_getsockopt(task, rcv, SOL_SOCKET, SO_RCVBUF);
            if (nxt_slow_path(rcvbuf < 0)) {
                goto getsockopt_fail;
            }
        }
    }

    port->max_size = nxt_min(max_size, (size_t) sndbuf);
    port->max_share = (64 * 1024);

    return NXT_OK;

getsockopt_fail:

    nxt_socket_close(task, port->pair[0]);
    nxt_socket_close(task, port->pair[1]);

socketpair_fail:

    nxt_mem_pool_destroy(port->mem_pool);

    return NXT_ERROR;
}


void
nxt_port_destroy(nxt_port_t *port)
{
    nxt_socket_close(port->socket.task, port->socket.fd);
    nxt_mem_pool_destroy(port->mem_pool);
}


void
nxt_port_write_enable(nxt_task_t *task, nxt_port_t *port)
{
    port->socket.fd = port->pair[1];
    port->socket.log = &nxt_main_log;
    port->socket.write_ready = 1;

    port->socket.write_work_queue = &task->thread->engine->fast_work_queue;
    port->socket.write_handler = nxt_port_write_handler;
    port->socket.error_handler = nxt_port_error_handler;
}


void
nxt_port_write_close(nxt_port_t *port)
{
    nxt_socket_close(port->socket.task, port->pair[1]);
    port->pair[1] = -1;
}


nxt_int_t
nxt_port_socket_write(nxt_task_t *task, nxt_port_t *port, nxt_uint_t type,
    nxt_fd_t fd, uint32_t stream, nxt_buf_t *b)
{
    nxt_queue_link_t     *link;
    nxt_port_send_msg_t  *msg;

    for (link = nxt_queue_first(&port->messages);
         link != nxt_queue_tail(&port->messages);
         link = nxt_queue_next(link))
    {
        msg = (nxt_port_send_msg_t *) link;

        if (msg->port_msg.stream == stream) {
            /*
             * An fd is ignored since a file descriptor
             * must be sent only in the first message of a stream.
             */
            nxt_buf_chain_add(&msg->buf, b);

            return NXT_OK;
        }
    }

    msg = nxt_mem_cache_zalloc0(port->mem_pool, sizeof(nxt_port_send_msg_t));
    if (nxt_slow_path(msg == NULL)) {
        return NXT_ERROR;
    }

    msg->buf = b;
    msg->fd = fd;
    msg->share = 0;

    msg->port_msg.stream = stream;
    msg->port_msg.type = type;
    msg->port_msg.last = 0;

    nxt_queue_insert_tail(&port->messages, &msg->link);

    if (port->socket.write_ready) {
        nxt_port_write_handler(task, port, NULL);
    }

    return NXT_OK;
}


static void
nxt_port_write_handler(nxt_task_t *task, void *obj, void *data)
{
    ssize_t                 n;
    nxt_uint_t              niov;
    nxt_port_t              *port;
    struct iovec            iov[NXT_IOBUF_MAX];
    nxt_queue_link_t        *link;
    nxt_port_send_msg_t     *msg;
    nxt_sendbuf_coalesce_t  sb;

    port = obj;

    do {
        link = nxt_queue_first(&port->messages);

        if (link == nxt_queue_tail(&port->messages)) {
            nxt_fd_event_block_write(task->thread->engine, &port->socket);
            return;
        }

        msg = (nxt_port_send_msg_t *) link;

        iov[0].iov_base = &msg->port_msg;
        iov[0].iov_len = sizeof(nxt_port_msg_t);

        sb.buf = msg->buf;
        sb.iobuf = &iov[1];
        sb.nmax = NXT_IOBUF_MAX - 1;
        sb.sync = 0;
        sb.last = 0;
        sb.size = sizeof(nxt_port_msg_t);
        sb.limit = port->max_size;

        niov = nxt_sendbuf_mem_coalesce(task, &sb);

        msg->port_msg.last = sb.last;

        n = nxt_socketpair_send(&port->socket, msg->fd, iov, niov + 1);

        if (n > 0) {
            if (nxt_slow_path((size_t) n != sb.size)) {
                nxt_log(task, NXT_LOG_CRIT,
                        "port %d: short write: %z instead of %uz",
                        port->socket.fd, n, sb.size);
                goto fail;
            }

            msg->buf = nxt_sendbuf_completion(task,
                                              port->socket.write_work_queue,
                                              msg->buf,
                                              n - sizeof(nxt_port_msg_t));

            if (msg->buf != NULL) {
                /*
                 * A file descriptor is sent only
                 * in the first message of a stream.
                 */
                msg->fd = -1;
                msg->share += n;

                if (msg->share >= port->max_share) {
                    msg->share = 0;
                    nxt_queue_remove(link);
                    nxt_queue_insert_tail(&port->messages, link);
                }

            } else {
                nxt_queue_remove(link);
                nxt_mem_cache_free0(port->mem_pool, msg,
                                    sizeof(nxt_port_send_msg_t));
            }

        } else if (nxt_slow_path(n == NXT_ERROR)) {
            goto fail;
        }

        /* n == NXT_AGAIN */

    } while (port->socket.write_ready);

    if (nxt_fd_event_is_disabled(port->socket.write)) {
        nxt_fd_event_enable_write(task->thread->engine, &port->socket);
    }

    return;

fail:

    nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                       nxt_port_error_handler, task, &port->socket, NULL);
}


void
nxt_port_read_enable(nxt_task_t *task, nxt_port_t *port)
{
    port->socket.fd = port->pair[0];
    port->socket.log = &nxt_main_log;

    port->socket.read_work_queue = &task->thread->engine->fast_work_queue;
    port->socket.read_handler = nxt_port_read_handler;
    port->socket.error_handler = nxt_port_error_handler;

    nxt_fd_event_enable_read(task->thread->engine, &port->socket);
}


void
nxt_port_read_close(nxt_port_t *port)
{
    nxt_socket_close(port->socket.task, port->pair[0]);
    port->pair[0] = -1;
}


static void
nxt_port_read_handler(nxt_task_t *task, void *obj, void *data)
{
    ssize_t         n;
    nxt_fd_t        fd;
    nxt_buf_t       *b;
    nxt_port_t      *port;
    struct iovec    iov[2];
    nxt_port_msg_t  msg;

    port = obj;

    for ( ;; ) {

        b = nxt_port_buf_alloc(port);

        if (nxt_slow_path(b == NULL)) {
            /* TODO: disable event for some time */
        }

        iov[0].iov_base = &msg;
        iov[0].iov_len = sizeof(nxt_port_msg_t);

        iov[1].iov_base = b->mem.pos;
        iov[1].iov_len = port->max_size;

        n = nxt_socketpair_recv(&port->socket, &fd, iov, 2);

        if (n > 0) {
            nxt_port_read_msg_process(task, port, &msg, fd, b, n);

            if (b->mem.pos == b->mem.free) {

                if (b->next != NULL) {
                    /* A sync buffer */
                    nxt_buf_free(port->mem_pool, b->next);
                }

                nxt_port_buf_free(port, b);
            }

            if (port->socket.read_ready) {
                continue;
            }

            return;
        }

        if (n == NXT_AGAIN) {
            nxt_port_buf_free(port, b);

            nxt_fd_event_enable_read(task->thread->engine, &port->socket);
            return;
        }

        /* n == 0 || n == NXT_ERROR */

        nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                           nxt_port_error_handler, task, &port->socket, NULL);
        return;
    }
}


static void
nxt_port_read_msg_process(nxt_task_t *task, nxt_port_t *port,
    nxt_port_msg_t *msg, nxt_fd_t fd, nxt_buf_t *b, size_t size)
{
    nxt_buf_t            *sync;
    nxt_port_recv_msg_t  recv_msg;

    if (nxt_slow_path(size < sizeof(nxt_port_msg_t))) {
        nxt_log(port->socket.task, NXT_LOG_CRIT,
                "port %d: too small message:%uz", port->socket.fd, size);
        goto fail;
    }

    recv_msg.stream = msg->stream;
    recv_msg.type = msg->type;
    recv_msg.fd = fd;
    recv_msg.buf = b;
    recv_msg.port = port;

    b->mem.free += size - sizeof(nxt_port_msg_t);

    if (msg->last) {
        sync = nxt_buf_sync_alloc(port->mem_pool, NXT_BUF_SYNC_LAST);
        if (nxt_slow_path(sync == NULL)) {
            goto fail;
        }

        b->next = sync;
    }

    port->handler(task, &recv_msg);

    return;

fail:

    if (fd != -1) {
        nxt_fd_close(fd);
    }
}


static nxt_buf_t *
nxt_port_buf_alloc(nxt_port_t *port)
{
    nxt_buf_t  *b;

    if (port->free_bufs != NULL) {
        b = port->free_bufs;
        port->free_bufs = b->next;

        b->mem.pos = b->mem.start;
        b->mem.free = b->mem.start;

    } else {
        b = nxt_buf_mem_alloc(port->mem_pool, port->max_size, 0);
        if (nxt_slow_path(b == NULL)) {
            return NULL;
        }
    }

    return b;
}


static void
nxt_port_buf_free(nxt_port_t *port, nxt_buf_t *b)
{
    b->next = port->free_bufs;
    port->free_bufs = b;
}


static void
nxt_port_error_handler(nxt_task_t *task, void *obj, void *data)
{
    /* TODO */
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void nxt_port_write_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_port_read_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_port_read_msg_process(nxt_task_t *task, nxt_port_t *port,
    nxt_port_recv_msg_t *msg, size_t size);
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
    nxt_fd_t fd, uint32_t stream, nxt_port_id_t reply_port, nxt_buf_t *b)
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
    msg->port_msg.pid = nxt_pid;
    msg->port_msg.reply_port = reply_port;
    msg->port_msg.type = type;
    msg->port_msg.last = 0;
    msg->port_msg.mmap = 0;

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
    nxt_port_t              *port;
    struct iovec            iov[NXT_IOBUF_MAX];
    nxt_queue_link_t        *link;
    nxt_port_send_msg_t     *msg;
    nxt_sendbuf_coalesce_t  sb;
    nxt_port_method_t       m;

    size_t                  plain_size;
    nxt_buf_t               *plain_buf;

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
        sb.size = 0;
        sb.limit = port->max_size;

        m = nxt_port_mmap_get_method(task, port, msg->buf);

        if (m == NXT_PORT_METHOD_MMAP) {
            sb.limit = (1ULL << 31) - 1;
        }

        nxt_sendbuf_mem_coalesce(task, &sb);

        plain_size = sb.size;
        plain_buf = msg->buf;

        /*
         * Send through mmap enabled only when payload
         * is bigger than PORT_MMAP_MIN_SIZE.
         */
        if (m == NXT_PORT_METHOD_MMAP && plain_size > PORT_MMAP_MIN_SIZE) {
            nxt_port_mmap_write(task, port, msg, &sb);

        } else {
            m = NXT_PORT_METHOD_PLAIN;
        }

        msg->port_msg.last = sb.last;

        n = nxt_socketpair_send(&port->socket, msg->fd, iov, sb.niov + 1);

        if (n > 0) {
            if (nxt_slow_path((size_t) n != sb.size + iov[0].iov_len)) {
                nxt_log(task, NXT_LOG_CRIT,
                        "port %d: short write: %z instead of %uz",
                        port->socket.fd, n, sb.size + iov[0].iov_len);
                goto fail;
            }

            if (msg->buf != plain_buf) {
                /*
                 * Complete crafted mmap_msgs buf and restore msg->buf
                 * for regular completion call.
                 */
                nxt_port_mmap_completion(task,
                                         port->socket.write_work_queue,
                                         msg->buf);

                msg->buf = plain_buf;
            }

            msg->buf = nxt_sendbuf_completion(task,
                                              port->socket.write_work_queue,
                                              msg->buf,
                                              plain_size);

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
    ssize_t              n;
    nxt_buf_t            *b;
    nxt_port_t           *port;
    struct iovec         iov[2];
    nxt_port_recv_msg_t  msg;

    port = msg.port = obj;

    for ( ;; ) {

        b = nxt_port_buf_alloc(port);

        if (nxt_slow_path(b == NULL)) {
            /* TODO: disable event for some time */
        }

        iov[0].iov_base = &msg.port_msg;
        iov[0].iov_len = sizeof(nxt_port_msg_t);

        iov[1].iov_base = b->mem.pos;
        iov[1].iov_len = port->max_size;

        n = nxt_socketpair_recv(&port->socket, &msg.fd, iov, 2);

        if (n > 0) {

            msg.buf = b;

            nxt_port_read_msg_process(task, port, &msg, n);

            if (b->mem.pos == b->mem.free) {
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
    nxt_port_recv_msg_t *msg, size_t size)
{
    nxt_buf_t  *b;
    nxt_buf_t  *orig_b;
    nxt_buf_t  **last_next;

    if (nxt_slow_path(size < sizeof(nxt_port_msg_t))) {
        nxt_log(port->socket.task, NXT_LOG_CRIT,
                "port %d: too small message:%uz", port->socket.fd, size);
        goto fail;
    }

    /* adjust size to actual buffer used size */
    size -= sizeof(nxt_port_msg_t);

    b = orig_b = msg->buf;
    b->mem.free += size;

    if (msg->port_msg.mmap) {
        nxt_port_mmap_read(task, port, msg, size);
        b = msg->buf;
    }

    last_next = &b->next;

    if (msg->port_msg.last) {
        /* find reference to last next, the NULL one */
        while (*last_next) {
            last_next = &(*last_next)->next;
        }

        *last_next = nxt_buf_sync_alloc(port->mem_pool, NXT_BUF_SYNC_LAST);
        if (nxt_slow_path(*last_next == NULL)) {
            goto fail;
        }
    }

    port->handler(task, msg);

    if (*last_next != NULL) {
        /* A sync buffer */
        nxt_buf_free(port->mem_pool, *last_next);
        *last_next = NULL;
    }

    if (orig_b != b) {
        /* complete mmap buffers */
        for (; b && nxt_buf_used_size(b) == 0;
            b = b->next) {
            nxt_debug(task, "complete buffer %p", b);

            nxt_work_queue_add(port->socket.read_work_queue,
                b->completion_handler, task, b, b->parent);
        }
    }

    return;

fail:

    if (msg->fd != -1) {
        nxt_fd_close(msg->fd);
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
        b->next = NULL;

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

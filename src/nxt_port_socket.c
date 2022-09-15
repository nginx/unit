
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_socket_msg.h>
#include <nxt_port_queue.h>
#include <nxt_port_memory_int.h>


#define NXT_PORT_MAX_ENQUEUE_BUF_SIZE \
          (int) (NXT_PORT_QUEUE_MSG_SIZE - sizeof(nxt_port_msg_t))


static nxt_bool_t nxt_port_can_enqueue_buf(nxt_buf_t *b);
static uint8_t nxt_port_enqueue_buf(nxt_task_t *task, nxt_port_msg_t *pm,
    void *qbuf, nxt_buf_t *b);
static nxt_int_t nxt_port_msg_chk_insert(nxt_task_t *task, nxt_port_t *port,
    nxt_port_send_msg_t *msg);
static nxt_port_send_msg_t *nxt_port_msg_alloc(const nxt_port_send_msg_t *m);
static void nxt_port_write_handler(nxt_task_t *task, void *obj, void *data);
static nxt_port_send_msg_t *nxt_port_msg_first(nxt_port_t *port);
nxt_inline void nxt_port_msg_close_fd(nxt_port_send_msg_t *msg);
nxt_inline void nxt_port_close_fds(nxt_fd_t *fd);
static nxt_buf_t *nxt_port_buf_completion(nxt_task_t *task,
    nxt_work_queue_t *wq, nxt_buf_t *b, size_t sent, nxt_bool_t mmap_mode);
static nxt_port_send_msg_t *nxt_port_msg_insert_tail(nxt_port_t *port,
    nxt_port_send_msg_t *msg);
static void nxt_port_read_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_port_queue_read_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_port_read_msg_process(nxt_task_t *task, nxt_port_t *port,
    nxt_port_recv_msg_t *msg);
static nxt_buf_t *nxt_port_buf_alloc(nxt_port_t *port);
static void nxt_port_buf_free(nxt_port_t *port, nxt_buf_t *b);
static void nxt_port_error_handler(nxt_task_t *task, void *obj, void *data);


nxt_int_t
nxt_port_socket_init(nxt_task_t *task, nxt_port_t *port, size_t max_size)
{
    nxt_int_t     sndbuf, rcvbuf, size;
    nxt_socket_t  snd, rcv;

    port->socket.task = task;

    port->pair[0] = -1;
    port->pair[1] = -1;

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

    return NXT_ERROR;
}


void
nxt_port_destroy(nxt_port_t *port)
{
    nxt_socket_close(port->socket.task, port->socket.fd);
    nxt_mp_destroy(port->mem_pool);
}


void
nxt_port_write_enable(nxt_task_t *task, nxt_port_t *port)
{
    port->socket.fd = port->pair[1];
    port->socket.log = &nxt_main_log;
    port->socket.write_ready = 1;

    port->engine = task->thread->engine;

    port->socket.write_work_queue = &port->engine->fast_work_queue;
    port->socket.write_handler = nxt_port_write_handler;
    port->socket.error_handler = nxt_port_error_handler;
}


void
nxt_port_write_close(nxt_port_t *port)
{
    nxt_socket_close(port->socket.task, port->pair[1]);
    port->pair[1] = -1;
}


static void
nxt_port_release_send_msg(nxt_port_send_msg_t *msg)
{
    if (msg->allocated) {
        nxt_free(msg);
    }
}


nxt_int_t
nxt_port_socket_write2(nxt_task_t *task, nxt_port_t *port, nxt_uint_t type,
    nxt_fd_t fd, nxt_fd_t fd2, uint32_t stream, nxt_port_id_t reply_port,
    nxt_buf_t *b)
{
    int                  notify;
    uint8_t              qmsg_size;
    nxt_int_t            res;
    nxt_port_send_msg_t  msg;
    struct {
        nxt_port_msg_t   pm;
        uint8_t          buf[NXT_PORT_MAX_ENQUEUE_BUF_SIZE];
    } qmsg;

    msg.link.next = NULL;
    msg.link.prev = NULL;

    msg.buf = b;
    msg.share = 0;
    msg.fd[0] = fd;
    msg.fd[1] = fd2;
    msg.close_fd = (type & NXT_PORT_MSG_CLOSE_FD) != 0;
    msg.allocated = 0;

    msg.port_msg.stream = stream;
    msg.port_msg.pid = nxt_pid;
    msg.port_msg.reply_port = reply_port;
    msg.port_msg.type = type & NXT_PORT_MSG_MASK;
    msg.port_msg.last = (type & NXT_PORT_MSG_LAST) != 0;
    msg.port_msg.mmap = 0;
    msg.port_msg.nf = 0;
    msg.port_msg.mf = 0;

    if (port->queue != NULL && type != _NXT_PORT_MSG_READ_QUEUE) {

        if (fd == -1 && nxt_port_can_enqueue_buf(b)) {
            qmsg.pm = msg.port_msg;

            qmsg_size = sizeof(qmsg.pm);

            if (b != NULL) {
                qmsg_size += nxt_port_enqueue_buf(task, &qmsg.pm, qmsg.buf, b);
            }

            res = nxt_port_queue_send(port->queue, &qmsg, qmsg_size, &notify);

            nxt_debug(task, "port{%d,%d} %d: enqueue %d notify %d, %d",
                      (int) port->pid, (int) port->id, port->socket.fd,
                      (int) qmsg_size, notify, res);

            if (b != NULL && nxt_fast_path(res == NXT_OK)) {
                if (qmsg.pm.mmap) {
                    b->is_port_mmap_sent = 1;
                }

                b->mem.pos = b->mem.free;

                nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                                   b->completion_handler, task, b, b->parent);
            }

            if (notify == 0) {
                return res;
            }

            msg.port_msg.type = _NXT_PORT_MSG_READ_QUEUE;
            msg.buf = NULL;

        } else {
            qmsg.buf[0] = _NXT_PORT_MSG_READ_SOCKET;

            res = nxt_port_queue_send(port->queue, qmsg.buf, 1, &notify);

            nxt_debug(task, "port{%d,%d} %d: enqueue 1 notify %d, %d",
                      (int) port->pid, (int) port->id, port->socket.fd,
                      notify, res);

            if (nxt_slow_path(res == NXT_AGAIN)) {
                return NXT_AGAIN;
            }
        }
    }

    res = nxt_port_msg_chk_insert(task, port, &msg);
    if (nxt_fast_path(res == NXT_DECLINED)) {
        nxt_port_write_handler(task, &port->socket, &msg);
        res = NXT_OK;
    }

    return res;
}


static nxt_bool_t
nxt_port_can_enqueue_buf(nxt_buf_t *b)
{
    if (b == NULL) {
        return 1;
    }

    if (b->next != NULL) {
        return 0;
    }

    return (nxt_buf_mem_used_size(&b->mem) <= NXT_PORT_MAX_ENQUEUE_BUF_SIZE
            || nxt_buf_is_port_mmap(b));
}


static uint8_t
nxt_port_enqueue_buf(nxt_task_t *task, nxt_port_msg_t *pm, void *qbuf,
    nxt_buf_t *b)
{
    ssize_t                  size;
    nxt_port_mmap_msg_t      *mm;
    nxt_port_mmap_header_t   *hdr;
    nxt_port_mmap_handler_t  *mmap_handler;

    size = nxt_buf_mem_used_size(&b->mem);

    if (size <= NXT_PORT_MAX_ENQUEUE_BUF_SIZE) {
        nxt_memcpy(qbuf, b->mem.pos, size);

        return size;
    }

    mmap_handler = b->parent;
    hdr = mmap_handler->hdr;
    mm = qbuf;

    mm->mmap_id = hdr->id;
    mm->chunk_id = nxt_port_mmap_chunk_id(hdr, b->mem.pos);
    mm->size = nxt_buf_mem_used_size(&b->mem);

    pm->mmap = 1;

    nxt_debug(task, "mmap_msg={%D, %D, %D}", mm->mmap_id, mm->chunk_id,
              mm->size);

    return sizeof(nxt_port_mmap_msg_t);
}


static nxt_int_t
nxt_port_msg_chk_insert(nxt_task_t *task, nxt_port_t *port,
    nxt_port_send_msg_t *msg)
{
    nxt_int_t  res;

    nxt_thread_mutex_lock(&port->write_mutex);

    if (nxt_fast_path(port->socket.write_ready
                      && nxt_queue_is_empty(&port->messages)))
    {
        res = NXT_DECLINED;

    } else {
        msg = nxt_port_msg_alloc(msg);

        if (nxt_fast_path(msg != NULL)) {
            nxt_queue_insert_tail(&port->messages, &msg->link);
            nxt_port_use(task, port, 1);
            res = NXT_OK;

        } else {
            res = NXT_ERROR;
        }
    }

    nxt_thread_mutex_unlock(&port->write_mutex);

    return res;
}


static nxt_port_send_msg_t *
nxt_port_msg_alloc(const nxt_port_send_msg_t *m)
{
    nxt_port_send_msg_t  *msg;

    msg = nxt_malloc(sizeof(nxt_port_send_msg_t));
    if (nxt_slow_path(msg == NULL)) {
        return NULL;
    }

    *msg = *m;

    msg->allocated = 1;

    return msg;
}


static void
nxt_port_fd_block_write(nxt_task_t *task, nxt_port_t *port, void *data)
{
    nxt_fd_event_block_write(task->thread->engine, &port->socket);
}


static void
nxt_port_fd_enable_write(nxt_task_t *task, nxt_port_t *port, void *data)
{
    nxt_fd_event_enable_write(task->thread->engine, &port->socket);
}


static void
nxt_port_write_handler(nxt_task_t *task, void *obj, void *data)
{
    int                     use_delta;
    size_t                  plain_size;
    ssize_t                 n;
    uint32_t                mmsg_buf[3 * NXT_IOBUF_MAX * 10];
    nxt_bool_t              block_write, enable_write;
    nxt_port_t              *port;
    struct iovec            iov[NXT_IOBUF_MAX * 10];
    nxt_work_queue_t        *wq;
    nxt_port_method_t       m;
    nxt_port_send_msg_t     *msg;
    nxt_sendbuf_coalesce_t  sb;

    port = nxt_container_of(obj, nxt_port_t, socket);

    block_write = 0;
    enable_write = 0;
    use_delta = 0;

    wq = &task->thread->engine->fast_work_queue;

    do {
        if (data) {
            msg = data;

        } else {
            msg = nxt_port_msg_first(port);

            if (msg == NULL) {
                block_write = 1;
                goto cleanup;
            }
        }

next_fragment:

        iov[0].iov_base = &msg->port_msg;
        iov[0].iov_len = sizeof(nxt_port_msg_t);

        sb.buf = msg->buf;
        sb.iobuf = &iov[1];
        sb.nmax = NXT_IOBUF_MAX - 1;
        sb.sync = 0;
        sb.last = 0;
        sb.size = 0;
        sb.limit = port->max_size;

        sb.limit_reached = 0;
        sb.nmax_reached = 0;

        m = nxt_port_mmap_get_method(task, port, msg->buf);

        if (m == NXT_PORT_METHOD_MMAP) {
            sb.limit = (1ULL << 31) - 1;
            sb.nmax = nxt_min(NXT_IOBUF_MAX * 10 - 1,
                              port->max_size / PORT_MMAP_MIN_SIZE);
        }

        sb.limit -= iov[0].iov_len;

        nxt_sendbuf_mem_coalesce(task, &sb);

        plain_size = sb.size;

        /*
         * Send through mmap enabled only when payload
         * is bigger than PORT_MMAP_MIN_SIZE.
         */
        if (m == NXT_PORT_METHOD_MMAP && plain_size > PORT_MMAP_MIN_SIZE) {
            nxt_port_mmap_write(task, port, msg, &sb, mmsg_buf);

        } else {
            m = NXT_PORT_METHOD_PLAIN;
        }

        msg->port_msg.last |= sb.last;
        msg->port_msg.mf = sb.limit_reached || sb.nmax_reached;

        n = nxt_socketpair_send(&port->socket, msg->fd, iov, sb.niov + 1);

        if (n > 0) {
            if (nxt_slow_path((size_t) n != sb.size + iov[0].iov_len)) {
                nxt_alert(task, "port %d: short write: %z instead of %uz",
                          port->socket.fd, n, sb.size + iov[0].iov_len);
                goto fail;
            }

            nxt_port_msg_close_fd(msg);

            msg->buf = nxt_port_buf_completion(task, wq, msg->buf, plain_size,
                                               m == NXT_PORT_METHOD_MMAP);

            if (msg->buf != NULL) {
                nxt_debug(task, "port %d: frag stream #%uD", port->socket.fd,
                          msg->port_msg.stream);

                /*
                 * A file descriptor is sent only
                 * in the first message of a stream.
                 */
                msg->fd[0] = -1;
                msg->fd[1] = -1;
                msg->share += n;
                msg->port_msg.nf = 1;

                if (msg->share >= port->max_share) {
                    msg->share = 0;

                    if (msg->link.next != NULL) {
                        nxt_thread_mutex_lock(&port->write_mutex);

                        nxt_queue_remove(&msg->link);
                        nxt_queue_insert_tail(&port->messages, &msg->link);

                        nxt_thread_mutex_unlock(&port->write_mutex);

                    } else {
                        msg = nxt_port_msg_insert_tail(port, msg);
                        if (nxt_slow_path(msg == NULL)) {
                            goto fail;
                        }

                        use_delta++;
                    }

                } else {
                    goto next_fragment;
                }

            } else {
                if (msg->link.next != NULL) {
                    nxt_thread_mutex_lock(&port->write_mutex);

                    nxt_queue_remove(&msg->link);
                    msg->link.next = NULL;

                    nxt_thread_mutex_unlock(&port->write_mutex);

                    use_delta--;
                }

                nxt_port_release_send_msg(msg);
            }

            if (data != NULL) {
                goto cleanup;
            }

        } else {
            if (nxt_slow_path(n == NXT_ERROR)) {
                if (msg->link.next == NULL) {
                    nxt_port_msg_close_fd(msg);

                    nxt_port_release_send_msg(msg);
                }

                goto fail;
            }

            if (msg->link.next == NULL) {
                msg = nxt_port_msg_insert_tail(port, msg);
                if (nxt_slow_path(msg == NULL)) {
                    goto fail;
                }

                use_delta++;
            }
        }

    } while (port->socket.write_ready);

    if (nxt_fd_event_is_disabled(port->socket.write)) {
        enable_write = 1;
    }

    goto cleanup;

fail:

    use_delta++;

    nxt_work_queue_add(wq, nxt_port_error_handler, task, &port->socket,
                       &port->socket);

cleanup:

    if (block_write && nxt_fd_event_is_active(port->socket.write)) {
        nxt_port_post(task, port, nxt_port_fd_block_write, NULL);
    }

    if (enable_write) {
        nxt_port_post(task, port, nxt_port_fd_enable_write, NULL);
    }

    if (use_delta != 0) {
        nxt_port_use(task, port, use_delta);
    }
}


static nxt_port_send_msg_t *
nxt_port_msg_first(nxt_port_t *port)
{
    nxt_queue_link_t     *lnk;
    nxt_port_send_msg_t  *msg;

    nxt_thread_mutex_lock(&port->write_mutex);

    lnk = nxt_queue_first(&port->messages);

    if (lnk == nxt_queue_tail(&port->messages)) {
        msg = NULL;

    } else {
        msg = nxt_queue_link_data(lnk, nxt_port_send_msg_t, link);
    }

    nxt_thread_mutex_unlock(&port->write_mutex);

    return msg;
}


nxt_inline void
nxt_port_msg_close_fd(nxt_port_send_msg_t *msg)
{
    if (!msg->close_fd) {
        return;
    }

    nxt_port_close_fds(msg->fd);
}


nxt_inline void
nxt_port_close_fds(nxt_fd_t *fd)
{
    if (fd[0] != -1) {
        nxt_fd_close(fd[0]);
        fd[0] = -1;
    }

    if (fd[1] != -1) {
        nxt_fd_close(fd[1]);
        fd[1] = -1;
    }
}


static nxt_buf_t *
nxt_port_buf_completion(nxt_task_t *task, nxt_work_queue_t *wq, nxt_buf_t *b,
    size_t sent, nxt_bool_t mmap_mode)
{
    size_t     size;
    nxt_buf_t  *next;

    while (b != NULL) {

        nxt_prefetch(b->next);

        if (!nxt_buf_is_sync(b)) {

            size = nxt_buf_used_size(b);

            if (size != 0) {

                if (sent == 0) {
                    break;
                }

                if (nxt_buf_is_port_mmap(b) && mmap_mode) {
                    /*
                     * buffer has been sent to other side which is now
                     * responsible for shared memory bucket release
                     */
                    b->is_port_mmap_sent = 1;
                }

                if (sent < size) {

                    if (nxt_buf_is_mem(b)) {
                        b->mem.pos += sent;
                    }

                    if (nxt_buf_is_file(b)) {
                        b->file_pos += sent;
                    }

                    break;
                }

                /* b->mem.free is NULL in file-only buffer. */
                b->mem.pos = b->mem.free;

                if (nxt_buf_is_file(b)) {
                    b->file_pos = b->file_end;
                }

                sent -= size;
            }
        }

        nxt_work_queue_add(wq, b->completion_handler, task, b, b->parent);

        next = b->next;
        b->next = NULL;
        b = next;
    }

    return b;
}


static nxt_port_send_msg_t *
nxt_port_msg_insert_tail(nxt_port_t *port, nxt_port_send_msg_t *msg)
{
    if (msg->allocated == 0) {
        msg = nxt_port_msg_alloc(msg);

        if (nxt_slow_path(msg == NULL)) {
            return NULL;
        }
    }

    nxt_thread_mutex_lock(&port->write_mutex);

    nxt_queue_insert_tail(&port->messages, &msg->link);

    nxt_thread_mutex_unlock(&port->write_mutex);

    return msg;
}


void
nxt_port_read_enable(nxt_task_t *task, nxt_port_t *port)
{
    port->socket.fd = port->pair[0];
    port->socket.log = &nxt_main_log;

    port->engine = task->thread->engine;

    port->socket.read_work_queue = &port->engine->fast_work_queue;
    port->socket.read_handler = port->queue != NULL
                                ? nxt_port_queue_read_handler
                                : nxt_port_read_handler;
    port->socket.error_handler = nxt_port_error_handler;

    nxt_fd_event_enable_read(port->engine, &port->socket);
}


void
nxt_port_read_close(nxt_port_t *port)
{
    port->socket.read_ready = 0;
    port->socket.read = NXT_EVENT_INACTIVE;
    nxt_socket_close(port->socket.task, port->pair[0]);
    port->pair[0] = -1;
}


static void
nxt_port_read_handler(nxt_task_t *task, void *obj, void *data)
{
    ssize_t              n;
    nxt_buf_t            *b;
    nxt_int_t            ret;
    nxt_port_t           *port;
    nxt_recv_oob_t       oob;
    nxt_port_recv_msg_t  msg;
    struct iovec         iov[2];

    port = msg.port = nxt_container_of(obj, nxt_port_t, socket);

    nxt_assert(port->engine == task->thread->engine);

    for ( ;; ) {
        b = nxt_port_buf_alloc(port);

        if (nxt_slow_path(b == NULL)) {
            /* TODO: disable event for some time */
        }

        iov[0].iov_base = &msg.port_msg;
        iov[0].iov_len = sizeof(nxt_port_msg_t);

        iov[1].iov_base = b->mem.pos;
        iov[1].iov_len = port->max_size;

        n = nxt_socketpair_recv(&port->socket, iov, 2, &oob);

        if (n > 0) {
            msg.fd[0] = -1;
            msg.fd[1] = -1;

            ret = nxt_socket_msg_oob_get(&oob, msg.fd,
                                         nxt_recv_msg_cmsg_pid_ref(&msg));
            if (nxt_slow_path(ret != NXT_OK)) {
                nxt_alert(task, "failed to get oob data from %d",
                          port->socket.fd);

                nxt_port_close_fds(msg.fd);

                goto fail;
            }

            msg.buf = b;
            msg.size = n;

            nxt_port_read_msg_process(task, port, &msg);

            /*
             * To disable instant completion or buffer re-usage,
             * handler should reset 'msg.buf'.
             */
            if (msg.buf == b) {
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

fail:
        /* n == 0 || error  */
        nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                           nxt_port_error_handler, task, &port->socket, NULL);
        return;
    }
}


static void
nxt_port_queue_read_handler(nxt_task_t *task, void *obj, void *data)
{
    ssize_t              n;
    nxt_buf_t            *b;
    nxt_int_t            ret;
    nxt_port_t           *port;
    struct iovec         iov[2];
    nxt_recv_oob_t       oob;
    nxt_port_queue_t     *queue;
    nxt_port_recv_msg_t  msg, *smsg;
    uint8_t              qmsg[NXT_PORT_QUEUE_MSG_SIZE];

    port = nxt_container_of(obj, nxt_port_t, socket);
    msg.port = port;

    nxt_assert(port->engine == task->thread->engine);

    queue = port->queue;
    nxt_atomic_fetch_add(&queue->nitems, 1);

    for ( ;; ) {

        if (port->from_socket == 0) {
            n = nxt_port_queue_recv(queue, qmsg);

            if (n < 0 && !port->socket.read_ready) {
                nxt_atomic_fetch_add(&queue->nitems, -1);

                n = nxt_port_queue_recv(queue, qmsg);
                if (n < 0) {
                    return;
                }

                nxt_atomic_fetch_add(&queue->nitems, 1);
            }

            if (n == 1 && qmsg[0] == _NXT_PORT_MSG_READ_SOCKET) {
                port->from_socket++;

                nxt_debug(task, "port{%d,%d} %d: dequeue 1 read_socket %d",
                          (int) port->pid, (int) port->id, port->socket.fd,
                          port->from_socket);

                continue;
            }

            nxt_debug(task, "port{%d,%d} %d: dequeue %d",
                      (int) port->pid, (int) port->id, port->socket.fd,
                      (int) n);

        } else {
            if ((smsg = port->socket_msg) != NULL && smsg->size != 0) {
                msg.port_msg = smsg->port_msg;
                b = smsg->buf;
                n = smsg->size;
                msg.fd[0] = smsg->fd[0];
                msg.fd[1] = smsg->fd[1];

                smsg->size = 0;

                port->from_socket--;

                nxt_debug(task, "port{%d,%d} %d: use suspended message %d",
                          (int) port->pid, (int) port->id, port->socket.fd,
                          (int) n);

                goto process;
            }

            n = -1;
        }

        if (n < 0 && !port->socket.read_ready) {
            nxt_atomic_fetch_add(&queue->nitems, -1);
            return;
        }

        b = nxt_port_buf_alloc(port);

        if (nxt_slow_path(b == NULL)) {
            /* TODO: disable event for some time */
        }

        if (n >= (ssize_t) sizeof(nxt_port_msg_t)) {
            nxt_memcpy(&msg.port_msg, qmsg, sizeof(nxt_port_msg_t));

            if (n > (ssize_t) sizeof(nxt_port_msg_t)) {
                nxt_memcpy(b->mem.pos, qmsg + sizeof(nxt_port_msg_t),
                           n - sizeof(nxt_port_msg_t));
            }

        } else {
            iov[0].iov_base = &msg.port_msg;
            iov[0].iov_len = sizeof(nxt_port_msg_t);

            iov[1].iov_base = b->mem.pos;
            iov[1].iov_len = port->max_size;

            n = nxt_socketpair_recv(&port->socket, iov, 2, &oob);

            if (n > 0) {
                msg.fd[0] = -1;
                msg.fd[1] = -1;

                ret = nxt_socket_msg_oob_get(&oob, msg.fd,
                                             nxt_recv_msg_cmsg_pid_ref(&msg));
                if (nxt_slow_path(ret != NXT_OK)) {
                    nxt_alert(task, "failed to get oob data from %d",
                              port->socket.fd);

                    nxt_port_close_fds(msg.fd);

                    return;
                }
            }

            if (n == (ssize_t) sizeof(nxt_port_msg_t)
                && msg.port_msg.type == _NXT_PORT_MSG_READ_QUEUE)
            {
                nxt_port_buf_free(port, b);

                nxt_debug(task, "port{%d,%d} %d: recv %d read_queue",
                          (int) port->pid, (int) port->id, port->socket.fd,
                          (int) n);

                continue;
            }

            nxt_debug(task, "port{%d,%d} %d: recvmsg %d",
                      (int) port->pid, (int) port->id, port->socket.fd,
                      (int) n);

            if (n > 0) {
                if (port->from_socket == 0) {
                    nxt_debug(task, "port{%d,%d} %d: suspend message %d",
                              (int) port->pid, (int) port->id, port->socket.fd,
                              (int) n);

                    smsg = port->socket_msg;

                    if (nxt_slow_path(smsg == NULL)) {
                        smsg = nxt_mp_alloc(port->mem_pool,
                                            sizeof(nxt_port_recv_msg_t));

                        if (nxt_slow_path(smsg == NULL)) {
                            nxt_alert(task, "port{%d,%d} %d: suspend message "
                                            "failed",
                                      (int) port->pid, (int) port->id,
                                      port->socket.fd);

                            return;
                        }

                        port->socket_msg = smsg;

                    } else {
                        if (nxt_slow_path(smsg->size != 0)) {
                            nxt_alert(task, "port{%d,%d} %d: too many suspend "
                                            "messages",
                                      (int) port->pid, (int) port->id,
                                      port->socket.fd);

                            return;
                        }
                    }

                    smsg->port_msg = msg.port_msg;
                    smsg->buf = b;
                    smsg->size = n;
                    smsg->fd[0] = msg.fd[0];
                    smsg->fd[1] = msg.fd[1];

                    continue;
                }

                port->from_socket--;
            }
        }

    process:

        if (n > 0) {
            msg.buf = b;
            msg.size = n;

            nxt_port_read_msg_process(task, port, &msg);

            /*
             * To disable instant completion or buffer re-usage,
             * handler should reset 'msg.buf'.
             */
            if (msg.buf == b) {
                nxt_port_buf_free(port, b);
            }

            continue;
        }

        if (n == NXT_AGAIN) {
            nxt_port_buf_free(port, b);

            nxt_fd_event_enable_read(task->thread->engine, &port->socket);

            continue;
        }

        /* n == 0 || n == NXT_ERROR */

        nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                           nxt_port_error_handler, task, &port->socket, NULL);
        return;
    }
}


typedef struct {
    uint32_t  stream;
    uint32_t  pid;
} nxt_port_frag_key_t;


static nxt_int_t
nxt_port_lvlhsh_frag_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_port_recv_msg_t  *fmsg;
    nxt_port_frag_key_t  *frag_key;

    fmsg = data;
    frag_key = (nxt_port_frag_key_t *) lhq->key.start;

    if (lhq->key.length == sizeof(nxt_port_frag_key_t)
        && frag_key->stream == fmsg->port_msg.stream
        && frag_key->pid == (uint32_t) fmsg->port_msg.pid)
    {
        return NXT_OK;
    }

    return NXT_DECLINED;
}


static void *
nxt_port_lvlhsh_frag_alloc(void *ctx, size_t size)
{
    return nxt_mp_align(ctx, size, size);
}


static void
nxt_port_lvlhsh_frag_free(void *ctx, void *p)
{
    nxt_mp_free(ctx, p);
}


static const nxt_lvlhsh_proto_t  lvlhsh_frag_proto  nxt_aligned(64) = {
    NXT_LVLHSH_DEFAULT,
    nxt_port_lvlhsh_frag_test,
    nxt_port_lvlhsh_frag_alloc,
    nxt_port_lvlhsh_frag_free,
};


static nxt_port_recv_msg_t *
nxt_port_frag_start(nxt_task_t *task, nxt_port_t *port,
    nxt_port_recv_msg_t *msg)
{
    nxt_int_t            res;
    nxt_lvlhsh_query_t   lhq;
    nxt_port_recv_msg_t  *fmsg;
    nxt_port_frag_key_t  frag_key;

    nxt_debug(task, "start frag stream #%uD", msg->port_msg.stream);

    fmsg = nxt_mp_alloc(port->mem_pool, sizeof(nxt_port_recv_msg_t));

    if (nxt_slow_path(fmsg == NULL)) {
        return NULL;
    }

    *fmsg = *msg;

    frag_key.stream = fmsg->port_msg.stream;
    frag_key.pid = fmsg->port_msg.pid;

    lhq.key_hash = nxt_murmur_hash2(&frag_key, sizeof(nxt_port_frag_key_t));
    lhq.key.length = sizeof(nxt_port_frag_key_t);
    lhq.key.start = (u_char *) &frag_key;
    lhq.proto = &lvlhsh_frag_proto;
    lhq.replace = 0;
    lhq.value = fmsg;
    lhq.pool = port->mem_pool;

    res = nxt_lvlhsh_insert(&port->frags, &lhq);

    switch (res) {

    case NXT_OK:
        return fmsg;

    case NXT_DECLINED:
        nxt_log(task, NXT_LOG_WARN, "duplicate frag stream #%uD",
                fmsg->port_msg.stream);
        nxt_mp_free(port->mem_pool, fmsg);

        return NULL;

    default:
        nxt_log(task, NXT_LOG_WARN, "failed to add frag stream #%uD",
                fmsg->port_msg.stream);

        nxt_mp_free(port->mem_pool, fmsg);

        return NULL;

    }
}


static nxt_port_recv_msg_t *
nxt_port_frag_find(nxt_task_t *task, nxt_port_t *port, nxt_port_recv_msg_t *msg)
{
    nxt_int_t            res;
    nxt_bool_t           last;
    nxt_lvlhsh_query_t   lhq;
    nxt_port_frag_key_t  frag_key;

    last = msg->port_msg.mf == 0;

    nxt_debug(task, "%s frag stream #%uD", last ? "last" : "next",
              msg->port_msg.stream);

    frag_key.stream = msg->port_msg.stream;
    frag_key.pid = msg->port_msg.pid;

    lhq.key_hash = nxt_murmur_hash2(&frag_key, sizeof(nxt_port_frag_key_t));
    lhq.key.length = sizeof(nxt_port_frag_key_t);
    lhq.key.start = (u_char *) &frag_key;
    lhq.proto = &lvlhsh_frag_proto;
    lhq.pool = port->mem_pool;

    res = last != 0 ? nxt_lvlhsh_delete(&port->frags, &lhq) :
          nxt_lvlhsh_find(&port->frags, &lhq);

    switch (res) {

    case NXT_OK:
        return lhq.value;

    default:
        nxt_log(task, NXT_LOG_INFO, "frag stream #%uD not found",
                frag_key.stream);

        return NULL;
    }
}


static void
nxt_port_read_msg_process(nxt_task_t *task, nxt_port_t *port,
    nxt_port_recv_msg_t *msg)
{
    nxt_buf_t            *b, *orig_b, *next;
    nxt_port_recv_msg_t  *fmsg;

    if (nxt_slow_path(msg->size < sizeof(nxt_port_msg_t))) {
        nxt_alert(task, "port %d: too small message:%uz",
                  port->socket.fd, msg->size);

        nxt_port_close_fds(msg->fd);

        return;
    }

    /* adjust size to actual buffer used size */
    msg->size -= sizeof(nxt_port_msg_t);

    b = orig_b = msg->buf;
    b->mem.free += msg->size;

    msg->cancelled = 0;

    if (nxt_slow_path(msg->port_msg.nf != 0)) {

        fmsg = nxt_port_frag_find(task, port, msg);

        if (nxt_slow_path(fmsg == NULL)) {
            goto fmsg_failed;
        }

        if (nxt_fast_path(fmsg->cancelled == 0)) {

            if (msg->port_msg.mmap) {
                nxt_port_mmap_read(task, msg);
            }

            nxt_buf_chain_add(&fmsg->buf, msg->buf);

            fmsg->size += msg->size;
            msg->buf = NULL;
            b = NULL;

            if (nxt_fast_path(msg->port_msg.mf == 0)) {

                b = fmsg->buf;

                port->handler(task, fmsg);

                msg->buf = fmsg->buf;
                msg->fd[0] = fmsg->fd[0];
                msg->fd[1] = fmsg->fd[1];

                /*
                 * To disable instant completion or buffer re-usage,
                 * handler should reset 'msg.buf'.
                 */
                if (!msg->port_msg.mmap && msg->buf == b) {
                    nxt_port_buf_free(port, b);
                }
            }
        }

        if (nxt_fast_path(msg->port_msg.mf == 0)) {
            nxt_mp_free(port->mem_pool, fmsg);
        }
    } else {
        if (nxt_slow_path(msg->port_msg.mf != 0)) {

            if (msg->port_msg.mmap && msg->cancelled == 0) {
                nxt_port_mmap_read(task, msg);
                b = msg->buf;
            }

            fmsg = nxt_port_frag_start(task, port, msg);

            if (nxt_slow_path(fmsg == NULL)) {
                goto fmsg_failed;
            }

            fmsg->port_msg.nf = 0;
            fmsg->port_msg.mf = 0;

            if (nxt_fast_path(msg->cancelled == 0)) {
                msg->buf = NULL;
                msg->fd[0] = -1;
                msg->fd[1] = -1;
                b = NULL;

            } else {
                nxt_port_close_fds(msg->fd);
            }
        } else {
            if (nxt_fast_path(msg->cancelled == 0)) {

                if (msg->port_msg.mmap) {
                    nxt_port_mmap_read(task, msg);
                    b = msg->buf;
                }

                port->handler(task, msg);
            }
        }
    }

fmsg_failed:

    if (msg->port_msg.mmap && orig_b != b) {

        /*
         * To disable instant buffer completion,
         * handler should reset 'msg->buf'.
         */
        if (msg->buf == b) {
            /* complete mmap buffers */
            while (b != NULL) {
                nxt_debug(task, "complete buffer %p", b);

                nxt_work_queue_add(port->socket.read_work_queue,
                    b->completion_handler, task, b, b->parent);

                next = b->next;
                b->next = NULL;
                b = next;
            }
        }

        /* restore original buf */
        msg->buf = orig_b;
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
    nxt_buf_chain_add(&b, port->free_bufs);
    port->free_bufs = b;
}


static void
nxt_port_error_handler(nxt_task_t *task, void *obj, void *data)
{
    int                  use_delta;
    nxt_buf_t            *b, *next;
    nxt_port_t           *port;
    nxt_work_queue_t     *wq;
    nxt_port_send_msg_t  *msg;

    nxt_debug(task, "port error handler %p", obj);
    /* TODO */

    port = nxt_container_of(obj, nxt_port_t, socket);

    use_delta = 0;

    if (obj == data) {
        use_delta--;
    }

    wq = &task->thread->engine->fast_work_queue;

    nxt_thread_mutex_lock(&port->write_mutex);

    nxt_queue_each(msg, &port->messages, nxt_port_send_msg_t, link) {

        nxt_port_msg_close_fd(msg);

        for (b = msg->buf; b != NULL; b = next) {
            next = b->next;
            b->next = NULL;

            if (nxt_buf_is_sync(b)) {
                continue;
            }

            nxt_work_queue_add(wq, b->completion_handler, task, b, b->parent);
        }

        nxt_queue_remove(&msg->link);
        use_delta--;

        nxt_port_release_send_msg(msg);

    } nxt_queue_loop;

    nxt_thread_mutex_unlock(&port->write_mutex);

    if (use_delta != 0) {
        nxt_port_use(task, port, use_delta);
    }
}

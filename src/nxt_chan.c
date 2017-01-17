
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void nxt_chan_write_handler(nxt_thread_t *thr, void *obj, void *data);
static void nxt_chan_read_handler(nxt_thread_t *thr, void *obj, void *data);
static void nxt_chan_read_msg_process(nxt_thread_t *thr, nxt_chan_t *chan,
    nxt_chan_msg_t *msg, nxt_fd_t fd, nxt_buf_t *b, size_t size);
static nxt_buf_t *nxt_chan_buf_alloc(nxt_chan_t *chan);
static void nxt_chan_buf_free(nxt_chan_t *chan, nxt_buf_t *b);
static void nxt_chan_error_handler(nxt_thread_t *thr, void *obj, void *data);


nxt_chan_t *
nxt_chan_alloc(void)
{
    nxt_chan_t      *chan;
    nxt_mem_pool_t  *mp;

    mp = nxt_mem_pool_create(1024);

    if (nxt_fast_path(mp != NULL)) {
        /* This allocation cannot fail. */
        chan = nxt_mem_zalloc(mp, sizeof(nxt_chan_t));
        chan->mem_pool = mp;

        chan->pair[0] = -1;
        chan->pair[1] = -1;

        nxt_queue_init(&chan->messages);

        return chan;
    }

    return NULL;
}


nxt_chan_t *
nxt_chan_create(size_t max_size)
{
    nxt_int_t     sndbuf, rcvbuf, size;
    nxt_chan_t    *chan;
    nxt_socket_t  snd, rcv;

    chan = nxt_chan_alloc();
    if (nxt_slow_path(chan == NULL)) {
        return NULL;
    }

    if (nxt_slow_path(nxt_socketpair_create(chan->pair) != NXT_OK)) {
        goto socketpair_fail;
    }

    snd = chan->pair[1];

    sndbuf = nxt_socket_getsockopt(snd, SOL_SOCKET, SO_SNDBUF);
    if (nxt_slow_path(sndbuf < 0)) {
        goto getsockopt_fail;
    }

    rcv = chan->pair[0];

    rcvbuf = nxt_socket_getsockopt(rcv, SOL_SOCKET, SO_RCVBUF);
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
        (void) nxt_socket_setsockopt(snd, SOL_SOCKET, SO_SNDBUF, max_size);

        sndbuf = nxt_socket_getsockopt(snd, SOL_SOCKET, SO_SNDBUF);
        if (nxt_slow_path(sndbuf < 0)) {
            goto getsockopt_fail;
        }

        size = sndbuf * 4;

        if (rcvbuf < size) {
            (void) nxt_socket_setsockopt(rcv, SOL_SOCKET, SO_RCVBUF, size);

            rcvbuf = nxt_socket_getsockopt(rcv, SOL_SOCKET, SO_RCVBUF);
            if (nxt_slow_path(rcvbuf < 0)) {
                goto getsockopt_fail;
            }
        }
    }

    chan->max_size = nxt_min(max_size, (size_t) sndbuf);
    chan->max_share = (64 * 1024);

    return chan;

getsockopt_fail:

    nxt_socket_close(chan->pair[0]);
    nxt_socket_close(chan->pair[1]);

socketpair_fail:

    nxt_mem_pool_destroy(chan->mem_pool);

    return NULL;
}


void
nxt_chan_destroy(nxt_chan_t *chan)
{
    nxt_socket_close(chan->socket.fd);
    nxt_mem_pool_destroy(chan->mem_pool);
}


void
nxt_chan_write_enable(nxt_thread_t *thr, nxt_chan_t *chan)
{
    chan->socket.fd = chan->pair[1];
    chan->socket.log = &nxt_main_log;
    chan->socket.write_ready = 1;

    chan->socket.write_work_queue = &thr->work_queue.main;
    chan->socket.write_handler = nxt_chan_write_handler;
    chan->socket.error_handler = nxt_chan_error_handler;
}


void
nxt_chan_write_close(nxt_chan_t *chan)
{
    nxt_socket_close(chan->pair[1]);
    chan->pair[1] = -1;
}


nxt_int_t
nxt_chan_write(nxt_chan_t *chan, nxt_uint_t type, nxt_fd_t fd, uint32_t stream,
    nxt_buf_t *b)
{
    nxt_thread_t         *thr;
    nxt_queue_link_t     *link;
    nxt_chan_send_msg_t  *msg;

    for (link = nxt_queue_first(&chan->messages);
         link != nxt_queue_tail(&chan->messages);
         link = nxt_queue_next(link))
    {
        msg = (nxt_chan_send_msg_t *) link;

        if (msg->chan_msg.stream == stream) {
            /*
             * An fd is ignored since a file descriptor
             * must be sent only in the first message of a stream.
             */
            nxt_buf_chain_add(&msg->buf, b);

            return NXT_OK;
        }
    }

    msg = nxt_mem_cache_zalloc0(chan->mem_pool, sizeof(nxt_chan_send_msg_t));
    if (nxt_slow_path(msg == NULL)) {
        return NXT_ERROR;
    }

    msg->buf = b;
    msg->fd = fd;
    msg->share = 0;

    msg->chan_msg.stream = stream;
    msg->chan_msg.type = type;
    msg->chan_msg.last = 0;

    nxt_queue_insert_tail(&chan->messages, &msg->link);

    if (chan->socket.write_ready) {
        thr = nxt_thread();
        nxt_chan_write_handler(thr, chan, NULL);
    }

    return NXT_OK;
}


static void
nxt_chan_write_handler(nxt_thread_t *thr, void *obj, void *data)
{
    ssize_t                 n;
    nxt_uint_t              niob;
    nxt_chan_t              *chan;
    struct iovec            iob[NXT_IOBUF_MAX];
    nxt_queue_link_t        *link;
    nxt_chan_send_msg_t     *msg;
    nxt_sendbuf_coalesce_t  sb;

    chan = obj;

    do {
        link = nxt_queue_first(&chan->messages);

        if (link == nxt_queue_tail(&chan->messages)) {
            nxt_event_fd_block_write(thr->engine, &chan->socket);
            return;
        }

        msg = (nxt_chan_send_msg_t *) link;

        nxt_iobuf_set(&iob[0], &msg->chan_msg, sizeof(nxt_chan_msg_t));

        sb.buf = msg->buf;
        sb.iobuf = &iob[1];
        sb.nmax = NXT_IOBUF_MAX - 1;
        sb.sync = 0;
        sb.last = 0;
        sb.size = sizeof(nxt_chan_msg_t);
        sb.limit = chan->max_size;

        niob = nxt_sendbuf_mem_coalesce(&sb);

        msg->chan_msg.last = sb.last;

        n = nxt_socketpair_send(&chan->socket, msg->fd, iob, niob + 1);

        if (n > 0) {
            if (nxt_slow_path((size_t) n != sb.size)) {
                nxt_log_alert(thr->log,
                              "chan %d: short write: %z instead of %uz",
                              chan->socket.fd, n, sb.size);
                goto fail;
            }

            msg->buf = nxt_sendbuf_completion(thr,
                                              chan->socket.write_work_queue,
                                              msg->buf,
                                              n - sizeof(nxt_chan_msg_t));

            if (msg->buf != NULL) {
                /*
                 * A file descriptor is sent only
                 * in the first message of a stream.
                 */
                msg->fd = -1;
                msg->share += n;

                if (msg->share >= chan->max_share) {
                    msg->share = 0;
                    nxt_queue_remove(link);
                    nxt_queue_insert_tail(&chan->messages, link);
                }

            } else {
                nxt_queue_remove(link);
                nxt_mem_cache_free0(chan->mem_pool, msg,
                                    sizeof(nxt_chan_send_msg_t));
            }

        } else if (nxt_slow_path(n == NXT_ERROR)) {
            goto fail;
        }

        /* n == NXT_AGAIN */

    } while (chan->socket.write_ready);

    if (nxt_event_fd_is_disabled(chan->socket.write)) {
        nxt_event_fd_enable_write(thr->engine, &chan->socket);
    }

    return;

fail:

    nxt_thread_work_queue_add(thr, &thr->work_queue.main,
                              nxt_chan_error_handler,
                              &chan->socket, NULL, chan->socket.log);
}


void
nxt_chan_read_enable(nxt_thread_t *thr, nxt_chan_t *chan)
{
    chan->socket.fd = chan->pair[0];
    chan->socket.log = &nxt_main_log;

    chan->socket.read_work_queue = &thr->work_queue.main;
    chan->socket.read_handler = nxt_chan_read_handler;
    chan->socket.error_handler = nxt_chan_error_handler;

    nxt_event_fd_enable_read(thr->engine, &chan->socket);
}


void
nxt_chan_read_close(nxt_chan_t *chan)
{
    nxt_socket_close(chan->pair[0]);
    chan->pair[0] = -1;
}


static void
nxt_chan_read_handler(nxt_thread_t *thr, void *obj, void *data)
{
    ssize_t         n;
    nxt_fd_t        fd;
    nxt_buf_t       *b;
    nxt_chan_t      *chan;
    nxt_iobuf_t     iob[2];
    nxt_chan_msg_t  msg;

    chan = obj;

    for ( ;; ) {

        b = nxt_chan_buf_alloc(chan);

        if (nxt_slow_path(b == NULL)) {
            /* TODO: disable event for some time */
        }

        nxt_iobuf_set(&iob[0], &msg, sizeof(nxt_chan_msg_t));
        nxt_iobuf_set(&iob[1], b->mem.pos, chan->max_size);

        n = nxt_socketpair_recv(&chan->socket, &fd, iob, 2);

        if (n > 0) {
            nxt_chan_read_msg_process(thr, chan, &msg, fd, b, n);

            if (b->mem.pos == b->mem.free) {

                if (b->next != NULL) {
                    /* A sync buffer */
                    nxt_buf_free(chan->mem_pool, b->next);
                }

                nxt_chan_buf_free(chan, b);
            }

            if (chan->socket.read_ready) {
                continue;
            }

            return;
        }

        if (n == NXT_AGAIN) {
            nxt_chan_buf_free(chan, b);

            nxt_event_fd_enable_read(thr->engine, &chan->socket);
            return;
        }

        /* n == 0 || n == NXT_ERROR */

        nxt_thread_work_queue_add(thr, &thr->work_queue.main,
                                  nxt_chan_error_handler,
                                  &chan->socket, NULL, chan->socket.log);
        return;
    }
}


static void
nxt_chan_read_msg_process(nxt_thread_t *thr, nxt_chan_t *chan,
    nxt_chan_msg_t *msg, nxt_fd_t fd, nxt_buf_t *b, size_t size)
{
    nxt_buf_t            *sync;
    nxt_chan_recv_msg_t  recv_msg;

    if (nxt_slow_path(size < sizeof(nxt_chan_msg_t))) {
        nxt_log_alert(chan->socket.log, "chan %d: too small message:%uz",
                      chan->socket.fd, size);
        goto fail;
    }

    recv_msg.stream = msg->stream;
    recv_msg.type = msg->type;
    recv_msg.fd = fd;
    recv_msg.buf = b;
    recv_msg.chan = chan;

    b->mem.free += size - sizeof(nxt_chan_msg_t);

    if (msg->last) {
        sync = nxt_buf_sync_alloc(chan->mem_pool, NXT_BUF_SYNC_LAST);
        if (nxt_slow_path(sync == NULL)) {
            goto fail;
        }

        b->next = sync;
    }

    chan->handler(thr, &recv_msg);

    return;

fail:

    if (fd != -1) {
        nxt_fd_close(fd);
    }
}


static nxt_buf_t *
nxt_chan_buf_alloc(nxt_chan_t *chan)
{
    nxt_buf_t  *b;

    if (chan->free_bufs != NULL) {
        b = chan->free_bufs;
        chan->free_bufs = b->next;

        b->mem.pos = b->mem.start;
        b->mem.free = b->mem.start;

    } else {
        b = nxt_buf_mem_alloc(chan->mem_pool, chan->max_size, 0);
        if (nxt_slow_path(b == NULL)) {
            return NULL;
        }
    }

    return b;
}


static void
nxt_chan_buf_free(nxt_chan_t *chan, nxt_buf_t *b)
{
    b->next = chan->free_bufs;
    chan->free_bufs = b;
}


static void
nxt_chan_error_handler(nxt_thread_t *thr, void *obj, void *data)
{
    /* TODO */
}

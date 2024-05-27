
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * sendfile() has been introduced in Linux 2.2.
 * It supported 32-bit offsets only.
 *
 * Linux 2.4.21 has introduced sendfile64().  However, even on 64-bit
 * platforms it returns EINVAL if the count argument is more than 2G-1 bytes.
 * In Linux 2.6.17 sendfile() has been internally changed to splice()
 * and this limitation has gone.
 */

#ifdef NXT_TEST_BUILD_LINUX_SENDFILE

#define MSG_NOSIGNAL      0x4000
#define MSG_MORE          0x8000

ssize_t nxt_linux_event_conn_io_sendfile(nxt_event_conn_t *c, nxt_buf_t *b,
    size_t limit);

static ssize_t nxt_sys_sendfile(int out_fd, int in_fd, off_t *offset,
    size_t count)
{
    return -1;
}

#else
#define nxt_sys_sendfile  sendfile
#endif


static ssize_t nxt_linux_send(nxt_event_conn_t *c, void *buf, size_t size,
    nxt_uint_t flags);
static ssize_t nxt_linux_sendmsg(nxt_event_conn_t *c,
    nxt_sendbuf_coalesce_t *sb, nxt_uint_t niov, nxt_uint_t flags);


ssize_t
nxt_linux_event_conn_io_sendfile(nxt_event_conn_t *c, nxt_buf_t *b,
    size_t limit)
{
    size_t                  size;
    ssize_t                 n;
    nxt_buf_t               *fb;
    nxt_err_t               err;
    nxt_off_t               offset;
    nxt_uint_t              niov, flags;
    struct iovec            iov[NXT_IOBUF_MAX];
    nxt_sendbuf_coalesce_t  sb;

    sb.buf = b;
    sb.iobuf = iov;
    sb.nmax = NXT_IOBUF_MAX;
    sb.sync = 0;
    sb.size = 0;
    sb.limit = limit;

    niov = nxt_sendbuf_mem_coalesce(c->socket.task, &sb);

    if (niov == 0 && sb.sync) {
        return 0;
    }

    fb = (sb.buf != NULL && nxt_buf_is_file(sb.buf)) ? sb.buf : NULL;

    if (niov != 0) {

        flags = MSG_NOSIGNAL;

        if (fb != NULL) {
            /*
             * The Linux-specific MSG_MORE flag is cheaper
             * than additional setsockopt(TCP_CORK) syscall.
             */
            flags |= MSG_MORE;
        }

        if (niov == 1) {
            /*
             * Disposal of surplus kernel msghdr
             * and iovec copy-in operations.
             */
            return nxt_linux_send(c, iov->iov_base, iov->iov_len, flags);
        }

        return nxt_linux_sendmsg(c, &sb, niov, flags);
    }

    size = nxt_sendbuf_file_coalesce(&sb);

    nxt_debug(c->socket.task, "sendfile(%d, %FD, @%O, %uz)",
              c->socket.fd, fb->file->fd, fb->file_pos, size);

    offset = fb->file_pos;

    n = nxt_sys_sendfile(c->socket.fd, fb->file->fd, &offset, size);

    err = (n == -1) ? nxt_errno : 0;

    nxt_debug(c->socket.task, "sendfile(): %z", n);

    if (n == -1) {
        switch (err) {

        case NXT_EAGAIN:
            c->socket.write_ready = 0;
            break;

        case NXT_EINTR:
            break;

        default:
            c->socket.error = err;
            nxt_log(c->socket.task, nxt_socket_error_level(err),
                    "sendfile(%d, %FD, %O, %uz) failed %E \"%FN\"",
                    c->socket.fd, fb->file->fd, fb->file_pos, size,
                    err, fb->file->name);

            return NXT_ERROR;
        }

        nxt_debug(c->socket.task, "sendfile() %E", err);

        return 0;
    }

    if (n < (ssize_t) size) {
        c->socket.write_ready = 0;
    }

    return n;
}


static ssize_t
nxt_linux_send(nxt_event_conn_t *c, void *buf, size_t size, nxt_uint_t flags)
{
    ssize_t    n;
    nxt_err_t  err;

    n = send(c->socket.fd, buf, size, flags);

    err = (n == -1) ? nxt_errno : 0;

    nxt_debug(c->socket.task, "send(%d, %p, %uz, 0x%uXi): %z",
              c->socket.fd, buf, size, flags, n);

    if (n == -1) {
        switch (err) {

        case NXT_EAGAIN:
            c->socket.write_ready = 0;
            break;

        case NXT_EINTR:
            break;

        default:
            c->socket.error = err;
            nxt_log(c->socket.task, nxt_socket_error_level(err),
                    "send(%d, %p, %uz, 0x%uXi) failed %E",
                    c->socket.fd, buf, size, flags, err);

            return NXT_ERROR;
        }

        nxt_debug(c->socket.task, "send() %E", err);

        return 0;
    }

    if (n < (ssize_t) size) {
        c->socket.write_ready = 0;
    }

    return n;
}


static ssize_t
nxt_linux_sendmsg(nxt_event_conn_t *c, nxt_sendbuf_coalesce_t *sb,
    nxt_uint_t niov, nxt_uint_t flags)
{
    ssize_t        n;
    nxt_err_t      err;
    struct msghdr  msg;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = sb->iobuf;
    msg.msg_iovlen = niov;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    n = sendmsg(c->socket.fd, &msg, flags);

    err = (n == -1) ? nxt_errno : 0;

    nxt_debug(c->socket.task, "sendmsg(%d, %ui, 0x%uXi): %z",
              c->socket.fd, niov, flags, n);

    if (n == -1) {
        switch (err) {

        case NXT_EAGAIN:
            c->socket.write_ready = 0;
            break;

        case NXT_EINTR:
            break;

        default:
            c->socket.error = err;
            nxt_log(c->socket.task, nxt_socket_error_level(err),
                    "sendmsg(%d, %ui, 0x%uXi) failed %E",
                    c->socket.fd, niov, flags, err);

            return NXT_ERROR;
        }

        nxt_debug(c->socket.task, "sendmsg() %E", err);

        return 0;
    }

    if (n < (ssize_t) sb->size) {
        c->socket.write_ready = 0;
    }

    return n;
}

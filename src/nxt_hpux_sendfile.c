
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


#ifdef NXT_TEST_BUILD_HPUX_SENDFILE

ssize_t nxt_hpux_event_conn_io_sendfile(nxt_event_conn_t *c, nxt_buf_t *b,
    size_t limit);

static ssize_t nxt_sys_sendfile(int s, int fd, off_t offset, size_t nbytes,
    const struct iovec *hdtrl, int flags)
{
    return -1;
}

#else

/* sendfile() is not declared if _XOPEN_SOURCE_EXTENDED is defined. */

sbsize_t sendfile(int s, int fd, off_t offset, bsize_t nbytes,
    const struct iovec *hdtrl, int flags);

#define nxt_sys_sendfile  sendfile

#endif


ssize_t
nxt_hpux_event_conn_io_sendfile(nxt_event_conn_t *c, nxt_buf_t *b, size_t limit)
{
    size_t                  file_size;
    ssize_t                 n;
    nxt_buf_t               *fb;
    nxt_err_t               err;
    nxt_uint_t              nhd, ntr;
    struct iovec            iov[NXT_IOBUF_MAX], *hdtrl;
    nxt_sendbuf_coalesce_t  sb;

    sb.buf = b;
    sb.iobuf = iov;
    sb.nmax = NXT_IOBUF_MAX;
    sb.sync = 0;
    sb.size = 0;
    sb.limit = limit;

    nhd = nxt_sendbuf_mem_coalesce(c->socket.task, &sb);

    if (nhd == 0 && sb.sync) {
        return 0;
    }

    if (nhd > 1 || sb.buf == NULL || !nxt_buf_is_file(sb.buf)) {
        return nxt_event_conn_io_writev(c, iov, nhd);
    }

    fb = sb.buf;

    file_size = nxt_sendbuf_file_coalesce(&sb);

    if (file_size == 0) {
        return nxt_event_conn_io_writev(c, iov, nhd);
    }

    sb.iobuf = &iov[1];
    sb.nmax = 1;

    ntr = nxt_sendbuf_mem_coalesce(c->socket.task, &sb);

    /*
     * Disposal of surplus kernel operations
     * if there are no headers and trailers.
     */

    if (nhd == 0) {
        hdtrl = NULL;
        iov[0].iov_base = NULL;
        iov[0].iov_len = 0;

    } else {
        hdtrl = iov;
    }

    if (ntr == 0) {
        iov[1].iov_base = NULL;
        iov[1].iov_len = 0;

    } else {
        hdtrl = iov;
    }

    nxt_debug(c->socket.task, "sendfile(%d, %FD, @%O, %uz) hd:%ui tr:%ui",
                  c->socket.fd, fb->file->fd, fb->file_pos, file_size,
                  nhd, ntr);

    n = nxt_sys_sendfile(c->socket.fd, fb->file->fd, fb->file_pos,
                         file_size, hdtrl, 0);

    err = (n == -1) ? nxt_errno : 0;

    nxt_debug(c->socket.task, "sendfile(): %uz", n);

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
                    "sendfile(%d, %FD, @%O, %uz) failed \"%FN\" hd:%ui tr:%ui",
                    c->socket.fd, fb->file_pos, file_size, &fb->file->name,
                    nhd, ntr);

            return NXT_ERROR;
        }

        nxt_debug(c->socket.task, "sendfile() %E", err);

        return 0;
    }

    if (n < (ssize_t) sb.size) {
        c->socket.write_ready = 0;
    }

    return n;
}

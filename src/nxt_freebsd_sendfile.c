
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * sendfile() has been introduced in FreeBSD 3.1,
 * however, early implementation had various bugs.
 * This code supports FreeBSD 5.0 implementation.
 */

#ifdef NXT_TEST_BUILD_FREEBSD_SENDFILE

ssize_t nxt_freebsd_event_conn_io_sendfile(nxt_event_conn_t *c, nxt_buf_t *b,
    size_t limit);

static int nxt_sys_sendfile(int fd, int s, off_t offset, size_t nbytes,
    struct sf_hdtr *hdtr, off_t *sbytes, int flags)
{
    return -1;
}

#else
#define nxt_sys_sendfile  sendfile
#endif


ssize_t
nxt_freebsd_event_conn_io_sendfile(nxt_event_conn_t *c, nxt_buf_t *b,
    size_t limit)
{
    size_t                  file_size;
    ssize_t                 n;
    nxt_buf_t               *fb;
    nxt_err_t               err;
    nxt_off_t               sent;
    nxt_uint_t              nhd, ntr;
    struct iovec            hd[NXT_IOBUF_MAX], tr[NXT_IOBUF_MAX];
    struct sf_hdtr          hdtr, *ht;
    nxt_sendbuf_coalesce_t  sb;

    sb.buf = b;
    sb.iobuf = hd;
    sb.nmax = NXT_IOBUF_MAX;
    sb.sync = 0;
    sb.size = 0;
    sb.limit = limit;

    nhd = nxt_sendbuf_mem_coalesce(c->socket.task, &sb);

    if (nhd == 0 && sb.sync) {
        return 0;
    }

    if (sb.buf == NULL || !nxt_buf_is_file(sb.buf)) {
        return nxt_event_conn_io_writev(c, hd, nhd);
    }

    fb = sb.buf;

    file_size = nxt_sendbuf_file_coalesce(&sb);

    if (file_size == 0) {
        return nxt_event_conn_io_writev(c, hd, nhd);
    }

    sb.iobuf = tr;

    ntr = nxt_sendbuf_mem_coalesce(c->socket.task, &sb);

    /*
     * Disposal of surplus kernel operations
     * if there are no headers or trailers.
     */

    ht = NULL;
    nxt_memzero(&hdtr, sizeof(struct sf_hdtr));

    if (nhd != 0) {
        ht = &hdtr;
        hdtr.headers = hd;
        hdtr.hdr_cnt = nhd;
    }

    if (ntr != 0) {
        ht = &hdtr;
        hdtr.trailers = tr;
        hdtr.trl_cnt = ntr;
    }

    nxt_debug(c->socket.task, "sendfile(%FD, %d, @%O, %uz) hd:%ui tr:%ui",
                  fb->file->fd, c->socket.fd, fb->file_pos, file_size,
                  nhd, ntr);

    sent = 0;
    n = nxt_sys_sendfile(fb->file->fd, c->socket.fd, fb->file_pos,
                         file_size, ht, &sent, 0);

    err = (n == -1) ? nxt_errno : 0;

    nxt_debug(c->socket.task, "sendfile(): %d sent:%O", n, sent);

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
                "sendfile(%FD, %d, %O, %uz) failed %E \"%FN\" hd:%ui tr:%ui",
                fb->file->fd, c->socket.fd, fb->file_pos, file_size, err,
                fb->file->name, nhd, ntr);

            return NXT_ERROR;
        }

        nxt_debug(c->socket.task, "sendfile() %E", err);

        return sent;

    } else if (sent == 0) {
        nxt_log(c->socket.task, NXT_LOG_ERR,
                "file \"%FN\" was truncated while sendfile()", fb->file->name);

        return NXT_ERROR;
    }

    if (sent < (nxt_off_t) sb.size) {
        c->socket.write_ready = 0;
    }

    return sent;
}

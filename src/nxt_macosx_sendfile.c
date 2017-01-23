
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/* sendfile() has been introduced in MacOSX 10.5 (Leopard) */

#ifdef NXT_TEST_BUILD_MACOSX_SENDFILE

ssize_t nxt_macosx_event_conn_io_sendfile(nxt_event_conn_t *c, nxt_buf_t *b,
    size_t limit);

static int nxt_sys_sendfile(int fd, int s, off_t offset, off_t *len,
    struct sf_hdtr *hdtr, int flags)
{
    return -1;
}

#else
#define nxt_sys_sendfile  sendfile
#endif


ssize_t
nxt_macosx_event_conn_io_sendfile(nxt_event_conn_t *c, nxt_buf_t *b,
    size_t limit)
{
    size_t                  hd_size, file_size;
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

    hd_size = sb.size;
    fb = sb.buf;

    file_size = nxt_sendbuf_file_coalesce(&sb);

    if (file_size == 0) {
        return nxt_event_conn_io_writev(c, hd, nhd);
    }

    sb.iobuf = tr;

    ntr = nxt_sendbuf_mem_coalesce(c->socket.task, &sb);

    /*
     * Disposal of surplus kernel operations if there are no headers
     * and trailers.  Besides sendfile() returns EINVAL if a sf_hdtr's
     * count is 0, but corresponding pointer is not NULL.
     */

    nxt_memzero(&hdtr, sizeof(struct sf_hdtr));
    ht = NULL;

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

    /*
     * MacOSX has the same bug as old FreeBSD (http://bugs.freebsd.org/33771).
     * However this bug has never been fixed and instead of this it has been
     * documented as a feature in MacOSX 10.7 (Lion) sendfile(2):
     *
     *   When a header or trailer is specified, the value of len argument
     *   indicates the maximum number of bytes in the header and/or file
     *   to be sent.  It does not control the trailer; if a trailer exists,
     *   all of it will be sent.
     */
    sent = hd_size + file_size;

    nxt_log_debug(c->socket.log,
                  "sendfile(%FD, %d, @%O, %O) hd:%ui tr:%ui hs:%uz",
                  fb->file->fd, c->socket.fd, fb->file_pos, sent,
                  nhd, ntr, hd_size);

    n = nxt_sys_sendfile(fb->file->fd, c->socket.fd,
                         fb->file_pos, &sent, ht, 0);

    err = (n == -1) ? nxt_errno : 0;

    nxt_log_debug(c->socket.log, "sendfile(): %d sent:%O", n, sent);

    if (n == -1) {
        switch (err) {

        case NXT_EAGAIN:
            c->socket.write_ready = 0;
            break;

        case NXT_EINTR:
            break;

        default:
            c->socket.error = err;
            nxt_log_error(nxt_socket_error_level(err, c->socket.log_error),
                          c->socket.log, "sendfile(%FD, %d, %O, %O) failed "
                          "%E \"%FN\" hd:%ui tr:%ui", fb->file->fd,
                          c->socket.fd, fb->file_pos, sent, err,
                          fb->file->name, nhd, ntr);

            return NXT_ERROR;
        }

        nxt_log_debug(c->socket.log, "sendfile() %E", err);

        return sent;
    }

    if (sent == 0) {
        nxt_log_error(NXT_LOG_ERR, c->socket.log,
                      "file \"%FN\" was truncated while sendfile()",
                      fb->file->name);

        return NXT_ERROR;
    }

    if (sent < (nxt_off_t) sb.size) {
        c->socket.write_ready = 0;
    }

    return sent;
}


#if 0

typedef struct {
    nxt_socket_t  socket;
    nxt_err_t     error;

    uint8_t       write_ready;  /* 1 bit */
    uint8_t       log_error;
} nxt_sendbuf_t;


ssize_t nxt_macosx_sendfile(nxt_thread_t *thr, nxt_sendbuf_t *sb, nxt_buf_t *b,
    size_t limit);
ssize_t nxt_writev(nxt_thread_t *thr, nxt_sendbuf_t *sb, nxt_iobuf_t *iob,
    nxt_uint_t niob);
ssize_t nxt_send(nxt_thread_t *thr, nxt_sendbuf_t *sb, void *buf, size_t size);


ssize_t
nxt_macosx_sendfile(nxt_thread_t *thr, nxt_sendbuf_t *sb, nxt_buf_t *b,
    size_t limit)
{
    size_t                  hd_size, file_size;
    ssize_t                 n;
    nxt_buf_t               *buf;
    nxt_err_t               err;
    nxt_off_t               sent;
    nxt_uint_t              nhd, ntr;
    struct iovec            hd[NXT_IOBUF_MAX], tr[NXT_IOBUF_MAX];
    struct sf_hdtr          hdtr, *ht;
    nxt_sendbuf_coalesce_t  sbc;

    sbc.buf = b;
    sbc.iobuf = hd;
    sbc.nmax = NXT_IOBUF_MAX;
    sbc.sync = 0;
    sbc.size = 0;
    sbc.limit = limit;

    nhd = nxt_sendbuf_mem_coalesce(&sbc);

    if (nhd == 0 && sbc.sync) {
        return 0;
    }

    if (sbc.buf == NULL || !nxt_buf_is_file(sbc.buf)) {
        return nxt_writev(thr, sb, hd, nhd);
    }

    hd_size = sbc.size;
    buf = sbc.buf;

    file_size = nxt_sendbuf_file_coalesce(&sbc);

    if (file_size == 0) {
        return nxt_writev(thr, sb, hd, nhd);
    }

    sbc.iobuf = tr;

    ntr = nxt_sendbuf_mem_coalesce(&sbc);

    /*
     * Disposal of surplus kernel operations if there are no headers
     * and trailers.  Besides sendfile() returns EINVAL if a sf_hdtr's
     * count is 0, but corresponding pointer is not NULL.
     */

    nxt_memzero(&hdtr, sizeof(struct sf_hdtr));
    ht = NULL;

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

    /*
     * MacOSX has the same bug as old FreeBSD (http://bugs.freebsd.org/33771).
     * However this bug has never been fixed and instead of this it has been
     * documented as a feature in MacOSX 10.7 (Lion) sendfile(2):
     *
     *   When a header or trailer is specified, the value of len argument
     *   indicates the maximum number of bytes in the header and/or file
     *   to be sent.  It does not control the trailer; if a trailer exists,
     *   all of it will be sent.
     */
    sent = hd_size + file_size;

    nxt_log_debug(thr->log, "sendfile(%FD, %d, @%O, %O) hd:%ui tr:%ui hs:%uz",
                  buf->file->fd, sb->socket, buf->file_pos, sent,
                  nhd, ntr, hd_size);

    n = nxt_sys_sendfile(buf->file->fd, sb->socket,
                         buf->file_pos, &sent, ht, 0);

    err = (n == -1) ? nxt_errno : 0;

    nxt_log_debug(thr->log, "sendfile(): %d sent:%O", n, sent);

    if (n == -1) {
        switch (err) {

        case NXT_EAGAIN:
            sb->write_ready = 0;
            break;

        case NXT_EINTR:
            break;

        default:
            sb->error = err;
            nxt_log_error(nxt_socket_error_level(err, sb->log_error), thr->log,
                          "sendfile(%FD, %d, %O, %O) failed %E \"%FN\" "
                          "hd:%ui tr:%ui", buf->file->fd, sb->socket,
                          buf->file_pos, sent, err, buf->file->name, nhd, ntr);

            return NXT_ERROR;
        }

        nxt_log_debug(thr->log, "sendfile() %E", err);

        return sent;
    }

    if (sent == 0) {
        nxt_log_error(NXT_LOG_ERR, thr->log,
                      "file \"%FN\" was truncated while sendfile()",
                      buf->file->name);

        return NXT_ERROR;
    }

    if (sent < (nxt_off_t) sbc.size) {
        sb->write_ready = 0;
    }

    return sent;
}


ssize_t
nxt_writev(nxt_thread_t *thr, nxt_sendbuf_t *sb, nxt_iobuf_t *iob,
    nxt_uint_t niob)
{
    ssize_t    n;
    nxt_err_t  err;

    if (niob == 1) {
        /* Disposal of surplus kernel iovec copy-in operation. */
        return nxt_send(thr, sb, iob->iov_base, iob->iov_len);
    }

    for ( ;; ) {
        n = writev(sb->socket, iob, niob);

        err = (n == -1) ? nxt_socket_errno : 0;

        nxt_log_debug(thr->log, "writev(%d, %ui): %d", sb->socket, niob, n);

        if (n > 0) {
            return n;
        }

        /* n == -1 */

        switch (err) {

        case NXT_EAGAIN:
            nxt_log_debug(thr->log, "writev() %E", err);
            sb->write_ready = 0;
            return NXT_AGAIN;

        case NXT_EINTR:
            nxt_log_debug(thr->log, "writev() %E", err);
            continue;

        default:
            sb->error = err;
            nxt_log_error(nxt_socket_error_level(err, sb->log_error), thr->log,
                          "writev(%d, %ui) failed %E", sb->socket, niob, err);
            return NXT_ERROR;
        }
    }
}


ssize_t
nxt_send(nxt_thread_t *thr, nxt_sendbuf_t *sb, void *buf, size_t size)
{
    ssize_t    n;
    nxt_err_t  err;

    for ( ;; ) {
        n = send(sb->socket, buf, size, 0);

        err = (n == -1) ? nxt_socket_errno : 0;

        nxt_log_debug(thr->log, "send(%d, %p, %uz): %z",
                      sb->socket, buf, size, n);

        if (n > 0) {
            return n;
        }

        /* n == -1 */

        switch (err) {

        case NXT_EAGAIN:
            nxt_log_debug(thr->log, "send() %E", err);
            sb->write_ready = 0;
            return NXT_AGAIN;

        case NXT_EINTR:
            nxt_log_debug(thr->log, "send() %E", err);
            continue;

        default:
            sb->error = err;
            nxt_log_error(nxt_socket_error_level(err, sb->log_error), thr->log,
                          "send(%d, %p, %uz) failed %E",
                          sb->socket, buf, size, err);
            return NXT_ERROR;
        }
    }
}

#endif

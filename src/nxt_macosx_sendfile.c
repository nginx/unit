
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
nxt_macosx_event_conn_io_sendfile(nxt_conn_t *c, nxt_buf_t *b, size_t limit)
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
                    "sendfile(%FD, %d, %O, %O) failed %E \"%FN\" hd:%ui tr:%ui",
                    fb->file->fd, c->socket.fd, fb->file_pos, sent, err,
                    fb->file->name, nhd, ntr);

            return NXT_ERROR;
        }

        nxt_debug(c->socket.task, "sendfile() %E", err);

        return sent;
    }

    if (sent == 0) {
        nxt_log(c->socket.task, NXT_LOG_ERR,
                "file \"%FN\" was truncated while sendfile()", fb->file->name);

        return NXT_ERROR;
    }

    if (sent < (nxt_off_t) sb.size) {
        c->socket.write_ready = 0;
    }

    return sent;
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/* send_file() has been introduced in AIX 4.3.2 */

ssize_t nxt_aix_event_conn_io_send_file(nxt_event_conn_t *c, nxt_buf_t *b,
    size_t limit);


ssize_t
nxt_aix_event_conn_io_send_file(nxt_event_conn_t *c, nxt_buf_t *b, size_t limit)
{
    ssize_t                 n;
    nxt_buf_t               *fb;
    nxt_err_t               err;
    nxt_off_t               file_size, sent;
    nxt_uint_t              nhd, ntr;
    struct iovec            hd[NXT_IOBUF_MAX], tr;
    struct sf_parms         sfp;
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

    if (nhd > 1 || sb.buf == NULL || !nxt_buf_is_file(sb.buf)) {
        return nxt_event_conn_io_writev(c, hd, nhd);
    }

    fb = sb.buf;

    file_size = nxt_sendbuf_file_coalesce(&sb);

    if (file_size == 0) {
        return nxt_event_conn_io_writev(c, hd, nhd);
    }

    sb.iobuf = &tr;
    sb.nmax = 1;

    ntr = nxt_sendbuf_mem_coalesce(c->socket.task, &sb);

    nxt_memzero(&sfp, sizeof(struct sf_parms));

    if (nhd != 0) {
        sfp.header_data = hd[0].iov_base;
        sfp.header_length = hd[0].iov_len;
    }

    sfp.file_descriptor = fb->file->fd;
    sfp.file_offset = fb->file_pos;
    sfp.file_bytes = file_size;

    if (ntr != 0) {
        sfp.trailer_data = tr.iov_base;
        sfp.trailer_length = tr.iov_len;
    }

    nxt_debug(c->socket.task, "send_file(%d) fd:%FD @%O:%O hd:%ui tr:%ui",
              c->socket.fd, fb->file->fd, fb->file_pos, file_size, nhd, ntr);

    n = send_file(&c->socket.fd, &sfp, 0);

    err = (n == -1) ? nxt_errno : 0;
    sent = sfp.bytes_sent;

    nxt_debug(c->socket.task, "send_file(%d): %d sent:%O",
              c->socket.fd, n, sent);

    /*
     * -1  an error has occurred, errno contains the error code;
     *  0  the command has completed successfully;
     *  1  the command was completed partially, some data has been
     *     transmitted but the command has to return for some reason,
     *     for example, the command was interrupted by signals.
     */
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
                "send_file(%d) failed %E \"%FN\" fd:%FD @%O:%O hd:%ui tr:%ui",
                c->socket.fd, err, fb->file->name, fb->file->fd, fb->file_pos,
                file_size, nhd, ntr);

            return NXT_ERROR;
        }

        nxt_debug(c->socket.task, "sendfile() %E", err);

        return sent;
    }

    if (n == 1) {
        return sent;
    }

    if (sent < (nxt_off_t) sb.size) {
        c->socket.write_ready = 0;
    }

    return sent;
}

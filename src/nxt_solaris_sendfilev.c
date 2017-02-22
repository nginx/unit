
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * sendfilev() has been introduced in Solaris 8 (7/01).
 * According to sendfilev(3EXT) it can write to:
 *
 *   a file descriptor to a regular file or to a AF_NCA, AF_INET, or
 *   AF_INET6 family type SOCK_STREAM socket that is open for writing.
 */

ssize_t nxt_solaris_event_conn_io_sendfilev(nxt_event_conn_t *c, nxt_buf_t *b,
    size_t limit);
static size_t nxt_solaris_buf_coalesce(nxt_buf_t *b, sendfilevec_t *sfv,
    int32_t *nsfv, nxt_bool_t *sync, size_t limit);


ssize_t
nxt_solaris_event_conn_io_sendfilev(nxt_event_conn_t *c, nxt_buf_t *b,
    size_t limit)
{
    size_t         sent;
    ssize_t        n;
    int32_t        nsfv;
    nxt_err_t      err;
    nxt_off_t      size;
    nxt_bool_t     sync;
    sendfilevec_t  sfv[NXT_IOBUF_MAX];

    if (c->sendfile == 0) {
        /* AF_UNIX does not support sendfilev(). */
        return nxt_event_conn_io_sendbuf(c, b, limit);
    }

    sync = 0;

    size = nxt_solaris_buf_coalesce(b, sfv, &nsfv, &sync, limit);

    nxt_debug(c->socket.task, "sendfilev(%d, %D)", c->socket.fd, nsfv);

    if (nsfv == 0 && sync) {
        return 0;
    }

    sent = 0;
    n = sendfilev(c->socket.fd, sfv, nsfv, &sent);

    err = (n == -1) ? nxt_errno : 0;

    nxt_debug(c->socket.task, "sendfilev(): %d sent:%uz", n, sent);

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
                    "sendfilev(%d, %D) failed %E", c->socket.fd, nsfv, err);

            return NXT_ERROR;
        }

        nxt_debug(c->socket.task, "sendfilev() %E", err);

        return sent;
    }

    if ((nxt_off_t) sent < size) {
        c->socket.write_ready = 0;
    }

    return sent;
}


static size_t
nxt_solaris_buf_coalesce(nxt_buf_t *b, sendfilevec_t *sfv, int32_t *nsfv,
    nxt_bool_t *sync, size_t limit)
{
    size_t     size, total;
    nxt_fd_t   fd, last_fd;
    nxt_int_t  i;
    nxt_off_t  pos, last_pos;

    i = -1;
    last_fd = -1;
    last_pos = 0;
    total = 0;

    for (total = 0; b != NULL && total < limit; b = b->next) {

        if (nxt_buf_is_file(b)) {

            fd = b->file->fd;
            pos = b->file_pos;
            size = b->file_end - pos;

            if (size == 0) {
                continue;
            }

            if (total + size > limit) {
                size = limit - total;
            }

        } else if (nxt_buf_is_mem(b)) {

            fd = SFV_FD_SELF;
            pos = (uintptr_t) b->mem.pos;
            size = b->mem.free - b->mem.pos;

            if (size == 0) {
                continue;
            }

            if (total + size > limit) {
                size = limit - total;
            }

        } else {
            *sync = 1;
            continue;
        }

        if (size == 0) {
            break;
        }

        if (fd != last_fd || pos != last_pos) {

            if (++i >= NXT_IOBUF_MAX) {
                goto done;
            }

            sfv[i].sfv_fd = fd;
            sfv[i].sfv_flag = 0;
            sfv[i].sfv_off = pos;
            sfv[i].sfv_len = size;

        } else {
            sfv[i].sfv_len += size;
        }

        total += size;
        last_pos = pos + size;
        last_fd = fd;
    }

    i++;

done:

    *nsfv = i;

    return total;
}

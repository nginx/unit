/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_socket_msg.h>


ssize_t
nxt_sendmsg(nxt_socket_t s, nxt_iobuf_t *iob, nxt_uint_t niob,
    const nxt_send_oob_t *oob)
{
    struct msghdr  msg;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iob;
    msg.msg_iovlen = niob;
    /* Flags are cleared just to suppress valgrind warning. */
    msg.msg_flags = 0;

    if (oob != NULL && oob->size != 0) {
        msg.msg_control = (void *) oob->buf;
        msg.msg_controllen = oob->size;

    } else {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
    }

    return sendmsg(s, &msg, 0);
}


ssize_t
nxt_recvmsg(nxt_socket_t s, nxt_iobuf_t *iob, nxt_uint_t niob,
    nxt_recv_oob_t *oob)
{
    ssize_t        n;
    struct msghdr  msg;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iob;
    msg.msg_iovlen = niob;
    msg.msg_control = oob->buf;
    msg.msg_controllen = sizeof(oob->buf);

    n = recvmsg(s, &msg, 0);

    if (nxt_fast_path(n != -1)) {
        oob->size = msg.msg_controllen;
    }

    return n;
}

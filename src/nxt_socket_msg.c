/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_socket_msg.h>


ssize_t
nxt_sendmsg(nxt_socket_t s, nxt_iobuf_t *iob, nxt_uint_t niob,
    const void *oob, size_t oobn)
{
    struct msghdr  msg;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iob;
    msg.msg_iovlen = niob;
    /* Flags are cleared just to suppress valgrind warning. */
    msg.msg_flags = 0;
    msg.msg_control = (void *) oob;
    msg.msg_controllen = oobn;

    if (oobn == 0) {
        msg.msg_control = NULL;
    }

    return sendmsg(s, &msg, 0);
}


ssize_t
nxt_recvmsg(nxt_socket_t s, nxt_iobuf_t *iob, nxt_uint_t niob,
    void *oob, size_t *oobn)
{
    ssize_t        n;
    struct msghdr  msg;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iob;
    msg.msg_iovlen = niob;
    msg.msg_control = oob;
    msg.msg_controllen = *oobn;

    n = recvmsg(s, &msg, 0);

    if (nxt_fast_path(n != -1)) {
        *oobn = msg.msg_controllen;
    }

    return n;
}

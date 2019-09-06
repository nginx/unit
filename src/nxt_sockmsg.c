/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_sockmsg.h"

#if (NXT_HAVE_MSGHDR_MSG_CONTROL)

/*
 * Linux, FreeBSD, Solaris X/Open sockets,
 * MacOSX, NetBSD, AIX, HP-UX X/Open sockets.
 */

ssize_t
nxt_sendmsg(nxt_socket_t s, nxt_fd_t fd, nxt_iobuf_t *iob, nxt_uint_t niob)
{
    struct msghdr       msg;
    union {
        struct cmsghdr  cm;
        char            space[CMSG_SPACE(sizeof(int))];
    } cmsg;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iob;
    msg.msg_iovlen = niob;
    /* Flags are cleared just to suppress valgrind warning. */
    msg.msg_flags = 0;

    if (fd != -1) {
        msg.msg_control = (caddr_t) &cmsg;
        msg.msg_controllen = sizeof(cmsg);

#if (NXT_VALGRIND)
        nxt_memzero(&cmsg, sizeof(cmsg));
#endif

        cmsg.cm.cmsg_len = CMSG_LEN(sizeof(int));
        cmsg.cm.cmsg_level = SOL_SOCKET;
        cmsg.cm.cmsg_type = SCM_RIGHTS;

        /*
         * nxt_memcpy() is used instead of simple
         *   *(int *) CMSG_DATA(&cmsg.cm) = fd;
         * because GCC 4.4 with -O2/3/s optimization may issue a warning:
         *   dereferencing type-punned pointer will break strict-aliasing rules
         *
         * Fortunately, GCC with -O1 compiles this nxt_memcpy()
         * in the same simple assignment as in the code above.
         */
        nxt_memcpy(CMSG_DATA(&cmsg.cm), &fd, sizeof(int));

    } else {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
    }

    return sendmsg(s, &msg, 0);
}


ssize_t
nxt_recvmsg(nxt_socket_t s, nxt_fd_t *fd, nxt_iobuf_t *iob, nxt_uint_t niob)
{
    ssize_t             n;
    struct msghdr       msg;
    union {
        struct cmsghdr  cm;
        char            space[CMSG_SPACE(sizeof(int))];
    } cmsg;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iob;
    msg.msg_iovlen = niob;
    msg.msg_control = (caddr_t) &cmsg;
    msg.msg_controllen = sizeof(cmsg);

    *fd = -1;

#if (NXT_VALGRIND)
    nxt_memzero(&cmsg, sizeof(cmsg));
#endif

    n = recvmsg(s, &msg, 0);

    if (n > 0
        && cmsg.cm.cmsg_len == CMSG_LEN(sizeof(int))
        && cmsg.cm.cmsg_level == SOL_SOCKET
        && cmsg.cm.cmsg_type == SCM_RIGHTS)
    {
        /* (*fd) = *(int *) CMSG_DATA(&cmsg.cm); */
        nxt_memcpy(fd, CMSG_DATA(&cmsg.cm), sizeof(int));
    }

    return n;
}

#else

/* Solaris 4.3BSD sockets. */

static ssize_t
nxt_sendmsg(nxt_socket_t s, nxt_fd_t fd, nxt_iobuf_t *iob, nxt_uint_t niob)
{
    struct msghdr  msg;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iob;
    msg.msg_iovlen = niob;

    if (fd != -1) {
        msg.msg_accrights = (caddr_t) &fd;
        msg.msg_accrightslen = sizeof(int);

    } else {
        msg.msg_accrights = NULL;
        msg.msg_accrightslen = 0;
    }

    return sendmsg(s, &msg, 0);
}


static ssize_t
nxt_recvmsg(nxt_socket_t s, nxt_fd_t *fd, nxt_iobuf_t *iob, nxt_uint_t niob)
{
    struct msghdr  msg;

    *fd = -1;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iob;
    msg.msg_iovlen = niob;
    msg.msg_accrights = (caddr_t) fd;
    msg.msg_accrightslen = sizeof(int);

    return recvmsg(s, &msg, 0);
}

#endif

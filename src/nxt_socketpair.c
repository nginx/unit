
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * SOCK_SEQPACKET protocol is supported for AF_UNIX in Solaris 8 X/Open
 * sockets, Linux 2.6.4, FreeBSD 9.0, NetBSD 6.0, and OpenBSD 5.0.
 */

/* SOCK_SEQPACKET is disabled to test SOCK_DGRAM on all platforms. */
#if (0 || NXT_HAVE_AF_UNIX_SOCK_SEQPACKET)
#define NXT_UNIX_SOCKET  SOCK_SEQPACKET
#else
#define NXT_UNIX_SOCKET  SOCK_DGRAM
#endif


static ssize_t nxt_sendmsg(nxt_socket_t s, nxt_fd_t fd, nxt_iobuf_t *iob,
    nxt_uint_t niob);
static ssize_t nxt_recvmsg(nxt_socket_t s, nxt_fd_t *fd, nxt_pid_t *pid, 
    nxt_iobuf_t *iob, nxt_uint_t niob);


nxt_int_t
nxt_socketpair_create(nxt_task_t *task, nxt_socket_t *pair)
{
    if (nxt_slow_path(socketpair(AF_UNIX, NXT_UNIX_SOCKET, 0, pair) != 0)) {
        nxt_alert(task, "socketpair() failed %E", nxt_errno);
        return NXT_ERROR;
    }

    nxt_debug(task, "socketpair(): %d:%d", pair[0], pair[1]);

    if (nxt_slow_path(nxt_socket_nonblocking(task, pair[0]) != NXT_OK)) {
        goto fail;
    }

    if (nxt_slow_path(fcntl(pair[0], F_SETFD, FD_CLOEXEC) == -1)) {
        goto fail;
    }

    if (nxt_slow_path(nxt_socket_nonblocking(task, pair[1]) != NXT_OK)) {
        goto fail;
    }

    if (nxt_slow_path(fcntl(pair[1], F_SETFD, FD_CLOEXEC) == -1)) {
        goto fail;
    }

    int enable_creds = 1;
    if (nxt_slow_path(setsockopt(pair[0], SOL_SOCKET, SO_PASSCRED,
                        &enable_creds, sizeof(enable_creds)) == -1)) {
        nxt_alert(task, "failed to set SO_PASSCRED %E", nxt_errno);
        goto fail;
    }

    enable_creds = 1;
    if (nxt_slow_path(setsockopt(pair[1], SOL_SOCKET, SO_PASSCRED,
                        &enable_creds, sizeof(enable_creds)) == -1)) {
        nxt_alert(task, "failed to set SO_PASSCRED %E", nxt_errno);
        goto fail;
    }

    return NXT_OK;

fail:

    nxt_socketpair_close(task, pair);

    return NXT_ERROR;
}


void
nxt_socketpair_close(nxt_task_t *task, nxt_socket_t *pair)
{
    nxt_socket_close(task, pair[0]);
    nxt_socket_close(task, pair[1]);
}


ssize_t
nxt_socketpair_send(nxt_fd_event_t *ev, nxt_fd_t fd, nxt_iobuf_t *iob,
    nxt_uint_t niob)
{
    ssize_t    n;
    nxt_err_t  err;

    for ( ;; ) {
        n = nxt_sendmsg(ev->fd, fd, iob, niob);

        err = (n == -1) ? nxt_socket_errno : 0;

        nxt_debug(ev->task, "sendmsg(%d, %FD, %ui): %z", ev->fd, fd, niob, n);

        if (n > 0) {
            return n;
        }

        /* n == -1 */

        switch (err) {

        case NXT_EAGAIN:
            nxt_debug(ev->task, "sendmsg(%d) not ready", ev->fd);
            break;

        /*
         * Returned (at least on OSX) when trying to send many small messages.
         */
        case NXT_ENOBUFS:
            nxt_debug(ev->task, "sendmsg(%d) no buffers", ev->fd);
            break;

        case NXT_EINTR:
            nxt_debug(ev->task, "sendmsg(%d) interrupted", ev->fd);
            continue;

        default:
            nxt_alert(ev->task, "sendmsg(%d, %FD, %ui) failed %E",
                      ev->fd, fd, niob, err);

            return NXT_ERROR;
        }

        ev->write_ready = 0;

        return NXT_AGAIN;
    }
}


ssize_t
nxt_socketpair_recv(nxt_fd_event_t *ev, nxt_fd_t *fd, nxt_pid_t *pid, 
    nxt_iobuf_t *iob, nxt_uint_t niob)
{
    ssize_t    n;
    nxt_err_t  err;

    for ( ;; ) {
        n = nxt_recvmsg(ev->fd, fd, pid, iob, niob);

        err = (n == -1) ? nxt_socket_errno : 0;

        nxt_debug(ev->task, "recvmsg(%d, %FD, %d, %ui): %z", ev->fd, *fd, 
                    *pid, niob, n);

        if (n > 0) {
            return n;
        }

        if (n == 0) {
            ev->closed = 1;
            ev->read_ready = 0;

            return n;
        }

        /* n == -1 */

        switch (err) {

        case NXT_EAGAIN:
            nxt_debug(ev->task, "recvmsg(%d) not ready", ev->fd);
            ev->read_ready = 0;

            return NXT_AGAIN;

        case NXT_EINTR:
            nxt_debug(ev->task, "recvmsg(%d) interrupted", ev->fd);
            continue;

        default:
            nxt_alert(ev->task, "recvmsg(%d, %p, %ui) failed %E",
                      ev->fd, fd, niob, err);

            return NXT_ERROR;
        }
    }
}


#if (NXT_HAVE_MSGHDR_MSG_CONTROL)

/*
 * Linux, FreeBSD, Solaris X/Open sockets,
 * MacOSX, NetBSD, AIX, HP-UX X/Open sockets.
 */

static ssize_t
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


static ssize_t
nxt_recvmsg(nxt_socket_t s, nxt_fd_t *fd, nxt_pid_t *pid, nxt_iobuf_t *iob, nxt_uint_t niob)
{
    ssize_t         n;
    struct msghdr   msg;
    struct cmsghdr  *cmsg;
    struct ucred    *creds;
    unsigned        sz;

    char oob[CMSG_SPACE(sizeof(int))+CMSG_SPACE(sizeof(struct ucred))];

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iob;
    msg.msg_iovlen = niob;
    msg.msg_control = (caddr_t) &oob;
    msg.msg_controllen = sizeof(oob);

    *fd = -1;
    *pid = -1;

#if (NXT_VALGRIND)
    nxt_memzero(&oob, sizeof(oob));
#endif

    n = recvmsg(s, &msg, 0);
    if (n <= 0) {
        return n;
    }

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        sz = cmsg->cmsg_len - CMSG_LEN(0);

        if (cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_RIGHTS &&
            sz == sizeof(int)) {

            /* (*fd) = *(int *) CMSG_DATA(cmsg); */
            nxt_memcpy(fd, CMSG_DATA(cmsg), sizeof(int));
        }
        
        if (cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_CREDENTIALS &&
            sz == sizeof(struct ucred)) {

            creds = (struct ucred*)CMSG_DATA(cmsg);
            *pid = creds->pid;
        }
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

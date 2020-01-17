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


void
nxt_socket_msg_set_oob(u_char *oob, size_t *oobn, int fd)
{
    struct msghdr   msg;
    struct cmsghdr  *cmsg;

    msg.msg_control    = (void *) oob;
    msg.msg_controllen = *oobn;

    *oobn = 0;
    cmsg = (struct cmsghdr *) oob;

#if (NXT_HAVE_MSGHDR_CMSGCRED)
    /*
     * Fill all padding fields with 0.
     * Code in Go 1.11 validate cmsghdr using padding field as part of len.
     * See Cmsghdr definition and socketControlMessageHeaderAndData function.
     */
    nxt_memzero(cmsg, sizeof(struct cmsghdr));

    cmsg->cmsg_len = CMSG_LEN(sizeof(nxt_socket_cred_t));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = NXT_CRED_CMSGTYPE;

    *oobn += CMSG_SPACE(sizeof(nxt_socket_cred_t));
    cmsg = CMSG_NXTHDR(&msg, cmsg);
#endif

    if (fd != -1) {
        nxt_memzero(cmsg, sizeof(struct cmsghdr));

        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;

        /*
         * nxt_memcpy() is used instead of simple
         *   *(int *) CMSG_DATA(&cmsg.cm) = fd;
         * because GCC 4.4 with -O2/3/s optimization may issue a warning:
         *   dereferencing type-punned pointer will break strict-aliasing rules
         *
         * Fortunately, GCC with -O1 compiles this nxt_memcpy()
         * in the same simple assignment as in the code above.
         */
        nxt_memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
        *oobn += CMSG_SPACE(sizeof(int));
        cmsg = CMSG_NXTHDR(&msg, cmsg);
    }
}


nxt_int_t
nxt_socket_msg_oob_info(u_char *oob, size_t oobn,
    nxt_fd_t *fd, nxt_pid_t *pid)
{
    size_t          cmsgsz;
    struct msghdr   msg;
    struct cmsghdr  *cmsg;

#if (NXT_CRED_USECMSG)
    nxt_socket_cred_t *creds;

    if (pid != NULL) {
        *pid = -1;
    }
#endif

    msg.msg_control    = oob;
    msg.msg_controllen = oobn;

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        cmsgsz = cmsg->cmsg_len - CMSG_LEN(0);

        if (cmsg->cmsg_level == SOL_SOCKET
            && cmsg->cmsg_type == SCM_RIGHTS
            && cmsgsz == sizeof(int))
        {
            /* (*fd) = *(int *) CMSG_DATA(cmsg); */
            nxt_memcpy(fd, CMSG_DATA(cmsg), sizeof(int));

            if (pid == NULL) {
                break;
            }
        }

#if (NXT_CRED_USECMSG)
        else if (pid != NULL && cmsg->cmsg_level == SOL_SOCKET
                 && cmsg->cmsg_type == NXT_CRED_CMSGTYPE
                 && cmsgsz == sizeof(nxt_socket_cred_t))
        {
            creds = (nxt_socket_cred_t *)CMSG_DATA(cmsg);
            *pid = NXT_CRED_GETPID(creds);
        }
#endif
    }

#if (NXT_CRED_USECMSG)
    /* For platforms supporting credential passing, it's enforced */
    if (nxt_slow_path(pid != NULL && *pid == -1)) {
        return NXT_ERROR;
    }
#endif

    return NXT_OK;
}

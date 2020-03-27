#ifndef _NXT_SOCKET_MSG_H_INCLUDED_
#define _NXT_SOCKET_MSG_H_INCLUDED_

#if (NXT_HAVE_UCRED)
#include <sys/un.h>
#endif


#if (NXT_HAVE_UCRED) && (NXT_HAVE_SOCKOPT_SO_PASSCRED)

#define NXT_CRED_USECMSG    1
#define NXT_CRED_CMSGTYPE   SCM_CREDENTIALS
#define NXT_CRED_GETPID(u)  (u->pid)

typedef struct ucred  nxt_socket_cred_t;

#elif (NXT_HAVE_MSGHDR_CMSGCRED)

#define NXT_CRED_USECMSG    1
#define NXT_CRED_CMSGTYPE   SCM_CREDS
#define NXT_CRED_GETPID(u)  (u->cmcred_pid)

typedef struct cmsgcred  nxt_socket_cred_t;

#endif

#if (NXT_CRED_USECMSG)
#define NXT_OOB_RECV_SIZE                                                     \
            (CMSG_SPACE(sizeof(int)) +                                        \
             CMSG_SPACE(sizeof(nxt_socket_cred_t)))
#else
#define NXT_OOB_RECV_SIZE                                                     \
            CMSG_SPACE(sizeof(int))
#endif

#if (NXT_CRED_USECMSG) && (NXT_HAVE_MSGHDR_CMSGCRED)
#define NXT_OOB_SEND_SIZE                                                     \
            (CMSG_SPACE(sizeof(int)) +                                        \
             CMSG_SPACE(sizeof(nxt_socket_cred_t)))
#else
#define NXT_OOB_SEND_SIZE                                                     \
            CMSG_SPACE(sizeof(int))
#endif


/**
 * The nxt_sendmsg is a wrapper for sendmsg.
 * The oob buffer and oobn size must be set using nxt_socket_msg_set_oob.
 */
NXT_EXPORT ssize_t nxt_sendmsg(nxt_socket_t s, nxt_iobuf_t *iob,
    nxt_uint_t niob, const void *oob, size_t oobn);

/**
 * The nxt_recvmsg is a wrapper for recvmsg.
 * The oob buffer must be consumed by using nxt_socket_msg_oob_info.
 */
NXT_EXPORT ssize_t nxt_recvmsg(nxt_socket_t s,
    nxt_iobuf_t *iob, nxt_uint_t niob, void *oob, size_t *oobn);


nxt_inline void
nxt_socket_msg_oob_init(u_char *oob, size_t *oobn)
{
    *oobn = 0;

#if (NXT_HAVE_MSGHDR_CMSGCRED)
    struct msghdr   msg;
    struct cmsghdr  *cmsg;

    msg.msg_control    = (void *) oob;
    msg.msg_controllen = *oobn;

    cmsg = (struct cmsghdr *) oob;
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
}


nxt_inline void
nxt_socket_msg_oob_set_fd(u_char *oob, size_t *oobn, int fd)
{
    struct msghdr   msg;
    struct cmsghdr  *cmsg;

    msg.msg_control    = (void *) oob;
    msg.msg_controllen = *oobn;

    cmsg = (struct cmsghdr *) oob + (*oobn);

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


nxt_inline void
nxt_socket_msg_oob_fd(u_char *oob, size_t oobn, nxt_fd_t *fd)
{
    size_t          cmsgsz;
    struct msghdr   msg;
    struct cmsghdr  *cmsg;

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

            return;
        }
    }
}


nxt_inline nxt_int_t
nxt_socket_msg_oob_get(u_char *oob, size_t oobn, nxt_fd_t *fd, nxt_pid_t *pid)
{
    size_t          cmsgsz;
    struct msghdr   msg;
    struct cmsghdr  *cmsg;

#if (NXT_CRED_USECMSG)
    nxt_socket_cred_t *creds;

    *pid = -1;
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
        else if (cmsg->cmsg_level == SOL_SOCKET
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
    if (nxt_slow_path(*pid == -1)) {
        return NXT_ERROR;
    }
#endif

    return NXT_OK;
}


#endif /* _NXT_SOCKET_MSG_H_INCLUDED_ */

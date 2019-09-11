#ifndef _NXT_SOCKET_MSG_H_INCLUDED_
#define _NXT_SOCKET_MSG_H_INCLUDED_

#if (NXT_HAVE_UCRED)
#include <sys/un.h>
#endif


#if (NXT_HAVE_UCRED) && (NXT_HAVE_SOCKOPT_SO_PASSCRED)

#define NXT_CRED_USECMSG    1
#define NXT_CRED_STRUCT     ucred
#define NXT_CRED_CMSGTYPE   SCM_CREDENTIALS
#define NXT_CRED_GETPID(u)  (u->pid)

#elif (NXT_HAVE_MSGHDR_CMSGCRED)

#define NXT_CRED_USECMSG    1
#define NXT_CRED_STRUCT     cmsgcred
#define NXT_CRED_CMSGTYPE   SCM_CREDS
#define NXT_CRED_GETPID(u)  (u->cmcred_pid)

#endif

#if (NXT_CRED_USECMSG)
#define NXT_OOB_RECV_SIZE                                                     \
            (CMSG_SPACE(sizeof(int)) + \
             CMSG_SPACE(sizeof(struct NXT_CRED_STRUCT)))
#else
#define NXT_OOB_RECV_SIZE                                                     \
            CMSG_SPACE(sizeof(int))
#endif

#if (NXT_CRED_USECMSG) && (NXT_HAVE_MSGHDR_CMSGCRED)
#define NXT_OOB_SEND_SIZE                                                     \
            (CMSG_SPACE(sizeof(int)) + \
             CMSG_SPACE(sizeof(struct NXT_CRED_STRUCT)))
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
 * The oob buffer must be consumed by using nxt_socket_msg_oob_data.
 */
NXT_EXPORT ssize_t nxt_recvmsg(nxt_socket_t s, 
    nxt_iobuf_t *iob, nxt_uint_t niob, void *oob, size_t *oobn);

NXT_EXPORT void
nxt_socket_msg_set_oob(u_char *oob, size_t *oobn, int fd);

NXT_EXPORT nxt_int_t
nxt_socket_msg_oob_info(u_char *oob, size_t oobn, 
    nxt_fd_t *fd, nxt_pid_t *pid);

#endif /* _NXT_SOCKET_MSG_H_INCLUDED_ */


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIX_ERRNO_H_INCLUDED_
#define _NXT_UNIX_ERRNO_H_INCLUDED_


typedef int                        nxt_err_t;


#define NXT_EPERM                  EPERM
#define NXT_ENOENT                 ENOENT
#define NXT_ENOPATH                ENOENT
#define NXT_ESRCH                  ESRCH
#define NXT_EINTR                  EINTR
#define NXT_ECHILD                 ECHILD
#define NXT_ENOMEM                 ENOMEM
#define NXT_EACCES                 EACCES
#define NXT_EBUSY                  EBUSY
#define NXT_EEXIST                 EEXIST
#define NXT_EXDEV                  EXDEV
#define NXT_ENOTDIR                ENOTDIR
#define NXT_EISDIR                 EISDIR
#define NXT_EINVAL                 EINVAL
#define NXT_ENOSPC                 ENOSPC
#define NXT_EPIPE                  EPIPE
#define NXT_EINPROGRESS            EINPROGRESS
#define NXT_EOPNOTSUPP             EOPNOTSUPP
#define NXT_EADDRINUSE             EADDRINUSE
#define NXT_ECONNABORTED           ECONNABORTED
#define NXT_ECONNRESET             ECONNRESET
#define NXT_ENOTCONN               ENOTCONN
#define NXT_ETIMEDOUT              ETIMEDOUT
#define NXT_ECONNREFUSED           ECONNREFUSED
#define NXT_ENAMETOOLONG           ENAMETOOLONG
#define NXT_ENETDOWN               ENETDOWN
#define NXT_ENETUNREACH            ENETUNREACH
#define NXT_EHOSTDOWN              EHOSTDOWN
#define NXT_EHOSTUNREACH           EHOSTUNREACH
#define NXT_ENOSYS                 ENOSYS
#define NXT_ECANCELED              ECANCELED
#define NXT_EILSEQ                 EILSEQ
#define NXT_ETIME                  ETIME
#define NXT_ENOMOREFILES           0
#define NXT_ENOBUFS                ENOBUFS

#if (NXT_HPUX)
/* HP-UX uses EWOULDBLOCK instead of EAGAIN. */
#define NXT_EAGAIN                 EWOULDBLOCK
#else
#define NXT_EAGAIN                 EAGAIN
#endif


#define NXT_OK                     0
#define NXT_ERROR                  (-1)
#define NXT_AGAIN                  (-2)
#define NXT_DECLINED               (-3)
#define NXT_DONE                   (-4)


#define                                                                       \
nxt_errno                                                                     \
    errno

#define                                                                       \
nxt_socket_errno                                                              \
    errno

#define                                                                       \
nxt_set_errno(err)                                                            \
    errno = err

#define                                                                       \
nxt_set_socket_errno(err)                                                     \
    errno = err


nxt_int_t nxt_strerror_start(void);


typedef u_char *(*nxt_strerror_t)(nxt_err_t err, u_char *errstr, size_t size);
extern nxt_strerror_t  nxt_strerror;


#endif /* _NXT_UNIX_ERRNO_H_INCLUDED_ */


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_SOCKET_H_INCLUDED_
#define _NXT_SOCKET_H_INCLUDED_


typedef int  nxt_socket_t;

#define NXT_NONBLOCK  1


/*
 * struct sockaddr and struct sockaddr_in are 16 bytes.
 *
 * struct sockaddr_in6 is:
 *     28 bytes on Linux, FreeBSD, MacOSX, NetBSD, OpenBSD, AIX, HP-UX;
 *     32 bytes on Solaris.
 *
 *
 * struct sockaddr_un is:
 *     94 bytes on HP-UX;
 *    106 bytes on FreeBSD, MacOSX, NetBSD, OpenBSD;
 *    110 bytes on Linux, Solaris;
 *   1025 bytes on AIX.
 *
 * The real maximum sockaddr_un length however different from defined length:
 *     OpenBSD can accept and return 105 bytes if address is not
 *         zero-terminated;
 *     Linux can accept 110 bytes and return 111 bytes;
 *     MacOSX and NetBSD can accept and return 255 bytes;
 *     Solaris can accept 257 bytes and return 258 bytes;
 * FreeBSD maximum sockaddr_un length is equal to defined length.
 *
 * POSIX.1g renamed AF_UNIX to AF_LOCAL, however, Solaris up to 10
 * version lacks AF_LOCAL.  AF_UNIX is defined even on Windows although
 * struct sockaddr_un is not.
 *
 * Unix domain socket address without a trailing zero is accepted at least by:
 *     Linux, FreeBSD, Solaris, MacOSX, NetBSD, and OpenBSD.
 * Linux and Solaris add the trailing zero and return sockaddr_un length
 * increased by one.  Others return sockaddr_un without the trailing zero.
 *
 * For unspecified Unix domain socket address
 *     NetBSD returns sockaddr_un length equal to 106 and fills sun_path[]
 *         with zeros;
 *     FreeBSD, Solaris, MacOSX, and OpenBSD return sockaddr_un length
 *         equal to 16 and fill sun_path[] with zeros;
 *     Linux returns sockaddr_un length equal to 2 without sun_path[];
 *
 *     4.4BSD getsockname() and getpeername() returned zero length.
 *     This behaviour has been inherited by BSD flavours and has been
 *     eventually changed in NetBSD 1.2, FreeBSD 3.0, and OpenBSD 5.3.
 *
 *
 * struct sockaddr_storage is:
 *    128 bytes on Linux, FreeBSD, MacOSX, NetBSD;
 *    256 bytes on Solaris, OpenBSD, and HP-UX;
 *   1288 bytes on AIX.
 *
 * struct sockaddr_storage is too large on some platforms
 * or less than real maximum struct sockaddr_un length.
 */

#if (NXT_HAVE_UNIX_DOMAIN)
#define NXT_SOCKADDR_LEN     sizeof(struct sockaddr_un)

#elif (NXT_HAVE_SOCKADDR_IN6)
#define NXT_SOCKADDR_LEN     sizeof(struct sockaddr_in6)

#else
#define NXT_SOCKADDR_LEN     sizeof(struct sockaddr_in)
#endif


typedef union {
    struct sockaddr          buf;
    uint64_t                 alignment;
    char                     space[NXT_SOCKADDR_LEN];
} nxt_sockaddr_buf_t;


/*
 * MAXHOSTNAMELEN is:
 *    64 on Linux;
 *   256 on FreeBSD, Solaris, MacOSX, NetBSD, OpenBSD.
 */
#define NXT_MAXHOSTNAMELEN  MAXHOSTNAMELEN


NXT_EXPORT nxt_socket_t nxt_socket_create(nxt_task_t *task, nxt_uint_t family,
    nxt_uint_t type, nxt_uint_t protocol, nxt_uint_t flags);
NXT_EXPORT void nxt_socket_close(nxt_task_t *task, nxt_socket_t s);
NXT_EXPORT void nxt_socket_defer_accept(nxt_task_t *task, nxt_socket_t s,
    nxt_sockaddr_t *sa);
NXT_EXPORT nxt_int_t nxt_socket_getsockopt(nxt_task_t *task, nxt_socket_t s,
    nxt_uint_t level, nxt_uint_t sockopt);
NXT_EXPORT nxt_int_t nxt_socket_setsockopt(nxt_task_t *task, nxt_socket_t s,
    nxt_uint_t level, nxt_uint_t sockopt, int val);
NXT_EXPORT nxt_int_t nxt_socket_bind(nxt_task_t *task, nxt_socket_t s,
    nxt_sockaddr_t *sa, nxt_bool_t test);
NXT_EXPORT nxt_int_t nxt_socket_connect(nxt_task_t *task, nxt_socket_t s,
    nxt_sockaddr_t *sa);
NXT_EXPORT void nxt_socket_shutdown(nxt_task_t *task, nxt_socket_t s,
    nxt_uint_t how);
nxt_uint_t nxt_socket_error_level(nxt_err_t err);

NXT_EXPORT nxt_int_t nxt_socketpair_create(nxt_task_t *task,
    nxt_socket_t *pair);
NXT_EXPORT void nxt_socketpair_close(nxt_task_t *task, nxt_socket_t *pair);
NXT_EXPORT ssize_t nxt_socketpair_send(nxt_fd_event_t *ev, nxt_fd_t fd,
    nxt_iobuf_t *iob, nxt_uint_t niob);
NXT_EXPORT ssize_t nxt_socketpair_recv(nxt_fd_event_t *ev, nxt_fd_t *fd,
    nxt_iobuf_t *iob, nxt_uint_t niob);


#define                                                                       \
nxt_socket_nonblocking(task, fd)                                              \
    nxt_fd_nonblocking(task, fd)

#define                                                                       \
nxt_socket_blocking(task, fd)                                                 \
    nxt_fd_blocking(task, fd)


#endif /* _NXT_SOCKET_H_INCLUDED_ */

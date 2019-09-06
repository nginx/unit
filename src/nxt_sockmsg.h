/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_SOCKMSG_H_INCLUDED_
#define _NXT_SOCKMSG_H_INCLUDED_

NXT_EXPORT ssize_t nxt_sendmsg(nxt_socket_t s, nxt_fd_t fd,
    nxt_iobuf_t *iob, nxt_uint_t niob);
NXT_EXPORT ssize_t nxt_recvmsg(nxt_socket_t s, nxt_fd_t *fd,
    nxt_iobuf_t *iob, nxt_uint_t niob);

#endif /* _NXT_SOCKMSG_H_INCLUDED_ */
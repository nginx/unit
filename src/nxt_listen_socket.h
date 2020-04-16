
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_LISTEN_SOCKET_H_INCLUDED_
#define _NXT_LISTEN_SOCKET_H_INCLUDED_


typedef struct {
    /* nxt_socket_t is int. */
    nxt_socket_t              socket;
    int                       backlog;

    nxt_work_queue_t          *work_queue;
    nxt_work_handler_t        handler;

    nxt_sockaddr_t            *sockaddr;

    uint32_t                  count;

    uint8_t                   flags;
    uint8_t                   read_after_accept;   /* 1 bit */

#if (NXT_TLS)
    uint8_t                   tls;                 /* 1 bit */
#endif
#if (NXT_INET6 && defined IPV6_V6ONLY)
    uint8_t                   ipv6only;            /* 2 bits */
#endif

    uint8_t                   socklen;
    uint8_t                   address_length;
} nxt_listen_socket_t;


#if (NXT_FREEBSD || NXT_MACOSX || NXT_OPENBSD)
/*
 * A backlog is limited by system-wide sysctl kern.ipc.somaxconn.
 * This is supported by FreeBSD 2.2, OpenBSD 2.0, and MacOSX.
 */
#define NXT_LISTEN_BACKLOG    -1

#else
/*
 * Linux, Solaris, and NetBSD treat negative value as 0.
 * 511 is a safe default.
 */
#define NXT_LISTEN_BACKLOG    511
#endif


NXT_EXPORT nxt_int_t nxt_listen_socket(nxt_task_t *task, nxt_socket_t s,
    int backlog);

NXT_EXPORT nxt_int_t nxt_listen_socket_create(nxt_task_t *task, nxt_mp_t *mp,
    nxt_listen_socket_t *ls);
NXT_EXPORT nxt_int_t nxt_listen_socket_update(nxt_task_t *task,
    nxt_listen_socket_t *ls, nxt_listen_socket_t *prev);
NXT_EXPORT void nxt_listen_socket_remote_size(nxt_listen_socket_t *ls);
NXT_EXPORT size_t nxt_listen_socket_pool_min_size(nxt_listen_socket_t *ls);


#endif /* _NXT_LISTEN_SOCKET_H_INCLUDED_ */

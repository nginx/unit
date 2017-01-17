
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static u_char *nxt_listen_socket_log_handler(void *ctx, u_char *pos,
    u_char *last);


nxt_int_t
nxt_listen_socket_create(nxt_listen_socket_t *ls, nxt_bool_t bind_test)
{
    nxt_log_t       log, *old;
    nxt_uint_t      family;
    nxt_socket_t    s;
    nxt_thread_t    *thr;
    nxt_sockaddr_t  *sa;

    sa = ls->sockaddr;

    thr = nxt_thread();
    old = thr->log;
    log = *thr->log;
    log.ctx_handler = nxt_listen_socket_log_handler;
    log.ctx = sa;
    thr->log = &log;

    family = sa->u.sockaddr.sa_family;

    s = nxt_socket_create(family, sa->type, 0, ls->flags);
    if (s == -1) {
        goto socket_fail;
    }

    if (nxt_socket_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, 1) != NXT_OK) {
        goto fail;
    }

#if (NXT_INET6 && defined IPV6_V6ONLY)

    if (family == AF_INET6 && ls->ipv6only) {
        int  ipv6only;

        ipv6only = (ls->ipv6only == 1);

        /* Ignore possible error. TODO: why? */
        (void) nxt_socket_setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, ipv6only);
    }

#endif

#if 0

    /* Ignore possible error. TODO: why? */
    (void) nxt_socket_setsockopt(s, SOL_SOCKET, SO_SNDBUF, 8192);

#endif

#ifdef TCP_DEFER_ACCEPT

    if (ls->read_after_accept) {
        /* Defer accept() maximum at 1 second. */
        /* Ignore possible error. TODO: why? */
        (void) nxt_socket_setsockopt(s, IPPROTO_TCP, TCP_DEFER_ACCEPT, 1);
    }

#endif

    switch (nxt_socket_bind(s, sa, bind_test)) {

    case NXT_OK:
        break;

    case NXT_ERROR:
        goto fail;

    default: /* NXT_DECLINED: EADDRINUSE on bind() test */
        return NXT_OK;
    }

#if (NXT_HAVE_UNIX_DOMAIN)

    if (family == AF_UNIX) {
        nxt_file_name_t     *name;
        nxt_file_access_t   access;

        name = (nxt_file_name_t *) sa->u.sockaddr_un.sun_path;

        access = (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

        if (nxt_file_set_access(name, access) != NXT_OK) {
            goto fail;
        }

        if (bind_test && nxt_file_delete(name) != NXT_OK) {
            goto fail;
        }
    }

#endif

    nxt_log_debug(&log, "listen(%d, %d)", s, ls->backlog);

    if (listen(s, ls->backlog) != 0) {
        nxt_log_alert(&log, "listen(%d, %d) failed %E",
                      s, ls->backlog, nxt_socket_errno);
        goto fail;
    }

    ls->socket = s;
    thr->log = old;

    return NXT_OK;

fail:

    nxt_socket_close(s);

socket_fail:

    thr->log = old;

    return NXT_ERROR;
}


nxt_int_t
nxt_listen_socket_update(nxt_listen_socket_t *ls, nxt_listen_socket_t *prev)
{
    nxt_log_t     log, *old;
    nxt_thread_t  *thr;

    ls->socket = prev->socket;

    thr = nxt_thread();
    old = thr->log;
    log = *thr->log;
    log.ctx_handler = nxt_listen_socket_log_handler;
    log.ctx = ls->sockaddr;
    thr->log = &log;

    nxt_log_debug(&log, "listen(%d, %d)", ls->socket, ls->backlog);

    if (listen(ls->socket, ls->backlog) != 0) {
        nxt_log_alert(&log, "listen(%d, %d) failed %E",
                      ls->socket, ls->backlog, nxt_socket_errno);
        goto fail;
    }

    thr->log = old;

    return NXT_OK;

fail:

    thr->log = old;

    return NXT_ERROR;
}


size_t
nxt_listen_socket_pool_min_size(nxt_listen_socket_t *ls)
{
    size_t  size;

    /*
     * The first nxt_sockaddr_t is intended for mandatory remote sockaddr
     * and textual representaion with port.  The second nxt_sockaddr_t
     * is intended for local sockaddr without textual representaion which
     * may be required to get specific address of connection received on
     * wildcard AF_INET and AF_INET6 addresses.  For AF_UNIX addresses
     * the local sockaddr is not required.
     */

    switch (ls->sockaddr->u.sockaddr.sa_family) {

#if (NXT_INET6)

    case AF_INET6:
        ls->socklen = sizeof(struct sockaddr_in6);

        size = offsetof(nxt_sockaddr_t, u) + sizeof(struct sockaddr_in6)
               + NXT_INET6_ADDR_STR_LEN + (sizeof(":65535") - 1);

        if (IN6_IS_ADDR_UNSPECIFIED(&ls->sockaddr->u.sockaddr_in6.sin6_addr)) {
            size += offsetof(nxt_sockaddr_t, u) + sizeof(struct sockaddr_in6);
        }

        break;

#endif

#if (NXT_HAVE_UNIX_DOMAIN)

    case AF_UNIX:
        /*
         * A remote socket is usually unbound and thus has unspecified Unix
         * domain sockaddr_un which can be shortcut to 3 bytes.  To handle
         * a bound remote socket correctly ls->socklen should be at least
         * sizeof(struct sockaddr_un), see comment in unix/nxt_socket.h.
         */
        ls->socklen = 3;
        size = ls->socklen + sizeof("unix:") - 1;

        break;

#endif

    default:
        ls->socklen = sizeof(struct sockaddr_in);

        size = offsetof(nxt_sockaddr_t, u) + sizeof(struct sockaddr_in)
               + NXT_INET_ADDR_STR_LEN + (sizeof(":65535") - 1);

        if (ls->sockaddr->u.sockaddr_in.sin_addr.s_addr == INADDR_ANY) {
            size += offsetof(nxt_sockaddr_t, u) + sizeof(struct sockaddr_in);
        }

        break;
    }

#if (NXT_SSLTLS)

    if (ls->ssltls) {
        size += 4 * sizeof(void *)   /* SSL/TLS connection */
                + sizeof(nxt_buf_mem_t)
                + sizeof(nxt_mem_pool_cleanup_t);
    }

#endif

    return size + sizeof(nxt_mem_pool_t)
                + sizeof(nxt_event_conn_t)
                + sizeof(nxt_log_t);
}


static u_char *
nxt_listen_socket_log_handler(void *ctx, u_char *pos, u_char *end)
{
    nxt_sockaddr_t  *sa;

    sa = ctx;

    return nxt_sprintf(pos, end, " while creating listening socket on %*s",
                       sa->text_len, sa->text);
}

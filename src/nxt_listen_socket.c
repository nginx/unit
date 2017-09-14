
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static u_char *nxt_listen_socket_log_handler(void *ctx, u_char *pos,
    u_char *last);


nxt_int_t
nxt_listen_socket(nxt_task_t *task, nxt_socket_t s, int backlog)
{
    nxt_debug(task, "listen(%d, %d)", s, backlog);

    if (nxt_fast_path(listen(s, backlog) == 0)) {
        return NXT_OK;
    }

    nxt_log(task, NXT_LOG_CRIT, "listen(%d, %d) failed %E",
            s, backlog, nxt_socket_errno);

    return NXT_ERROR;
}


nxt_int_t
nxt_listen_socket_create(nxt_task_t *task, nxt_listen_socket_t *ls,
    nxt_bool_t bind_test)
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

    s = nxt_socket_create(task, family, sa->type, 0, ls->flags);
    if (s == -1) {
        goto socket_fail;
    }

    if (nxt_socket_setsockopt(task, s, SOL_SOCKET, SO_REUSEADDR, 1) != NXT_OK) {
        goto fail;
    }

#if (NXT_INET6 && defined IPV6_V6ONLY)

    if (family == AF_INET6 && ls->ipv6only) {
        int  ipv6only;

        ipv6only = (ls->ipv6only == 1);

        /* Ignore possible error. TODO: why? */
        (void) nxt_socket_setsockopt(task, s, IPPROTO_IPV6, IPV6_V6ONLY,
                                     ipv6only);
    }

#endif

#if 0

    /* Ignore possible error. TODO: why? */
    (void) nxt_socket_setsockopt(task, s, SOL_SOCKET, SO_SNDBUF, 8192);

#endif

    if (ls->read_after_accept) {
        nxt_socket_defer_accept(task, s, sa);
    }

    switch (nxt_socket_bind(task, s, sa, bind_test)) {

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

        access = (S_IRUSR | S_IWUSR);

        if (nxt_file_set_access(name, access) != NXT_OK) {
            goto fail;
        }

        if (bind_test && nxt_file_delete(name) != NXT_OK) {
            goto fail;
        }
    }

#endif

    nxt_debug(task, "listen(%d, %d)", s, ls->backlog);

    if (listen(s, ls->backlog) != 0) {
        nxt_log(task, NXT_LOG_CRIT, "listen(%d, %d) failed %E",
                s, ls->backlog, nxt_socket_errno);
        goto fail;
    }

    ls->socket = s;
    thr->log = old;

    return NXT_OK;

fail:

    nxt_socket_close(task, s);

socket_fail:

    thr->log = old;

    return NXT_ERROR;
}


nxt_int_t
nxt_listen_socket_update(nxt_task_t *task, nxt_listen_socket_t *ls,
    nxt_listen_socket_t *prev)
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

    nxt_debug(task, "listen(%d, %d)", ls->socket, ls->backlog);

    if (listen(ls->socket, ls->backlog) != 0) {
        nxt_log(task, NXT_LOG_CRIT, "listen(%d, %d) failed %E",
                ls->socket, ls->backlog, nxt_socket_errno);
        goto fail;
    }

    thr->log = old;

    return NXT_OK;

fail:

    thr->log = old;

    return NXT_ERROR;
}


void
nxt_listen_socket_remote_size(nxt_listen_socket_t *ls, nxt_sockaddr_t *sa)
{
    switch (sa->u.sockaddr.sa_family) {

#if (NXT_INET6)

    case AF_INET6:
        ls->socklen = sizeof(struct sockaddr_in6);
        ls->address_length = NXT_INET6_ADDR_STR_LEN;

        break;

#endif

#if (NXT_HAVE_UNIX_DOMAIN)

    case AF_UNIX:
        /*
         * A remote socket is usually unbound and thus has unspecified Unix
         * domain sockaddr_un which can be shortcut to 3 bytes.  To handle
         * a bound remote socket correctly ls->socklen should be larger, see
         * comment in nxt_socket.h.
         */
        ls->socklen = offsetof(struct sockaddr_un, sun_path) + 1;
        ls->address_length = sizeof("unix:") - 1;

        break;

#endif

    default:
    case AF_INET:
        ls->socklen = sizeof(struct sockaddr_in);
        ls->address_length = NXT_INET_ADDR_STR_LEN;

        break;
    }
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
        ls->address_length = NXT_INET6_ADDR_STR_LEN;

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
         * sizeof(struct sockaddr_un), see comment in nxt_socket.h.
         */
        ls->socklen = 3;
        size = ls->socklen + sizeof("unix:") - 1;
        ls->address_length = sizeof("unix:") - 1;

        break;

#endif

    default:
        ls->socklen = sizeof(struct sockaddr_in);
        ls->address_length = NXT_INET_ADDR_STR_LEN;

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

    return size // + sizeof(nxt_mem_pool_t)
                + sizeof(nxt_conn_t)
                + sizeof(nxt_log_t);
}


static u_char *
nxt_listen_socket_log_handler(void *ctx, u_char *pos, u_char *end)
{
    nxt_sockaddr_t  *sa;

    sa = ctx;

    return nxt_sprintf(pos, end, " while creating listening socket on %*s",
                       sa->length, sa->start);
}

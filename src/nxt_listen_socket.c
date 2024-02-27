
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

    nxt_alert(task, "listen(%d, %d) failed %E", s, backlog, nxt_socket_errno);

    return NXT_ERROR;
}


nxt_int_t
nxt_listen_socket_create(nxt_task_t *task, nxt_mp_t *mp,
    nxt_listen_socket_t *ls)
{
    nxt_log_t          log, *old;
    nxt_uint_t         family;
    nxt_socket_t       s;
    nxt_thread_t       *thr;
    nxt_sockaddr_t     *sa;
#if (NXT_HAVE_UNIX_DOMAIN)
    int                ret;
    u_char             *p;
    nxt_err_t          err;
    nxt_socket_t       ts;
    nxt_sockaddr_t     *orig_sa;
    nxt_file_name_t    *name, *tmp;
    nxt_file_access_t  access;
#endif

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
        goto fail;
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

#if (NXT_HAVE_UNIX_DOMAIN)

    if (family == AF_UNIX
        && sa->type == SOCK_STREAM
        && sa->u.sockaddr_un.sun_path[0] != '\0')
    {
        orig_sa = sa;

        sa = nxt_sockaddr_alloc(mp, sa->socklen + 4, sa->length + 4);
        if (sa == NULL) {
            goto fail;
        }

        sa->type = SOCK_STREAM;
        sa->u.sockaddr_un.sun_family = AF_UNIX;

        p = nxt_cpystr((u_char *) sa->u.sockaddr_un.sun_path,
                       (u_char *) orig_sa->u.sockaddr_un.sun_path);
        nxt_memcpy(p, ".tmp", 4);

        nxt_sockaddr_text(sa);

        (void) unlink(sa->u.sockaddr_un.sun_path);

    } else {
        orig_sa = NULL;
    }

#endif

    if (nxt_socket_bind(task, s, sa) != NXT_OK) {
        goto fail;
    }

#if (NXT_HAVE_UNIX_DOMAIN)

    if (family == AF_UNIX) {
        const char     *user;
        const char     *group;
        nxt_runtime_t  *rt = thr->runtime;

        name = (nxt_file_name_t *) sa->u.sockaddr_un.sun_path;
        access = rt->control_mode > 0 ? rt->control_mode : S_IRUSR | S_IWUSR;

        if (nxt_file_set_access(name, access) != NXT_OK) {
            goto listen_fail;
        }

        user = rt->control_user;
        group = rt->control_group;

        if (nxt_file_chown(name, user, group) != NXT_OK) {
            goto listen_fail;
        }
    }

#endif

    nxt_debug(task, "listen(%d, %d)", s, ls->backlog);

    if (listen(s, ls->backlog) != 0) {
        nxt_alert(task, "listen(%d, %d) failed %E",
                  s, ls->backlog, nxt_socket_errno);
        goto listen_fail;
    }

#if (NXT_HAVE_UNIX_DOMAIN)

    if (orig_sa != NULL) {
        ts = nxt_socket_create(task, AF_UNIX, SOCK_STREAM, 0, 0);
        if (ts == -1) {
            goto listen_fail;
        }

        ret = connect(ts, &orig_sa->u.sockaddr, orig_sa->socklen);

        err = nxt_socket_errno;

        nxt_socket_close(task, ts);

        if (ret == 0) {
            nxt_alert(task, "connect(%d, %*s) socket already in use",
                      ts, (size_t) orig_sa->length,
                      nxt_sockaddr_start(orig_sa));

            goto listen_fail;
        }

        if (err != NXT_ENOENT && err != NXT_ECONNREFUSED) {
            nxt_alert(task, "connect(%d, %*s) failed %E",
                      ts, (size_t) orig_sa->length,
                      nxt_sockaddr_start(orig_sa), err);

            goto listen_fail;
        }

        tmp = (nxt_file_name_t *) sa->u.sockaddr_un.sun_path;
        name = (nxt_file_name_t *) orig_sa->u.sockaddr_un.sun_path;

        if (nxt_file_rename(tmp, name) != NXT_OK) {
            goto listen_fail;
        }
    }

#endif

    ls->socket = s;
    thr->log = old;

    return NXT_OK;

listen_fail:

#if (NXT_HAVE_UNIX_DOMAIN)

    if (family == AF_UNIX) {
        name = (nxt_file_name_t *) sa->u.sockaddr_un.sun_path;

        (void) nxt_file_delete(name);
    }

#endif

fail:

    if (s != -1) {
        nxt_socket_close(task, s);
    }

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
        nxt_alert(task, "listen(%d, %d) failed %E",
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
nxt_listen_socket_remote_size(nxt_listen_socket_t *ls)
{
    switch (ls->sockaddr->u.sockaddr.sa_family) {

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
        ls->address_length = nxt_length("unix:");

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
               + NXT_INET6_ADDR_STR_LEN + nxt_length(":65535");

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
        size = ls->socklen + nxt_length("unix:");
        ls->address_length = nxt_length("unix:");

        break;

#endif

    default:
        ls->socklen = sizeof(struct sockaddr_in);
        ls->address_length = NXT_INET_ADDR_STR_LEN;

        size = offsetof(nxt_sockaddr_t, u) + sizeof(struct sockaddr_in)
               + NXT_INET_ADDR_STR_LEN + nxt_length(":65535");

        if (ls->sockaddr->u.sockaddr_in.sin_addr.s_addr == INADDR_ANY) {
            size += offsetof(nxt_sockaddr_t, u) + sizeof(struct sockaddr_in);
        }

        break;
    }

#if (NXT_TLS)

    if (ls->tls) {
        size += 4 * sizeof(void *)       /* SSL/TLS connection */
                + sizeof(nxt_buf_mem_t)
                + sizeof(nxt_work_t);    /* nxt_mp_cleanup */
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
                       (size_t) sa->length, nxt_sockaddr_start(sa));
}

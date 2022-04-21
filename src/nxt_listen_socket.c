
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static u_char *nxt_listen_socket_log_handler(void *ctx, u_char *pos,
    u_char *end);


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
    nxt_err_t          err;
#if (NXT_HAVE_UNIX_DOMAIN)
    u_char             *p;
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

    s = nxt_socket_create(task, family, sa->type, 0, ls->flags, &err);
    if (s == -1) {

#if (NXT_INET6)

        if (err == EAFNOSUPPORT && sa->u.sockaddr.sa_family == AF_INET6) {
            ls->error = NXT_SOCKET_ERROR_NOINET6;
        }

#endif

        if (ls->start != NULL && ls->end != NULL)
            ls->end = nxt_sprintf(ls->start, ls->end,
                                  "nxt_socket_create(\"%*s\") failed %E",
                                  (size_t) sa->length, nxt_sockaddr_start(sa), err);
        goto fail;
    }

    if (nxt_socket_setsockopt(task, s, SOL_SOCKET, SO_REUSEADDR, 1) != NXT_OK) {
        if (ls->start != NULL && ls->end != NULL)
            ls->end = nxt_sprintf(ls->start, ls->end,
                                  "nxt_socket_setsockopt(\"%*s\", SO_REUSEADDR) failed",
                                  (size_t) sa->length, nxt_sockaddr_start(sa));
        goto fail;
    }

#if (NXT_INET6 && defined IPV6_V6ONLY)

    if (family == AF_INET6 && ls->ipv6only) {
        int  ipv6only;

        ipv6only = (ls->ipv6only == 1);

        if (nxt_socket_setsockopt(task, s, IPPROTO_IPV6, IPV6_V6ONLY,
                                  ipv6only) != NXT_OK) {
            if (ls->start != NULL && ls->end != NULL)
                ls->end = nxt_sprintf(ls->start, ls->end,
                                      "nxt_socket_setsockopt(\"%*s\", IPV6_V6ONLY) failed",
                                      (size_t) sa->length, nxt_sockaddr_start(sa));
            goto fail;
        }
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
            if (ls->start != NULL && ls->end != NULL)
                ls->end = nxt_sprintf(ls->start, ls->end,
                                      "nxt_sockaddr_alloc(%*s) failed",
                                      (size_t) sa->length, nxt_sockaddr_start(sa));
            goto fail;
        }

        sa->type = SOCK_STREAM;
        sa->u.sockaddr_un.sun_family = AF_UNIX;

        p = nxt_cpystr((u_char *) sa->u.sockaddr_un.sun_path,
                       (u_char *) orig_sa->u.sockaddr_un.sun_path);
        nxt_memcpy(p, NXT_TMP_EXT, 4);

        nxt_sockaddr_text(sa);

        name = (nxt_file_name_t *) sa->u.sockaddr_un.sun_path;

        if (nxt_socket_release_by_path(name) != NXT_OK) {
            if (ls->start != NULL && ls->end != NULL)
                ls->end = nxt_sprintf(ls->start, ls->end,
                                      "nxt_socket_release_by_path(%FN) failed",
                                      name);
            goto fail;
        }

    } else {
        orig_sa = NULL;
    }

#endif

    if (nxt_socket_bind(task, s, sa, &err) != NXT_OK) {

#if (NXT_HAVE_UNIX_DOMAIN)

        if (sa->u.sockaddr.sa_family == AF_UNIX) {
            switch (err) {

            case EACCES:
                ls->error = NXT_SOCKET_ERROR_ACCESS;
                break;

            case ENOENT:
            case ENOTDIR:
                ls->error = NXT_SOCKET_ERROR_PATH;
                break;
            }

        } else
#endif
        {
            switch (err) {

                case EACCES:
                    ls->error = NXT_SOCKET_ERROR_PORT;
                    break;

                case EADDRINUSE:
                    ls->error = NXT_SOCKET_ERROR_INUSE;
                    break;

                case EADDRNOTAVAIL:
                    ls->error = NXT_SOCKET_ERROR_NOADDR;
                    break;
            }
        }

        if (ls->start != NULL && ls->end != NULL)
            ls->end = nxt_sprintf(ls->start, ls->end,
                                  "nxt_socket_bind(%d, %*s) failed %E",
                                  s, (size_t) sa->length, nxt_sockaddr_start(sa),
                                  err);
        goto fail;
    }

#if (NXT_HAVE_UNIX_DOMAIN)

    if (family == AF_UNIX) {
        name = (nxt_file_name_t *) sa->u.sockaddr_un.sun_path;

        access = (ls->access) ? ls->access : (S_IRUSR | S_IWUSR);

        if (nxt_file_set_access(name, access) != NXT_OK) {
            if (ls->start != NULL && ls->end != NULL)
                ls->end = nxt_sprintf(ls->start, ls->end,
                                      "nxt_file_set_access(%FN) failed",
                                      name);
            goto listen_fail;
        }
    }

#endif

    if (ls->start == NULL) {
        nxt_debug(task, "listen(%d, %d)", s, ls->backlog);

        if (listen(s, ls->backlog) != 0) {
            err = nxt_socket_errno;
            nxt_alert(task, "listen(%d, %d) failed %E",
                      s, ls->backlog, err);
            if (ls->start != NULL && ls->end != NULL)
                ls->end = nxt_sprintf(ls->start, ls->end,
                                      "listen(%d, %d) failed %E",
                                      s, ls->backlog, err);
            goto listen_fail;
        }

#if (NXT_HAVE_UNIX_DOMAIN)

        if (orig_sa != NULL) {

            if (nxt_listen_socket_saddr_check(task, orig_sa) != NXT_OK) {
                nxt_alert(task, "nxt_listen_socket_saddr_check(%*s) failed",
                          (size_t) sa->length, nxt_sockaddr_start(sa));
                if (ls->start != NULL && ls->end != NULL)
                    ls->end = nxt_sprintf(ls->start, ls->end,
                                          "nxt_listen_socket_connect(%*s) failed",
                                          (size_t) sa->length, nxt_sockaddr_start(sa));
                goto listen_fail;
            }

            tmp = (nxt_file_name_t *) sa->u.sockaddr_un.sun_path;
            name = (nxt_file_name_t *) orig_sa->u.sockaddr_un.sun_path;

            if (nxt_file_rename(tmp, name) != NXT_OK) {
                nxt_alert(task, "nxt_file_rename(%FN, %FN) failed",
                          tmp, name);
                if (ls->start != NULL && ls->end != NULL)
                    ls->end = nxt_sprintf(ls->start, ls->end,
                                          "nxt_file_rename(%FN, %FN) failed",
                                          tmp, name);
                goto listen_fail;
            }

        }

#endif

    }

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
nxt_listen_socket_saddr_check(nxt_task_t *task, nxt_sockaddr_t *sa)
{
    nxt_socket_t    ts;
    nxt_int_t       ret;
    nxt_err_t       err;

    ts = nxt_socket_create(task, AF_UNIX, SOCK_STREAM, 0, 0, NULL);
    if (ts == -1) {
        return NXT_ERROR;
    }

    ret = connect(ts, &sa->u.sockaddr, sa->socklen);
    err = nxt_socket_errno;

    nxt_socket_close(task, ts);

    if (ret == 0) {
        nxt_alert(task, "connect(%d, %*s) succeed, address already in use",
                  ts, (size_t) sa->length,
                  nxt_sockaddr_start(sa));
        return NXT_ERROR;
    }

    if (err != NXT_ENOENT && err != NXT_ECONNREFUSED) {
        nxt_alert(task, "connect(%d, %*s) failed %E",
                  ts, (size_t) sa->length,
                  nxt_sockaddr_start(sa), err);
        return NXT_ERROR;
    }

    return NXT_OK;
}


nxt_int_t
nxt_listen_socket_tmp_rename(nxt_task_t *task, nxt_sockaddr_t *sa)
{
    size_t           TMP_EXT_SIZE = sizeof(NXT_TMP_EXT),
                     TMP_SIZE = sa->socklen + TMP_EXT_SIZE,
                     name_size;
    nxt_file_name_t  tmp[TMP_SIZE], *name;

    nxt_memzero(&tmp, TMP_SIZE);

    name = (nxt_file_name_t *) sa->u.sockaddr_un.sun_path;
    name_size = nxt_strlen(name);

    nxt_memcpy(tmp, name, name_size);
    nxt_memcpy(tmp + name_size, NXT_TMP_EXT, TMP_EXT_SIZE);

    if (nxt_file_rename(tmp, name) != NXT_OK) {
        nxt_alert(task, "nxt_file_rename(%FN, %FN) failed",
                  tmp, name);
        return NXT_ERROR;
    }

    return NXT_OK;
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

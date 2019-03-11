
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


void
nxt_job_resolve(nxt_job_resolve_t *jbr)
{
    int                 err;
    u_char              *host;
    size_t              length;
    nxt_mp_t            *mp;
    nxt_uint_t          n;
    nxt_sockaddr_t      *sa;
    struct addrinfo     hint, *res, *r;
    nxt_work_handler_t  handler;

    #define NXT_BUFSIZE  64
    u_char               buf[NXT_BUFSIZE];

    handler = jbr->error_handler;
    res = NULL;

    length = jbr->name.length + 1;

    if (nxt_fast_path(length <= NXT_BUFSIZE)) {
        host = buf;

    } else {
        host = nxt_mp_alloc(jbr->job.mem_pool, length);
        if (nxt_slow_path(host == NULL)) {
            goto fail;
        }
    }

    nxt_cpystrn(host, jbr->name.start, length);

    nxt_memzero(&hint, sizeof(struct addrinfo));
    hint.ai_socktype = SOCK_STREAM;

    err = getaddrinfo((char *) host, NULL, &hint, &res);

    if (err != 0) {
        nxt_thread_log_error(jbr->log_level,
                             "getaddrinfo(\"%s\") failed (%d: %s)",
                             host, err, gai_strerror(err));
        goto fail;
    }

    n = 0;
    for (r = res; r != NULL; r = r->ai_next) {

        switch (r->ai_addr->sa_family) {
#if (NXT_INET6)
        case AF_INET6:
#endif
        case AF_INET:
            n++;
            break;

        default:
            break;
        }
    }

    jbr->count = n;
    mp = jbr->job.mem_pool;

    jbr->sockaddrs = nxt_mp_alloc(mp, n * sizeof(nxt_sockaddr_t *));
    if (nxt_slow_path(jbr->sockaddrs == NULL)) {
        goto fail;
    }

    n = 0;
    for (r = res; r != NULL; r = r->ai_next) {

        switch (r->ai_addr->sa_family) {
#if (NXT_INET6)
        case AF_INET6:
            length = NXT_INET6_ADDR_STR_LEN;
            break;
#endif
        case AF_INET:
            length = NXT_INET_ADDR_STR_LEN;
            break;

        default:
            continue;
        }

        sa = nxt_sockaddr_create(mp, r->ai_addr, r->ai_addrlen, length);
        if (nxt_slow_path(sa == NULL)) {
            goto fail;
        }

        jbr->sockaddrs[n++] = sa;

        if (jbr->port != 0) {

            switch (sa->u.sockaddr.sa_family) {
            case AF_INET:
                sa->u.sockaddr_in.sin_port = jbr->port;
                break;
#if (NXT_INET6)
            case AF_INET6:
                sa->u.sockaddr_in6.sin6_port = jbr->port;
                break;
#endif
            default:
                break;
            }
        }
    }

    handler = jbr->ready_handler;

fail:

    if (nxt_fast_path(res != NULL)) {
        freeaddrinfo(res);
    }

    if (host != buf) {
        nxt_mp_free(jbr->job.mem_pool, host);
    }

    nxt_job_return(jbr->job.task, &jbr->job, handler);
}

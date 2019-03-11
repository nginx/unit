
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


#if (NXT_INET6)
static u_char *nxt_inet6_ntop(u_char *addr, u_char *buf, u_char *end);
#endif

static nxt_sockaddr_t *nxt_sockaddr_unix_parse(nxt_mp_t *mp, nxt_str_t *addr);
static nxt_sockaddr_t *nxt_sockaddr_inet6_parse(nxt_mp_t *mp, nxt_str_t *addr);
static nxt_sockaddr_t *nxt_sockaddr_inet_parse(nxt_mp_t *mp, nxt_str_t *addr);

static nxt_int_t nxt_job_sockaddr_unix_parse(nxt_job_sockaddr_parse_t *jbs);
static nxt_int_t nxt_job_sockaddr_inet6_parse(nxt_job_sockaddr_parse_t *jbs);
static nxt_int_t nxt_job_sockaddr_inet_parse(nxt_job_sockaddr_parse_t *jbs);


nxt_sockaddr_t *
nxt_sockaddr_cache_alloc(nxt_event_engine_t *engine, nxt_listen_socket_t *ls)
{
    uint8_t         hint;
    size_t          size;
    nxt_sockaddr_t  *sa;

    hint = (uint8_t) -1;
    size = offsetof(nxt_sockaddr_t, u) + ls->socklen + ls->address_length;

    sa = nxt_event_engine_mem_alloc(engine, &hint, size);

    if (nxt_fast_path(sa != NULL)) {
        /* Zero only beginning of structure up to sockaddr_un.sun_path[1]. */
        nxt_memzero(sa, offsetof(nxt_sockaddr_t, u.sockaddr.sa_data[1]));

        sa->cache_hint = hint;
        sa->socklen = ls->socklen;
        sa->length = ls->address_length;

        sa->type = ls->sockaddr->type;
        /*
         * Set address family for unspecified Unix domain socket,
         * because these sockaddr's are not updated by old BSD systems,
         * see comment in nxt_conn_io_accept().
         */
        sa->u.sockaddr.sa_family = ls->sockaddr->u.sockaddr.sa_family;
    }

    return sa;
}


void
nxt_sockaddr_cache_free(nxt_event_engine_t *engine, nxt_conn_t *c)
{
    nxt_event_engine_mem_free(engine, &c->remote->cache_hint, c->remote);
}


nxt_sockaddr_t *
nxt_sockaddr_alloc(nxt_mp_t *mp, socklen_t socklen, size_t address_length)
{
    size_t          size;
    nxt_sockaddr_t  *sa;

    size = offsetof(nxt_sockaddr_t, u) + socklen + address_length;

    /*
     * The current struct sockaddr's define 32-bit fields at maximum
     * and may define 64-bit AF_INET6 fields in the future.  Alignment
     * of memory allocated by nxt_mp_zalloc() is enough for these fields.
     * If 128-bit alignment will be required then nxt_mem_malloc() and
     * nxt_memzero() should be used instead.
     */

    sa = nxt_mp_zalloc(mp, size);

    if (nxt_fast_path(sa != NULL)) {
        sa->socklen = socklen;
        sa->length = address_length;
    }

    return sa;
}


nxt_sockaddr_t *
nxt_sockaddr_create(nxt_mp_t *mp, struct sockaddr *sockaddr, socklen_t length,
    size_t address_length)
{
    size_t          size, copy;
    nxt_sockaddr_t  *sa;

    size = length;
    copy = length;

#if (NXT_HAVE_UNIX_DOMAIN)

    /*
     * Unspecified Unix domain sockaddr_un form and length are very
     * platform depended (see comment in nxt_socket.h).  Here they are
     * normalized to the sockaddr_un with single zero byte sun_path[].
     */

    if (size <= offsetof(struct sockaddr_un, sun_path)) {
        /*
         * Small socket length means a short unspecified Unix domain
         * socket address:
         *
         *   getsockname() and getpeername() on OpenBSD prior to 5.3
         *   return zero length and does not update a passed sockaddr
         *   buffer at all.
         *
         *   Linux returns length equal to 2, i.e. sockaddr_un without
         *   sun_path[], unix(7):
         *
         *     unnamed: A stream socket that has not been bound
         *     to a pathname using bind(2) has no name.  Likewise,
         *     the two sockets created by socketpair(2) are unnamed.
         *     When the address of an unnamed socket is returned by
         *     getsockname(2), getpeername(2), and accept(2), its
         *     length is sizeof(sa_family_t), and sun_path should
         *     not be inspected.
         */
        size = offsetof(struct sockaddr_un, sun_path) + 1;

#if !(NXT_LINUX)

    } else if (sockaddr->sa_family == AF_UNIX && sockaddr->sa_data[0] == '\0') {
        /*
         * Omit nonsignificant zeros of the unspecified Unix domain socket
         * address.  This test is disabled for Linux since Linux abstract
         * socket address also starts with zero.  However Linux unspecified
         * Unix domain socket address is short and is handled above.
         */
        size = offsetof(struct sockaddr_un, sun_path) + 1;
        copy = size;

#endif
    }

#endif  /* NXT_HAVE_UNIX_DOMAIN */

    sa = nxt_sockaddr_alloc(mp, size, address_length);

    if (nxt_fast_path(sa != NULL)) {
        nxt_memcpy(&sa->u.sockaddr, sockaddr, copy);

#if (NXT_HAVE_UNIX_DOMAIN && NXT_OPENBSD)

        if (length == 0) {
            sa->u.sockaddr.sa_family = AF_UNIX;
        }

#endif
    }

    return sa;
}


nxt_sockaddr_t *
nxt_sockaddr_copy(nxt_mp_t *mp, nxt_sockaddr_t *src)
{
    size_t          length;
    nxt_sockaddr_t  *dst;

    length = offsetof(nxt_sockaddr_t, u) + src->socklen;

    dst = nxt_mp_alloc(mp, length);

    if (nxt_fast_path(dst != NULL)) {
        nxt_memcpy(dst, src, length);
    }

    return dst;
}


nxt_sockaddr_t *
nxt_getsockname(nxt_task_t *task, nxt_mp_t *mp, nxt_socket_t s)
{
    int                 ret;
    size_t              length;
    socklen_t           socklen;
    nxt_sockaddr_buf_t  sockaddr;

    socklen = NXT_SOCKADDR_LEN;

    ret = getsockname(s, &sockaddr.buf, &socklen);

    if (nxt_fast_path(ret == 0)) {

        switch (sockaddr.buf.sa_family) {
#if (NXT_INET6)
        case AF_INET6:
            length = NXT_INET6_ADDR_STR_LEN;
            break;
#endif

#if (NXT_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            length = nxt_length("unix:") + socklen;
#endif
            break;

        case AF_INET:
            length = NXT_INET_ADDR_STR_LEN;
            break;

        default:
            length = 0;
            break;
        }

        return nxt_sockaddr_create(mp, &sockaddr.buf, socklen, length);
    }

    nxt_log(task, NXT_LOG_ERR, "getsockname(%d) failed %E", s, nxt_errno);

    return NULL;
}


void
nxt_sockaddr_text(nxt_sockaddr_t *sa)
{
    size_t    offset;
    u_char    *p, *start, *end, *octet;
    uint32_t  port;

    offset = offsetof(nxt_sockaddr_t, u) + sa->socklen;
    sa->start = offset;
    sa->port_start = offset;

    start = nxt_pointer_to(sa, offset);
    end = start + sa->length;

    switch (sa->u.sockaddr.sa_family) {

    case AF_INET:
        sa->address_start = offset;

        octet = (u_char *) &sa->u.sockaddr_in.sin_addr;

        p = nxt_sprintf(start, end, "%ud.%ud.%ud.%ud",
                        octet[0], octet[1], octet[2], octet[3]);

        sa->address_length = p - start;
        sa->port_start += sa->address_length + 1;

        port = sa->u.sockaddr_in.sin_port;

        break;

#if (NXT_INET6)

    case AF_INET6:
        sa->address_start = offset + 1;

        p = start;
        *p++ = '[';

        p = nxt_inet6_ntop(sa->u.sockaddr_in6.sin6_addr.s6_addr, p, end);

        sa->address_length = p - (start + 1);
        sa->port_start += sa->address_length + 3;

        *p++ = ']';

        port = sa->u.sockaddr_in6.sin6_port;

        break;

#endif

#if (NXT_HAVE_UNIX_DOMAIN)

    case AF_UNIX:
        sa->address_start = offset;

        p = (u_char *) sa->u.sockaddr_un.sun_path;

#if (NXT_LINUX)

        if (p[0] == '\0') {
            size_t  length;

            /* Linux abstract socket address has no trailing zero. */
            length = sa->socklen - offsetof(struct sockaddr_un, sun_path);

            p = nxt_sprintf(start, end, "unix:@%*s", length - 1, p + 1);

        } else {
            p = nxt_sprintf(start, end, "unix:%s", p);
        }

#else  /* !(NXT_LINUX) */

        p = nxt_sprintf(start, end, "unix:%s", p);

#endif

        sa->address_length = p - start;
        sa->port_start += sa->address_length;
        sa->length = p - start;

        return;

#endif  /* NXT_HAVE_UNIX_DOMAIN */

    default:
        return;
    }

    p = nxt_sprintf(p, end, ":%d", ntohs(port));

    sa->length = p - start;
}


uint32_t
nxt_sockaddr_port_number(nxt_sockaddr_t *sa)
{
    uint32_t  port;

    switch (sa->u.sockaddr.sa_family) {

#if (NXT_INET6)

    case AF_INET6:
        port = sa->u.sockaddr_in6.sin6_port;
        break;

#endif

#if (NXT_HAVE_UNIX_DOMAIN)

    case AF_UNIX:
        return 0;

#endif

    default:
        port = sa->u.sockaddr_in.sin_port;
        break;
    }

    return ntohs((uint16_t) port);
}


nxt_bool_t
nxt_sockaddr_cmp(nxt_sockaddr_t *sa1, nxt_sockaddr_t *sa2)
{
    if (sa1->socklen != sa2->socklen) {
        return 0;
    }

    if (sa1->type != sa2->type) {
        return 0;
    }

    if (sa1->u.sockaddr.sa_family != sa2->u.sockaddr.sa_family) {
        return 0;
    }

    /*
     * sockaddr struct's cannot be compared in whole since kernel
     * may fill some fields in inherited sockaddr struct's.
     */

    switch (sa1->u.sockaddr.sa_family) {

#if (NXT_INET6)

    case AF_INET6:
        if (sa1->u.sockaddr_in6.sin6_port != sa2->u.sockaddr_in6.sin6_port) {
            return 0;
        }

        if (nxt_memcmp(&sa1->u.sockaddr_in6.sin6_addr,
                       &sa2->u.sockaddr_in6.sin6_addr, 16)
            != 0)
        {
            return 0;
        }

        return 1;

#endif

#if (NXT_HAVE_UNIX_DOMAIN)

    case AF_UNIX:
        {
            size_t  length;

            length = sa1->socklen - offsetof(struct sockaddr_un, sun_path);

            if (nxt_memcmp(&sa1->u.sockaddr_un.sun_path,
                           &sa2->u.sockaddr_un.sun_path, length)
                != 0)
            {
                return 0;
            }

            return 1;
        }

#endif

    default: /* AF_INET */
        if (sa1->u.sockaddr_in.sin_port != sa2->u.sockaddr_in.sin_port) {
            return 0;
        }

        if (sa1->u.sockaddr_in.sin_addr.s_addr
            != sa2->u.sockaddr_in.sin_addr.s_addr)
        {
            return 0;
        }

        return 1;
    }
}


size_t
nxt_sockaddr_ntop(nxt_sockaddr_t *sa, u_char *buf, u_char *end, nxt_bool_t port)
{
    u_char  *p;

    switch (sa->u.sockaddr.sa_family) {

    case AF_INET:
        p = (u_char *) &sa->u.sockaddr_in.sin_addr;

        if (port) {
            p = nxt_sprintf(buf, end, "%ud.%ud.%ud.%ud:%d",
                            p[0], p[1], p[2], p[3],
                            ntohs(sa->u.sockaddr_in.sin_port));
        } else {
            p = nxt_sprintf(buf, end, "%ud.%ud.%ud.%ud",
                            p[0], p[1], p[2], p[3]);
        }

        return p - buf;

#if (NXT_INET6)

    case AF_INET6:
        p = buf;

        if (port) {
            *p++ = '[';
        }

        p = nxt_inet6_ntop(sa->u.sockaddr_in6.sin6_addr.s6_addr, p, end);

        if (port) {
            p = nxt_sprintf(p, end, "]:%d",
                            ntohs(sa->u.sockaddr_in6.sin6_port));
        }

        return p - buf;
#endif

#if (NXT_HAVE_UNIX_DOMAIN)

    case AF_UNIX:

#if (NXT_LINUX)

        p = (u_char *) sa->u.sockaddr_un.sun_path;

        if (p[0] == '\0') {
            size_t  length;

            /* Linux abstract socket address has no trailing zero. */

            length = sa->socklen - offsetof(struct sockaddr_un, sun_path) - 1;
            p = nxt_sprintf(buf, end, "unix:\\0%*s", length, p + 1);

        } else {
            p = nxt_sprintf(buf, end, "unix:%s", p);
        }

#else  /* !(NXT_LINUX) */

        p = nxt_sprintf(buf, end, "unix:%s", sa->u.sockaddr_un.sun_path);

#endif

        return p - buf;

#endif  /* NXT_HAVE_UNIX_DOMAIN */

    default:
        return 0;
    }
}


#if (NXT_INET6)

static u_char *
nxt_inet6_ntop(u_char *addr, u_char *buf, u_char *end)
{
    u_char       *p;
    size_t       zero_groups, last_zero_groups, ipv6_bytes;
    nxt_uint_t   i, zero_start, last_zero_start;

    const size_t  max_inet6_length =
                        nxt_length("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");

    if (buf + max_inet6_length > end) {
        return buf;
    }

    zero_start = 8;
    zero_groups = 0;
    last_zero_start = 8;
    last_zero_groups = 0;

    for (i = 0; i < 16; i += 2) {

        if (addr[i] == 0 && addr[i + 1] == 0) {

            if (last_zero_groups == 0) {
                last_zero_start = i;
            }

            last_zero_groups++;

        } else {
            if (zero_groups < last_zero_groups) {
                zero_groups = last_zero_groups;
                zero_start = last_zero_start;
            }

            last_zero_groups = 0;
        }
    }

    if (zero_groups < last_zero_groups) {
        zero_groups = last_zero_groups;
        zero_start = last_zero_start;
    }

    ipv6_bytes = 16;
    p = buf;

    if (zero_start == 0) {

               /* IPv4-mapped address */
        if ((zero_groups == 5 && addr[10] == 0xFF && addr[11] == 0xFF)
               /* IPv4-compatible address */
            || (zero_groups == 6)
               /* not IPv6 loopback address */
            || (zero_groups == 7 && addr[14] != 0 && addr[15] != 1))
        {
            ipv6_bytes = 12;
        }

        *p++ = ':';
    }

    for (i = 0; i < ipv6_bytes; i += 2) {

        if (i == zero_start) {
            /* Output maximum number of consecutive zero groups as "::". */
            i += (zero_groups - 1) * 2;
            *p++ = ':';
            continue;
        }

        p = nxt_sprintf(p, end, "%uxd", (addr[i] << 8) + addr[i + 1]);

        if (i < 14) {
            *p++ = ':';
        }
    }

    if (ipv6_bytes == 12) {
        p = nxt_sprintf(p, end, "%ud.%ud.%ud.%ud",
                        addr[12], addr[13], addr[14], addr[15]);
    }

    return p;
}

#endif


nxt_sockaddr_t *
nxt_sockaddr_parse(nxt_mp_t *mp, nxt_str_t *addr)
{
    nxt_sockaddr_t  *sa;

    if (addr->length > 6 && nxt_memcmp(addr->start, "unix:", 5) == 0) {
        sa = nxt_sockaddr_unix_parse(mp, addr);

    } else if (addr->length != 0 && addr->start[0] == '[') {
        sa = nxt_sockaddr_inet6_parse(mp, addr);

    } else {
        sa = nxt_sockaddr_inet_parse(mp, addr);
    }

    if (nxt_fast_path(sa != NULL)) {
        nxt_sockaddr_text(sa);
    }

    return sa;
}


static nxt_sockaddr_t *
nxt_sockaddr_unix_parse(nxt_mp_t *mp, nxt_str_t *addr)
{
#if (NXT_HAVE_UNIX_DOMAIN)
    size_t          length, socklen;
    u_char          *path;
    nxt_sockaddr_t  *sa;

    /*
     * Actual sockaddr_un length can be lesser or even larger than defined
     * struct sockaddr_un length (see comment in nxt_socket.h).  So
     * limit maximum Unix domain socket address length by defined sun_path[]
     * length because some OSes accept addresses twice larger than defined
     * struct sockaddr_un.  Also reserve space for a trailing zero to avoid
     * ambiguity, since many OSes accept Unix domain socket addresses
     * without a trailing zero.
     */
    const size_t max_len = sizeof(struct sockaddr_un)
                           - offsetof(struct sockaddr_un, sun_path) - 1;

    /* Cutting "unix:". */
    length = addr->length - 5;
    path = addr->start + 5;

    if (length > max_len) {
        nxt_thread_log_error(NXT_LOG_ERR,
                             "unix domain socket \"%V\" name is too long",
                             addr);
        return NULL;
    }

    socklen = offsetof(struct sockaddr_un, sun_path) + length + 1;

#if (NXT_LINUX)

    /*
     * Linux unix(7):
     *
     *   abstract: an abstract socket address is distinguished by the fact
     *   that sun_path[0] is a null byte ('\0').  The socket's address in
     *   this namespace is given by the additional bytes in sun_path that
     *   are covered by the specified length of the address structure.
     *   (Null bytes in the name have no special significance.)
     */
    if (path[0] == '@') {
        path[0] = '\0';
        socklen--;
    }

#endif

    sa = nxt_sockaddr_alloc(mp, socklen, addr->length);

    if (nxt_fast_path(sa != NULL)) {
        sa->u.sockaddr_un.sun_family = AF_UNIX;
        nxt_memcpy(sa->u.sockaddr_un.sun_path, path, length);
    }

    return sa;

#else  /* !(NXT_HAVE_UNIX_DOMAIN) */

    nxt_thread_log_error(NXT_LOG_ERR,
                         "unix domain socket \"%V\" is not supported", addr);

    return NULL;

#endif
}


static nxt_sockaddr_t *
nxt_sockaddr_inet6_parse(nxt_mp_t *mp, nxt_str_t *addr)
{
#if (NXT_INET6)
    u_char          *p, *start, *end;
    size_t          length;
    nxt_int_t       ret, port;
    nxt_sockaddr_t  *sa;

    length = addr->length - 1;
    start = addr->start + 1;

    end = nxt_memchr(start, ']', length);

    if (end != NULL) {
        sa = nxt_sockaddr_alloc(mp, sizeof(struct sockaddr_in6),
                                NXT_INET6_ADDR_STR_LEN);
        if (nxt_slow_path(sa == NULL)) {
            return NULL;
        }

        ret = nxt_inet6_addr(&sa->u.sockaddr_in6.sin6_addr, start, end - start);

        if (nxt_fast_path(ret == NXT_OK)) {
            p = end + 1;
            length = (start + length) - p;

            if (length > 2 && *p == ':') {
                port = nxt_int_parse(p + 1, length - 1);

                if (port > 0 && port < 65536) {
                    sa->u.sockaddr_in6.sin6_port = htons((in_port_t) port);
                    sa->u.sockaddr_in6.sin6_family = AF_INET6;

                    return sa;
                }
            }

            nxt_thread_log_error(NXT_LOG_ERR, "invalid port in \"%V\"", addr);

            return NULL;
        }
    }

    nxt_thread_log_error(NXT_LOG_ERR, "invalid IPv6 address in \"%V\"", addr);

    return NULL;

#else  /* !(NXT_INET6) */

    nxt_thread_log_error(NXT_LOG_ERR, "IPv6 socket \"%V\" is not supported",
                         addr);
    return NULL;

#endif
}


static nxt_sockaddr_t *
nxt_sockaddr_inet_parse(nxt_mp_t *mp, nxt_str_t *addr)
{
    u_char          *p;
    size_t          length;
    nxt_int_t       port;
    in_addr_t       inaddr;
    nxt_sockaddr_t  *sa;

    p = nxt_memchr(addr->start, ':', addr->length);

    if (nxt_fast_path(p != NULL)) {
        inaddr = INADDR_ANY;
        length = p - addr->start;

        if (length != 1 || addr->start[0] != '*') {
            inaddr = nxt_inet_addr(addr->start, length);

            if (nxt_slow_path(inaddr == INADDR_NONE)) {
                nxt_thread_log_error(NXT_LOG_ERR, "invalid address \"%V\"",
                                     addr);
                return NULL;
            }
        }

        p++;
        length = (addr->start + addr->length) - p;
        port = nxt_int_parse(p, length);

        if (port > 0 && port < 65536) {
            sa = nxt_sockaddr_alloc(mp, sizeof(struct sockaddr_in),
                                    NXT_INET_ADDR_STR_LEN);

            if (nxt_fast_path(sa != NULL)) {
                sa->u.sockaddr_in.sin_family = AF_INET;
                sa->u.sockaddr_in.sin_port = htons((in_port_t) port);
                sa->u.sockaddr_in.sin_addr.s_addr = inaddr;
            }

            return sa;
        }
    }

    nxt_thread_log_error(NXT_LOG_ERR, "invalid port in \"%V\"", addr);

    return NULL;
}


void
nxt_job_sockaddr_parse(nxt_job_sockaddr_parse_t *jbs)
{
    u_char              *p;
    size_t              length;
    nxt_int_t           ret;
    nxt_work_handler_t  handler;

    nxt_job_set_name(&jbs->resolve.job, "job sockaddr parse");

    length = jbs->addr.length;
    p = jbs->addr.start;

    if (length > 6 && nxt_memcmp(p, "unix:", 5) == 0) {
        ret = nxt_job_sockaddr_unix_parse(jbs);

    } else if (length != 0 && *p == '[') {
        ret = nxt_job_sockaddr_inet6_parse(jbs);

    } else {
        ret = nxt_job_sockaddr_inet_parse(jbs);
    }

    switch (ret) {

    case NXT_OK:
        handler = jbs->resolve.ready_handler;
        break;

    case NXT_ERROR:
        handler = jbs->resolve.error_handler;
        break;

    default: /* NXT_AGAIN */
        return;
    }

    nxt_job_return(jbs->resolve.job.task, &jbs->resolve.job, handler);
}


static nxt_int_t
nxt_job_sockaddr_unix_parse(nxt_job_sockaddr_parse_t *jbs)
{
#if (NXT_HAVE_UNIX_DOMAIN)
    size_t          length, socklen;
    u_char          *path;
    nxt_mp_t        *mp;
    nxt_sockaddr_t  *sa;

    /*
     * Actual sockaddr_un length can be lesser or even larger than defined
     * struct sockaddr_un length (see comment in nxt_socket.h).  So
     * limit maximum Unix domain socket address length by defined sun_path[]
     * length because some OSes accept addresses twice larger than defined
     * struct sockaddr_un.  Also reserve space for a trailing zero to avoid
     * ambiguity, since many OSes accept Unix domain socket addresses
     * without a trailing zero.
     */
    const size_t max_len = sizeof(struct sockaddr_un)
                           - offsetof(struct sockaddr_un, sun_path) - 1;

    /* cutting "unix:" */
    length = jbs->addr.length - 5;
    path = jbs->addr.start + 5;

    if (length > max_len) {
        nxt_thread_log_error(jbs->resolve.log_level,
                             "unix domain socket \"%V\" name is too long",
                             &jbs->addr);
        return NXT_ERROR;
    }

    socklen = offsetof(struct sockaddr_un, sun_path) + length + 1;

#if (NXT_LINUX)

    /*
     * Linux unix(7):
     *
     *   abstract: an abstract socket address is distinguished by the fact
     *   that sun_path[0] is a null byte ('\0').  The socket's address in
     *   this namespace is given by the additional bytes in sun_path that
     *   are covered by the specified length of the address structure.
     *   (Null bytes in the name have no special significance.)
     */
    if (path[0] == '\0') {
        socklen--;
    }

#endif

    mp = jbs->resolve.job.mem_pool;

    jbs->resolve.sockaddrs = nxt_mp_alloc(mp, sizeof(void *));

    if (nxt_fast_path(jbs->resolve.sockaddrs != NULL)) {
        sa = nxt_sockaddr_alloc(mp, socklen, jbs->addr.length);

        if (nxt_fast_path(sa != NULL)) {
            jbs->resolve.count = 1;
            jbs->resolve.sockaddrs[0] = sa;

            sa->u.sockaddr_un.sun_family = AF_UNIX;
            nxt_memcpy(sa->u.sockaddr_un.sun_path, path, length);

            return NXT_OK;
        }
    }

    return NXT_ERROR;

#else  /* !(NXT_HAVE_UNIX_DOMAIN) */

    nxt_thread_log_error(jbs->resolve.log_level,
                         "unix domain socket \"%V\" is not supported",
                         &jbs->addr);
    return NXT_ERROR;

#endif
}


static nxt_int_t
nxt_job_sockaddr_inet6_parse(nxt_job_sockaddr_parse_t *jbs)
{
#if (NXT_INET6)
    u_char           *p, *addr, *addr_end;
    size_t           length;
    nxt_mp_t         *mp;
    nxt_int_t        port;
    nxt_sockaddr_t   *sa;
    struct in6_addr  *in6_addr;

    length = jbs->addr.length - 1;
    addr = jbs->addr.start + 1;

    addr_end = nxt_memchr(addr, ']', length);

    if (addr_end == NULL) {
        goto invalid_address;
    }

    mp = jbs->resolve.job.mem_pool;

    jbs->resolve.sockaddrs = nxt_mp_alloc(mp, sizeof(void *));

    if (nxt_slow_path(jbs->resolve.sockaddrs == NULL)) {
        return NXT_ERROR;
    }

    sa = nxt_sockaddr_alloc(mp, sizeof(struct sockaddr_in6),
                            NXT_INET6_ADDR_STR_LEN);

    if (nxt_slow_path(sa == NULL)) {
        return NXT_ERROR;
    }

    jbs->resolve.count = 1;
    jbs->resolve.sockaddrs[0] = sa;

    in6_addr = &sa->u.sockaddr_in6.sin6_addr;

    if (nxt_inet6_addr(in6_addr, addr, addr_end - addr) != NXT_OK) {
        goto invalid_address;
    }

    p = addr_end + 1;
    length = (addr + length) - p;

    if (length == 0) {
        jbs->no_port = 1;
        port = jbs->resolve.port;
        goto found;
    }

    if (*p == ':') {
        port = nxt_int_parse(p + 1, length - 1);

        if (port >= 1 && port <= 65535) {
            port = htons((in_port_t) port);
            goto found;
        }
    }

    nxt_thread_log_error(jbs->resolve.log_level,
                         "invalid port in \"%V\"", &jbs->addr);

    return NXT_ERROR;

found:

    sa->u.sockaddr_in6.sin6_family = AF_INET6;
    sa->u.sockaddr_in6.sin6_port = (in_port_t) port;

    if (IN6_IS_ADDR_UNSPECIFIED(in6_addr)) {
        jbs->wildcard = 1;
    }

    return NXT_OK;

invalid_address:

    nxt_thread_log_error(jbs->resolve.log_level,
                         "invalid IPv6 address in \"%V\"", &jbs->addr);
    return NXT_ERROR;

#else

    nxt_thread_log_error(jbs->resolve.log_level,
                         "IPv6 socket \"%V\" is not supported", &jbs->addr);
    return NXT_ERROR;

#endif
}


static nxt_int_t
nxt_job_sockaddr_inet_parse(nxt_job_sockaddr_parse_t *jbs)
{
    u_char          *p, *host;
    size_t          length;
    nxt_mp_t        *mp;
    nxt_int_t       port;
    in_addr_t       addr;
    nxt_sockaddr_t  *sa;

    addr = INADDR_ANY;

    length = jbs->addr.length;
    host = jbs->addr.start;

    p = nxt_memchr(host, ':', length);

    if (p == NULL) {

        /* single value port, address, or host name */

        port = nxt_int_parse(host, length);

        if (port > 0) {
            if (port < 1 || port > 65535) {
                goto invalid_port;
            }

            /* "*:XX" */
            port = htons((in_port_t) port);
            jbs->resolve.port = (in_port_t) port;

        } else {
            jbs->no_port = 1;

            addr = nxt_inet_addr(host, length);

            if (addr == INADDR_NONE) {
                jbs->resolve.name.length = length;
                jbs->resolve.name.start = host;

                nxt_job_resolve(&jbs->resolve);
                return NXT_AGAIN;
            }

            /* "x.x.x.x" */
            port = jbs->resolve.port;
        }

    } else {

        /* x.x.x.x:XX or host:XX */

        p++;
        length = (host + length) - p;
        port = nxt_int_parse(p, length);

        if (port < 1 || port > 65535) {
            goto invalid_port;
        }

        port = htons((in_port_t) port);

        length = (p - 1) - host;

        if (length != 1 || host[0] != '*') {
            addr = nxt_inet_addr(host, length);

            if (addr == INADDR_NONE) {
                jbs->resolve.name.length = length;
                jbs->resolve.name.start = host;
                jbs->resolve.port = (in_port_t) port;

                nxt_job_resolve(&jbs->resolve);
                return NXT_AGAIN;
            }

            /* "x.x.x.x:XX" */
        }
    }

    mp = jbs->resolve.job.mem_pool;

    jbs->resolve.sockaddrs = nxt_mp_alloc(mp, sizeof(void *));
    if (nxt_slow_path(jbs->resolve.sockaddrs == NULL)) {
        return NXT_ERROR;
    }

    sa = nxt_sockaddr_alloc(mp, sizeof(struct sockaddr_in),
                            NXT_INET_ADDR_STR_LEN);

    if (nxt_fast_path(sa != NULL)) {
        jbs->resolve.count = 1;
        jbs->resolve.sockaddrs[0] = sa;

        jbs->wildcard = (addr == INADDR_ANY);

        sa->u.sockaddr_in.sin_family = AF_INET;
        sa->u.sockaddr_in.sin_port = (in_port_t) port;
        sa->u.sockaddr_in.sin_addr.s_addr = addr;

        return NXT_OK;
    }

    return NXT_ERROR;

invalid_port:

    nxt_thread_log_error(jbs->resolve.log_level,
                         "invalid port in \"%V\"", &jbs->addr);

    return NXT_ERROR;
}


in_addr_t
nxt_inet_addr(u_char *buf, size_t length)
{
    u_char      c, *end;
    in_addr_t   addr;
    nxt_uint_t  digit, octet, dots;

    addr = 0;
    octet = 0;
    dots = 0;

    end = buf + length;

    while (buf < end) {

        c = *buf++;

        digit = c - '0';
        /* values below '0' become large unsigned integers */

        if (digit < 10) {
            octet = octet * 10 + digit;
            continue;
        }

        if (c == '.' && octet < 256) {
            addr = (addr << 8) + octet;
            octet = 0;
            dots++;
            continue;
        }

        return INADDR_NONE;
    }

    if (dots == 3 && octet < 256) {
        addr = (addr << 8) + octet;
        return htonl(addr);
    }

    return INADDR_NONE;
}


#if (NXT_INET6)

nxt_int_t
nxt_inet6_addr(struct in6_addr *in6_addr, u_char *buf, size_t length)
{
    u_char      c, *addr, *zero_start, *ipv4, *dst, *src, *end;
    nxt_uint_t  digit, group, nibbles, groups_left;

    if (length == 0) {
        return NXT_ERROR;
    }

    end = buf + length;

    if (buf[0] == ':') {
        buf++;
    }

    addr = in6_addr->s6_addr;
    zero_start = NULL;
    groups_left = 8;
    nibbles = 0;
    group = 0;
    ipv4 = NULL;

    while (buf < end) {
        c = *buf++;

        if (c == ':') {
            if (nibbles != 0) {
                ipv4 = buf;

                *addr++ = (u_char) (group >> 8);
                *addr++ = (u_char) (group & 0xFF);
                groups_left--;

                if (groups_left != 0) {
                    nibbles = 0;
                    group = 0;
                    continue;
                }

            } else {
                if (zero_start == NULL) {
                    ipv4 = buf;
                    zero_start = addr;
                    continue;
                }
            }

            return NXT_ERROR;
        }

        if (c == '.' && nibbles != 0) {

            if (groups_left < 2 || ipv4 == NULL) {
                return NXT_ERROR;
            }

            group = nxt_inet_addr(ipv4, end - ipv4);
            if (group == INADDR_NONE) {
                return NXT_ERROR;
            }

            group = ntohl(group);

            *addr++ = (u_char) ((group >> 24) & 0xFF);
            *addr++ = (u_char) ((group >> 16) & 0xFF);
            groups_left--;

            /* the low 16-bit are copied below */
            break;
        }

        nibbles++;

        if (nibbles > 4) {
            return NXT_ERROR;
        }

        group <<= 4;

        digit = c - '0';
        /* values below '0' become large unsigned integers */

        if (digit < 10) {
            group += digit;
            continue;
        }

        c |= 0x20;
        digit = c - 'a';
        /* values below 'a' become large unsigned integers */

        if (digit < 6) {
            group += 10 + digit;
            continue;
        }

        return NXT_ERROR;
    }

    if (nibbles == 0 && zero_start == NULL) {
        return NXT_ERROR;
    }

    *addr++ = (u_char) (group >> 8);
    *addr++ = (u_char) (group & 0xFF);
    groups_left--;

    if (groups_left != 0) {

        if (zero_start != NULL) {

            /* moving part before consecutive zero groups to the end */

            groups_left *= 2;
            src = addr - 1;
            dst = src + groups_left;

            while (src >= zero_start) {
                *dst-- = *src--;
            }

            nxt_memzero(zero_start, groups_left);

            return NXT_OK;
        }

    } else {
        if (zero_start == NULL) {
            return NXT_OK;
        }
    }

    return NXT_ERROR;
}

#endif


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_SOCKADDR_H_INCLUDED_
#define _NXT_SOCKADDR_H_INCLUDED_


/*
 * The nxt_sockaddr_t should be allocated using nxt_sockaddr_alloc()
 * with actual "struct sockaddr_..." size:
 *    nxt_sockaddr_alloc(pool, sizeof(struct sockaddr_in))
 */

struct nxt_sockaddr_s {
    /*
     * A sockaddr textual representation is optional and may be in two forms:
     * with port or without port.  If a nxt_sockaddr_t is intended to listen(),
     * bind() or connect() then the textual representation must be present and
     * must include the port.  nxt_event_conn_accept() creates a textual
     * representation without the port.
     */
    u_char                        *text;

    /*
     * text_len, socket type and socklen are stored
     * together on 64-bit platforms without sockaddr.sa_len.
     */
    uint16_t                      text_len;
    uint16_t                      type;
#if !(NXT_SOCKADDR_SA_LEN)
    socklen_t                     _socklen;
#endif

    union {
        struct sockaddr           sockaddr;
        struct sockaddr_in        sockaddr_in;
#if (NXT_INET6)
        struct sockaddr_in6       sockaddr_in6;
#endif
#if (NXT_HAVE_UNIX_DOMAIN)
        struct sockaddr_un        sockaddr_un;
#endif
    } u;
};


typedef struct {
    nxt_job_resolve_t             resolve;
    nxt_str_t                     addr;

    uint8_t                       wildcard;   /* 1 bit */
    uint8_t                       no_port;    /* 1 bit */
} nxt_job_sockaddr_parse_t;


NXT_EXPORT nxt_sockaddr_t *nxt_sockaddr_alloc(nxt_mem_pool_t *mp, socklen_t len)
    NXT_MALLOC_LIKE;
NXT_EXPORT nxt_sockaddr_t *nxt_sockaddr_create(nxt_mem_pool_t *mp,
    struct sockaddr *sockaddr, socklen_t len)
    NXT_MALLOC_LIKE;
NXT_EXPORT nxt_sockaddr_t *nxt_sockaddr_copy(nxt_mem_pool_t *mp,
    nxt_sockaddr_t *src)
    NXT_MALLOC_LIKE;
NXT_EXPORT nxt_sockaddr_t *nxt_getsockname(nxt_mem_pool_t *mp, nxt_socket_t s)
    NXT_MALLOC_LIKE;
NXT_EXPORT nxt_int_t nxt_sockaddr_text(nxt_mem_pool_t *mp, nxt_sockaddr_t *sa,
    nxt_bool_t port);


#if (NXT_SOCKADDR_SA_LEN)

#define                                                                       \
nxt_socklen_set(sa, len)                                                      \
    (sa)->u.sockaddr.sa_len = (socklen_t) (len)


#define                                                                       \
nxt_socklen(sa)                                                               \
    ((sa)->u.sockaddr.sa_len)

#else

#define                                                                       \
nxt_socklen_set(sa, len)                                                      \
    (sa)->_socklen = (socklen_t) (len)


#define                                                                       \
nxt_socklen(sa)                                                               \
    ((sa)->_socklen)

#endif


NXT_EXPORT uint32_t nxt_sockaddr_port(nxt_sockaddr_t *sa);
NXT_EXPORT nxt_bool_t nxt_sockaddr_cmp(nxt_sockaddr_t *sa1,
    nxt_sockaddr_t *sa2);
NXT_EXPORT size_t nxt_sockaddr_ntop(nxt_sockaddr_t *sa, u_char *buf,
    u_char *end,
    nxt_bool_t port);
NXT_EXPORT void nxt_job_sockaddr_parse(nxt_job_sockaddr_parse_t *jbs);
NXT_EXPORT in_addr_t nxt_inet_addr(u_char *buf, size_t len);
#if (NXT_INET6)
NXT_EXPORT nxt_int_t nxt_inet6_addr(struct in6_addr *in6_addr, u_char *buf,
    size_t len);
#endif

#if (NXT_HAVE_UNIX_DOMAIN)
#define nxt_unix_addr_path_len(sa)                                            \
    (nxt_socklen(sa) - offsetof(struct sockaddr_un, sun_path))
#endif


#define NXT_INET_ADDR_STR_LEN     (sizeof("255.255.255.255") - 1)

#define NXT_INET6_ADDR_STR_LEN                                                \
    (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1)

#define NXT_UNIX_ADDR_STR_LEN                                                 \
    ((sizeof("unix:") - 1)                                                    \
     + (sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path)))


#if (NXT_HAVE_UNIX_DOMAIN)
#define NXT_SOCKADDR_STR_LEN      NXT_UNIX_ADDR_STR_LEN

#elif (NXT_INET6)
#define NXT_SOCKADDR_STR_LEN      NXT_INET6_ADDR_STR_LEN

#else
#define NXT_SOCKADDR_STR_LEN      NXT_INET_ADDR_STR_LEN
#endif


#if (NXT_INET6)
#define NXT_SOCKPORT_STR_LEN      (sizeof("[]:65535") - 1)

#else
#define NXT_SOCKPORT_STR_LEN      (sizeof(":65535") - 1)
#endif


nxt_inline size_t
nxt_sockaddr_text_len(nxt_sockaddr_t *sa)
{
    switch (sa->u.sockaddr.sa_family) {

#if (NXT_INET6)
    case AF_INET6:
        return NXT_INET6_ADDR_STR_LEN;
#endif

#if (NXT_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        return NXT_UNIX_ADDR_STR_LEN;
#endif

    default:
        return NXT_INET_ADDR_STR_LEN;
    }
}


#endif /* _NXT_SOCKADDR_H_INCLUDED_ */

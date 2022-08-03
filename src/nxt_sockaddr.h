
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

/*
 * A textual sockaddr representation is stored after struct sockaddr union
 * and allocated as a whole.
 */

struct nxt_sockaddr_s {
    /* Socket type: SOCKS_STREAM, SOCK_DGRAM, etc. */
    uint8_t                       type;
    /* Size of struct sockaddr. */
    uint8_t                       socklen;
    /*
     * Textual sockaddr representation, e.g.: "127.0.0.1:8000",
     * "[::1]:8000", and "unix:/path/to/socket".
     */
    uint8_t                       start;
    uint8_t                       length;
    /*
     * Textual address representation, e.g: "127.0.0.1", "::1",
     * and "unix:/path/to/socket".
     */
    uint8_t                       address_start;
    uint8_t                       address_length;
    /*
     * Textual port representation, e.g. "8000".
     * Port length is (start + length) - port_start.
     */
    uint8_t                       port_start;

    /* A cache hist used to place sockaddr into appropriate free list. */
    uint8_t                       cache_hint;

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


nxt_sockaddr_t *nxt_sockaddr_cache_alloc(nxt_event_engine_t *engine,
    nxt_listen_socket_t *ls);
void nxt_sockaddr_cache_free(nxt_event_engine_t *engine, nxt_conn_t *c);

NXT_EXPORT nxt_sockaddr_t *nxt_sockaddr_alloc(nxt_mp_t *mp, socklen_t socklen,
    size_t address_length)
    NXT_MALLOC_LIKE;
NXT_EXPORT nxt_sockaddr_t *nxt_sockaddr_create(nxt_mp_t *mp,
    struct sockaddr *sockaddr, socklen_t socklen, size_t address_length)
    NXT_MALLOC_LIKE;
NXT_EXPORT nxt_sockaddr_t *nxt_sockaddr_copy(nxt_mp_t *mp, nxt_sockaddr_t *src)
    NXT_MALLOC_LIKE;
NXT_EXPORT nxt_sockaddr_t *nxt_getsockname(nxt_task_t *task, nxt_mp_t *mp,
    nxt_socket_t s)
    NXT_MALLOC_LIKE;
NXT_EXPORT void nxt_sockaddr_text(nxt_sockaddr_t *sa);


NXT_EXPORT uint32_t nxt_sockaddr_port_number(nxt_sockaddr_t *sa);
NXT_EXPORT nxt_bool_t nxt_sockaddr_cmp(nxt_sockaddr_t *sa1,
    nxt_sockaddr_t *sa2);
NXT_EXPORT nxt_sockaddr_t *nxt_sockaddr_parse(nxt_mp_t *mp, nxt_str_t *addr);
NXT_EXPORT nxt_sockaddr_t *nxt_sockaddr_parse_optport(nxt_mp_t *mp,
    nxt_str_t *addr);
NXT_EXPORT in_addr_t nxt_inet_addr(u_char *buf, size_t len);
#if (NXT_INET6)
NXT_EXPORT nxt_int_t nxt_inet6_addr(struct in6_addr *in6_addr, u_char *buf,
    size_t len);
#endif
NXT_EXPORT nxt_bool_t nxt_inet6_probe(nxt_str_t *addr);


#define NXT_INET_ADDR_STR_LEN     nxt_length("255.255.255.255:65535")

#define NXT_INET6_ADDR_STR_LEN                                                \
    nxt_length("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")


#define nxt_sockaddr_size(sa)                                                 \
    (offsetof(nxt_sockaddr_t, u) + sa->socklen + sa->length)
#define nxt_sockaddr_start(sa)    nxt_pointer_to(sa, (sa)->start)
#define nxt_sockaddr_address(sa)  nxt_pointer_to(sa, (sa)->address_start)
#define nxt_sockaddr_port(sa)     nxt_pointer_to(sa, (sa)->port_start)
#define nxt_sockaddr_port_length(sa)                                          \
    (((sa)->start + (sa)->length) - (sa)->port_start)


#endif /* _NXT_SOCKADDR_H_INCLUDED_ */

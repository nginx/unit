
/*
 * Copyright (C) Axel Duch
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_conf.h>

#ifndef _NXT_HTTP_ROUTE_ADDR_H_INCLUDED_
#define _NXT_HTTP_ROUTE_ADDR_H_INCLUDED_


enum {
    NXT_HTTP_ROUTE_ADDR_ANY = 0,
    NXT_HTTP_ROUTE_ADDR_RANGE,
    NXT_HTTP_ROUTE_ADDR_EXACT,
    NXT_HTTP_ROUTE_ADDR_CIDR,
};


enum {
    NXT_ADDR_PATTERN_PORT_ERROR = NXT_OK + 1,
    NXT_ADDR_PATTERN_CV_TYPE_ERROR,
    NXT_ADDR_PATTERN_LENGTH_ERROR,
    NXT_ADDR_PATTERN_FORMAT_ERROR,
    NXT_ADDR_PATTERN_RANGE_OVERLAP_ERROR,
    NXT_ADDR_PATTERN_CIDR_ERROR,
    NXT_ADDR_PATTERN_NO_IPv6_ERROR,
    NXT_ADDR_PATTERN_NO_UNIX_ERROR,
};


typedef struct {
    in_addr_t  start;
    in_addr_t  end;
} nxt_http_route_addr_range_t;


#if (NXT_INET6)
typedef struct {
    struct in6_addr  start;
    struct in6_addr  end;
} nxt_http_route_in6_addr_range_t;
#endif


typedef struct {
    uint8_t       match_type:2;
    uint8_t       negative:1;
    uint8_t       addr_family;

    struct {
        uint16_t  start;
        uint16_t  end;
    } port;
} nxt_http_route_addr_base_t;


typedef struct {
    nxt_http_route_addr_base_t           base;

    union {
        nxt_http_route_addr_range_t      v4;
#if (NXT_INET6)
        nxt_http_route_in6_addr_range_t  v6;
#endif
    } addr;
} nxt_http_route_addr_pattern_t;


NXT_EXPORT nxt_int_t nxt_http_route_addr_pattern_parse(nxt_mp_t *mp,
    nxt_http_route_addr_pattern_t *pattern, nxt_conf_value_t *cv);

#endif /* _NXT_HTTP_ROUTE_ADDR_H_INCLUDED_ */

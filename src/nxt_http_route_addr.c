
/*
 * Copyright (C) Axel Duch
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_http_route_addr.h>


#if (NXT_INET6)
static nxt_bool_t nxt_valid_ipv6_blocks(u_char *c, size_t len);
#endif


nxt_int_t
nxt_http_route_addr_pattern_parse(nxt_mp_t *mp,
    nxt_http_route_addr_pattern_t *pattern, nxt_conf_value_t *cv)
{
    u_char                       *delim;
    nxt_int_t                    ret, cidr_prefix;
    nxt_str_t                    addr, port;
    nxt_http_route_addr_base_t   *base;
    nxt_http_route_addr_range_t  *inet;

    if (nxt_conf_type(cv) != NXT_CONF_STRING) {
        return NXT_ADDR_PATTERN_CV_TYPE_ERROR;
    }

    nxt_conf_get_string(cv, &addr);

    base = &pattern->base;

    if (addr.length > 0 && addr.start[0] == '!') {
        addr.start++;
        addr.length--;

        base->negative = 1;

    } else {
        base->negative = 0;
    }

    if (nxt_str_eq(&addr, "unix", 4)) {
#if (NXT_HAVE_UNIX_DOMAIN)
        base->addr_family = AF_UNIX;

        return NXT_OK;
#else
        return NXT_ADDR_PATTERN_NO_UNIX_ERROR;
#endif
    }

    if (nxt_slow_path(addr.length < 2)) {
        return NXT_ADDR_PATTERN_LENGTH_ERROR;
    }

    nxt_str_null(&port);

    if (addr.start[0] == '*' && addr.start[1] == ':') {
        port.start = addr.start + 2;
        port.length = addr.length - 2;
        base->addr_family = AF_UNSPEC;
        base->match_type = NXT_HTTP_ROUTE_ADDR_ANY;

        goto parse_port;
    }

    if (nxt_inet6_probe(&addr)) {
#if (NXT_INET6)
        u_char                           *end;
        uint8_t                          i;
        nxt_int_t                        len;
        nxt_http_route_in6_addr_range_t  *inet6;

        base->addr_family = AF_INET6;

        if (addr.start[0] == '[') {
            addr.start++;
            addr.length--;

            end = addr.start + addr.length;

            port.start = nxt_rmemstrn(addr.start, end, "]:", 2);
            if (nxt_slow_path(port.start == NULL)) {
                return NXT_ADDR_PATTERN_FORMAT_ERROR;
            }

            addr.length = port.start - addr.start;
            port.start += nxt_length("]:");
            port.length = end - port.start;
        }

        inet6 = &pattern->addr.v6;

        delim = memchr(addr.start, '-', addr.length);
        if (delim != NULL) {
            len = delim - addr.start;
            if (nxt_slow_path(!nxt_valid_ipv6_blocks(addr.start, len))) {
                return NXT_ADDR_PATTERN_FORMAT_ERROR;
            }

            ret = nxt_inet6_addr(&inet6->start, addr.start, len);
            if (nxt_slow_path(ret != NXT_OK)) {
                return NXT_ADDR_PATTERN_FORMAT_ERROR;
            }

            len = addr.start + addr.length - delim - 1;
            if (nxt_slow_path(!nxt_valid_ipv6_blocks(delim + 1, len))) {
                return NXT_ADDR_PATTERN_FORMAT_ERROR;
            }

            ret = nxt_inet6_addr(&inet6->end, delim + 1, len);
            if (nxt_slow_path(ret != NXT_OK)) {
                return NXT_ADDR_PATTERN_FORMAT_ERROR;
            }

            if (nxt_slow_path(memcmp(&inet6->start, &inet6->end,
                                         sizeof(struct in6_addr)) > 0))
            {
                return NXT_ADDR_PATTERN_RANGE_OVERLAP_ERROR;
            }

            base->match_type = NXT_HTTP_ROUTE_ADDR_RANGE;

            goto parse_port;
        }

        delim = memchr(addr.start, '/', addr.length);
        if (delim != NULL) {
            cidr_prefix = nxt_int_parse(delim + 1,
                                        addr.start + addr.length - (delim + 1));
            if (nxt_slow_path(cidr_prefix < 0 || cidr_prefix > 128)) {
                return NXT_ADDR_PATTERN_CIDR_ERROR;
            }

            addr.length = delim - addr.start;
            if (nxt_slow_path(!nxt_valid_ipv6_blocks(addr.start,
                                                     addr.length)))
            {
                return NXT_ADDR_PATTERN_FORMAT_ERROR;
            }

            ret = nxt_inet6_addr(&inet6->start, addr.start, addr.length);
            if (nxt_slow_path(ret != NXT_OK)) {
                return NXT_ADDR_PATTERN_FORMAT_ERROR;
            }

            if (nxt_slow_path(cidr_prefix == 0)) {
                base->match_type = NXT_HTTP_ROUTE_ADDR_ANY;

                goto parse_port;
            }

            if (nxt_slow_path(cidr_prefix == 128)) {
                base->match_type = NXT_HTTP_ROUTE_ADDR_EXACT;

                goto parse_port;
            }

            base->match_type = NXT_HTTP_ROUTE_ADDR_CIDR;

            for (i = 0; i < sizeof(struct in6_addr); i++) {
                if (cidr_prefix >= 8) {
                    inet6->end.s6_addr[i] = 0xFF;
                    cidr_prefix -= 8;

                    continue;
                }

                if (cidr_prefix > 0) {
                    inet6->end.s6_addr[i] = 0xFF & (0xFF << (8 - cidr_prefix));
                    inet6->start.s6_addr[i] &= inet6->end.s6_addr[i];
                    cidr_prefix = 0;

                    continue;
                }

                inet6->start.s6_addr[i] = 0;
                inet6->end.s6_addr[i] = 0;
            }

            goto parse_port;
        }

        base->match_type = NXT_HTTP_ROUTE_ADDR_EXACT;

        if (nxt_slow_path(!nxt_valid_ipv6_blocks(addr.start, addr.length))) {
            return NXT_ADDR_PATTERN_FORMAT_ERROR;
        }

        ret = nxt_inet6_addr(&inet6->start, addr.start, addr.length);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ADDR_PATTERN_FORMAT_ERROR;
        }

        goto parse_port;
#endif
        return NXT_ADDR_PATTERN_NO_IPv6_ERROR;
    }

    base->addr_family = AF_INET;

    delim = memchr(addr.start, ':', addr.length);
    if (delim != NULL) {
        port.start = delim + 1;
        port.length = addr.start + addr.length - port.start;
        addr.length = delim - addr.start;
    }

    inet = &pattern->addr.v4;

    delim = memchr(addr.start, '-', addr.length);
    if (delim != NULL) {
        inet->start = nxt_inet_addr(addr.start, delim - addr.start);
        if (nxt_slow_path(inet->start == INADDR_NONE)) {
            return NXT_ADDR_PATTERN_FORMAT_ERROR;
        }

        inet->end = nxt_inet_addr(delim + 1,
                                  addr.start + addr.length - (delim + 1));
        if (nxt_slow_path(inet->end == INADDR_NONE)) {
            return NXT_ADDR_PATTERN_FORMAT_ERROR;
        }

        if (nxt_slow_path(memcmp(&inet->start, &inet->end,
                                     sizeof(struct in_addr)) > 0))
        {
            return NXT_ADDR_PATTERN_RANGE_OVERLAP_ERROR;
        }

        base->match_type = NXT_HTTP_ROUTE_ADDR_RANGE;

        goto parse_port;
    }

    delim = memchr(addr.start, '/', addr.length);
    if (delim != NULL) {
        cidr_prefix = nxt_int_parse(delim + 1,
                                    addr.start + addr.length - (delim + 1));
        if (nxt_slow_path(cidr_prefix < 0 || cidr_prefix > 32)) {
            return NXT_ADDR_PATTERN_CIDR_ERROR;
        }

        addr.length = delim - addr.start;
        inet->end = htonl(0xFFFFFFFF & (0xFFFFFFFFULL << (32 - cidr_prefix)));

        inet->start = nxt_inet_addr(addr.start, addr.length) & inet->end;
        if (nxt_slow_path(inet->start == INADDR_NONE)) {
            return NXT_ADDR_PATTERN_FORMAT_ERROR;
        }

        if (cidr_prefix == 0) {
            base->match_type = NXT_HTTP_ROUTE_ADDR_ANY;

            goto parse_port;
        }

        if (cidr_prefix < 32) {
            base->match_type = NXT_HTTP_ROUTE_ADDR_CIDR;

            goto parse_port;
        }
    }

    inet->start = nxt_inet_addr(addr.start, addr.length);
    if (nxt_slow_path(inet->start == INADDR_NONE)) {
        return NXT_ADDR_PATTERN_FORMAT_ERROR;
    }

    base->match_type = NXT_HTTP_ROUTE_ADDR_EXACT;

parse_port:

    if (port.length == 0) {
        if (nxt_slow_path(port.start != NULL)) {
            return NXT_ADDR_PATTERN_FORMAT_ERROR;
        }

        base->port.start = 0;
        base->port.end = 65535;

        return NXT_OK;
    }

    delim = memchr(port.start, '-', port.length - 1);
    if (delim != NULL) {
        ret = nxt_int_parse(port.start, delim - port.start);
        if (nxt_slow_path(ret < 0 || ret > 65535)) {
            return NXT_ADDR_PATTERN_PORT_ERROR;
        }

        base->port.start = ret;

        ret = nxt_int_parse(delim + 1, port.start + port.length - (delim + 1));
        if (nxt_slow_path(ret < base->port.start || ret > 65535)) {
            return NXT_ADDR_PATTERN_PORT_ERROR;
        }

        base->port.end = ret;

    } else {
        ret = nxt_int_parse(port.start, port.length);
        if (nxt_slow_path(ret < 0 || ret > 65535)) {
            return NXT_ADDR_PATTERN_PORT_ERROR;
        }

        base->port.start = ret;
        base->port.end = ret;
    }

    return NXT_OK;
}


#if (NXT_INET6)

static nxt_bool_t
nxt_valid_ipv6_blocks(u_char *c, size_t len)
{
    u_char      *end;
    nxt_uint_t  colon_gap;

    end = c + len;
    colon_gap = 0;

    while (c != end) {
        if (*c == ':') {
            colon_gap = 0;
            c++;

            continue;
        }

        colon_gap++;
        c++;

        if (nxt_slow_path(colon_gap > 4)) {
            return 0;
        }
    }

    return 1;
}

#endif

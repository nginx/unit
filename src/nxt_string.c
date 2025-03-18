
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


nxt_str_t *
nxt_str_alloc(nxt_mp_t *mp, size_t length)
{
    nxt_str_t  *s;

    /* The string start is allocated aligned to be close to nxt_str_t. */
    s = nxt_mp_get(mp, sizeof(nxt_str_t) + length);

    if (nxt_fast_path(s != NULL)) {
        s->length = length;
        s->start = nxt_pointer_to(s, sizeof(nxt_str_t));
    }

    return s;
}


/*
 * nxt_str_dup() creates a new string with a copy of a source string.
 * If length of the source string is zero, then the new string anyway
 * gets a pointer somewhere in mem_pool.
 */

nxt_str_t *
nxt_str_dup(nxt_mp_t *mp, nxt_str_t *dst, const nxt_str_t *src)
{
    u_char  *p;

    if (dst == NULL) {
        /* The string start is allocated aligned to be close to nxt_str_t. */
        dst = nxt_mp_get(mp, sizeof(nxt_str_t) + src->length);
        if (nxt_slow_path(dst == NULL)) {
            return NULL;
        }

        p = (u_char *) dst;
        p += sizeof(nxt_str_t);
        dst->start = p;

    } else {
        dst->start = nxt_mp_nget(mp, src->length);
        if (nxt_slow_path(dst->start == NULL)) {
            return NULL;
        }
    }

    nxt_memcpy(dst->start, src->start, src->length);
    dst->length = src->length;

    return dst;
}


/*
 * nxt_str_cstrz() creates a C style zero-terminated copy of a source
 * nxt_str_t.  The function is intended to create strings suitable
 * for libc and kernel interfaces so result is pointer to char instead
 * of u_char to minimize casts.
 */

char *
nxt_str_cstrz(nxt_mp_t *mp, const nxt_str_t *src)
{
    char  *p, *dst;

    dst = nxt_mp_alloc(mp, src->length + 1);

    if (nxt_fast_path(dst != NULL)) {
        p = nxt_cpymem(dst, src->start, src->length);
        *p = '\0';
    }

    return dst;
}


void
nxt_memcpy_lowcase(u_char *dst, const u_char *src, size_t length)
{
    u_char  c;

    while (length != 0) {
        c = *src++;
        *dst++ = nxt_lowcase(c);
        length--;
    }
}


void
nxt_memcpy_upcase(u_char *dst, const u_char *src, size_t length)
{
    u_char  c;

    while (length != 0) {
        c = *src++;
        *dst++ = nxt_upcase(c);
        length--;
    }
}


u_char *
nxt_cpystr(u_char *dst, const u_char *src)
{
    for ( ;; ) {
        *dst = *src;

        if (*dst == '\0') {
            break;
        }

        dst++;
        src++;
    }

    return dst;
}


u_char *
nxt_cpystrn(u_char *dst, const u_char *src, size_t length)
{
    if (length == 0) {
        return dst;
    }

    while (--length != 0) {
        *dst = *src;

        if (*dst == '\0') {
            return dst;
        }

        dst++;
        src++;
    }

    *dst = '\0';

    return dst;
}


nxt_int_t
nxt_strcasecmp(const u_char *s1, const u_char *s2)
{
    u_char     c1, c2;
    nxt_int_t  n;

    for ( ;; ) {
        c1 = *s1++;
        c2 = *s2++;

        c1 = nxt_lowcase(c1);
        c2 = nxt_lowcase(c2);

        n = c1 - c2;

        if (n != 0) {
            return n;
        }

        if (c1 == 0) {
            return 0;
        }
    }
}


nxt_int_t
nxt_strncasecmp(const u_char *s1, const u_char *s2, size_t length)
{
    u_char     c1, c2;
    nxt_int_t  n;

    while (length-- != 0) {
        c1 = *s1++;
        c2 = *s2++;

        c1 = nxt_lowcase(c1);
        c2 = nxt_lowcase(c2);

        n = c1 - c2;

        if (n != 0) {
            return n;
        }

        if (c1 == 0) {
            return 0;
        }
    }

    return 0;
}


nxt_int_t
nxt_memcasecmp(const void *p1, const void *p2, size_t length)
{
    u_char        c1, c2;
    nxt_int_t     n;
    const u_char  *s1, *s2;

    s1 = p1;
    s2 = p2;

    while (length-- != 0) {
        c1 = *s1++;
        c2 = *s2++;

        c1 = nxt_lowcase(c1);
        c2 = nxt_lowcase(c2);

        n = c1 - c2;

        if (n != 0) {
            return n;
        }
    }

    return 0;
}


/*
 * nxt_memstrn() is intended for search of static substring "ss"
 * with known length "length" in string "s" limited by parameter "end".
 * Zeros are ignored in both strings.
 */

u_char *
nxt_memstrn(const u_char *s, const u_char *end, const char *ss, size_t length)
{
    u_char  c1, c2, *s2;

    s2 = (u_char *) ss;
    c2 = *s2++;
    length--;

    while (s < end) {
        c1 = *s++;

        if (c1 == c2) {

            if (s + length > end) {
                return NULL;
            }

            if (memcmp(s, s2, length) == 0) {
                return (u_char *) s - 1;
            }
        }
    }

    return NULL;
}


/*
 * nxt_strcasestrn() is intended for caseless search of static substring
 * "ss" with known length "length" in string "s" limited by parameter "end".
 * Zeros are ignored in both strings.
 */

u_char *
nxt_memcasestrn(const u_char *s, const u_char *end, const char *ss,
    size_t length)
{
    u_char  c1, c2, *s2;

    s2 = (u_char *) ss;
    c2 = *s2++;
    c2 = nxt_lowcase(c2);
    length--;

    while (s < end) {
        c1 = *s++;
        c1 = nxt_lowcase(c1);

        if (c1 == c2) {

            if (s + length > end) {
                return NULL;
            }

            if (nxt_memcasecmp(s, s2, length) == 0) {
                return (u_char *) s - 1;
            }
        }
    }

    return NULL;
}


/*
 * nxt_rstrstrn() is intended to search for static substring "ss"
 * with known length "length" in string "s" limited by parameter "end"
 * in reverse order.  Zeros are ignored in both strings.
 */

u_char *
nxt_rmemstrn(const u_char *s, const u_char *end, const char *ss, size_t length)
{
    u_char        c1, c2;
    const u_char  *s1, *s2;

    s1 = end - length;
    s2 = (u_char *) ss;
    c2 = *s2++;
    length--;

    while (s < s1) {
        c1 = *s1;

        if (c1 == c2) {
            if (memcmp(s1 + 1, s2, length) == 0) {
                return (u_char *) s1;
            }
        }

        s1--;
    }

    return NULL;
}


size_t
nxt_str_strip(const u_char *start, u_char *end)
{
    u_char  *p;

    for (p = end - 1; p >= start; p--) {
        if (*p != '\r' && *p != '\n') {
            break;
        }
    }

    return (p + 1) - start;
}


nxt_int_t
nxt_strverscmp(const u_char *s1, const u_char *s2)
{
    u_char     c1, c2;
    nxt_int_t  diff;

    enum {
        st_str = 0,
        st_num,
        st_zero,
        st_frac,
    } state;

    state = st_str;

    for ( ;; ) {
        c1 = *s1++;
        c2 = *s2++;

        diff = c1 - c2;

        if (diff != 0) {
            break;
        }

        if (c1 == '\0') {
            return 0;
        }

        if (!nxt_isdigit(c1)) {
            state = st_str;
            continue;
        }

        if (state == st_str) {
            state = (c1 != '0') ? st_num : st_zero;
            continue;
        }

        if (state == st_zero && c1 != '0') {
            state = st_frac;
            continue;
        }
    }

    switch (state) {

    case st_str:

        if ((u_char) (c1 - '1') > 8 || (u_char) (c2 - '1') > 8) {
            return diff;
        }

        c1 = *s1++;
        c2 = *s2++;

        /* Fall through. */

    case st_num:

        while (nxt_isdigit(c1) && nxt_isdigit(c2)) {
            c1 = *s1++;
            c2 = *s2++;
        }

        if (nxt_isdigit(c1)) {
            return 1;
        }

        if (nxt_isdigit(c2)) {
            return -1;
        }

        return diff;

    case st_zero:

        if (c1 == '0' || c2 == '\0') {
            return -1;
        }

        if (c2 == '0' || c1 == '\0') {
            return 1;
        }

        /* Fall through. */

    case st_frac:
    default:
        return diff;
    }
}


nxt_bool_t
nxt_strvers_match(u_char *version, u_char *prefix, size_t length)
{
    u_char  next, last;

    if (length == 0) {
        return 1;
    }

    if (nxt_strncmp(version, prefix, length) == 0) {

        next = version[length];

        if (next == '\0') {
            return 1;
        }

        last = version[length - 1];

        if (nxt_isdigit(last) != nxt_isdigit(next)) {
            /* This is a version part boundary. */
            return 1;
        }
    }

    return 0;
}


const uint8_t  nxt_hex2int[256]
    nxt_aligned(32) =
{
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 16, 16, 16, 16, 16, 16,
    16, 10, 11, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 10, 11, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
};


static const uint32_t  nxt_uri_escape[] = {
    0xffffffff, /* 1111 1111 1111 1111 1111 1111 1111 1111 */

                /* ?>=< ;:98 7654 3210 /.-, +*)( '&%$ #"! */
    0xd000002d, /* 1101 0000 0000 0000 0000 0000 0010 1101 */

                /* _^]\ [ZYX WVUT SRQP ONML KJIH GFED CBA@ */
    0x50000000, /* 0101 0000 0000 0000 0000 0000 0000 0000 */

                /*  ~}| {zyx wvut srqp onml kjih gfed cba` */
    0xb8000001, /* 1011 1000 0000 0000 0000 0000 0000 0001 */

    0xffffffff, /* 1111 1111 1111 1111 1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111 1111 1111 1111 1111 */
    0xffffffff, /* 1111 1111 1111 1111 1111 1111 1111 1111 */
    0xffffffff  /* 1111 1111 1111 1111 1111 1111 1111 1111 */
};


u_char *
nxt_decode_uri(u_char *dst, u_char *src, size_t length)
{
    u_char   *end, ch;
    uint8_t  d0, d1;

    nxt_prefetch(&nxt_hex2int['0']);

    end = src + length;

    while (src < end) {
        ch = *src++;

        if (ch == '%') {
            if (nxt_slow_path(end - src < 2)) {
                return NULL;
            }

            d0 = nxt_hex2int[*src++];
            d1 = nxt_hex2int[*src++];

            if (nxt_slow_path((d0 | d1) >= 16)) {
                return NULL;
            }

            ch = (d0 << 4) + d1;
        }

        *dst++ = ch;
    }

    return dst;
}


u_char *
nxt_decode_uri_plus(u_char *dst, u_char *src, size_t length)
{
    u_char   *end, ch;
    uint8_t  d0, d1;

    nxt_prefetch(&nxt_hex2int['0']);

    end = src + length;

    while (src < end) {
        ch = *src++;

        switch (ch) {
        case '%':
            if (nxt_slow_path(end - src < 2)) {
                return NULL;
            }

            d0 = nxt_hex2int[*src++];
            d1 = nxt_hex2int[*src++];

            if (nxt_slow_path((d0 | d1) >= 16)) {
                return NULL;
            }

            ch = (d0 << 4) + d1;
            break;

        case '+':
            ch = ' ';
            break;
        }

        *dst++ = ch;
    }

    return dst;
}


uintptr_t
nxt_encode_uri(u_char *dst, u_char *src, size_t length)
{
    u_char      *end;
    nxt_uint_t  n;

    static const u_char  hex[16] NXT_NONSTRING = "0123456789ABCDEF";

    end = src + length;

    if (dst == NULL) {

        /* Find the number of the characters to be escaped. */

        n = 0;

        while (src < end) {

            if (nxt_uri_escape[*src >> 5] & (1U << (*src & 0x1f))) {
                n++;
            }

            src++;
        }

        return (uintptr_t) n;
    }

    while (src < end) {

        if (nxt_uri_escape[*src >> 5] & (1U << (*src & 0x1f))) {
            *dst++ = '%';
            *dst++ = hex[*src >> 4];
            *dst++ = hex[*src & 0xf];

        } else {
            *dst++ = *src;
        }

        src++;
    }

    return (uintptr_t) dst;
}


uintptr_t
nxt_encode_complex_uri(u_char *dst, u_char *src, size_t length)
{
    u_char      *reserved, *end, ch;
    nxt_uint_t  n;

    static const u_char  hex[16] NXT_NONSTRING = "0123456789ABCDEF";

    reserved = (u_char *) "?#\0";

    end = src + length;

    if (dst == NULL) {

        /* Find the number of the characters to be escaped. */

        n = 0;

        while (src < end) {
            ch = *src++;

            if (nxt_uri_escape[ch >> 5] & (1U << (ch & 0x1f))) {
                if (ch == reserved[0]) {
                    reserved++;
                    continue;
                }

                if (ch == reserved[1]) {
                    reserved += 2;
                    continue;
                }

                n++;
            }
        }

        return (uintptr_t) n;
    }

    while (src < end) {
        ch = *src++;

        if (nxt_uri_escape[ch >> 5] & (1U << (ch & 0x1f))) {
            if (ch == reserved[0]) {
                reserved++;

            } else if (ch == reserved[1]) {
                reserved += 2;

            } else {
                *dst++ = '%';
                *dst++ = hex[ch >> 4];
                *dst++ = hex[ch & 0xf];
                continue;
            }
        }

        *dst++ = ch;
    }

    return (uintptr_t) dst;
}


nxt_bool_t
nxt_is_complex_uri_encoded(u_char *src, size_t length)
{
    u_char   *reserved, *end, ch;
    uint8_t  d0, d1;

    reserved = (u_char *) "?#\0";

    for (end = src + length; src < end; src++) {
        ch = *src;

        if (nxt_uri_escape[ch >> 5] & (1U << (ch & 0x1f))) {
            if (ch == '%') {
                if (end - src < 2) {
                    return 0;
                }

                d0 = nxt_hex2int[*++src];
                d1 = nxt_hex2int[*++src];

                if ((d0 | d1) >= 16) {
                    return 0;
                }

                continue;
            }

            if (ch == reserved[0]) {
                reserved++;
                continue;
            }

            if (ch == reserved[1]) {
                reserved += 2;
                continue;
            }

            return 0;
        }
    }

    return 1;
}


ssize_t
nxt_base64_decode(u_char *dst, u_char *src, size_t length)
{
    u_char   *end, *p;
    size_t   pad;
    uint8_t  v1, v2, v3, v4;

    static const uint8_t  decode[] = {
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77, 77, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
        77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 77,
        77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
    };

    end = src + length;
    pad = (4 - (length % 4)) % 4;

    if (dst == NULL) {
        if (pad > 2) {
            return NXT_ERROR;
        }

        while (src < end) {
            if (decode[*src] != 77) {
                src++;
                continue;
            }

            if (pad == 0) {
                pad = end - src;

                if ((pad == 1 || (pad == 2 && src[1] == '=')) && src[0] == '=')
                {
                    break;
                }
            }

            return NXT_ERROR;
        }

        return (length + 3) / 4 * 3 - pad;
    }

    nxt_assert(length != 0);

    if (pad == 0) {
        pad = (end[-1] == '=') + (end[-2] == '=');
        end -= (pad + 3) & 4;

    } else {
        end -= 4 - pad;
    }

    p = dst;

    while (src < end) {
        v1 = decode[src[0]];
        v2 = decode[src[1]];
        v3 = decode[src[2]];
        v4 = decode[src[3]];

        *p++ = (v1 << 2 | v2 >> 4);
        *p++ = (v2 << 4 | v3 >> 2);
        *p++ = (v3 << 6 | v4);

        src += 4;
    }

    if (pad > 0) {
        v1 = decode[src[0]];
        v2 = decode[src[1]];

        *p++ = (v1 << 2 | v2 >> 4);

        if (pad == 1) {
            v3 = decode[src[2]];
            *p++ = (v2 << 4 | v3 >> 2);
        }
    }

    return (p - dst);
}

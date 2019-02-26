
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
nxt_memcasecmp(const u_char *s1, const u_char *s2, size_t length)
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

            if (nxt_memcmp(s, s2, length) == 0) {
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
            if (nxt_memcmp(s1 + 1, s2, length) == 0) {
                return (u_char *) s1;
            }
        }

        s1--;
    }

    return NULL;
}


size_t
nxt_str_strip(u_char *start, u_char *end)
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


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


nxt_str_t *
nxt_str_alloc(nxt_mem_pool_t *mp, size_t len)
{
    nxt_str_t  *s;

    /* The string data is allocated aligned to be close to nxt_str_t. */
    s = nxt_mem_alloc(mp, sizeof(nxt_str_t) + len);

    if (nxt_fast_path(s != NULL)) {
        s->len = len;
        s->data = (u_char *) s + sizeof(nxt_str_t);
    }

    return s;
}


/*
 * nxt_str_dup() creates a new string with a copy of a source string.
 * If length of the source string is zero, then the new string anyway
 * gets a pointer somewhere in mem_pool.
 */

nxt_str_t *
nxt_str_dup(nxt_mem_pool_t *mp, nxt_str_t *dst, const nxt_str_t *src)
{
    u_char  *p;

    if (dst == NULL) {
        /* The string data is allocated aligned to be close to nxt_str_t. */
        dst = nxt_mem_alloc(mp, sizeof(nxt_str_t) + src->len);
        if (nxt_slow_path(dst == NULL)) {
            return NULL;
        }

        p = (u_char *) dst;
        p += sizeof(nxt_str_t);
        dst->data = p;

    } else {
        dst->data = nxt_mem_nalloc(mp, src->len);
        if (nxt_slow_path(dst->data == NULL)) {
            return NULL;
        }
    }

    nxt_memcpy(dst->data, src->data, src->len);
    dst->len = src->len;

    return dst;
}


/*
 * nxt_str_copy() creates a C style zero-terminated copy of a source
 * nxt_str_t.  The function is intended to create strings suitable
 * for libc and kernel interfaces so result is pointer to char instead
 * of u_char to minimize casts.  The copy is aligned to 2 bytes thus
 * the lowest bit may be used as marker.
 */

char *
nxt_str_copy(nxt_mem_pool_t *mp, const nxt_str_t *src)
{
    char  *p, *dst;

    dst = nxt_mem_align(mp, 2, src->len + 1);

    if (nxt_fast_path(dst != NULL)) {
        p = nxt_cpymem(dst, src->data, src->len);
        *p = '\0';
    }

    return dst;
}


void
nxt_memcpy_lowcase(u_char *dst, const u_char *src, size_t len)
{
    u_char  c;

    while (len != 0) {
        c = *src++;
        *dst++ = nxt_lowcase(c);
        len--;
    }
}


u_char *
nxt_cpystrn(u_char *dst, const u_char *src, size_t len)
{
    if (len == 0) {
        return dst;
    }

    while (--len != 0) {
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
nxt_strncasecmp(const u_char *s1, const u_char *s2, size_t len)
{
    u_char     c1, c2;
    nxt_int_t  n;

    while (len-- != 0) {
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
nxt_memcasecmp(const u_char *s1, const u_char *s2, size_t len)
{
    u_char     c1, c2;
    nxt_int_t  n;

    while (len-- != 0) {
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
 * with known length "len" in string "s" limited by parameter "end".
 * Zeros are ignored in both strings.
 */

u_char *
nxt_memstrn(const u_char *s, const u_char *end, const char *ss, size_t len)
{
    u_char  c1, c2, *s2;

    s2 = (u_char *) ss;
    c2 = *s2++;
    len--;

    while (s < end) {
        c1 = *s++;

        if (c1 == c2) {

            if (s + len > end) {
                return NULL;
            }

            if (nxt_memcmp(s, s2, len) == 0) {
                return (u_char *) s - 1;
            }
        }
    }

    return NULL;
}


/*
 * nxt_strcasestrn() is intended for caseless search of static substring
 * "ss" with known length "len" in string "s" limited by parameter "end".
 * Zeros are ignored in both strings.
 */

u_char *
nxt_memcasestrn(const u_char *s, const u_char *end, const char *ss, size_t len)
{
    u_char  c1, c2, *s2;

    s2 = (u_char *) ss;
    c2 = *s2++;
    c2 = nxt_lowcase(c2);
    len--;

    while (s < end) {
        c1 = *s++;
        c1 = nxt_lowcase(c1);

        if (c1 == c2) {

            if (s + len > end) {
                return NULL;
            }

            if (nxt_memcasecmp(s, s2, len) == 0) {
                return (u_char *) s - 1;
            }
        }
    }

    return NULL;
}


/*
 * nxt_rstrstrn() is intended to search for static substring "ss"
 * with known length "len" in string "s" limited by parameter "end"
 * in reverse order.  Zeros are ignored in both strings.
 */

u_char *
nxt_rmemstrn(const u_char *s, const u_char *end, const char *ss, size_t len)
{
    u_char        c1, c2;
    const u_char  *s1, *s2;

    s1 = end - len;
    s2 = (u_char *) ss;
    c2 = *s2++;
    len--;

    while (s < s1) {
        c1 = *s1;

        if (c1 == c2) {
            if (nxt_memcmp(s1 + 1, s2, len) == 0) {
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
        if (*p != NXT_CR && *p != NXT_LF) {
            break;
        }
    }

    return (p + 1) - start;
}

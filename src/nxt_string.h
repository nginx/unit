
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_STRING_H_INCLUDED_
#define _NXT_STRING_H_INCLUDED_


#define                                                                       \
nxt_lowcase(c)                                                                \
    (u_char) ((c >= 'A' && c <= 'Z') ? c | 0x20 : c)

#define                                                                       \
nxt_upcase(c)                                                                 \
    (u_char) ((c >= 'a' && c <= 'z') ? c & ~0x20 : c)

#define                                                                       \
nxt_isdigit(c)                                                                \
    ((u_char) ((c) - '0') <= 9)


#define                                                                       \
nxt_strlen(s)                                                                 \
    strlen((char *) s)


#define                                                                       \
nxt_memzero(buf, length)                                                      \
    (void) memset(buf, 0, length)


#define                                                                       \
nxt_memset(buf, c, length)                                                    \
    (void) memset(buf, c, length)


#define                                                                       \
nxt_memcpy(dst, src, length)                                                  \
    (void) memcpy(dst, src, length)


NXT_EXPORT void nxt_memcpy_lowcase(u_char *dst, const u_char *src,
    size_t length);
NXT_EXPORT void nxt_memcpy_upcase(u_char *dst, const u_char *src,
    size_t length);


/*
 * nxt_cpymem() is an inline function but not a macro to
 * eliminate possible double evaluation of length "length".
 */
nxt_inline void *
nxt_cpymem(void *dst, const void *src, size_t length)
{
    return ((u_char *) memcpy(dst, src, length)) + length;
}


#define                                                                       \
nxt_memmove(dst, src, length)                                                 \
    (void) memmove(dst, src, length)


#define                                                                       \
nxt_memcmp(s1, s2, length)                                                    \
    memcmp((char *) s1, (char *) s2, length)


#define                                                                       \
nxt_memchr(s, c, length)                                                      \
    memchr((char *) s, c, length)


#define                                                                       \
nxt_strcmp(s1, s2)                                                            \
    strcmp((char *) s1, (char *) s2)


#define                                                                       \
nxt_strncmp(s1, s2, length)                                                   \
    strncmp((char *) s1, (char *) s2, length)


NXT_EXPORT u_char *nxt_cpystrn(u_char *dst, const u_char *src, size_t length);
NXT_EXPORT nxt_int_t nxt_strcasecmp(const u_char *s1, const u_char *s2);
NXT_EXPORT nxt_int_t nxt_strncasecmp(const u_char *s1, const u_char *s2,
    size_t length);
NXT_EXPORT nxt_int_t nxt_memcasecmp(const u_char *s1, const u_char *s2,
    size_t length);

NXT_EXPORT u_char *nxt_memstrn(const u_char *s, const u_char *end,
    const char *ss, size_t length);
NXT_EXPORT u_char *nxt_memcasestrn(const u_char *s, const u_char *end,
    const char *ss, size_t length);
NXT_EXPORT u_char *nxt_rmemstrn(const u_char *s, const u_char *end,
    const char *ss, size_t length);
NXT_EXPORT size_t nxt_str_strip(u_char *start, u_char *end);


typedef struct {
    size_t                    length;
    u_char                    *start;
} nxt_str_t;


#define nxt_string(str)       { nxt_length(str), (u_char *) str }
#define nxt_string_zero(str)  { sizeof(str), (u_char *) str }
#define nxt_null_string       { 0, NULL }


#define                                                                       \
nxt_str_set(str, text)                                                        \
    do {                                                                      \
        (str)->length = nxt_length(text);                                     \
        (str)->start = (u_char *) text;                                       \
    } while (0)


#define                                                                       \
nxt_str_null(str)                                                             \
    do {                                                                      \
        (str)->length = 0;                                                    \
        (str)->start = NULL;                                                  \
    } while (0)


NXT_EXPORT nxt_str_t *nxt_str_alloc(nxt_mp_t *mp, size_t length);
NXT_EXPORT nxt_str_t *nxt_str_dup(nxt_mp_t *mp, nxt_str_t *dst,
    const nxt_str_t *src);
NXT_EXPORT char *nxt_str_cstrz(nxt_mp_t *mp, const nxt_str_t *src);


#define                                                                       \
nxt_strstr_eq(s1, s2)                                                         \
    (((s1)->length == (s2)->length)                                           \
      && (nxt_memcmp((s1)->start, (s2)->start, (s1)->length) == 0))


#define                                                                       \
nxt_strcasestr_eq(s1, s2)                                                     \
    (((s1)->length == (s2)->length)                                           \
      && (nxt_memcasecmp((s1)->start, (s2)->start, (s1)->length) == 0))


#define                                                                       \
nxt_str_eq(s, p, _length)                                                     \
    (((s)->length == _length) && (nxt_memcmp((s)->start, p, _length) == 0))


#define                                                                       \
nxt_str_start(s, p, _length)                                                  \
    (((s)->length >= _length) && (nxt_memcmp((s)->start, p, _length) == 0))


#define                                                                       \
nxt_strchr_eq(s, c)                                                           \
    (((s)->length == 1) && ((s)->start[0] == c))


#define                                                                       \
nxt_strchr_start(s, c)                                                        \
    (((s)->length != 0) && ((s)->start[0] == c))


NXT_EXPORT nxt_int_t nxt_strverscmp(const u_char *s1, const u_char *s2);
NXT_EXPORT nxt_bool_t nxt_strvers_match(u_char *version, u_char *prefix,
    size_t length);


#endif /* _NXT_STRING_H_INCLUDED_ */

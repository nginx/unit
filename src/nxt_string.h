
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


#define NXT_CR             (u_char) 13
#define NXT_LF             (u_char) 10
#define NXT_CRLF           "\x0d\x0a"
#define NXT_CRLF_SIZE      (sizeof(NXT_CRLF) - 1)


#define NXT_LINEFEED_SIZE  1

#define                                                                       \
nxt_linefeed(p)                                                               \
    *p++ = NXT_LF


#define                                                                       \
nxt_strlen(s)                                                                 \
    strlen((char *) s)


#define                                                                       \
nxt_memzero(buf, len)                                                         \
    (void) memset(buf, 0, len)


#define                                                                       \
nxt_memset(buf, c, len)                                                       \
    (void) memset(buf, c, len)


#define                                                                       \
nxt_memcpy(dst, src, len)                                                     \
    (void) memcpy(dst, src, len)


NXT_EXPORT void nxt_memcpy_lowcase(u_char *dst, const u_char *src, size_t len);


/*
 * nxt_cpymem() is an inline function but not macro to
 * eliminate possible double evaluation of length "len".
 */
nxt_inline void *
nxt_cpymem(void *dst, const void *src, size_t len)
{
    return ((u_char *) memcpy(dst, src, len)) + len;
}


#define                                                                       \
nxt_memmove(dst, src, len)                                                    \
    (void) memmove(dst, src, len)


#define                                                                       \
nxt_memcmp(s1, s2, len)                                                       \
    memcmp((char *) s1, (char *) s2, len)


#define                                                                       \
nxt_memchr(s, c, len)                                                         \
    memchr((char *) s, c, len)


#define                                                                       \
nxt_strcmp(s1, s2)                                                            \
    strcmp((char *) s1, (char *) s2)


#define                                                                       \
nxt_strncmp(s1, s2, len)                                                      \
    strncmp((char *) s1, (char *) s2, len)


NXT_EXPORT u_char *nxt_cpystrn(u_char *dst, const u_char *src, size_t len);
NXT_EXPORT nxt_int_t nxt_strcasecmp(const u_char *s1, const u_char *s2);
NXT_EXPORT nxt_int_t nxt_strncasecmp(const u_char *s1, const u_char *s2,
    size_t len);
NXT_EXPORT nxt_int_t nxt_memcasecmp(const u_char *s1, const u_char *s2,
    size_t len);

NXT_EXPORT u_char *nxt_memstrn(const u_char *s, const u_char *end,
    const char *ss, size_t len);
NXT_EXPORT u_char *nxt_memcasestrn(const u_char *s, const u_char *end,
    const char *ss, size_t len);
NXT_EXPORT u_char *nxt_rmemstrn(const u_char *s, const u_char *end,
    const char *ss, size_t len);
NXT_EXPORT size_t nxt_str_strip(u_char *start, u_char *end);


typedef struct {
    size_t                    len;
    u_char                    *data;
} nxt_str_t;


#define nxt_string(str)       { sizeof(str) - 1, (u_char *) str }
#define nxt_string_zero(str)  { sizeof(str), (u_char *) str }
#define nxt_null_string       { 0, NULL }


#define                                                                       \
nxt_str_set(str, text)                                                        \
    do {                                                                      \
        (str)->len = sizeof(text) - 1;                                        \
        (str)->data = (u_char *) text;                                        \
    } while (0)


#define                                                                       \
nxt_str_null(str)                                                             \
    do {                                                                      \
        (str)->len = 0;                                                       \
        (str)->data = NULL;                                                   \
    } while (0)


NXT_EXPORT nxt_str_t *nxt_str_alloc(nxt_mem_pool_t *mp, size_t len);
NXT_EXPORT nxt_str_t *nxt_str_dup(nxt_mem_pool_t *mp, nxt_str_t *dst,
    const nxt_str_t *src);
NXT_EXPORT char *nxt_str_copy(nxt_mem_pool_t *mp, const nxt_str_t *src);


#define                                                                       \
nxt_strstr_eq(s1, s2)                                                         \
    (((s1)->len == (s2)->len)                                                 \
      && (nxt_memcmp((s1)->data, (s2)->data, (s1)->len) == 0))


#define                                                                       \
nxt_strcasestr_eq(s1, s2)                                                     \
    (((s1)->len == (s2)->len)                                                 \
      && (nxt_memcasecmp((s1)->data, (s2)->data, (s1)->len) == 0))


#define                                                                       \
nxt_str_eq(s, p, _len)                                                        \
    (((s)->len == _len) && (nxt_memcmp((s)->data, p, _len) == 0))


#define                                                                       \
nxt_str_start(s, p, _len)                                                     \
    (((s)->len > _len) && (nxt_memcmp((s)->data, p, _len) == 0))


#define                                                                       \
nxt_strchr_eq(s, c)                                                           \
    (((s)->len == 1) && ((s)->data[0] == c))


#define                                                                       \
nxt_strchr_start(s, c)                                                        \
    (((s)->len != 0) && ((s)->data[0] == c))


#endif /* _NXT_STRING_H_INCLUDED_ */


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UTF8_H_INCLUDED_
#define _NXT_UTF8_H_INCLUDED_


/*
 * Since the maximum valid Unicode character is 0x0010FFFF, the maximum
 * difference between Unicode characters is lesser 0x0010FFFF and
 * 0x0EEE0EEE can be used as value to indicate UTF-8 encoding error.
 */
#define NXT_UTF8_SORT_INVALID  0x0EEE0EEE


NXT_EXPORT u_char *nxt_utf8_encode(u_char *p, uint32_t u);
NXT_EXPORT uint32_t nxt_utf8_decode(const u_char **start, const u_char *end);
NXT_EXPORT uint32_t nxt_utf8_decode2(const u_char **start, const u_char *end);
NXT_EXPORT nxt_int_t nxt_utf8_casecmp(const u_char *start1,
    const u_char *start2, size_t len1, size_t len2);
NXT_EXPORT uint32_t nxt_utf8_lowcase(const u_char **start, const u_char *end);
NXT_EXPORT ssize_t nxt_utf8_length(const u_char *p, size_t len);
NXT_EXPORT nxt_bool_t nxt_utf8_is_valid(const u_char *p, size_t len);


/* nxt_utf8_next() expects a valid UTF-8 string. */

nxt_inline const u_char *
nxt_utf8_next(const u_char *p, const u_char *end)
{
    u_char  c;

    c = *p++;

    if ((c & 0x80) != 0) {

        do {
            /*
             * The first UTF-8 byte is either 0xxxxxxx or 11xxxxxx.
             * The next UTF-8 bytes are 10xxxxxx.
             */
            c = *p;

            if ((c & 0xC0) != 0x80) {
                return p;
            }

            p++;

        } while (p < end);
    }

    return p;
}


#endif /* _NXT_UTF8_H_INCLUDED_ */


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>

/*
 * The nxt_unicode_lowcase.h file is the auto-generated file from
 * the CaseFolding-6.3.0.txt file provided by Unicode, Inc.:
 *
 *   ./lib/src/nxt_unicode_lowcase.pl CaseFolding-6.3.0.txt
 *
 * This file should be copied to system specific nxt_unicode_SYSTEM_lowcase.h
 * file and utf8_file_name_test should be built with this file.
 * Then a correct system specific file should be generated:
 *
 *   ./build/utf8_file_name_test | ./lib/src/nxt_unicode_lowcase.pl
 *
 * Only common and simple case foldings are supported.  Full case foldings
 * is not supported.  Combined characters are also not supported.
 */

#if (NXT_MACOSX)
#include <nxt_unicode_macosx_lowcase.h>

#else
#include <nxt_unicode_lowcase.h>
#endif


u_char *
nxt_utf8_encode(u_char *p, uint32_t u)
{
    if (u < 0x80) {
        *p++ = (u_char) (u & 0xFF);
        return p;
    }

    if (u < 0x0800) {
        *p++ = (u_char) (( u >> 6)          | 0xC0);
        *p++ = (u_char) (( u        & 0x3F) | 0x80);
        return p;
    }

    if (u < 0x10000) {
        *p++ = (u_char) ( (u >> 12)         | 0xE0);
        *p++ = (u_char) (((u >>  6) & 0x3F) | 0x80);
        *p++ = (u_char) (( u        & 0x3F) | 0x80);
        return p;
    }

    if (u < 0x110000) {
        *p++ = (u_char) ( (u >> 18)         | 0xF0);
        *p++ = (u_char) (((u >> 12) & 0x3F) | 0x80);
        *p++ = (u_char) (((u >>  6) & 0x3F) | 0x80);
        *p++ = (u_char) (( u        & 0x3F) | 0x80);
        return p;
    }

    return NULL;
}


/*
 * nxt_utf8_decode() decodes UTF-8 sequences and returns a valid
 * character 0x00 - 0x10FFFF, or 0xFFFFFFFF for invalid or overlong
 * UTF-8 sequence.
 */

uint32_t
nxt_utf8_decode(const u_char **start, const u_char *end)
{
    uint32_t  u;

    u = (uint32_t) **start;

    if (u < 0x80) {
        (*start)++;
        return u;
    }

    return nxt_utf8_decode2(start, end);
}


/*
 * nxt_utf8_decode2() decodes two and more bytes UTF-8 sequences only
 * and returns a valid character 0x80 - 0x10FFFF, or 0xFFFFFFFF for
 * invalid or overlong UTF-8 sequence.
 */

uint32_t
nxt_utf8_decode2(const u_char **start, const u_char *end)
{
    u_char        c;
    size_t        n;
    uint32_t      u, overlong;
    const u_char  *p;

    p = *start;
    u = (uint32_t) *p;

    if (u >= 0xE0) {

        if (u >= 0xF0) {

            if (nxt_slow_path(u > 0xF4)) {
                /*
                 * The maximum valid Unicode character is 0x10FFFF
                 * which is encoded as 0xF4 0x8F 0xBF 0xBF.
                 */
                return 0xFFFFFFFF;
            }

            u &= 0x07;
            overlong = 0x00FFFF;
            n = 3;

        } else {
            u &= 0x0F;
            overlong = 0x07FF;
            n = 2;
        }

    } else if (u >= 0xC2) {

        /* 0x80 is encoded as 0xC2 0x80. */

        u &= 0x1F;
        overlong = 0x007F;
        n = 1;

    } else {
        /* u <= 0xC2 */
        return 0xFFFFFFFF;
    }

    p++;

    if (nxt_fast_path(p + n <= end)) {

        do {
            c = *p++;
            /*
             * The byte must in the 0x80 - 0xBF range.
             * Values below 0x80 become >= 0x80.
             */
            c = c - 0x80;

            if (nxt_slow_path(c > 0x3F)) {
                return 0xFFFFFFFF;
            }

            u = (u << 6) | c;
            n--;

        } while (n != 0);

        if (overlong < u && u < 0x110000) {
            *start = p;
            return u;
        }
    }

    return 0xFFFFFFFF;
}


/*
 * nxt_utf8_casecmp() tests only up to the minimum of given lengths, but
 * requires lengths of both strings because otherwise nxt_utf8_decode2()
 * may fail due to incomplete sequence.
 */

nxt_int_t
nxt_utf8_casecmp(const u_char *start1, const u_char *start2, size_t len1,
    size_t len2)
{
    int32_t       n;
    uint32_t      u1, u2;
    const u_char  *end1, *end2;

    end1 = start1 + len1;
    end2 = start2 + len2;

    while (start1 < end1 && start2 < end2) {

        u1 = nxt_utf8_lowcase(&start1, end1);

        u2 = nxt_utf8_lowcase(&start2, end2);

        if (nxt_slow_path((u1 | u2) == 0xFFFFFFFF)) {
            return NXT_UTF8_SORT_INVALID;
        }

        n = u1 - u2;

        if (n != 0) {
            return (nxt_int_t) n;
        }
    }

    return 0;
}


uint32_t
nxt_utf8_lowcase(const u_char **start, const u_char *end)
{
    uint32_t        u;
    const uint32_t  *block;

    u = (uint32_t) **start;

    if (nxt_fast_path(u < 0x80)) {
        (*start)++;

        return nxt_unicode_block_000[u];
    }

    u = nxt_utf8_decode2(start, end);

    if (u <= NXT_UNICODE_MAX_LOWCASE) {
        block = nxt_unicode_blocks[u / NXT_UNICODE_BLOCK_SIZE];

        if (block != NULL) {
            return block[u % NXT_UNICODE_BLOCK_SIZE];
        }
    }

    return u;
}


ssize_t
nxt_utf8_length(const u_char *p, size_t len)
{
    ssize_t       length;
    const u_char  *end;

    length = 0;

    end = p + len;

    while (p < end) {
        if (nxt_slow_path(nxt_utf8_decode(&p, end) == 0xFFFFFFFF)) {
            return -1;
        }

        length++;
    }

    return length;
}


nxt_bool_t
nxt_utf8_is_valid(const u_char *p, size_t len)
{
    const u_char  *end;

    end = p + len;

    while (p < end) {
        if (nxt_slow_path(nxt_utf8_decode(&p, end) == 0xFFFFFFFF)) {
            return 0;
        }
    }

    return 1;
}

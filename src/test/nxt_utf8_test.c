
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_tests.h"


#define NXT_UTF8_START_TEST  0xC2
//#define NXT_UTF8_START_TEST  0


static u_char  invalid[] = {

    /* Invalid first byte less than 0xC2. */
    1, 0x80, 0x00, 0x00, 0x00,
    1, 0xC0, 0x00, 0x00, 0x00,
    2, 0xC0, 0x00, 0x00, 0x00,
    3, 0xC0, 0x00, 0x00, 0x00,
    4, 0xC0, 0x00, 0x00, 0x00,

    /* Invalid 0x110000 value. */
    4, 0xF4, 0x90, 0x80, 0x80,

    /* Incomplete length. */
    2, 0xE0, 0xAF, 0xB5, 0x00,

    /* Overlong values. */
    2, 0xC0, 0x80, 0x00, 0x00,
    2, 0xC1, 0xB3, 0x00, 0x00,
    3, 0xE0, 0x80, 0x80, 0x00,
    3, 0xE0, 0x81, 0xB3, 0x00,
    3, 0xE0, 0x90, 0x9A, 0x00,
    4, 0xF0, 0x80, 0x8A, 0x80,
    4, 0xF0, 0x80, 0x81, 0xB3,
    4, 0xF0, 0x80, 0xAF, 0xB5,
};


static nxt_int_t
nxt_utf8_overlong(nxt_thread_t *thr, u_char *overlong, size_t len)
{
    u_char        *p, utf8[4];
    size_t        size;
    uint32_t      u, d;
    nxt_uint_t    i;
    const u_char  *pp;

    pp = overlong;

    d = nxt_utf8_decode(&pp, overlong + len);

    len = pp - overlong;

    if (d != 0xFFFFFFFF) {
        p = nxt_utf8_encode(utf8, d);

        size = (p != NULL) ? p - utf8 : 0;

        if (len != size || memcmp(overlong, utf8, size) != 0) {

            u = 0;
            for (i = 0; i < len; i++) {
                u = (u << 8) + overlong[i];
            }

            nxt_log_alert(thr->log,
                          "nxt_utf8_decode(%05uxD, %uz) failed: %05uxD, %uz",
                          u, len, d, size);

            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


nxt_int_t
nxt_utf8_test(nxt_thread_t *thr)
{
    u_char        *p, utf8[4];
    size_t        len;
    int32_t       n;
    uint32_t      u, d;
    nxt_uint_t    i, k, l, m;
    const u_char  *pp;

    nxt_thread_time_update(thr);

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "utf8 test started");

    /* Test valid UTF-8. */

    for (u = 0; u < 0x110000; u++) {

        p = nxt_utf8_encode(utf8, u);

        if (p == NULL) {
            nxt_log_alert(thr->log, "nxt_utf8_encode(%05uxD) failed", u);
            return NXT_ERROR;
        }

        pp = utf8;

        d = nxt_utf8_decode(&pp, p);

        if (u != d) {
            nxt_log_alert(thr->log, "nxt_utf8_decode(%05uxD) failed: %05uxD",
                          u, d);
            return NXT_ERROR;
        }
    }

    /* Test some invalid UTF-8. */

    for (i = 0; i < sizeof(invalid); i += 5) {

        len = invalid[i];
        utf8[0] = invalid[i + 1];
        utf8[1] = invalid[i + 2];
        utf8[2] = invalid[i + 3];
        utf8[3] = invalid[i + 4];

        pp = utf8;

        d = nxt_utf8_decode(&pp, utf8 + len);

        if (d != 0xFFFFFFFF) {

            u = 0;
            for (i = 0; i < len; i++) {
                u = (u << 8) + utf8[i];
            }

            nxt_log_alert(thr->log,
                          "nxt_utf8_decode(%05uxD, %uz) failed: %05uxD",
                          u, len, d);
            return NXT_ERROR;
        }
    }

    /* Test all overlong UTF-8. */

    for (i = NXT_UTF8_START_TEST; i < 256; i++) {
        utf8[0] = i;

        if (nxt_utf8_overlong(thr, utf8, 1) != NXT_OK) {
            return NXT_ERROR;
        }

        for (k = 0; k < 256; k++) {
            utf8[1] = k;

            if (nxt_utf8_overlong(thr, utf8, 2) != NXT_OK) {
                return NXT_ERROR;
            }

            for (l = 0; l < 256; l++) {
                utf8[2] = l;

                if (nxt_utf8_overlong(thr, utf8, 3) != NXT_OK) {
                    return NXT_ERROR;
                }

                for (m = 0; m < 256; m++) {
                    utf8[3] = m;

                    if (nxt_utf8_overlong(thr, utf8, 4) != NXT_OK) {
                        return NXT_ERROR;
                    }
                }
            }
        }
    }

    n = nxt_utf8_casecmp((u_char *) "ABC АБВ ΑΒΓ",
                         (u_char *) "abc абв αβγ",
                         nxt_length("ABC АБВ ΑΒΓ"),
                         nxt_length("abc абв αβγ"));

    if (n != 0) {
        nxt_log_alert(thr->log, "nxt_utf8_casecmp() failed");
        return NXT_ERROR;
    }

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "utf8 test passed");
    return NXT_OK;
}


/*
 * Copyright (C) NGINX, Inc.
 * Copyright (C) Valentin V. Bartenev
 */

#include <nxt_main.h>
#include "nxt_tests.h"


typedef struct {
    const char  *v1;
    const char  res;
    const char  *v2;
} nxt_strverscmp_test_t;


nxt_int_t
nxt_strverscmp_test(nxt_thread_t *thr)
{
    nxt_int_t   ret;
    nxt_uint_t  i;

    static const nxt_strverscmp_test_t  tests[] = {
        { "word",   '=', "word" },
        { "42",     '=', "42" },
        { "000",    '=', "000" },
        { "2",      '>', "1" },
        { "2",      '<', "10" },
        { "rc2",    '>', "rc" },
        { "rc2",    '<', "rc3" },
        { "1.13.8", '>', "1.1.9" },
        { "1.9",    '<', "1.13.8" },
        { "9.9",    '<', "10.0" },
        { "1",      '>', "007" },
        { "2b01",   '<', "2b013" },
        { "011",    '>', "01" },
        { "011",    '>', "01.1" },
        { "011",    '>', "01+1" },
        { "011",    '<', "01:1" },
        { "011",    '<', "01b" },
        { "020",    '>', "01b" },
        { "a0",     '>', "a01" },
        { "b00",    '<', "b01" },
        { "c000",   '<', "c01" },
        { "000",    '<', "00" },
        { "000",    '<', "00a" },
        { "00.",    '>', "000" },
        { "a.0",    '<', "a0" },
        { "b11",    '>', "b0" },
    };

    nxt_thread_time_update(thr);

    for (i = 0; i < nxt_nitems(tests); i++) {

        ret = nxt_strverscmp((u_char *) tests[i].v1, (u_char *) tests[i].v2);

        switch (tests[i].res) {

        case '<':
            if (ret < 0) {
                continue;
            }

            break;

        case '=':
            if (ret == 0) {
                continue;
            }

            break;

        case '>':
            if (ret > 0) {
                continue;
            }

            break;
        }

        nxt_log_alert(thr->log,
                      "nxt_strverscmp() test \"%s\" %c \"%s\" failed: %i",
                      tests[i].v1, tests[i].res, tests[i].v2, ret);

        return NXT_ERROR;
    }

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "nxt_strverscmp() test passed");

    return NXT_OK;
}

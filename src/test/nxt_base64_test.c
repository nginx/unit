
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_tests.h"


nxt_int_t
nxt_base64_test(nxt_thread_t *thr)
{
    ssize_t     ret;
    nxt_uint_t  i;

    static struct {
        nxt_str_t  enc;
        nxt_str_t  dec;

    } tests[] = {
        { nxt_string("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                     "abcdefghijklmnopqrstuvwxyz"
                     "0123456789+//+9876543210"
                     "zyxwvutsrqponmlkjihgfedcba"
                     "ZYXWVUTSRQPONMLKJIHGFEDCBA"),
          nxt_string("\x00\x10\x83\x10\x51\x87\x20\x92\x8b\x30\xd3\x8f"
                     "\x41\x14\x93\x51\x55\x97\x61\x96\x9b\x71\xd7\x9f"
                     "\x82\x18\xa3\x92\x59\xa7\xa2\x9a\xab\xb2\xdb\xaf"
                     "\xc3\x1c\xb3\xd3\x5d\xb7\xe3\x9e\xbb\xf3\xdf\xbf"
                     "\xff\xef\x7c\xef\xae\x78\xdf\x6d\x74\xcf\x2c\x70"
                     "\xbe\xeb\x6c\xae\xaa\x68\x9e\x69\x64\x8e\x28\x60"
                     "\x7d\xe7\x5c\x6d\xa6\x58\x5d\x65\x54\x4d\x24\x50"
                     "\x3c\xe3\x4c\x2c\xa2\x48\x1c\x61\x44\x0c\x20\x40") },

        { nxt_string("Aa=="),
          nxt_string("\x01") },
        { nxt_string("0Z"),
          nxt_string("\xd1") },
        { nxt_string("0aA="),
          nxt_string("\xd1\xa0") },
        { nxt_string("z/+"),
          nxt_string("\xcf\xff") },
        { nxt_string("z9+Npe=="),
          nxt_string("\xcf\xdf\x8d\xa5") },
        { nxt_string("/+98765"),
          nxt_string("\xff\xef\x7c\xef\xae") },

        { nxt_string("aBc_"),
          nxt_null_string },
        { nxt_string("5"),
          nxt_null_string },
        { nxt_string("M==="),
          nxt_null_string },
        { nxt_string("===="),
          nxt_null_string },
        { nxt_string("Ab="),
          nxt_null_string },
        { nxt_string("00=0"),
          nxt_null_string },
        { nxt_string("\0"),
          nxt_null_string },
        { nxt_string("\r\naaaa"),
          nxt_null_string },
        { nxt_string("=0000"),
          nxt_null_string },
    };

    u_char  buf[96];

    nxt_thread_time_update(thr);

    for (i = 0; i < nxt_nitems(tests); i++) {
        ret = nxt_base64_decode(NULL, tests[i].enc.start, tests[i].enc.length);

        if (ret == NXT_ERROR && tests[i].dec.start == NULL) {
            continue;
        }

        if ((size_t) ret != tests[i].dec.length) {
            nxt_log_alert(thr->log,
                          "nxt_base64_decode() test \"%V\" failed: incorrect "
                          "length of decoded string %z, expected %uz",
                          &tests[i].enc, ret, tests[i].dec.length);
            return NXT_ERROR;
        }

        ret = nxt_base64_decode(buf, tests[i].enc.start, tests[i].enc.length);

        if (!nxt_str_eq(&tests[i].dec, buf, (size_t) ret)) {
            nxt_log_alert(thr->log, "nxt_base64_decode() test \"%V\" failed");
            return NXT_ERROR;
        }
    }

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "nxt_base64_decode() test passed");

    return NXT_OK;
}

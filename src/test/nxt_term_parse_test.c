
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_tests.h"


typedef struct {
    nxt_str_t   string;
    nxt_bool_t  is_sec;
    nxt_int_t   value;
} nxt_term_parse_test_t;


static const nxt_term_parse_test_t  terms[] = {
    { nxt_string("1y"),                    1,  365 * 24 * 60 * 60 },
    { nxt_string("1w"),                    1,  7 * 24 * 60 * 60 },
    { nxt_string("1w"),                    0,  7 * 24 * 60 * 60 * 1000 },
    { nxt_string("1w  1d"),                0,  8 * 24 * 60 * 60 * 1000 },
    { nxt_string("1w  d"),                 0,  -1 },
    { nxt_string("w"),                     0,  -1 },
    { nxt_string("1d 1w"),                 0,  -1 },
    { nxt_string("25d"),                   0,  -2 },
    { nxt_string("300"),                   1,  300 },
    { nxt_string("300"),                   0,  300000 },
    { nxt_string("300s"),                  1,  300 },
    { nxt_string("300ms"),                 0,  300 },
    { nxt_string("1y 1M 1w1d1h1m1s"),      1,
                       (((((365 + 30 + 7 + 1) * 24 + 1) * 60) + 1) * 60) + 1 },
};


nxt_int_t
nxt_term_parse_test(nxt_thread_t *thr)
{
    nxt_int_t        val;
    nxt_uint_t       i;
    const nxt_str_t  *s;

    nxt_thread_time_update(thr);

    for (i = 0; i < nxt_nitems(terms); i++) {

        s = &terms[i].string;
        val = nxt_term_parse(s->start, s->length, terms[i].is_sec);

        if (val != terms[i].value) {
            nxt_log_alert(thr->log,
                          "term parse test failed: \"%V\": %i %i",
                          s, terms[i].value, val);
            return NXT_ERROR;
        }
    }

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "term parse test passed");
    return NXT_OK;
}

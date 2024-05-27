
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_tests.h"


typedef struct {
    const char  *format;
    const char  *test;
    double       number;
} nxt_sprintf_double_test_t;


static const nxt_sprintf_double_test_t  double_test[] =
{
    { "%3.5f", "1234.56700", 1234.567 },
    { "%3.0f", "1234", 1234.567 },
    { "%f", "1234.567", 1234.567 },
    { "%f", "0.1", 0.1 },
    { "%f", "0.000001", 0.000001 },
    { "%f", "4503599627370495", 4503599627370495.0 },
};


static nxt_int_t
nxt_sprintf_test_double(u_char *buf, u_char *end, const char *fmt,
    const char *test, double n)
{
    u_char  *p;

    p = nxt_sprintf(buf, end, fmt, n);
    *p = '\0';

    return nxt_strcmp(buf, test);
}


nxt_int_t
nxt_sprintf_test(nxt_thread_t *thr)
{
    nxt_int_t   ret;
    nxt_uint_t  i;
    u_char      *end, buf[64];

    nxt_thread_time_update(thr);

    end = buf + 64;

    for (i = 0; i < nxt_nitems(double_test); i++) {

        ret = nxt_sprintf_test_double(buf, end, double_test[i].format,
                                      double_test[i].test,
                                      double_test[i].number);

        if (ret == NXT_OK) {
            continue;
        }

        nxt_log_alert(thr->log, "nxt_sprintf(\"%s\") failed: \"%s\" vs \"%s\"",
                      double_test[i].format, double_test[i].test, buf);

        return NXT_ERROR;
    }

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "nxt_sprintf() test passed");
    return NXT_OK;
}

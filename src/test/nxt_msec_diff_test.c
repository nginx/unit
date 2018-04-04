
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_tests.h"


static const nxt_msec_t  pairs[] = {

    0x00000000, 0x00000001,
    0x00000000, 0x7FFFFFFF,

    0x7FFFFFFF, 0x80000000,
    0x7FFFFFFF, 0x80000001,

    0x80000000, 0x80000001,
    0x80000000, 0xFFFFFFFF,

    0xFFFFFFFF, 0x00000000,
    0xFFFFFFFF, 0x00000001,
};


nxt_int_t
nxt_msec_diff_test(nxt_thread_t *thr, nxt_msec_less_t less)
{
    nxt_uint_t  i;

    nxt_thread_time_update(thr);

    for (i = 0; i < nxt_nitems(pairs); i += 2) {

        if (!less(pairs[i], pairs[i + 1])) {
            nxt_log_alert(thr->log,
                          "msec diff test failed: 0x%08XM 0x%08XM",
                          pairs[i], pairs[i + 1]);
            return NXT_ERROR;
        }
    }

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "msec diff test passed");
    return NXT_OK;
}

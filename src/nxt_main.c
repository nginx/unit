
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_cycle.h>


extern char  **environ;


int nxt_cdecl
main(int argc, char **argv)
{
    nxt_int_t     ret;
    nxt_thread_t  *thr;

    if (nxt_lib_start("nginext", argv, &environ) != NXT_OK) {
        return 1;
    }

//    nxt_main_log.level = NXT_LOG_INFO;

    thr = nxt_thread();
    nxt_thread_time_update(thr);

    nxt_main_log.handler = nxt_log_time_handler;

    nxt_log_error(NXT_LOG_INFO, thr->log, "nginext started");

    ret = nxt_cycle_create(thr, &nxt_main_task, NULL, NULL);

    if (ret != NXT_OK) {
        return 1;
    }

    nxt_event_engine_start(thr->engine);

    nxt_unreachable();
    return 0;
}

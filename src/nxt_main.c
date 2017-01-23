
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

    static nxt_str_t   nxt_config_name = nxt_string_zero("nginx.conf");

    if (nxt_lib_start("nginman", argv, &environ) != NXT_OK) {
        return 1;
    }

//    nxt_main_log.level = NXT_LOG_INFO;

    thr = nxt_thread();
    nxt_thread_time_update(thr);

    nxt_main_log.handler = nxt_log_time_handler;

    nxt_log_error(NXT_LOG_INFO, thr->log, "nginman started");

    ret = nxt_cycle_create(thr, &nxt_main_task, NULL, NULL, &nxt_config_name);

    if (ret != NXT_OK) {
        return 1;
    }

    nxt_event_engine_start(thr->engine);

    nxt_unreachable();
    return 0;
}

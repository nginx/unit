
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_otel.h>
#include <nxt_runtime.h>


extern char  **environ;


void otel_phase1_log_callback(u_char *arg) {
    printf("otel: %s", (char *) arg);
}

int nxt_cdecl
main(int argc, char **argv)
{
    nxt_int_t  ret;

    if (nxt_lib_start("unit", argv, &environ) != NXT_OK) {
        return 1;
    }

//    nxt_main_log.level = NXT_LOG_INFO;

    nxt_main_log.handler = nxt_log_time_handler;

#if (NXT_HAVE_OTEL)
    nxt_otel_init(&otel_phase1_log_callback);
#endif
    ret = nxt_runtime_create(&nxt_main_task);

    if (ret != NXT_OK) {
        return 1;
    }

    nxt_log(&nxt_main_task, NXT_LOG_INFO, "unit " NXT_VERSION " started");

    nxt_event_engine_start(nxt_main_task.thread->engine);

    nxt_unreachable();
    return 0;
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void nxt_log_moderate_timer_handler(nxt_task_t *task, void *obj,
    void *data);


nxt_bool_t
nxt_log_moderate_allow(nxt_log_moderation_t *mod)
{
    nxt_uint_t    n;
    nxt_time_t    now;
    nxt_bool_t    allow, timer;
    nxt_thread_t  *thr;

    thr = nxt_thread();
    now = nxt_thread_time(thr);

    allow = 0;
    timer = 0;

    nxt_thread_spin_lock(&mod->lock);

    n = mod->count++;

    if (now != mod->last) {

        if (n <= mod->limit) {
            mod->last = now;
            mod->count = 1;
            allow = 1;
        }

        /* "n > mod->limit" means that timer has already been set. */

    } else {

        if (n < mod->limit) {
            allow = 1;

        } else if (n == mod->limit) {
            /*
             * There is a race condition on 32-bit many core system
             * capable to fail an operation 2^32 times per second.
             * This can be fixed by storing mod->count as uint64_t.
             */
            timer = 1;
            mod->pid = nxt_pid;
        }
    }

    nxt_thread_spin_unlock(&mod->lock);

    if (timer) {
        mod->timer.work_queue = &thr->engine->fast_work_queue;
        mod->timer.handler = nxt_log_moderate_timer_handler;
        mod->timer.log = &nxt_main_log;
        mod->timer.task = &nxt_main_task;

        nxt_timer_add(thr->engine, &mod->timer, 1000);
    }

    return allow;
}


static void
nxt_log_moderate_timer_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_bool_t            msg;
    nxt_timer_t           *ev;
    nxt_atomic_uint_t     n;
    nxt_log_moderation_t  *mod;

    ev = obj;
    mod = nxt_timer_data(ev, nxt_log_moderation_t, timer);

    nxt_thread_spin_lock(&mod->lock);

    mod->last = nxt_thread_time(task->thread);
    n = mod->count;
    mod->count = 0;
    msg = (mod->pid == nxt_pid);

    nxt_thread_spin_unlock(&mod->lock);

    if (msg) {
        nxt_log_error(mod->level, &nxt_main_log, "%s %uA times",
                      mod->msg, n - mod->limit);
    }
}

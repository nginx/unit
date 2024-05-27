
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * Signals are handled only via a main thread event engine work queue.
 * There are three ways to route signals to the work queue:
 *
 * 1) Using signal event notifications if an event facility supports it:
 *    kqueue and epoll/signalfd.  This method is used regardless of thread mode.
 *
 * 2) Multi-threaded mode: a dedicated signal thread which waits in sigwait()
 *    and post a signal number to the main thread event engine.
 *
 * 3) Single-threaded mode: a signal handler which posts a signal number
 *    to the event engine.
 */


static nxt_int_t nxt_signal_action(int signo, void (*handler)(int));
static void nxt_signal_thread(void *data);


nxt_event_signals_t *
nxt_event_engine_signals(const nxt_sig_event_t *sigev)
{
    nxt_event_signals_t  *signals;

    signals = nxt_zalloc(sizeof(nxt_event_signals_t));
    if (signals == NULL) {
        return NULL;
    }

    signals->sigev = sigev;

    if (nxt_signal_action(SIGSYS, SIG_IGN) != NXT_OK) {
        goto fail;
    }

    if (nxt_signal_action(SIGPIPE, SIG_IGN) != NXT_OK) {
        goto fail;
    }

    sigemptyset(&signals->sigmask);

    while (sigev->signo != 0) {
        sigaddset(&signals->sigmask, sigev->signo);
        sigev++;
    }

    if (sigprocmask(SIG_BLOCK, &signals->sigmask, NULL) != 0) {
        nxt_main_log_alert("sigprocmask(SIG_BLOCK) failed %E", nxt_errno);
        goto fail;
    }

    return signals;

fail:

    nxt_free(signals);

    return NULL;
}


static nxt_int_t
nxt_signal_action(int signo, void (*handler)(int))
{
    struct sigaction  sa;

    nxt_memzero(&sa, sizeof(struct sigaction));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = handler;

    if (sigaction(signo, &sa, NULL) == 0) {
        return NXT_OK;
    }

    nxt_main_log_alert("sigaction(%d) failed %E", signo, nxt_errno);

    return NXT_ERROR;
}


static void
nxt_signal_handler(int signo)
{
    nxt_thread_t  *thr;

    thr = nxt_thread();

    /* Thread is running in a single context now. */
    thr->time.signal++;

    nxt_thread_time_update(thr);

    nxt_main_log_error(NXT_LOG_INFO, "signal handler: %d", signo);

    nxt_event_engine_signal(thr->engine, signo);

    thr->time.signal--;
}


nxt_int_t
nxt_signal_thread_start(nxt_event_engine_t *engine)
{
    nxt_thread_link_t      *link;
    const nxt_sig_event_t  *sigev;

    if (engine->signals->process == nxt_pid) {
        return NXT_OK;
    }

    if (sigprocmask(SIG_BLOCK, &engine->signals->sigmask, NULL) != 0) {
        nxt_main_log_alert("sigprocmask(SIG_BLOCK) failed %E", nxt_errno);
        return NXT_ERROR;
    }

    /*
     * kqueue sets signal handlers to SIG_IGN and sigwait() ignores
     * them after the switch of event facility from "kqueue" to "select".
     */

    for (sigev = engine->signals->sigev; sigev->signo != 0; sigev++) {
        if (nxt_signal_action(sigev->signo, nxt_signal_handler) != NXT_OK) {
            return NXT_ERROR;
        }
    }

    link = nxt_zalloc(sizeof(nxt_thread_link_t));

    if (nxt_fast_path(link != NULL)) {
        link->start = nxt_signal_thread;
        link->work.data = engine;

        if (nxt_thread_create(&engine->signals->thread, link) == NXT_OK) {
            engine->signals->process = nxt_pid;
            return NXT_OK;
        }
    }

    return NXT_ERROR;
}


static void
nxt_signal_thread(void *data)
{
    int                 signo;
    nxt_err_t           err;
    nxt_thread_t        *thr;
    nxt_event_engine_t  *engine;

    engine = data;

    thr = nxt_thread();

    nxt_main_log_debug("signal thread");

    for ( ;; ) {
        err = sigwait(&engine->signals->sigmask, &signo);

        nxt_thread_time_update(thr);

        if (nxt_fast_path(err == 0)) {
            nxt_main_log_error(NXT_LOG_INFO, "signo: %d", signo);

            nxt_event_engine_signal(engine, signo);

        } else {
            nxt_main_log_alert("sigwait() failed %E", err);
        }
    }
}


void
nxt_signal_thread_stop(nxt_event_engine_t *engine)
{
    nxt_thread_handle_t  thread;

    thread = engine->signals->thread;

    nxt_thread_cancel(thread);
    nxt_thread_wait(thread);
}

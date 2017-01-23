
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


nxt_uint_t    nxt_ncpu = 1;
nxt_uint_t    nxt_pagesize;
nxt_task_t    nxt_main_task;
nxt_atomic_t  nxt_task_ident;
nxt_random_t  nxt_random_data;

nxt_thread_declare_data(nxt_thread_t, nxt_thread_context);


#if (NXT_DEBUG && NXT_FREEBSD)
/*
 * Fill memory with 0xA5 after malloc() and with 0x5A before free().
 * malloc() options variable has to override the libc symbol, otherwise
 * it has no effect.
 */
#if __FreeBSD_version < 1000011
const char *_malloc_options = "J";
#else
const char *malloc_conf = "junk:true";
#endif
#endif


nxt_int_t
nxt_lib_start(const char *app, char **argv, char ***envp)
{
    int           n;
    nxt_int_t     flags;
    nxt_bool_t    update;
    nxt_thread_t  *thr;

    flags = nxt_stderr_start();

    nxt_log_start(app);

    nxt_pid = getpid();
    nxt_ppid = getppid();

#if (NXT_DEBUG)

    nxt_main_log.level = NXT_LOG_DEBUG;

#if (NXT_LINUX)
    /* Fill memory with 0xAA after malloc() and with 0x55 before free(). */
    mallopt(M_PERTURB, 0x55);
#endif

#if (NXT_MACOSX)
    /* Fill memory with 0xAA after malloc() and with 0x55 before free(). */
    setenv("MallocScribble", "1", 0);
#endif

#endif /* NXT_DEBUG */

    /* Thread log is required for nxt_malloc() in nxt_strerror_start(). */

    nxt_thread_init_data(nxt_thread_context);
    thr = nxt_thread();
    thr->log = &nxt_main_log;

#if (NXT_THREADS)
    thr->handle = nxt_thread_handle();
    thr->time.signal = -1;
#endif

    nxt_main_task.thread = thr;
    nxt_main_task.log = thr->log;
    nxt_main_task.ident = nxt_task_next_ident();

    if (nxt_strerror_start() != NXT_OK) {
        return NXT_ERROR;
    }

    if (flags != -1) {
        nxt_log_debug(thr->log, "stderr flags: 0x%04Xd", flags);
    }

#ifdef _SC_NPROCESSORS_ONLN
    /* Linux, FreeBSD, Solaris, MacOSX. */
    n = sysconf(_SC_NPROCESSORS_ONLN);

#elif (NXT_HPUX)
    n = mpctl(MPC_GETNUMSPUS, NULL, NULL);

#endif

    nxt_log_debug(thr->log, "ncpu: %ui", n);

    if (n > 1) {
        nxt_ncpu = n;
    }

    nxt_thread_spin_init(nxt_ncpu, 0);

    nxt_random_init(&nxt_random_data);

    nxt_pagesize = getpagesize();

    nxt_log_debug(thr->log, "pagesize: %ui", nxt_pagesize);

    if (argv != NULL) {
        update = (argv[0] == app);

        nxt_process_arguments(argv, envp);

        if (update) {
            nxt_log_start(nxt_process_argv[0]);
        }
    }

    return NXT_OK;
}


void
nxt_lib_stop(void)
{
    /* TODO: stop engines */

#if (NXT_THREADS0)

    for ( ;; ) {
        nxt_thread_pool_t  *tp;

        nxt_thread_spin_lock(&cycle->lock);

        tp = cycle->thread_pools;
        cycle->thread_pools = (tp != NULL) ? tp->next : NULL;

        nxt_thread_spin_unlock(&cycle->lock);

        if (tp == NULL) {
            break;
        }

        nxt_thread_pool_destroy(tp);
    }

#else

    exit(0);
    nxt_unreachable();

#endif
}

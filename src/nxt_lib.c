
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


nxt_uint_t    nxt_ncpu = 1;
nxt_uint_t    nxt_pagesize;
nxt_task_t    nxt_main_task;
nxt_atomic_t  nxt_task_ident;

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
    nxt_thread_t  *thread;

    flags = nxt_stderr_start();

    nxt_log_start(app);

    nxt_pid = getpid();
    nxt_ppid = getppid();
    nxt_euid = geteuid();
    nxt_egid = getegid();

#if (NXT_DEBUG)

    nxt_main_log.level = NXT_LOG_DEBUG;

#if (NXT_HAVE_MALLOPT)
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
    thread = nxt_thread();
    thread->log = &nxt_main_log;

    thread->handle = nxt_thread_handle();
    thread->time.signal = -1;
    nxt_thread_time_update(thread);

    nxt_main_task.thread = thread;
    nxt_main_task.log = thread->log;
    nxt_main_task.ident = nxt_task_next_ident();

    if (nxt_strerror_start() != NXT_OK) {
        return NXT_ERROR;
    }

    if (flags != -1) {
        nxt_debug(&nxt_main_task, "stderr flags: 0x%04Xd", flags);
    }

#ifdef _SC_NPROCESSORS_ONLN
    /* Linux, FreeBSD, Solaris, MacOSX. */
    n = sysconf(_SC_NPROCESSORS_ONLN);

#elif (NXT_HPUX)
    n = mpctl(MPC_GETNUMSPUS, NULL, NULL);

#else
    n = 0;

#endif

    nxt_debug(&nxt_main_task, "ncpu: %d", n);

    if (n > 1) {
        nxt_ncpu = n;
    }

    nxt_thread_spin_init(nxt_ncpu, 0);

    nxt_random_init(&thread->random);

    nxt_pagesize = getpagesize();

    nxt_debug(&nxt_main_task, "pagesize: %ui", nxt_pagesize);

    if (argv != NULL) {
        update = (argv[0] == app);

        nxt_process_arguments(&nxt_main_task, argv, envp);

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

#if 0

    for ( ;; ) {
        nxt_thread_pool_t  *tp;

        nxt_thread_spin_lock(&rt->lock);

        tp = rt->thread_pools;
        rt->thread_pools = (tp != NULL) ? tp->next : NULL;

        nxt_thread_spin_unlock(&rt->lock);

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

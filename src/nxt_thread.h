
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIX_THREAD_H_INCLUDED_
#define _NXT_UNIX_THREAD_H_INCLUDED_


/*
 * Thread Specific Data
 *
 * The interface unifies two TSD implementations: the __thread storage
 * class and pthread specific data.  It works also in non-threaded mode.
 * The interface is optimized for the __thread storage class and non-threaded
 * mode, since the __thread storage is faster and is supported in modern
 * versions of Linux, FreeBSD, Solaris, and MacOSX.  Pthread specific data
 * is considered as a fallback option.
 *
 * The underlining interfaces are different: pthread data must be allocated
 * by hand and may be accessed only by using pointers whereas __thread data
 * allocation is transparent and it is accessed directly.
 *
 * pthread_getspecific() is usually faster than pthread_setspecific()
 * (much faster on MacOSX), so there is no nxt_thread_set_data() interface
 * for this reason.  It is better to store frequently alterable thread
 * log pointer in nxt_thread_t, but not in a dedicated key.
 */

#if (NXT_HAVE_THREAD_STORAGE_CLASS)

#define nxt_thread_extern_data(type, tsd)                                     \
    NXT_EXPORT extern __thread type  tsd

#define nxt_thread_declare_data(type, tsd)                                    \
    __thread type  tsd

#define nxt_thread_init_data(tsd)

#define nxt_thread_get_data(tsd)                                              \
    &tsd


#else /* NXT_HAVE_PTHREAD_SPECIFIC_DATA */

/*
 * nxt_thread_get_data() is used as
 *    p = nxt_thread_get_data(tsd),
 * but the tsd address is actually required.  This could be resolved by macro
 *    #define nxt_thread_get_data(tsd)  nxt_thread_get_data_addr(&tsd)
 * or by definition nxt_thread_specific_data_t as an array.
 *
 * On Linux and Solaris pthread_key_t is unsigned integer.
 * On FreeBSD, NetBSD, OpenBSD, and HP-UX pthread_key_t is integer.
 * On MacOSX and AIX pthread_key_t is unsigned long integer.
 * On Cygwin pthread_key_t is pointer to void.
 */

typedef struct {
    nxt_atomic_t             key;
    size_t                   size;
} nxt_thread_specific_data_t[1];


#define nxt_thread_extern_data(type, tsd)                                     \
    NXT_EXPORT extern nxt_thread_specific_data_t  tsd

#define nxt_thread_declare_data(type, tsd)                                    \
    nxt_thread_specific_data_t tsd = { { (nxt_atomic_int_t) -1, sizeof(type) } }

NXT_EXPORT void nxt_thread_init_data(nxt_thread_specific_data_t tsd);

#define nxt_thread_get_data(tsd)                                              \
    pthread_getspecific((pthread_key_t) tsd->key)

#endif


typedef void (*nxt_thread_start_t)(void *data);

typedef struct {
    nxt_thread_start_t       start;
    nxt_event_engine_t       *engine;
    nxt_work_t               work;
} nxt_thread_link_t;


NXT_EXPORT nxt_int_t nxt_thread_create(nxt_thread_handle_t *handle,
    nxt_thread_link_t *link);
NXT_EXPORT nxt_thread_t *nxt_thread_init(void);
NXT_EXPORT void nxt_thread_exit(nxt_thread_t *thr);
NXT_EXPORT void nxt_thread_cancel(nxt_thread_handle_t handle);
NXT_EXPORT void nxt_thread_wait(nxt_thread_handle_t handle);


#define nxt_thread_handle()                                                   \
    pthread_self()


typedef pthread_mutex_t      nxt_thread_mutex_t;

NXT_EXPORT nxt_int_t nxt_thread_mutex_create(nxt_thread_mutex_t *mtx);
NXT_EXPORT void nxt_thread_mutex_destroy(nxt_thread_mutex_t *mtx);
NXT_EXPORT nxt_int_t nxt_thread_mutex_lock(nxt_thread_mutex_t *mtx);
NXT_EXPORT nxt_bool_t nxt_thread_mutex_trylock(nxt_thread_mutex_t *mtx);
NXT_EXPORT nxt_int_t nxt_thread_mutex_unlock(nxt_thread_mutex_t *mtx);


typedef pthread_cond_t       nxt_thread_cond_t;

NXT_EXPORT nxt_int_t nxt_thread_cond_create(nxt_thread_cond_t *cond);
NXT_EXPORT void nxt_thread_cond_destroy(nxt_thread_cond_t *cond);
NXT_EXPORT nxt_int_t nxt_thread_cond_signal(nxt_thread_cond_t *cond);
NXT_EXPORT nxt_err_t nxt_thread_cond_wait(nxt_thread_cond_t *cond,
    nxt_thread_mutex_t *mtx, nxt_nsec_t timeout);


#if (NXT_HAVE_PTHREAD_YIELD)
#define nxt_thread_yield()                                                    \
    pthread_yield()

#elif (NXT_HAVE_PTHREAD_YIELD_NP)
#define nxt_thread_yield()                                                    \
    pthread_yield_np()

#else
#define nxt_thread_yield()                                                    \
    nxt_sched_yield()

#endif


struct nxt_thread_s {
    nxt_log_t                *log;
    nxt_log_t                main_log;

    nxt_task_t               *task;

    nxt_tid_t                tid;
    nxt_thread_handle_t      handle;
    nxt_thread_link_t        *link;
    nxt_thread_pool_t        *thread_pool;

    nxt_thread_time_t        time;

    nxt_runtime_t            *runtime;
    nxt_event_engine_t       *engine;
    void                     *data;

#if 0
    /*
     * Although pointer to a current fiber should be a property of
     * engine->fibers, its placement here eliminates 2 memory accesses.
     */
    nxt_fiber_t              *fiber;
#endif

    nxt_random_t             random;
};


#endif /* _NXT_UNIX_THREAD_H_INCLUDED_ */

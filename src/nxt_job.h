
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_JOB_H_INCLUDED_
#define _NXT_JOB_H_INCLUDED_


/*
 * A job may run by separate thread, so each job should have its
 * its own mem_pool.  A job itself is allocated from this mem_pool.
 * On job completion a job initiator can destroy the job at once
 * with nxt_job_destroy() or can postpone the destruction with
 * nxt_job_cleanup_add(), if the initiator uses data from the job's
 * mem_pool.
 *
 * Several child jobs may run in context of another job in the same
 * thread.  In this case the child job may use a mem_pool of the
 * parent job and the child job is allocated using the mem_pool's cache.
 * nxt_job_destroy() just returns the job to the cache.  All job
 * allocations however still remain in the parent mem_pool.
 *
 * The first thread in job thread pool is created on demand.  If this
 * operation fails the job abort handler is called.  It also is called
 * if the job is canceled.  To avoid race condition the abort handler
 * always runs in context of a thread initiated the job.  The abort
 * handler may be as simple as nxt_job_destroy().
 */


typedef struct {
    void                *data;

    nxt_task_t          *task;

    nxt_work_handler_t  abort_handler;

    uint16_t            cache_size;
    uint8_t             cancel;          /* 1 bit */

    nxt_mp_t            *mem_pool;
    nxt_queue_link_t    link;

    nxt_thread_pool_t   *thread_pool;
    nxt_event_engine_t  *engine;
    nxt_log_t           *log;

    nxt_work_t          work;

#if (NXT_DEBUG)
    const char          *name;
#endif

} nxt_job_t;


NXT_EXPORT void *nxt_job_create(nxt_mp_t *mp, size_t size);
NXT_EXPORT void nxt_job_init(nxt_job_t *job, size_t size);
NXT_EXPORT void nxt_job_destroy(nxt_task_t *task, void *data);
NXT_EXPORT nxt_int_t nxt_job_cleanup_add(nxt_mp_t *mp, nxt_job_t *job);

NXT_EXPORT void nxt_job_start(nxt_task_t *task, nxt_job_t *job,
    nxt_work_handler_t handler);
NXT_EXPORT void nxt_job_return(nxt_task_t *task, nxt_job_t *job,
    nxt_work_handler_t handler);


#define nxt_job_cancel(job)                                                   \
    (job)->cancel = 1


#if (NXT_DEBUG)

#define nxt_job_set_name(job, text)                                           \
    (job)->name = text

#else

#define nxt_job_set_name(job, text)

#endif


#endif /* _NXT_JOB_H_INCLUDED_ */

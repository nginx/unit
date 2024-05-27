
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void nxt_job_thread_trampoline(nxt_task_t *task, void *obj, void *data);
static void nxt_job_thread_return_handler(nxt_task_t *task, void *obj,
    void *data);


void *
nxt_job_create(nxt_mp_t *mp, size_t size)
{
    size_t     cache_size;
    nxt_job_t  *job;

    if (mp == NULL) {
        mp = nxt_mp_create(1024, 128, 256, 32);
        if (nxt_slow_path(mp == NULL)) {
            return NULL;
        }

        job = nxt_mp_zget(mp, size);
        cache_size = 0;

    } else {
        job = nxt_mp_zalloc(mp, size);
        cache_size = size;
    }

    if (nxt_slow_path(job == NULL)) {
        return NULL;
    }

    job->cache_size = (uint16_t) cache_size;
    job->mem_pool = mp;
    nxt_job_set_name(job, "job");

    /* Allow safe nxt_queue_remove() in nxt_job_destroy(). */
    nxt_queue_self(&job->link);

    return job;
}


void
nxt_job_init(nxt_job_t *job, size_t size)
{
    nxt_memzero(job, size);

    nxt_job_set_name(job, "job");

    nxt_queue_self(&job->link);
}


void
nxt_job_destroy(nxt_task_t *task, void *data)
{
    nxt_job_t  *job;

    job = data;

    nxt_queue_remove(&job->link);

    if (job->cache_size == 0) {

        if (job->mem_pool != NULL) {
            nxt_mp_destroy(job->mem_pool);
        }

    } else {
        nxt_mp_free(job->mem_pool, job);
    }
}


#if 0

nxt_int_t
nxt_job_cleanup_add(nxt_mp_t *mp, nxt_job_t *job)
{
    nxt_mem_pool_cleanup_t  *mpcl;

    mpcl = nxt_mem_pool_cleanup(mp, 0);

    if (nxt_fast_path(mpcl != NULL)) {
        mpcl->handler = nxt_job_destroy;
        mpcl->data = job;
        return NXT_OK;
    }

    return NXT_ERROR;
}

#endif


/*
 * The (void *) casts in nxt_thread_pool_post() and nxt_event_engine_post()
 * calls and to the "nxt_work_handler_t" are required by Sun C.
 */

void
nxt_job_start(nxt_task_t *task, nxt_job_t *job, nxt_work_handler_t handler)
{
    nxt_debug(task, "%s start", job->name);

    if (job->thread_pool != NULL) {
        nxt_int_t  ret;

        job->engine = task->thread->engine;

        nxt_work_set(&job->work, nxt_job_thread_trampoline,
                     job->task, job, (void *) handler);

        ret = nxt_thread_pool_post(job->thread_pool, &job->work);

        if (ret == NXT_OK) {
            return;
        }

        handler = job->abort_handler;
    }

    handler(job->task, job, job->data);
}


/* A trampoline function is called by a thread pool thread. */

static void
nxt_job_thread_trampoline(nxt_task_t *task, void *obj, void *data)
{
    nxt_job_t           *job;
    nxt_work_handler_t  handler;

    job = obj;
    handler = (nxt_work_handler_t) data;

    nxt_debug(task, "%s thread", job->name);

    if (nxt_slow_path(job->cancel)) {
        nxt_job_return(task, job, job->abort_handler);

    } else {
        handler(job->task, job, job->data);
    }
}


void
nxt_job_return(nxt_task_t *task, nxt_job_t *job, nxt_work_handler_t handler)
{
    nxt_debug(task, "%s return", job->name);

    if (job->engine != NULL) {
        /* A return function is called in thread pool thread context. */

        nxt_work_set(&job->work, nxt_job_thread_return_handler,
                     job->task, job, (void *) handler);

        nxt_event_engine_post(job->engine, &job->work);

        return;
    }

    if (nxt_slow_path(job->cancel)) {
        nxt_debug(task, "%s cancellation", job->name);
        handler = job->abort_handler;
    }

    nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                       handler, job->task, job, job->data);
}


static void
nxt_job_thread_return_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_job_t           *job;
    nxt_work_handler_t  handler;

    job = obj;
    handler = (nxt_work_handler_t) data;

    job->task->thread = task->thread;

    if (nxt_slow_path(job->cancel)) {
        nxt_debug(task, "%s cancellation", job->name);
        handler = job->abort_handler;
    }

    handler(job->task, job, job->data);
}

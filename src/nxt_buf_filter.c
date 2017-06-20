
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static nxt_int_t nxt_buf_filter_nobuf(nxt_buf_filter_t *f);
nxt_inline void nxt_buf_filter_next(nxt_buf_filter_t *f);
static void nxt_buf_filter_file_read_start(nxt_task_t *task,
    nxt_buf_filter_t *f);
static void nxt_buf_filter_file_read(nxt_task_t *task, nxt_buf_filter_t *f);
static void nxt_buf_filter_file_job_completion(nxt_task_t *task, void *obj,
    void *data);
static void nxt_buf_filter_buf_completion(nxt_task_t *task, void *obj,
    void *data);
static void nxt_buf_filter_file_read_error(nxt_task_t *task, void *obj,
    void *data);


void
nxt_buf_filter_add(nxt_task_t *task, nxt_buf_filter_t *f, nxt_buf_t *b)
{
    nxt_buf_chain_add(&f->input, b);

    nxt_buf_filter(task, f, NULL);
}


void
nxt_buf_filter(nxt_task_t *task, void *obj, void *data)
{
    nxt_int_t         ret;
    nxt_buf_t         *b;
    nxt_buf_filter_t  *f;

    f = obj;

    nxt_debug(task, "buf filter");

    if (f->done) {
        return;
    }

    f->queued = 0;

    for ( ;; ) {
        /*
         * f->input is a chain of original incoming buffers: memory,
         *     mapped, file, and sync buffers;
         * f->current is a currently processed memory buffer or a chain
         *     of memory/file or mapped/file buffers which are read of
         *     or populated from file;
         * f->output is a chain of output buffers;
         * f->last is the last output buffer in the chain.
         */

        b = f->current;

        nxt_debug(task, "buf filter current: %p", b);

        if (b == NULL) {

            if (f->reading) {
                return;
            }

            b = f->input;

            nxt_debug(task, "buf filter input: %p", b);

            if (b == NULL) {
                /*
                 * The end of the input chain, pass
                 * the output chain to the next filter.
                 */
                nxt_buf_filter_next(f);

                return;
            }

            if (nxt_buf_is_mem(b)) {

                f->current = b;
                f->input = b->next;
                b->next = NULL;

            } else if (nxt_buf_is_file(b)) {

                if (f->run->filter_ready(f) != NXT_OK) {
                    nxt_buf_filter_next(f);
                }

                nxt_buf_filter_file_read_start(task, f);
                return;
            }
        }

        if (nxt_buf_is_sync(b)) {

            ret = NXT_OK;
            f->current = b;
            f->input = b->next;
            b->next = NULL;

            if (nxt_buf_is_nobuf(b)) {
                ret = f->run->filter_sync_nobuf(f);

            } else if (nxt_buf_is_flush(b)) {
                ret = f->run->filter_sync_flush(f);

            } else if (nxt_buf_is_last(b)) {
                ret = f->run->filter_sync_last(f);

                f->done = (ret == NXT_OK);
            }

            if (nxt_fast_path(ret == NXT_OK)) {
                continue;
            }

            if (nxt_slow_path(ret == NXT_ERROR)) {
                goto fail;
            }

            /* ret == NXT_AGAIN: No filter internal buffers available. */
            goto nobuf;
        }

        ret = f->run->filter_process(f);

        if (nxt_fast_path(ret == NXT_OK)) {
            b = f->current;
            /*
             * A filter may just move f->current to f->output
             * and then set f->current to NULL.
             */
            if (b != NULL && b->mem.pos == b->mem.free) {
                f->current = b->next;
                nxt_thread_work_queue_add(task->thread, f->work_queue,
                                          b->completion_handler,
                                          task, b, b->parent);
            }

            continue;
        }

        if (nxt_slow_path(ret == NXT_ERROR)) {
            goto fail;
        }

        /* ret == NXT_AGAIN: No filter internal buffers available. */
        goto nobuf;
    }

nobuf:

    /* ret == NXT_AGAIN: No filter internal buffers available. */

    if (nxt_buf_filter_nobuf(f) == NXT_OK) {
        return;
    }

fail:

    nxt_thread_work_queue_add(task->thread, f->work_queue, f->run->filter_error,
                              task, f, f->data);
}


static nxt_int_t
nxt_buf_filter_nobuf(nxt_buf_filter_t *f)
{
    nxt_buf_t  *b;

    nxt_thread_log_debug("buf filter nobuf");

    b = nxt_buf_sync_alloc(f->mem_pool, NXT_BUF_SYNC_NOBUF);

    if (nxt_fast_path(b != NULL)) {

        nxt_buf_chain_add(&f->output, b);
        f->last = NULL;

        f->run->filter_next(f);

        f->output = NULL;

        return NXT_OK;
    }

    return NXT_ERROR;
}


nxt_inline void
nxt_buf_filter_next(nxt_buf_filter_t *f)
{
    if (f->output != NULL) {
        f->last = NULL;

        f->run->filter_next(f);
        f->output = NULL;
    }
}


void
nxt_buf_filter_enqueue(nxt_task_t *task, nxt_buf_filter_t *f)
{
    nxt_debug(task, "buf filter enqueue: %d", f->queued);

    if (!f->queued && !f->done) {
        f->queued = 1;
        nxt_thread_work_queue_add(task->thread, f->work_queue, nxt_buf_filter,
                                  task, f, NULL);
    }
}


static void
nxt_buf_filter_file_read_start(nxt_task_t *task, nxt_buf_filter_t *f)
{
    nxt_job_file_t         *jbf;
    nxt_buf_filter_file_t  *ff;

    ff = f->run->job_file_create(f);

    if (nxt_slow_path(ff == NULL)) {
        nxt_thread_work_queue_add(task->thread, f->work_queue,
                                  f->run->filter_error,
                                  task, f, f->data);
        return;
    }

    f->filter_file = ff;

    jbf = &ff->job_file;
    jbf->file = *f->input->file;

    jbf->ready_handler = nxt_buf_filter_file_job_completion;
    jbf->error_handler = nxt_buf_filter_file_read_error;

    nxt_job_set_name(&jbf->job, "buf filter job file");

    f->reading = 1;

    nxt_buf_filter_file_read(task, f);
}


static void
nxt_buf_filter_file_read(nxt_task_t *task, nxt_buf_filter_t *f)
{
    nxt_int_t              ret;
    nxt_off_t              size;
    nxt_buf_t              *b;
    nxt_buf_filter_file_t  *ff;

    ff = f->filter_file;

    if (ff->job_file.buffer != NULL) {
        /* File is now being read. */
        return;
    }

    size = f->input->file_end - f->input->file_pos;

    if (size > (nxt_off_t) NXT_SIZE_T_MAX) {
        /*
         * Small size value is a hint for buffer pool allocation
         * size, but if size of the size_t type is lesser than size
         * of the nxt_off_t type, the large size value may be truncated,
         * so use a default buffer pool allocation size.
         */
        size = 0;
    }

    if (f->mmap) {
        ret = nxt_buf_pool_mmap_alloc(&ff->buffers, (size_t) size);

    } else {
        ret = nxt_buf_pool_file_alloc(&ff->buffers, (size_t) size);
    }

    if (nxt_fast_path(ret == NXT_OK)) {
        b = ff->buffers.current;

        b->file_pos = f->input->file_pos;
        b->file_end = f->input->file_pos;
        b->file = f->input->file;

        ff->job_file.buffer = b;
        ff->job_file.offset = f->input->file_pos;

        f->run->job_file_retain(f);

        nxt_job_file_read(task, &ff->job_file.job);
        return;
    }

    if (nxt_fast_path(ret != NXT_ERROR)) {

        /* ret == NXT_AGAIN: No buffers available. */

        if (f->buffering) {
            f->buffering = 0;

            if (nxt_fast_path(f->run->filter_flush(f) != NXT_ERROR)) {
                return;
            }

        } else if (nxt_fast_path(nxt_buf_filter_nobuf(f) == NXT_OK)) {
            return;
        }
    }

    nxt_thread_work_queue_add(task->thread, f->work_queue, f->run->filter_error,
                              task, f, f->data);
}


typedef struct {
    nxt_buf_filter_t  *filter;
    nxt_buf_t         *buf;
} nxt_buf_filter_ctx_t;


static void
nxt_buf_filter_file_job_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t             *b;
    nxt_bool_t            done;
    nxt_job_file_t        *jbf;
    nxt_buf_filter_t      *f;
    nxt_buf_filter_ctx_t  *ctx;

    jbf = obj;
    f = data;
    b = jbf->buffer;
    jbf->buffer = NULL;

    nxt_debug(task, "buf filter file completion: \"%FN\" %O-%O",
              jbf->file.name, b->file_pos, b->file_end);

    f->run->job_file_release(f);

    ctx = nxt_mem_cache_alloc0(f->mem_pool, sizeof(nxt_buf_filter_ctx_t));
    if (nxt_slow_path(ctx == NULL)) {
        goto fail;
    }

    ctx->filter = f;
    ctx->buf = f->input;

    f->input->file_pos = b->file_end;

    done = (f->input->file_pos == f->input->file_end);

    if (done) {
        f->input = f->input->next;
        f->reading = 0;
    }

    b->data = f->data;
    b->completion_handler = nxt_buf_filter_buf_completion;
    b->parent = (nxt_buf_t *) ctx;
    b->next = NULL;

    nxt_buf_chain_add(&f->current, b);

    nxt_buf_filter(task, f, NULL);

    if (b->mem.pos == b->mem.free) {
        /*
         * The buffer has been completely processed by nxt_buf_filter(),
         * its completion handler has been placed in workqueue and
         * nxt_buf_filter_buf_completion() should be eventually called.
         */
        return;
    }

    if (!done) {
        /* Try to allocate another buffer and read the next file part. */
        nxt_buf_filter_file_read(task, f);
    }

    return;

fail:

    nxt_thread_work_queue_add(task->thread, f->work_queue, f->run->filter_error,
                              task, f, f->data);
}


static void
nxt_buf_filter_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t             *fb, *b;
    nxt_buf_filter_t      *f;
    nxt_buf_filter_ctx_t  *ctx;

    b = obj;
    ctx = data;
    f = ctx->filter;

    nxt_debug(task, "buf filter completion: %p \"%FN\" %O-%O",
              b, f->filter_file->job_file.file.name, b->file_pos, b->file_end);

    /* nxt_http_send_filter() might clear a buffer's file status. */
    b->is_file = 1;

    fb = ctx->buf;

    nxt_mp_free(f->mem_pool, ctx);
    nxt_buf_pool_free(&f->filter_file->buffers, b);

    if (fb->file_pos < fb->file_end) {
        nxt_buf_filter_file_read(task, f);
        return;
    }

    if (b->file_end == fb->file_end) {
        nxt_buf_pool_destroy(&f->filter_file->buffers);

        nxt_job_destroy(&f->filter_file->job_file.job);

        nxt_thread_work_queue_add(task->thread, f->work_queue,
                                  fb->completion_handler,
                                  task, fb, fb->parent);
    }

    nxt_buf_filter(task, f, NULL);
}


static void
nxt_buf_filter_file_read_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_filter_t  *f;

    f = data;

    nxt_thread_work_queue_add(task->thread, f->work_queue, f->run->filter_error,
                              task, f, f->data);
}

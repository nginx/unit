
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


typedef struct {
    nxt_job_t           job;
    nxt_buf_t           *out;
    size_t              sent;
    size_t              limit;
    nxt_work_handler_t  ready_handler;
} nxt_job_sendfile_t;


static void nxt_event_conn_job_sendfile_start(nxt_task_t *task, void *obj,
    void *data);
static void nxt_event_conn_job_sendfile_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_event_conn_job_sendfile_return(nxt_task_t *task, void *obj,
    void *data);
static nxt_buf_t *nxt_event_conn_job_sendfile_completion(nxt_task_t *task,
    nxt_conn_t *c, nxt_buf_t *b);


void
nxt_event_conn_job_sendfile(nxt_task_t *task, nxt_conn_t *c)
{
    nxt_fd_event_disable(task->thread->engine, &c->socket);

    /* A work item data is not used in nxt_event_conn_job_sendfile_start(). */
    nxt_event_conn_job_sendfile_start(task, c, NULL);
}


static void
nxt_event_conn_job_sendfile_start(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t              *c;
    nxt_iobuf_t             b;
    nxt_job_sendfile_t      *jbs;
    nxt_sendbuf_coalesce_t  sb;

    c = obj;

    nxt_debug(task, "event conn sendfile fd:%d", c->socket.fd);

    jbs = nxt_job_create(c->mem_pool, sizeof(nxt_job_sendfile_t));

    if (nxt_slow_path(jbs == NULL)) {
        c->write_state->error_handler(task, c, NULL);
        return;
    }

    c->socket.write_handler = nxt_event_conn_job_sendfile_start;
    c->socket.error_handler = c->write_state->error_handler;

    jbs->job.data = c;
    nxt_job_set_name(&jbs->job, "job sendfile");

    jbs->limit = nxt_event_conn_write_limit(c);

    if (jbs->limit != 0) {

        sb.buf = c->write;
        sb.iobuf = &b;
        sb.nmax = 1;
        sb.sync = 0;
        sb.size = 0;
        sb.limit = jbs->limit;

        if (nxt_sendbuf_mem_coalesce(c->socket.task, &sb) != 0 || !sb.sync) {

            jbs->job.thread_pool = c->u.thread_pool;
            jbs->job.log = c->socket.log;
            jbs->out = c->write;
            c->write = NULL;
            jbs->ready_handler = nxt_event_conn_job_sendfile_return;

            c->block_read = 1;
            c->block_write = 1;

            nxt_job_start(task, &jbs->job, nxt_event_conn_job_sendfile_handler);
            return;
        }
    }

    nxt_event_conn_job_sendfile_return(task, jbs, c);
}


static void
nxt_event_conn_job_sendfile_handler(nxt_task_t *task, void *obj, void *data)
{
    ssize_t             ret;
    nxt_buf_t           *b;
    nxt_bool_t          first;
    nxt_conn_t          *c;
    nxt_job_sendfile_t  *jbs;

    jbs = obj;
    c = data;

    nxt_debug(task, "event conn job sendfile fd:%d", c->socket.fd);

    first = c->socket.write_ready;
    b = jbs->out;

    do {
        ret = c->io->old_sendbuf(c, b, jbs->limit);

        if (ret == NXT_AGAIN) {
            break;
        }

        if (nxt_slow_path(ret == NXT_ERROR)) {
            goto done;
        }

        jbs->sent += ret;
        jbs->limit -= ret;

        b = nxt_sendbuf_update(b, ret);

        if (b == NULL) {
            goto done;
        }

        if (jbs->limit == 0) {

            if (c->rate == NULL) {
                jbs->limit = c->max_chunk;
                goto fast;
            }

            goto done;
        }

    } while (c->socket.write_ready);

    if (first && task->thread->thread_pool->work_queue.head != NULL) {
        goto fast;
    }

done:

    nxt_job_return(task, &jbs->job, jbs->ready_handler);
    return;

fast:

    nxt_work_set(&jbs->job.work, nxt_event_conn_job_sendfile_handler,
                 jbs->job.task, jbs, c);

    nxt_thread_pool_post(task->thread->thread_pool, &jbs->job.work);
}


static void
nxt_event_conn_job_sendfile_return(nxt_task_t *task, void *obj, void *data)
{
    size_t              sent;
    nxt_buf_t           *b;
    nxt_bool_t          done;
    nxt_conn_t          *c;
    nxt_job_sendfile_t  *jbs;

    jbs = obj;
    c = data;

    c->block_read = 0;
    c->block_write = 0;

    sent = jbs->sent;
    c->sent += sent;

    nxt_debug(task, "event conn sendfile sent:%z", sent);

    b = jbs->out;

    /* The job must be destroyed before connection error handler. */
    nxt_job_destroy(task, jbs);

    if (0 /* STUB: c->write_state->process_buffers */) {
        b = nxt_event_conn_job_sendfile_completion(task, c, b);

        done = (b == NULL);

        /* Add data which might be added after sendfile job has started. */
        nxt_buf_chain_add(&b, c->write);
        c->write = b;

        if (done) {
            /* All data has been sent. */

            if (b != NULL) {
                /* But new data has been added. */
                nxt_event_conn_job_sendfile_start(task, c, NULL);
            }

            return;
        }
    }

    if (sent != 0 && c->write_state->timer_autoreset) {
        nxt_timer_disable(task->thread->engine, &c->write_timer);
    }

    if (c->socket.error == 0
        && !nxt_event_conn_write_delayed(task->thread->engine, c, sent))
    {
        nxt_conn_timer(task->thread->engine, c, c->write_state,
                       &c->write_timer);

        nxt_fd_event_oneshot_write(task->thread->engine, &c->socket);
    }

    if (sent != 0) {
        nxt_work_queue_add(c->write_work_queue, c->write_state->ready_handler,
                           task, c, c->socket.data);
        /*
         * Fall through if first operations were
         * successful but the last one failed.
         */
    }

    if (nxt_slow_path(c->socket.error != 0)) {
        nxt_work_queue_add(c->write_work_queue, c->write_state->error_handler,
                           task, c, c->socket.data);
    }
}


static nxt_buf_t *
nxt_event_conn_job_sendfile_completion(nxt_task_t *task, nxt_conn_t *c,
    nxt_buf_t *b)
{
    while (b != NULL) {

        nxt_prefetch(b->next);

        if (nxt_buf_is_mem(b) && b->mem.pos != b->mem.free) {
            break;

        } else if (nxt_buf_is_file(b) && b->file_pos != b->file_end) {
            break;
        }

        nxt_work_queue_add(c->write_work_queue,
                           b->completion_handler, task, b, b->parent);

        b = b->next;
    }

    return b;
}

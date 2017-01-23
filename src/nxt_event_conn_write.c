
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void nxt_event_conn_average_rate_update(nxt_event_write_rate_t *rate,
    size_t sent, nxt_msec_t now);
NXT_LIB_UNIT_TEST_STATIC double
    nxt_event_conn_exponential_approximation(double n);
static void nxt_event_conn_write_timer_handler(nxt_task_t *task, void *obj,
    void *data);


void
nxt_event_conn_write(nxt_task_t *task, nxt_event_conn_t *c)
{
    if (task->thread->engine->batch != 0) {
        nxt_event_conn_write_enqueue(task->thread, task, c);

    } else {
        c->io->write(task, c, c->socket.data);
    }
}


void
nxt_event_conn_io_write(nxt_task_t *task, void *obj, void *data)
{
    size_t              sent, limit;
    ssize_t             ret;
    nxt_buf_t           *b;
    nxt_event_conn_t    *c;
    nxt_event_engine_t  *engine;

    c = obj;

    nxt_debug(task, "event conn write fd:%d", c->socket.fd);

    if (!c->socket.write_ready || c->delayed || c->write == NULL) {
        return;
    }

    engine = task->thread->engine;

    c->socket.write_handler = nxt_event_conn_io_write;
    c->socket.error_handler = c->write_state->error_handler;

    ret = NXT_DECLINED;
    sent = 0;
    b = c->write;

    limit = nxt_event_conn_write_limit(c);

    while (limit != 0) {

        ret = c->io->write_chunk(c, b, limit);

        if (ret < 0) {
            /* ret == NXT_AGAIN || ret == NXT_ERROR. */
            break;
        }

        sent += ret;
        limit -= ret;

        if (c->write_state->process_buffers) {
            b = nxt_sendbuf_completion(task, c->write_work_queue, b, ret);
            c->write = b;

        } else {
            b = nxt_sendbuf_update(b, ret);
        }

        if (b == NULL) {
            nxt_event_fd_block_write(engine, &c->socket);
            break;
        }

        if (!c->socket.write_ready) {
            ret = NXT_AGAIN;
            break;
        }
    }

    nxt_debug(task, "event conn: %i sent:%z", ret, sent);

    if (sent != 0) {
        if (c->write_state->autoreset_timer) {
            nxt_event_timer_disable(&c->write_timer);
        }
    }

    if (ret != NXT_ERROR
        && !nxt_event_conn_write_delayed(engine, c, sent))
    {
        if (limit == 0) {
            /*
             * Postpone writing until next event poll to allow to
             * process other recevied events and to get new events.
             */
            c->write_timer.handler = nxt_event_conn_write_timer_handler;
            nxt_event_timer_add(engine, &c->write_timer, 0);

        } else if (ret == NXT_AGAIN) {
            /*
             * SSL libraries can require to toggle either write or read
             * event if renegotiation occurs during SSL write operation.
             * This case is handled on the event_io->send() level.  Timer
             * can be set here because it should be set only for write
             * direction.
             */
            nxt_event_conn_timer(engine, c, c->write_state, &c->write_timer);
        }
    }

    if (ret == 0 || sent != 0) {
        /* "ret == 0" means a sync buffer was processed. */
        c->sent += sent;
        nxt_event_conn_io_handle(task->thread, c->write_work_queue,
                                 c->write_state->ready_handler, task, c, data);
        /*
         * Fall through if first operations were
         * successful but the last one failed.
         */
    }

    if (nxt_slow_path(ret == NXT_ERROR)) {
        nxt_event_fd_block_write(engine, &c->socket);

        nxt_event_conn_io_handle(task->thread, c->write_work_queue,
                                 c->write_state->error_handler, task, c, data);
    }
}


size_t
nxt_event_conn_write_limit(nxt_event_conn_t *c)
{
    ssize_t                 limit, correction;
    nxt_event_write_rate_t  *rate;

    rate = c->rate;

    if (rate == NULL) {
        return c->max_chunk;
    }

    limit = rate->limit;
    correction = limit - (size_t) rate->average;

    nxt_log_debug(c->socket.log, "event conn correction:%z average:%0.3f",
                  correction, rate->average);

    limit += correction;

    if (limit <= 0) {
        return 0;
    }

    if (rate->limit_after != 0) {
        limit += rate->limit_after;
        limit = nxt_min((size_t) limit, rate->max_limit);
    }

    return nxt_min((size_t) limit, c->max_chunk);
}


nxt_bool_t
nxt_event_conn_write_delayed(nxt_event_engine_t *engine, nxt_event_conn_t *c,
    size_t sent)
{
    nxt_msec_t              timer;
    nxt_event_write_rate_t  *rate;

    rate = c->rate;

    if (rate != NULL) {
        nxt_event_conn_average_rate_update(rate, sent, engine->timers.now);

        if (rate->limit_after == 0) {
            timer = sent * 1000 / rate->limit;

        } else if (rate->limit_after >= sent) {
            timer = sent * 1000 / rate->max_limit;
            rate->limit_after -= sent;

        } else {
            sent -= rate->limit_after;
            timer = rate->limit_after * 1000 / rate->max_limit
                    + sent * 1000 / rate->limit;
            rate->limit_after = 0;
        }

        nxt_log_debug(c->socket.log, "event conn timer: %M", timer);

        if (timer != 0) {
            c->delayed = 1;

            nxt_event_fd_block_write(engine, &c->socket);

            c->write_timer.handler = nxt_event_conn_write_timer_handler;
            nxt_event_timer_add(engine, &c->write_timer, timer);

            return 1;
        }
    }

    return 0;
}


/* Exponentially weighted moving average rate for a given interval. */

static void
nxt_event_conn_average_rate_update(nxt_event_write_rate_t *rate, size_t sent,
    nxt_msec_t now)
{
    double            weight, delta;
    nxt_msec_t        elapsed;
    const nxt_uint_t  interval = 10;  /* 10s */

    elapsed = now - rate->last;

    if (elapsed == 0) {
        return;
    }

    rate->last = now;
    delta = (double) elapsed / 1000;

    weight = nxt_event_conn_exponential_approximation(-delta / interval);

    rate->average = (1 - weight) * sent / delta + weight * rate->average;

    nxt_thread_log_debug("event conn delta:%0.3f, weight:%0.3f, average:%0.3f",
                         delta, weight, rate->average);
}


/*
 * exp() takes tens or hundreds nanoseconds on modern CPU.
 * This is a faster exp() approximation based on IEEE-754 format
 * layout and described in "A Fast, Compact Approximation of
 * the Exponential Function" * by N. N. Schraudolph, 1999.
 */

NXT_LIB_UNIT_TEST_STATIC double
nxt_event_conn_exponential_approximation(double x)
{
    union {
        double   d;
        int64_t  n;
    } exp;

    if (x < -100) {
        /*
         * The approximation is correct in -700 to 700 range.
         * The "x" argument is always negative.
         */
        return 0;
    }

    /*
     * x * 2^52 / ln(2) + (1023 * 2^52 - 261140389990637.73
     *
     * 52 is the number of mantissa bits;
     * 1023 is the exponent bias;
     * 261140389990637.73 is the adjustment parameter to
     * improve the approximation.  The parameter is equal to
     *
     *     2^52 * ln[ 3 / (8 * ln(2)) + 0.5 ] / ln(2)
     *
     * Only significant digits of the double float format
     * are used to present the double float constants.
     */
    exp.n = x * 4503599627370496.0 / 0.69314718055994530
            + (4607182418800017408.0 - 261140389990637.73);

    return exp.d;
}


static void
nxt_event_conn_write_timer_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_conn_t   *c;
    nxt_event_timer_t  *ev;

    ev = obj;

    nxt_debug(task, "event conn conn timer");

    c = nxt_event_write_timer_conn(ev);
    c->delayed = 0;

    c->io->write(task, c, c->socket.data);
}


ssize_t
nxt_event_conn_io_write_chunk(nxt_event_conn_t *c, nxt_buf_t *b, size_t limit)
{
    ssize_t  ret;

    ret = c->io->sendbuf(c, b, limit);

    if ((ret == NXT_AGAIN || !c->socket.write_ready)
        && nxt_event_fd_is_disabled(c->socket.write))
    {
        nxt_event_fd_enable_write(c->socket.task->thread->engine, &c->socket);
    }

    return ret;
}


ssize_t
nxt_event_conn_io_sendbuf(nxt_event_conn_t *c, nxt_buf_t *b, size_t limit)
{
    nxt_uint_t              niob;
    struct iovec            iob[NXT_IOBUF_MAX];
    nxt_sendbuf_coalesce_t  sb;

    sb.buf = b;
    sb.iobuf = iob;
    sb.nmax = NXT_IOBUF_MAX;
    sb.sync = 0;
    sb.size = 0;
    sb.limit = limit;

    niob = nxt_sendbuf_mem_coalesce(c->socket.task, &sb);

    if (niob == 0 && sb.sync) {
        return 0;
    }

    return nxt_event_conn_io_writev(c, iob, niob);
}


ssize_t
nxt_event_conn_io_writev(nxt_event_conn_t *c, nxt_iobuf_t *iob, nxt_uint_t niob)
{
    ssize_t    n;
    nxt_err_t  err;

    if (niob == 1) {
        /* Disposal of surplus kernel iovec copy-in operation. */
        return nxt_event_conn_io_send(c, iob->iov_base, iob->iov_len);
    }

    for ( ;; ) {
        n = writev(c->socket.fd, iob, niob);

        err = (n == -1) ? nxt_socket_errno : 0;

        nxt_log_debug(c->socket.log, "writev(%d, %ui): %d",
                      c->socket.fd, niob, n);

        if (n > 0) {
            return n;
        }

        /* n == -1 */

        switch (err) {

        case NXT_EAGAIN:
            nxt_log_debug(c->socket.log, "writev() %E", err);
            c->socket.write_ready = 0;
            return NXT_AGAIN;

        case NXT_EINTR:
            nxt_log_debug(c->socket.log, "writev() %E", err);
            continue;

        default:
            c->socket.error = err;
            nxt_log_error(nxt_socket_error_level(err, c->socket.log_error),
                          c->socket.log, "writev(%d, %ui) failed %E",
                          c->socket.fd, niob, err);
            return NXT_ERROR;
        }
    }
}


ssize_t
nxt_event_conn_io_send(nxt_event_conn_t *c, void *buf, size_t size)
{
    ssize_t    n;
    nxt_err_t  err;

    for ( ;; ) {
        n = send(c->socket.fd, buf, size, 0);

        err = (n == -1) ? nxt_socket_errno : 0;

        nxt_debug(c->socket.task, "send(%d, %p, %uz): %z",
                  c->socket.fd, buf, size, n);

        if (n > 0) {
            return n;
        }

        /* n == -1 */

        switch (err) {

        case NXT_EAGAIN:
            nxt_debug(c->socket.task, "send() %E", err);
            c->socket.write_ready = 0;
            return NXT_AGAIN;

        case NXT_EINTR:
            nxt_debug(c->socket.task, "send() %E", err);
            continue;

        default:
            c->socket.error = err;
            nxt_log(c->socket.task,
                    nxt_socket_error_level(err, c->socket.log_error),
                    "send(%d, %p, %uz) failed %E",
                    c->socket.fd, buf, size, err);
            return NXT_ERROR;
        }
    }
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


#define NXT_FASTCGI_DATA_MIDDLE         0
#define NXT_FASTCGI_DATA_END_ON_BORDER  1
#define NXT_FASTCGI_DATA_END            2


static nxt_int_t nxt_fastcgi_buffer(nxt_fastcgi_parse_t *fp, nxt_buf_t ***tail,
    nxt_buf_t *in);


void
nxt_fastcgi_record_parse(nxt_task_t *task, nxt_fastcgi_parse_t *fp,
    nxt_buf_t *in)
{
    u_char        ch;
    nxt_int_t     ret, stream;
    nxt_buf_t     *b, *nb, **tail[2];
    const char    *msg;
    enum {
        sw_fastcgi_version = 0,
        sw_fastcgi_type,
        sw_fastcgi_request_id_high,
        sw_fastcgi_request_id_low,
        sw_fastcgi_content_length_high,
        sw_fastcgi_content_length_low,
        sw_fastcgi_padding_length,
        sw_fastcgi_reserved,
        sw_fastcgi_data,
        sw_fastcgi_padding,
        sw_fastcgi_end_request,
    } state;

    fp->out[0] = NULL;
    fp->out[1] = NULL;

    tail[0] = &fp->out[0];
    tail[1] = &fp->out[1];

    state = fp->state;

    for (b = in; b != NULL; b = b->next) {

        if (nxt_buf_is_sync(b)) {
            **tail = b;
            *tail = &b->next;
            continue;
        }

        fp->pos = b->mem.pos;

        while (fp->pos < b->mem.free) {
            /*
             * The sw_fastcgi_data state is tested outside the
             * switch to preserve fp->pos and to not touch memory.
             */
            if (state == sw_fastcgi_data) {

                /*
                 * fp->type here can be only NXT_FASTCGI_STDOUT
                 * or NXT_FASTCGI_STDERR.  NXT_FASTCGI_END_REQUEST
                 * is tested in sw_fastcgi_reserved.
                 */
                stream = fp->type - NXT_FASTCGI_STDOUT;

                ret = nxt_fastcgi_buffer(fp, &tail[stream], b);

                if (ret == NXT_FASTCGI_DATA_MIDDLE) {
                    goto next;
                }

                if (nxt_slow_path(ret == NXT_ERROR)) {
                    fp->error = 1;
                    goto done;
                }

                if (fp->padding == 0) {
                    state = sw_fastcgi_version;

                } else {
                    state = sw_fastcgi_padding;
                }

                if (ret == NXT_FASTCGI_DATA_END_ON_BORDER) {
                    goto next;
                }

                /* ret == NXT_FASTCGI_DATA_END */
            }

            ch = *fp->pos++;

            nxt_thread_log_debug("fastcgi record byte: %02Xd", ch);

            switch (state) {

            case sw_fastcgi_version:
                if (nxt_fast_path(ch == 1)) {
                    state = sw_fastcgi_type;
                    continue;
                }

                msg = "unsupported FastCGI protocol version";
                goto fastcgi_error;

            case sw_fastcgi_type:
                switch (ch) {
                case NXT_FASTCGI_STDOUT:
                case NXT_FASTCGI_STDERR:
                case NXT_FASTCGI_END_REQUEST:
                    fp->type = ch;
                    state = sw_fastcgi_request_id_high;
                    continue;
                default:
                    msg = "invalid FastCGI record type";
                    goto fastcgi_error;
                }

            case sw_fastcgi_request_id_high:
                /* FastCGI multiplexing is not supported. */
                if (nxt_fast_path(ch == 0)) {
                    state = sw_fastcgi_request_id_low;
                    continue;
                }

                msg = "unexpected FastCGI request ID high byte";
                goto fastcgi_error;

            case sw_fastcgi_request_id_low:
                if (nxt_fast_path(ch == 1)) {
                    state = sw_fastcgi_content_length_high;
                    continue;
                }

                msg = "unexpected FastCGI request ID low byte";
                goto fastcgi_error;

            case sw_fastcgi_content_length_high:
                fp->length = ch << 8;
                state = sw_fastcgi_content_length_low;
                continue;

            case sw_fastcgi_content_length_low:
                fp->length |= ch;
                state = sw_fastcgi_padding_length;
                continue;

            case sw_fastcgi_padding_length:
                fp->padding = ch;
                state = sw_fastcgi_reserved;
                continue;

            case sw_fastcgi_reserved:
                nxt_thread_log_debug("fastcgi record type:%d "
                                     "length:%uz padding:%d",
                                     fp->type, fp->length, fp->padding);

                if (nxt_fast_path(fp->type != NXT_FASTCGI_END_REQUEST)) {
                    state = sw_fastcgi_data;
                    continue;
                }

                state = sw_fastcgi_end_request;
                continue;

            case sw_fastcgi_data:
                /*
                 * This state is processed before the switch.
                 * It added here just to suppress a warning.
                 */
                continue;

            case sw_fastcgi_padding:
                /*
                 * No special fast processing of padding
                 * because it usually takes just 1-7 bytes.
                 */
                fp->padding--;

                if (fp->padding == 0) {
                    nxt_thread_log_debug("fastcgi record end");
                    state = sw_fastcgi_version;
                }
                continue;

            case sw_fastcgi_end_request:
                /* Just skip 8 bytes of END_REQUEST. */
                fp->length--;

                if (fp->length != 0) {
                    continue;
                }

                fp->done = 1;

                nxt_thread_log_debug("fastcgi end request");

                goto done;
            }
        }

        if (b->retain == 0) {
            /* No record data was found in a buffer. */
            nxt_thread_current_work_queue_add(task->thread,
                                              b->completion_handler,
                                              task, b, b->parent);
        }

    next:

        continue;
    }

    fp->state = state;

    return;

fastcgi_error:

    nxt_thread_log_error(NXT_LOG_ERR, "upstream sent %s: %d", msg, ch);

    fp->fastcgi_error = 1;

done:

    nb = fp->last_buf(fp);

    if (nxt_fast_path(nb != NULL)) {
        *tail[0] = nb;

    } else {
        fp->error = 1;
    }

    // STUB: fp->fastcgi_error = 1;
    // STUB: fp->error = 1;

    return;
}


static nxt_int_t
nxt_fastcgi_buffer(nxt_fastcgi_parse_t *fp, nxt_buf_t ***tail, nxt_buf_t *in)
{
    u_char     *p;
    size_t     size;
    nxt_buf_t  *b;

    if (fp->length == 0) {
        return NXT_FASTCGI_DATA_END;
    }

    p = fp->pos;
    size = in->mem.free - p;

    if (fp->length >= size && in->retain == 0) {
        /*
         * Use original buffer if the buffer is lesser than or equal to
         * FastCGI record size and this is the first record in the buffer.
         */
        in->mem.pos = p;
        **tail = in;
        *tail = &in->next;

    } else {
        b = nxt_buf_mem_alloc(fp->mem_pool, 0, 0);
        if (nxt_slow_path(b == NULL)) {
            return NXT_ERROR;
        }

        **tail = b;
        *tail = &b->next;

        b->parent = in;
        in->retain++;
        b->mem.pos = p;
        b->mem.start = p;

        if (fp->length < size) {
            p += fp->length;
            fp->pos = p;

            b->mem.free = p;
            b->mem.end = p;

            return NXT_FASTCGI_DATA_END;
        }

        b->mem.free = in->mem.free;
        b->mem.end = in->mem.free;
    }

    fp->length -= size;

    if (fp->length == 0) {
        return NXT_FASTCGI_DATA_END_ON_BORDER;
    }

    return NXT_FASTCGI_DATA_MIDDLE;
}

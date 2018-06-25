
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


#define NXT_HTTP_CHUNK_MIDDLE         0
#define NXT_HTTP_CHUNK_END_ON_BORDER  1
#define NXT_HTTP_CHUNK_END            2


#define                                                                       \
nxt_size_is_sufficient(cs)                                                    \
    (cs < ((__typeof__(cs)) 1 << (sizeof(cs) * 8 - 4)))


static nxt_int_t nxt_http_chunk_buffer(nxt_http_chunk_parse_t *hcp,
    nxt_buf_t ***tail, nxt_buf_t *in);


nxt_buf_t *
nxt_http_chunk_parse(nxt_task_t *task, nxt_http_chunk_parse_t *hcp,
    nxt_buf_t *in)
{
    u_char        c, ch;
    nxt_int_t     ret;
    nxt_buf_t     *b, *out, *nb, **tail;
    enum {
        sw_start = 0,
        sw_chunk_size,
        sw_chunk_size_linefeed,
        sw_chunk_end_newline,
        sw_chunk_end_linefeed,
        sw_chunk,
    } state;

    out = NULL;
    tail = &out;

    state = hcp->state;

    for (b = in; b != NULL; b = b->next) {

        hcp->pos = b->mem.pos;

        while (hcp->pos < b->mem.free) {
            /*
             * The sw_chunk state is tested outside the switch
             * to preserve hcp->pos and to not touch memory.
             */
            if (state == sw_chunk) {
                ret = nxt_http_chunk_buffer(hcp, &tail, b);

                if (ret == NXT_HTTP_CHUNK_MIDDLE) {
                    goto next;
                }

                if (nxt_slow_path(ret == NXT_ERROR)) {
                    hcp->error = 1;
                    goto done;
                }

                state = sw_chunk_end_newline;

                if (ret == NXT_HTTP_CHUNK_END_ON_BORDER) {
                    goto next;
                }

                /* ret == NXT_HTTP_CHUNK_END_ON_BORDER */
            }

            ch = *hcp->pos++;

            switch (state) {

            case sw_start:
                state = sw_chunk_size;

                c = ch - '0';

                if (c <= 9) {
                    hcp->chunk_size = c;
                    continue;
                }

                c = (ch | 0x20) - 'a';

                if (c <= 5) {
                    hcp->chunk_size = 0x0A + c;
                    continue;
                }

                goto chunk_error;

            case sw_chunk_size:

                c = ch - '0';

                if (c > 9) {
                    c = (ch | 0x20) - 'a';

                    if (nxt_fast_path(c <= 5)) {
                        c += 0x0A;

                    } else if (nxt_fast_path(ch == '\r')) {
                        state = sw_chunk_size_linefeed;
                        continue;

                    } else {
                        goto chunk_error;
                    }
                }

                if (nxt_fast_path(nxt_size_is_sufficient(hcp->chunk_size))) {
                    hcp->chunk_size = (hcp->chunk_size << 4) + c;
                    continue;
                }

                goto chunk_error;

            case sw_chunk_size_linefeed:
                if (nxt_fast_path(ch == '\n')) {

                    if (hcp->chunk_size != 0) {
                        state = sw_chunk;
                        continue;
                    }

                    hcp->last = 1;
                    state = sw_chunk_end_newline;
                    continue;
                }

                goto chunk_error;

            case sw_chunk_end_newline:
                if (nxt_fast_path(ch == '\r')) {
                    state = sw_chunk_end_linefeed;
                    continue;
                }

                goto chunk_error;

            case sw_chunk_end_linefeed:
                if (nxt_fast_path(ch == '\n')) {

                    if (!hcp->last) {
                        state = sw_start;
                        continue;
                    }

                    goto done;
                }

                goto chunk_error;

            case sw_chunk:
                /*
                 * This state is processed before the switch.
                 * It added here just to suppress a warning.
                 */
                continue;
            }
        }

        if (b->retain == 0) {
            /* No chunk data was found in a buffer. */
            nxt_thread_current_work_queue_add(task->thread,
                                              b->completion_handler,
                                              task, b, b->parent);

        }

    next:

        continue;
    }

    hcp->state = state;

    return out;

chunk_error:

    hcp->chunk_error = 1;

done:

    nb = nxt_buf_sync_alloc(hcp->mem_pool, NXT_BUF_SYNC_LAST);

    if (nxt_fast_path(nb != NULL)) {
        *tail = nb;

    } else {
        hcp->error = 1;
    }

    // STUB: hcp->chunk_error = 1;
    // STUB: hcp->error = 1;

    return out;
}


static nxt_int_t
nxt_http_chunk_buffer(nxt_http_chunk_parse_t *hcp, nxt_buf_t ***tail,
    nxt_buf_t *in)
{
    u_char     *p;
    size_t     size;
    nxt_buf_t  *b;

    p = hcp->pos;
    size = in->mem.free - p;

    if (hcp->chunk_size >= size && in->retain == 0) {
        /*
         * Use original buffer if the buffer is lesser than or equal
         * to a chunk size and this is the first chunk in the buffer.
         */
        in->mem.pos = p;
        **tail = in;
        *tail = &in->next;

    } else {
        b = nxt_buf_mem_alloc(hcp->mem_pool, 0, 0);
        if (nxt_slow_path(b == NULL)) {
            return NXT_ERROR;
        }

        **tail = b;
        *tail = &b->next;

        b->parent = in;
        in->retain++;
        b->mem.pos = p;
        b->mem.start = p;

        if (hcp->chunk_size < size) {
            p += hcp->chunk_size;
            hcp->pos = p;

            b->mem.free = p;
            b->mem.end = p;

            return NXT_HTTP_CHUNK_END;
        }

        b->mem.free = in->mem.free;
        b->mem.end = in->mem.free;
    }

    hcp->chunk_size -= size;

    if (hcp->chunk_size == 0) {
        return NXT_HTTP_CHUNK_END_ON_BORDER;
    }

    return NXT_HTTP_CHUNK_MIDDLE;
}

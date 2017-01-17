
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


nxt_uint_t
nxt_recvbuf_mem_coalesce(nxt_recvbuf_coalesce_t *rb)
{
    u_char     *last;
    size_t     size, total;
    nxt_int_t  n;
    nxt_buf_t  *b;

    total = 0;
    last = NULL;
    n = -1;

    for (b = rb->buf; b != NULL; b = b->next) {

        nxt_prefetch(b->next);

        size = b->mem.end - b->mem.free;

        if (b->mem.free != last) {

            if (++n >= rb->nmax) {
                goto done;
            }

            nxt_iobuf_set(&rb->iobuf[n], b->mem.free, size);

        } else {
            nxt_iobuf_add(&rb->iobuf[n], size);
        }

        nxt_thread_log_debug("recvbuf: %ui, %p, %uz", n,
                             nxt_iobuf_data(&rb->iobuf[n]),
                             nxt_iobuf_size(&rb->iobuf[n]));

        total += size;
        last = b->mem.end;
    }

    n++;

done:

    rb->size = total;

    return n;
}


void
nxt_recvbuf_update(nxt_buf_t *b, size_t sent)
{
    size_t  size;

    while (b != NULL && sent != 0) {

        nxt_prefetch(b->next);

        if (!nxt_buf_is_sync(b)) {

            size = b->mem.end - b->mem.free;

            if (sent < size) {
                b->mem.free += sent;
                return;
            }

            b->mem.free = b->mem.end;
            sent -= size;
        }

        b = b->next;
    }
}

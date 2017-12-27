
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#include "nxt_go_run_ctx.h"
#include "nxt_go_log.h"
#include "nxt_go_process.h"
#include "nxt_go_array.h"
#include "nxt_go_mutex.h"
#include "nxt_go_port_memory.h"

#include "_cgo_export.h"

#include <nxt_port_memory_int.h>
#include <nxt_main.h>


static nxt_int_t
nxt_go_ctx_msg_rbuf(nxt_go_run_ctx_t *ctx, nxt_go_msg_t *msg, nxt_buf_t *buf,
    uint32_t n)
{
    size_t               nchunks;
    nxt_go_port_mmap_t   *port_mmap;
    nxt_port_mmap_msg_t  *mmap_msg;

    if (nxt_slow_path(msg->mmap_msg == NULL)) {
        if (n > 0) {
            nxt_go_warn("failed to get plain buf #%d", (int) n);

            return NXT_ERROR;
        }

        buf->mem.start = (u_char *) (msg->port_msg + 1);
        buf->mem.pos = buf->mem.start;
        buf->mem.end = buf->mem.start + msg->raw_size;
        buf->mem.free = buf->mem.end;

        return NXT_OK;
    }

    mmap_msg = msg->mmap_msg + n;
    if (nxt_slow_path(mmap_msg >= msg->end)) {
        nxt_go_warn("no more data in shm #%d", (int) n);

        return NXT_ERROR;
    }

    if (nxt_slow_path(mmap_msg->mmap_id >= ctx->process->incoming.nelts)) {
        nxt_go_warn("incoming shared memory segment #%d not found "
                    "for process %d", (int) mmap_msg->mmap_id,
                    (int) msg->port_msg->pid);

        return NXT_ERROR;
    }

    nxt_go_mutex_lock(&ctx->process->incoming_mutex);

    port_mmap = nxt_go_array_at(&ctx->process->incoming, mmap_msg->mmap_id);
    buf->mem.start = nxt_port_mmap_chunk_start(port_mmap->hdr,
                                               mmap_msg->chunk_id);
    buf->mem.pos = buf->mem.start;
    buf->mem.free = buf->mem.start + mmap_msg->size;

    nxt_go_mutex_unlock(&ctx->process->incoming_mutex);

    nchunks = mmap_msg->size / PORT_MMAP_CHUNK_SIZE;
    if ((mmap_msg->size % PORT_MMAP_CHUNK_SIZE) != 0) {
        nchunks++;
    }

    buf->mem.end = buf->mem.start + nchunks * PORT_MMAP_CHUNK_SIZE;

    return NXT_OK;
}

static nxt_int_t
nxt_go_ctx_init_rbuf(nxt_go_run_ctx_t *ctx)
{
    return nxt_go_ctx_msg_rbuf(ctx, &ctx->msg, &ctx->rbuf, ctx->nrbuf);
}

static void
nxt_go_ctx_init_msg(nxt_go_msg_t *msg, nxt_port_msg_t *port_msg,
    size_t payload_size)
{
    void                 *data, *end;
    nxt_port_mmap_msg_t  *mmap_msg;

    memset(msg, 0, sizeof(nxt_go_msg_t));

    msg->port_msg = port_msg;
    msg->raw_size = payload_size;

    data = port_msg + 1;
    end = nxt_pointer_to(data, payload_size);

    if (port_msg->tracking) {
        msg->tracking = data;
        data = msg->tracking + 1;
    }

    if (nxt_fast_path(port_msg->mmap != 0)) {
        msg->mmap_msg = data;
        msg->end = end;

        mmap_msg = msg->mmap_msg;
        while(mmap_msg < msg->end) {
            msg->data_size += mmap_msg->size;
            mmap_msg += 1;
        }

    } else {
        msg->mmap_msg = NULL;
        msg->end = NULL;
        msg->data_size = payload_size;
    }
}

void
nxt_go_ctx_release_msg(nxt_go_run_ctx_t *ctx, nxt_go_msg_t *msg)
{
    u_char               *b, *e;
    nxt_chunk_id_t       c;
    nxt_go_port_mmap_t   *port_mmap;
    nxt_port_mmap_msg_t  *mmap_msg, *end;

    if (nxt_slow_path(msg->mmap_msg == NULL)) {
        return;
    }

    mmap_msg = msg->mmap_msg;
    end = msg->end;

    nxt_go_mutex_lock(&ctx->process->incoming_mutex);

    for (; mmap_msg < end; mmap_msg++ ) {
        port_mmap = nxt_go_array_at(&ctx->process->incoming, mmap_msg->mmap_id);

        c = mmap_msg->chunk_id;
        b = nxt_port_mmap_chunk_start(port_mmap->hdr, c);
        e = b + mmap_msg->size;

        while (b < e) {
            nxt_port_mmap_set_chunk_free(port_mmap->hdr->free_map, c);

            b += PORT_MMAP_CHUNK_SIZE;
            c++;
        }
    }

    nxt_go_mutex_unlock(&ctx->process->incoming_mutex);
}


nxt_int_t
nxt_go_ctx_init(nxt_go_run_ctx_t *ctx, nxt_port_msg_t *port_msg,
    size_t payload_size)
{
    nxt_atomic_t                  *val;
    nxt_go_port_mmap_t            *port_mmap;
    nxt_port_mmap_tracking_msg_t  *tracking;

    memset(ctx, 0, sizeof(nxt_go_run_ctx_t));

    ctx->process = nxt_go_get_process(port_msg->pid);
    if (nxt_slow_path(ctx->process == NULL)) {
        nxt_go_warn("failed to get process %d", port_msg->pid);

        return NXT_ERROR;
    }

    nxt_go_ctx_init_msg(&ctx->msg, port_msg, payload_size);

    if (ctx->msg.tracking != NULL) {
        tracking = ctx->msg.tracking;

        if (nxt_slow_path(tracking->mmap_id >= ctx->process->incoming.nelts)) {
            nxt_go_warn("incoming shared memory segment #%d not found "
                        "for process %d", (int) tracking->mmap_id,
                        (int) port_msg->pid);

            return NXT_ERROR;
        }

        nxt_go_mutex_lock(&ctx->process->incoming_mutex);

        port_mmap = nxt_go_array_at(&ctx->process->incoming, tracking->mmap_id);

        nxt_go_mutex_unlock(&ctx->process->incoming_mutex);

        val = port_mmap->hdr->tracking + tracking->tracking_id;

        ctx->cancelled = nxt_atomic_cmp_set(val, port_msg->stream, 0) == 0;

        if (ctx->cancelled) {
            nxt_port_mmap_set_chunk_free(port_mmap->hdr->free_tracking_map,
                                         tracking->tracking_id);

            return NXT_OK;
        }
    }

    ctx->msg_last = &ctx->msg;

    ctx->wport_msg.stream = port_msg->stream;
    ctx->wport_msg.pid = getpid();
    ctx->wport_msg.type = _NXT_PORT_MSG_DATA;
    ctx->wport_msg.mmap = 1;

    ctx->wmmap_msg = (nxt_port_mmap_msg_t *) ( &ctx->wport_msg + 1 );

    return nxt_go_ctx_init_rbuf(ctx);
}


nxt_int_t
nxt_go_ctx_flush(nxt_go_run_ctx_t *ctx, int last)
{
    int       i;
    nxt_int_t rc;

    if (last != 0) {
        ctx->wport_msg.last = 1;
    }

    nxt_go_debug("flush buffers (%d)", last);

    for (i = 0; i < ctx->nwbuf; i++) {
        nxt_port_mmap_msg_t *m = ctx->wmmap_msg + i;

        nxt_go_debug("  mmap_msg[%d]={%d, %d, %d}", i,
                     m->mmap_id, m->chunk_id, m->size);
    }

    rc = nxt_go_port_send(ctx->msg.port_msg->pid, ctx->msg.port_msg->reply_port,
                          &ctx->wport_msg, sizeof(nxt_port_msg_t) +
                          ctx->nwbuf * sizeof(nxt_port_mmap_msg_t), NULL, 0);

    nxt_go_debug("  port send res = %d", rc);

    ctx->nwbuf = 0;

    memset(&ctx->wbuf, 0, sizeof(ctx->wbuf));

    return rc;
}


nxt_buf_t *
nxt_go_port_mmap_get_buf(nxt_go_run_ctx_t *ctx, size_t size)
{
    size_t                  nchunks;
    nxt_buf_t               *buf;
    nxt_chunk_id_t          c;
    nxt_go_port_mmap_t      *port_mmap;
    nxt_port_mmap_msg_t     *mmap_msg;
    nxt_port_mmap_header_t  *hdr;

    c = 0;

    buf = &ctx->wbuf;

    hdr = nxt_go_port_mmap_get(ctx->process, ctx->msg.port_msg->reply_port, &c,
                               0);
    if (nxt_slow_path(hdr == NULL)) {
        nxt_go_warn("failed to get port_mmap");

        return NULL;
    }

    buf->mem.start = nxt_port_mmap_chunk_start(hdr, c);
    buf->mem.pos = buf->mem.start;
    buf->mem.free = buf->mem.start;
    buf->mem.end = buf->mem.start + PORT_MMAP_CHUNK_SIZE;

    buf->parent = hdr;

    mmap_msg = ctx->wmmap_msg + ctx->nwbuf;
    mmap_msg->mmap_id = hdr->id;
    mmap_msg->chunk_id = c;
    mmap_msg->size = 0;

    nchunks = size / PORT_MMAP_CHUNK_SIZE;
    if ((size % PORT_MMAP_CHUNK_SIZE) != 0 || nchunks == 0) {
        nchunks++;
    }

    c++;
    nchunks--;

    /* Try to acquire as much chunks as required. */
    while (nchunks > 0) {

        if (nxt_port_mmap_chk_set_chunk_busy(hdr->free_map, c) == 0) {
            break;
        }

        buf->mem.end += PORT_MMAP_CHUNK_SIZE;
        c++;
        nchunks--;
    }

    ctx->nwbuf++;

    return buf;
}


nxt_int_t
nxt_go_port_mmap_increase_buf(nxt_buf_t *b, size_t size, size_t min_size)
{
    size_t                  nchunks, free_size;
    nxt_chunk_id_t          c, start;
    nxt_port_mmap_header_t  *hdr;

    free_size = nxt_buf_mem_free_size(&b->mem);

    if (nxt_slow_path(size <= free_size)) {
        return NXT_OK;
    }

    hdr = b->parent;

    start = nxt_port_mmap_chunk_id(hdr, b->mem.end);

    size -= free_size;

    nchunks = size / PORT_MMAP_CHUNK_SIZE;
    if ((size % PORT_MMAP_CHUNK_SIZE) != 0 || nchunks == 0) {
        nchunks++;
    }

    c = start;

    /* Try to acquire as much chunks as required. */
    while (nchunks > 0) {

        if (nxt_port_mmap_chk_set_chunk_busy(hdr->free_map, c) == 0) {
            break;
        }

        c++;
        nchunks--;
    }

    if (nchunks != 0
        && min_size > free_size + PORT_MMAP_CHUNK_SIZE * (c - start))
    {
        c--;
        while (c >= start) {
            nxt_port_mmap_set_chunk_free(hdr->free_map, c);
            c--;
        }

        return NXT_ERROR;

    } else {
        b->mem.end += PORT_MMAP_CHUNK_SIZE * (c - start);

        return NXT_OK;
    }
}


nxt_int_t
nxt_go_ctx_write(nxt_go_run_ctx_t *ctx, void *data, size_t len)
{
    size_t                  free_size, copy_size;
    nxt_buf_t               *buf;
    nxt_port_mmap_msg_t     *mmap_msg;

    buf = &ctx->wbuf;

    while (len > 0) {
        if (ctx->nwbuf == 0) {
            buf = nxt_go_port_mmap_get_buf(ctx, len);

            if (nxt_slow_path(buf == NULL)) {
                return NXT_ERROR;
            }
        }

        do {
            free_size = nxt_buf_mem_free_size(&buf->mem);

            if (free_size > 0) {
                copy_size = nxt_min(free_size, len);

                buf->mem.free = nxt_cpymem(buf->mem.free, data, copy_size);

                mmap_msg = ctx->wmmap_msg + ctx->nwbuf - 1;
                mmap_msg->size += copy_size;

                len -= copy_size;
                data = nxt_pointer_to(data, copy_size);

                if (len == 0) {
                    return NXT_OK;
                }
            }

        } while (nxt_go_port_mmap_increase_buf(buf, len, 1) == NXT_OK);

        if (ctx->nwbuf >= 8) {
            nxt_go_ctx_flush(ctx, 0);
        }

        buf = nxt_go_port_mmap_get_buf(ctx, len);

        if (nxt_slow_path(buf == NULL)) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_go_ctx_read_size_(nxt_go_run_ctx_t *ctx, size_t *size)
{
    nxt_buf_t  *buf;
    nxt_int_t  rc;

    do {
        buf = &ctx->rbuf;

        if (nxt_slow_path(nxt_buf_mem_used_size(&buf->mem) < 1)) {
            if (nxt_fast_path(nxt_buf_mem_used_size(&buf->mem) == 0)) {

                ctx->nrbuf++;
                rc = nxt_go_ctx_init_rbuf(ctx);
                if (nxt_slow_path(rc != NXT_OK)) {
                    nxt_go_warn("read size: init rbuf failed");
                    return rc;
                }

                continue;
            }
            nxt_go_warn("read size: used size is not 0");
            return NXT_ERROR;
        }

        if (buf->mem.pos[0] >= 128) {
            if (nxt_slow_path(nxt_buf_mem_used_size(&buf->mem) < 4)) {
                nxt_go_warn("read size: used size < 4");
                return NXT_ERROR;
            }
        }

        break;
    } while (1);

    buf->mem.pos = nxt_app_msg_read_length(buf->mem.pos, size);

    return NXT_OK;
}


nxt_int_t
nxt_go_ctx_read_size(nxt_go_run_ctx_t *ctx, size_t *size)
{
    nxt_int_t  rc;

    rc = nxt_go_ctx_read_size_(ctx, size);

    if (nxt_fast_path(rc == NXT_OK)) {
        nxt_go_debug("read_size: %d", (int)*size);
    }

    return rc;
}


nxt_int_t
nxt_go_ctx_read_str(nxt_go_run_ctx_t *ctx, nxt_str_t *str)
{
    size_t     length;
    nxt_int_t  rc;
    nxt_buf_t  *buf;

    rc = nxt_go_ctx_read_size_(ctx, &length);
    if (nxt_slow_path(rc != NXT_OK)) {
        nxt_go_warn("read str: read size failed");
        return rc;
    }

    buf = &ctx->rbuf;

    if (nxt_slow_path(nxt_buf_mem_used_size(&buf->mem) < (intptr_t) length)) {
        nxt_go_warn("read str: used size too small %d < %d",
                    (int) nxt_buf_mem_used_size(&buf->mem), (int) length);
        return NXT_ERROR;
    }

    if (length > 0) {
        str->start = buf->mem.pos;
        str->length = length - 1;

        buf->mem.pos += length;

        nxt_go_debug("read_str: %d %.*s",
                     (int) length - 1, (int) length - 1, str->start);

    } else {
        str->start = NULL;
        str->length = 0;

        nxt_go_debug("read_str: NULL");
    }

    return NXT_OK;
}


size_t
nxt_go_ctx_read_raw(nxt_go_run_ctx_t *ctx, void *dst, size_t size)
{
    size_t     res, read_size;
    nxt_int_t  rc;
    nxt_buf_t  *buf;

    res = 0;

    while (size > 0) {
        buf = &ctx->rbuf;

        if (nxt_slow_path(nxt_buf_mem_used_size(&buf->mem) == 0)) {
            ctx->nrbuf++;
            rc = nxt_go_ctx_init_rbuf(ctx);
            if (nxt_slow_path(rc != NXT_OK)) {
                nxt_go_warn("read raw: init rbuf failed");
                return res;
            }

            continue;
        }

        read_size = nxt_buf_mem_used_size(&buf->mem);
        read_size = nxt_min(read_size, size);

        dst = nxt_cpymem(dst, buf->mem.pos, read_size);

        size -= read_size;
        buf->mem.pos += read_size;
        res += read_size;
    }

    nxt_go_debug("read_raw: %d", (int) res);

    return res;
}

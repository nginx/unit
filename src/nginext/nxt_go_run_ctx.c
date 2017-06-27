
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#ifndef NXT_CONFIGURE


#include "nxt_go_run_ctx.h"
#include "nxt_go_log.h"
#include "nxt_go_process.h"
#include "nxt_go_array.h"
#include "nxt_go_mutex.h"
#include "nxt_go_port_memory.h"

#include <nxt_port_memory_int.h>
#include <nxt_main.h>
#include <nxt_go_gen.h>


static nxt_int_t
nxt_go_ctx_msg_rbuf(nxt_go_run_ctx_t *ctx, nxt_go_msg_t *msg, nxt_buf_t *buf,
    uint32_t n)
{
    size_t               nchunks;
    nxt_port_mmap_t      *port_mmap;
    nxt_port_mmap_msg_t  *mmap_msg;

    if (nxt_slow_path(msg->mmap_msg == NULL)) {
        if (n > 0) {
            nxt_go_warn("failed to get plain buf #%d", (int)n);

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
        nxt_go_warn("no more data in shm #%d", (int)n);

        return NXT_ERROR;
    }

    if (nxt_slow_path(mmap_msg->mmap_id >= ctx->process->incoming.nelts)) {
        nxt_go_warn("incoming shared memory segment #%d not found "
                    "for process %d", (int)mmap_msg->mmap_id,
                    (int)msg->port_msg->pid);

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
    nxt_port_mmap_msg_t  *mmap_msg;

    memset(msg, 0, sizeof(nxt_go_msg_t));

    msg->port_msg = port_msg;
    msg->raw_size = payload_size;

    if (nxt_fast_path(port_msg->mmap != 0)) {
        msg->mmap_msg = (nxt_port_mmap_msg_t *) (port_msg + 1);
        msg->end = nxt_pointer_to(msg->mmap_msg, payload_size);

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
    nxt_port_mmap_t      *port_mmap;
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
            nxt_port_mmap_set_chunk_free(port_mmap->hdr, c);

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
    memset(ctx, 0, sizeof(nxt_go_run_ctx_t));

    ctx->process = nxt_go_get_process(port_msg->pid);
    if (nxt_slow_path(ctx->process == NULL)) {
        nxt_go_warn("failed to get process %d", port_msg->pid);

        return NXT_ERROR;
    }

    nxt_go_ctx_init_msg(&ctx->msg, port_msg, payload_size);

    ctx->msg_last = &ctx->msg;

    ctx->wport_msg.stream = port_msg->stream;
    ctx->wport_msg.pid = getpid();
    ctx->wport_msg.type = NXT_PORT_MSG_DATA;
    ctx->wport_msg.mmap = 1;

    return nxt_go_ctx_init_rbuf(ctx);
}


void
nxt_go_ctx_add_msg(nxt_go_run_ctx_t *ctx, nxt_port_msg_t *port_msg, size_t size)
{
    nxt_go_msg_t  *msg;

    msg = malloc(sizeof(nxt_go_msg_t));

    nxt_go_ctx_init_msg(msg, port_msg, size - sizeof(nxt_port_msg_t));

    msg->start_offset = ctx->msg_last->start_offset;

    if (ctx->msg_last == &ctx->msg) {
        msg->start_offset += ctx->r.body.preread.length;
    } else {
        msg->start_offset += ctx->msg_last->data_size;
    }

    ctx->msg_last->next = msg;
    ctx->msg_last = msg;
}


nxt_int_t
nxt_go_ctx_flush(nxt_go_run_ctx_t *ctx, int last)
{
    nxt_int_t rc;

    if (last != 0) {
        ctx->wport_msg.last = 1;
    }

    nxt_go_debug("flush buffers (%d)", last);

    rc = nxt_go_port_send(ctx->msg.port_msg->pid, ctx->msg.port_msg->reply_port,
                          &ctx->wport_msg, sizeof(nxt_port_msg_t) +
                          ctx->nwbuf * sizeof(nxt_port_mmap_msg_t), NULL, 0);

    ctx->nwbuf = 0;

    memset(&ctx->wbuf, 0, sizeof(ctx->wbuf));

    return rc;
}


nxt_int_t
nxt_go_ctx_write(nxt_go_run_ctx_t *ctx, void *data, size_t len)
{
    size_t                  nchunks;
    nxt_buf_t               *buf;
    nxt_chunk_id_t          c;
    nxt_port_mmap_t         *port_mmap;
    nxt_port_mmap_msg_t     *mmap_msg;
    nxt_port_mmap_header_t  *hdr;

    buf = &ctx->wbuf;

    if (ctx->nwbuf > 0 && nxt_buf_mem_free_size(&buf->mem) >= len) {
        memcpy(buf->mem.free, data, len);
        buf->mem.free += len;

        mmap_msg = ctx->wmmap_msg + ctx->nwbuf - 1;
        mmap_msg->size += len;

        return NXT_OK;
    }

    if (ctx->nwbuf >= 8) {
        nxt_go_ctx_flush(ctx, 0);
    }

    c = 0;

    hdr = nxt_go_port_mmap_get(ctx->process,
                               ctx->msg.port_msg->reply_port, &c);
    if (nxt_slow_path(hdr == NULL)) {
        nxt_go_warn("failed to get port_mmap");

        return NXT_ERROR;
    }

    buf->mem.start = nxt_port_mmap_chunk_start(hdr, c);
    buf->mem.pos = buf->mem.start;
    buf->mem.free = buf->mem.start;
    buf->mem.end = buf->mem.start + PORT_MMAP_CHUNK_SIZE;

    mmap_msg = ctx->wmmap_msg + ctx->nwbuf;
    mmap_msg->mmap_id = hdr->id;
    mmap_msg->chunk_id = c;

    nchunks = len / PORT_MMAP_CHUNK_SIZE;
    if ((len % PORT_MMAP_CHUNK_SIZE) != 0 || nchunks == 0) {
        nchunks++;
    }

    c++;
    nchunks--;

    /* Try to acquire as much chunks as required. */
    while (nchunks > 0) {

        if (nxt_port_mmap_get_chunk_busy(hdr, c)) {
            break;
        }
        nxt_port_mmap_set_chunk_busy(hdr, c);

        buf->mem.end += PORT_MMAP_CHUNK_SIZE;
        c++;
        nchunks--;
    }

    if (nxt_buf_mem_free_size(&buf->mem) < len) {
        len = nxt_buf_mem_free_size(&buf->mem);

    }

    memcpy(buf->mem.free, data, len);
    buf->mem.free += len;

    mmap_msg->size = len;

    ctx->nwbuf++;

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

    if (nxt_slow_path(nxt_buf_mem_used_size(&buf->mem) < (intptr_t)length)) {
        nxt_go_warn("read str: used size too small %d < %d",
                    (int)nxt_buf_mem_used_size(&buf->mem), (int)length);
        return NXT_ERROR;
    }

    if (length > 0) {
        str->start = buf->mem.pos;
        str->length = length - 1;

        buf->mem.pos += length;

        nxt_go_debug("read_str: %d %.*s", (int)length - 1, (int)length - 1,
                        str->start);
    } else {
        str->start = NULL;
        str->length = 0;

        nxt_go_debug("read_str: NULL");
    }

    return NXT_OK;
}


#endif /* NXT_CONFIGURE */

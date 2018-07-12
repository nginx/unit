
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#include "nxt_go_run_ctx.h"
#include "nxt_go_log.h"
#include "nxt_go_port.h"

#include "_cgo_export.h"

#include <nxt_main.h>

int
nxt_go_response_write(nxt_go_request_t r, uintptr_t buf, size_t len)
{
    nxt_int_t         rc;
    nxt_go_run_ctx_t  *ctx;

    if (nxt_slow_path(r == 0)) {
        return 0;
    }

    nxt_go_debug("write: %d", (int) len);

    ctx = (nxt_go_run_ctx_t *) r;
    rc = nxt_go_ctx_write(ctx, (void *) buf, len);

    return rc == NXT_OK ? len : -1;
}


void
nxt_go_response_flush(nxt_go_request_t r)
{
    nxt_go_run_ctx_t  *ctx;

    if (nxt_slow_path(r == 0)) {
        return;
    }

    ctx = (nxt_go_run_ctx_t *) r;

    if (ctx->nwbuf > 0) {
        nxt_go_ctx_flush(ctx, 0);
    }
}


int
nxt_go_request_read(nxt_go_request_t r, uintptr_t dst, size_t dst_len)
{
    size_t            res;
    nxt_go_run_ctx_t  *ctx;

    if (nxt_slow_path(r == 0)) {
        return 0;
    }

    ctx = (nxt_go_run_ctx_t *) r;

    dst_len = nxt_min(dst_len, ctx->request.body.preread_size);

    res = nxt_go_ctx_read_raw(ctx, (void *) dst, dst_len);

    ctx->request.body.preread_size -= res;

    return res;
}


int
nxt_go_request_close(nxt_go_request_t r)
{
    return 0;
}


int
nxt_go_request_done(nxt_go_request_t r)
{
    nxt_int_t          res;
    nxt_go_run_ctx_t   *ctx;
    nxt_go_msg_t       *msg, *b;

    if (nxt_slow_path(r == 0)) {
        return 0;
    }

    ctx = (nxt_go_run_ctx_t *) r;

    res = nxt_go_ctx_flush(ctx, 1);

    nxt_go_ctx_release_msg(ctx, &ctx->msg);

    msg = ctx->msg.next;
    while (msg != NULL) {
        nxt_go_ctx_release_msg(ctx, msg);

        b = msg;
        msg = b->next;

        free(b);
    }

    free(ctx);

    return res;
}


void
nxt_go_ready(uint32_t stream)
{
    nxt_port_msg_t  port_msg;

    port_msg.stream = stream;
    port_msg.pid = getpid();
    port_msg.reply_port = 0;
    port_msg.type = _NXT_PORT_MSG_PROCESS_READY;
    port_msg.last = 1;
    port_msg.mmap = 0;
    port_msg.nf = 0;
    port_msg.mf = 0;
    port_msg.tracking = 0;

    nxt_go_main_send(&port_msg, sizeof(port_msg), NULL, 0);
}


nxt_go_request_t
nxt_go_process_port_msg(uintptr_t buf, size_t buf_len, uintptr_t oob, size_t oob_len)
{
    return nxt_go_port_on_read((void *) buf, buf_len, (void *) oob, oob_len);
}


const char *
nxt_go_version()
{
    return NXT_VERSION;
}

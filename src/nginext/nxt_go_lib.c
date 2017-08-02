
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#ifdef NXT_CONFIGURE

#include <stdio.h>
#include "nxt_go_lib.h"

// Stubs to compile during configure process.
int
nxt_go_response_write(nxt_go_request_t r, void *buf, size_t len)
{
    return -1;
}

int
nxt_go_request_read(nxt_go_request_t r, off_t off, void *dst, size_t dst_len)
{
    return -1;
}

int
nxt_go_request_read_from(nxt_go_request_t r, off_t off, void *dst,
    size_t dst_len, void *src, size_t src_len)
{
    return -1;
}

int
nxt_go_request_close(nxt_go_request_t r)
{
    return -1;
}

int
nxt_go_request_done(nxt_go_request_t r)
{
    return -1;
}

void
nxt_go_ready()
{
}

nxt_go_request_t
nxt_go_process_port_msg(void *buf, size_t buf_len, void *oob, size_t oob_len)
{
    return 0;
}

#else

#include "nxt_go_run_ctx.h"
#include "nxt_go_log.h"
#include "nxt_go_port.h"

#include <nxt_main.h>
#include <nxt_go_gen.h>

int
nxt_go_response_write(nxt_go_request_t r, void *buf, size_t len)
{
    nxt_int_t         rc;
    nxt_go_run_ctx_t  *ctx;

    if (nxt_slow_path(r == 0)) {
        return 0;
    }

    nxt_go_debug("write: %d %.*s", (int) len, (int) len, (char *) buf);

    ctx = (nxt_go_run_ctx_t *) r;
    rc = nxt_go_ctx_write(ctx, buf, len);

    return rc == NXT_OK ? len : -1;
}


int
nxt_go_request_read(nxt_go_request_t r, off_t off, void *dst, size_t dst_len)
{
    nxt_go_msg_t              *msg;
    nxt_go_run_ctx_t          *ctx;
    nxt_app_request_body_t    *b;
    nxt_app_request_header_t  *h;

    if (nxt_slow_path(r == 0)) {
        return 0;
    }

    ctx = (nxt_go_run_ctx_t *) r;
    b = &ctx->r.body;
    h = &ctx->r.header;

    if (off >= h->parsed_content_length) {
        return 0;
    }

    if (off < b->preread.length) {
        dst_len = nxt_min(b->preread.length - off, dst_len);

        if (dst_len != 0) {
            nxt_memcpy(dst, b->preread.start + off, dst_len);
        }

        return dst_len;
    }

    /* TODO find msg to read */

    return NXT_AGAIN;
}


int
nxt_go_request_read_from(nxt_go_request_t r, off_t off, void *dst,
    size_t dst_len, void *src, size_t src_len)
{
    nxt_go_run_ctx_t  *ctx;

    if (nxt_slow_path(r == 0)) {
        return 0;
    }

    ctx = (nxt_go_run_ctx_t *) r;

    nxt_go_ctx_add_msg(ctx, src, src_len);

    return nxt_go_request_read(r, off, dst, dst_len);
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
nxt_go_ready()
{
    char           *go_stream;
    nxt_port_msg_t port_msg;

    go_stream = getenv("NXT_GO_STREAM");

    if (go_stream == NULL) {
        return;
    }

    port_msg.stream = atol(go_stream);
    port_msg.pid = getpid();
    port_msg.reply_port = 0;
    port_msg.type = _NXT_PORT_MSG_READY;
    port_msg.last = 1;
    port_msg.mmap = 0;

    nxt_go_master_send(&port_msg, sizeof(port_msg), NULL, 0);
}


nxt_go_request_t
nxt_go_process_port_msg(void *buf, size_t buf_len, void *oob, size_t oob_len)
{
    return nxt_go_port_on_read(buf, buf_len, oob, oob_len);
}


#endif /* NXT_CONFIGURE */

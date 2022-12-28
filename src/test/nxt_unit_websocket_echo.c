
/*
 * Copyright (C) NGINX, Inc.
 */

#include <string.h>
#include <stdlib.h>

#include <nxt_unit.h>
#include <nxt_unit_request.h>
#include <nxt_clang.h>
#include <nxt_websocket.h>
#include <nxt_unit_websocket.h>


static void
ws_echo_request_handler(nxt_unit_request_info_t *req)
{
    int         rc;
    const char  *target;

    rc = NXT_UNIT_OK;
    target = nxt_unit_sptr_get(&req->request->target);

    if (strcmp(target, "/") == 0) {
        if (!nxt_unit_request_is_websocket_handshake(req)) {
            goto notfound;
        }

        rc = nxt_unit_response_init(req, 101, 0, 0);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            goto fail;
        }

        nxt_unit_response_upgrade(req);
        nxt_unit_response_send(req);

        return;
    }

notfound:

    rc = nxt_unit_response_init(req, 404, 0, 0);

fail:

    nxt_unit_request_done(req, rc);
}


static void
ws_echo_websocket_handler(nxt_unit_websocket_frame_t *ws)
{
    uint8_t                  opcode;
    ssize_t                  size;
    nxt_unit_request_info_t  *req;

    static size_t            buf_size = 0;
    static uint8_t           *buf = NULL;

    if (buf_size < ws->content_length) {
        buf = realloc(buf, ws->content_length);
        buf_size = ws->content_length;
    }

    req = ws->req;
    opcode = ws->header->opcode;

    if (opcode == NXT_WEBSOCKET_OP_PONG) {
        nxt_unit_websocket_done(ws);
        return;
    }

    size = nxt_unit_websocket_read(ws, buf, ws->content_length);

    nxt_unit_websocket_send(req, opcode, ws->header->fin, buf, size);
    nxt_unit_websocket_done(ws);

    if (opcode == NXT_WEBSOCKET_OP_CLOSE) {
        nxt_unit_request_done(req, NXT_UNIT_OK);
    }
}


int
main(void)
{
    nxt_unit_ctx_t   *ctx;
    nxt_unit_init_t  init;

    memset(&init, 0, sizeof(nxt_unit_init_t));

    init.callbacks.request_handler = ws_echo_request_handler;
    init.callbacks.websocket_handler = ws_echo_websocket_handler;

    ctx = nxt_unit_init(&init);
    if (ctx == NULL) {
        return 1;
    }

    nxt_unit_run(ctx);
    nxt_unit_done(ctx);

    return 0;
}

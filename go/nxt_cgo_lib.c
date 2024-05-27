
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#include "_cgo_export.h"

#include <nxt_unit.h>
#include <nxt_unit_request.h>


static ssize_t nxt_cgo_port_send(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port,
    const void *buf, size_t buf_size, const void *oob, size_t oob_size);
static ssize_t nxt_cgo_port_recv(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port,
    void *buf, size_t buf_size, void *oob, size_t *oob_size);

int
nxt_cgo_run(uintptr_t handler)
{
    int              rc;
    nxt_unit_ctx_t   *ctx;
    nxt_unit_init_t  init;

    memset(&init, 0, sizeof(init));

    init.callbacks.request_handler = nxt_go_request_handler;
    init.callbacks.add_port        = nxt_go_add_port;
    init.callbacks.remove_port     = nxt_go_remove_port;
    init.callbacks.port_send       = nxt_cgo_port_send;
    init.callbacks.port_recv       = nxt_cgo_port_recv;
    init.callbacks.shm_ack_handler = nxt_go_shm_ack_handler;
    init.callbacks.ready_handler   = nxt_go_ready;

    init.data = (void *) handler;

    ctx = nxt_unit_init(&init);
    if (ctx == NULL) {
        return NXT_UNIT_ERROR;
    }

    rc = nxt_unit_run_ctx(ctx);

    nxt_unit_done(ctx);

    return rc;
}


static ssize_t
nxt_cgo_port_send(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port,
    const void *buf, size_t buf_size, const void *oob, size_t oob_size)
{
    return nxt_go_port_send(port->id.pid, port->id.id,
                            (void *) buf, buf_size, (void *) oob, oob_size);
}


static ssize_t
nxt_cgo_port_recv(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port,
    void *buf, size_t buf_size, void *oob, size_t *oob_size)
{
    return nxt_go_port_recv(port->id.pid, port->id.id,
                            buf, buf_size, oob, oob_size);
}


ssize_t
nxt_cgo_response_write(nxt_unit_request_info_t *req, uintptr_t start,
    uint32_t len)
{
    return nxt_unit_response_write_nb(req, (void *) start, len, 0);
}


ssize_t
nxt_cgo_request_read(nxt_unit_request_info_t *req, uintptr_t dst,
    uint32_t dst_len)
{
    return nxt_unit_request_read(req, (void *) dst, dst_len);
}


void
nxt_cgo_warn(const char *msg, uint32_t msg_len)
{
    nxt_unit_warn(NULL, "%.*s", (int) msg_len, (char *) msg);
}


void
nxt_cgo_alert(const char *msg, uint32_t msg_len)
{
    nxt_unit_alert(NULL, "%.*s", (int) msg_len, (char *) msg);
}


/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#include "_cgo_export.h"

#include <nxt_main.h>
#include <nxt_unit.h>
#include <nxt_unit_request.h>


static void nxt_cgo_request_handler(nxt_unit_request_info_t *req);
static nxt_cgo_str_t *nxt_cgo_str_init(nxt_cgo_str_t *dst,
    nxt_unit_sptr_t *sptr, uint32_t length);
static int nxt_cgo_add_port(nxt_unit_ctx_t *, nxt_unit_port_t *port);
static void nxt_cgo_remove_port(nxt_unit_ctx_t *, nxt_unit_port_id_t *port_id);
static ssize_t nxt_cgo_port_send(nxt_unit_ctx_t *, nxt_unit_port_id_t *port_id,
    const void *buf, size_t buf_size, const void *oob, size_t oob_size);
static ssize_t nxt_cgo_port_recv(nxt_unit_ctx_t *, nxt_unit_port_id_t *port_id,
    void *buf, size_t buf_size, void *oob, size_t oob_size);

int
nxt_cgo_run(uintptr_t handler)
{
    int              rc;
    nxt_unit_ctx_t   *ctx;
    nxt_unit_init_t  init;

    memset(&init, 0, sizeof(init));

    init.callbacks.request_handler = nxt_cgo_request_handler;
    init.callbacks.add_port        = nxt_cgo_add_port;
    init.callbacks.remove_port     = nxt_cgo_remove_port;
    init.callbacks.port_send       = nxt_cgo_port_send;
    init.callbacks.port_recv       = nxt_cgo_port_recv;

    init.data = (void *) handler;

    ctx = nxt_unit_init(&init);
    if (nxt_slow_path(ctx == NULL)) {
        return NXT_UNIT_ERROR;
    }

    rc = nxt_unit_run(ctx);

    nxt_unit_done(ctx);

    return rc;
}


static void
nxt_cgo_request_handler(nxt_unit_request_info_t *req)
{
    uint32_t            i;
    uintptr_t           go_req;
    nxt_cgo_str_t       method, uri, name, value, proto, host, remote_addr;
    nxt_unit_field_t    *f;
    nxt_unit_request_t  *r;

    r = req->request;

    go_req = nxt_go_request_create((uintptr_t) req,
                nxt_cgo_str_init(&method, &r->method, r->method_length),
                nxt_cgo_str_init(&uri, &r->target, r->target_length));

    nxt_go_request_set_proto(go_req,
        nxt_cgo_str_init(&proto, &r->version, r->version_length), 1, 1);

    for (i = 0; i < r->fields_count; i++) {
        f = &r->fields[i];

        nxt_go_request_add_header(go_req,
            nxt_cgo_str_init(&name, &f->name, f->name_length),
            nxt_cgo_str_init(&value, &f->value, f->value_length));
    }

    nxt_go_request_set_content_length(go_req, r->content_length);
    nxt_go_request_set_host(go_req,
        nxt_cgo_str_init(&host, &r->server_name, r->server_name_length));
    nxt_go_request_set_remote_addr(go_req,
        nxt_cgo_str_init(&remote_addr, &r->remote, r->remote_length));

    nxt_go_request_handler(go_req, (uintptr_t) req->unit->data);
}


static nxt_cgo_str_t *
nxt_cgo_str_init(nxt_cgo_str_t *dst, nxt_unit_sptr_t *sptr, uint32_t length)
{
    dst->length = length;
    dst->start = nxt_unit_sptr_get(sptr);

    return dst;
}


static int
nxt_cgo_add_port(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port)
{
    nxt_go_add_port(port->id.pid, port->id.id,
                    port->in_fd, port->out_fd);

    return nxt_unit_add_port(ctx, port);
}


static void
nxt_cgo_remove_port(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id)
{
    nxt_go_remove_port(port_id->pid, port_id->id);

    nxt_unit_remove_port(ctx, port_id);
}


static ssize_t
nxt_cgo_port_send(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id,
    const void *buf, size_t buf_size, const void *oob, size_t oob_size)
{
    return nxt_go_port_send(port_id->pid, port_id->id,
                            (void *) buf, buf_size, (void *) oob, oob_size);
}


static ssize_t
nxt_cgo_port_recv(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id,
    void *buf, size_t buf_size, void *oob, size_t oob_size)
{
    return nxt_go_port_recv(port_id->pid, port_id->id,
                            buf, buf_size, oob, oob_size);
}


int
nxt_cgo_response_create(uintptr_t req, int status, int fields,
    uint32_t fields_size)
{
    return nxt_unit_response_init((nxt_unit_request_info_t *) req,
                                  status, fields, fields_size);
}


int
nxt_cgo_response_add_field(uintptr_t req, uintptr_t name, uint8_t name_len,
    uintptr_t value, uint32_t value_len)
{
    return nxt_unit_response_add_field((nxt_unit_request_info_t *) req,
                                       (char *) name, name_len,
                                       (char *) value, value_len);
}


int
nxt_cgo_response_send(uintptr_t req)
{
    return nxt_unit_response_send((nxt_unit_request_info_t *) req);
}


ssize_t
nxt_cgo_response_write(uintptr_t req, uintptr_t start, uint32_t len)
{
    int  rc;

    rc = nxt_unit_response_write((nxt_unit_request_info_t *) req,
                                 (void *) start, len);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return -1;
    }

    return len;
}


ssize_t
nxt_cgo_request_read(uintptr_t req, uintptr_t dst, uint32_t dst_len)
{
    return nxt_unit_request_read((nxt_unit_request_info_t *) req,
                                 (void *) dst, dst_len);
}


int
nxt_cgo_request_close(uintptr_t req)
{
    return 0;
}


void
nxt_cgo_request_done(uintptr_t req, int res)
{
    nxt_unit_request_done((nxt_unit_request_info_t *) req, res);
}


void
nxt_cgo_warn(uintptr_t msg, uint32_t msg_len)
{
    nxt_unit_warn(NULL, "%.*s", (int) msg_len, (char *) msg);
}

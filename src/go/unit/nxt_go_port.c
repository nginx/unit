
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#include "nxt_go_port.h"
#include "nxt_go_log.h"
#include "nxt_go_process.h"
#include "nxt_go_run_ctx.h"

#include "_cgo_export.h"

#include <nxt_main.h>


#define nxt_go_str(p) ((nxt_go_str_t *)(p))

static nxt_go_request_t
nxt_go_data_handler(nxt_port_msg_t *port_msg, size_t size)
{
    size_t                    s;
    nxt_str_t                 n, v;
    nxt_int_t                 rc;
    nxt_uint_t                i;
    nxt_go_run_ctx_t          *ctx;
    nxt_go_request_t          r;
    nxt_app_request_header_t  *h;

    ctx = malloc(sizeof(nxt_go_run_ctx_t) + size);

    memcpy(ctx->port_msg, port_msg, size);
    port_msg = ctx->port_msg;

    size -= sizeof(nxt_port_msg_t);

    nxt_go_ctx_init(ctx, port_msg, size);

    if (nxt_slow_path(ctx->cancelled)) {
        nxt_go_debug("request already cancelled by router");
        free(ctx);
        return 0;
    }

    r = (nxt_go_request_t)(ctx);
    h = &ctx->request.header;

    nxt_go_ctx_read_str(ctx, &h->method);
    nxt_go_ctx_read_str(ctx, &h->target);
    nxt_go_ctx_read_str(ctx, &h->path);

    nxt_go_ctx_read_size(ctx, &s);
    if (s > 0) {
        s--;
        h->query.start = h->target.start + s;
        h->query.length = h->target.length - s;

        if (h->path.start == NULL) {
            h->path.start = h->target.start;
            h->path.length = s - 1;
        }
    }

    if (h->path.start == NULL) {
        h->path = h->target;
    }

    ctx->go_request = nxt_go_new_request(r, port_msg->stream,
                                   nxt_go_str(&h->method),
                                   nxt_go_str(&h->target));

    nxt_go_ctx_read_str(ctx, &h->version);

    nxt_go_request_set_proto(ctx->go_request, nxt_go_str(&h->version),
                             h->version.start[5] - '0',
                             h->version.start[7] - '0');

    nxt_go_ctx_read_str(ctx, &ctx->request.remote);
    if (ctx->request.remote.start != NULL) {
        nxt_go_request_set_remote_addr(ctx->go_request,
                                       nxt_go_str(&ctx->request.remote));
    }

    nxt_go_ctx_read_str(ctx, &h->host);
    nxt_go_ctx_read_str(ctx, &h->cookie);
    nxt_go_ctx_read_str(ctx, &h->content_type);
    nxt_go_ctx_read_str(ctx, &h->content_length);

    if (h->host.start != NULL) {
        nxt_go_request_set_host(ctx->go_request, nxt_go_str(&h->host));
    }

    nxt_go_ctx_read_size(ctx, &s);
    h->parsed_content_length = s;

    do {
        rc = nxt_go_ctx_read_str(ctx, &n);

        if (n.length == 0) {
            break;
        }

        rc = nxt_go_ctx_read_str(ctx, &v);
        nxt_go_request_add_header(ctx->go_request, nxt_go_str(&n),
                                  nxt_go_str(&v));
    } while(1);

    nxt_go_ctx_read_size(ctx, &s);
    ctx->request.body.preread_size = s;

    if (h->parsed_content_length > 0) {
        nxt_go_request_set_content_length(ctx->go_request,
                                          h->parsed_content_length);
    }

    if (ctx->request.body.preread_size < h->parsed_content_length) {
        nxt_go_warn("preread_size < content_length");
    }

    return ctx->go_request;
}

nxt_go_request_t
nxt_go_port_on_read(void *buf, size_t buf_size, void *oob, size_t oob_size)
{
    void                     *buf_end;
    void                     *payload;
    size_t                   payload_size;
    nxt_fd_t                 fd;
    struct cmsghdr           *cm;
    nxt_port_msg_t           *port_msg;
    nxt_port_msg_new_port_t  *new_port_msg;

    fd = -1;
    nxt_go_debug("on read: %d (%d)", (int) buf_size, (int) oob_size);

    cm = oob;
    if (oob_size >= CMSG_SPACE(sizeof(int))
        && cm->cmsg_len == CMSG_LEN(sizeof(int))
        && cm->cmsg_level == SOL_SOCKET
        && cm->cmsg_type == SCM_RIGHTS) {

        nxt_memcpy(&fd, CMSG_DATA(cm), sizeof(int));
        nxt_go_debug("fd = %d", fd);
    }

    port_msg = buf;
    if (buf_size < sizeof(nxt_port_msg_t)) {
        nxt_go_warn("message too small (%d bytes)", (int) buf_size);
        goto fail;
    }

    buf_end = ((char *) buf) + buf_size;

    payload = port_msg + 1;
    payload_size = buf_size - sizeof(nxt_port_msg_t);

    if (port_msg->mmap) {
        nxt_go_debug("using data in shared memory");
    }

    if (port_msg->type >= NXT_PORT_MSG_MAX) {
        nxt_go_warn("unknown message type (%d)", (int) port_msg->type);
        goto fail;
    }

    switch (port_msg->type) {
    case _NXT_PORT_MSG_QUIT:
        nxt_go_debug("quit");

        nxt_go_set_quit();
        break;

    case _NXT_PORT_MSG_NEW_PORT:
        nxt_go_debug("new port");
        new_port_msg = payload;

        nxt_go_new_port(new_port_msg->pid, new_port_msg->id, new_port_msg->type,
            -1, fd);
        break;

    case _NXT_PORT_MSG_CHANGE_FILE:
        nxt_go_debug("change file");
        break;

    case _NXT_PORT_MSG_MMAP:
        nxt_go_debug("mmap");

        nxt_go_new_incoming_mmap(port_msg->pid, fd);
        break;

    case _NXT_PORT_MSG_DATA:
        nxt_go_debug("data");

        return nxt_go_data_handler(port_msg, buf_size);

    case _NXT_PORT_MSG_REMOVE_PID:
        nxt_go_debug("remove pid");

        /* TODO remove all ports for this pid in Go */
        /* TODO remove incoming & outgoing mmaps for this pid */
        break;

    default:
        goto fail;
    }


fail:

    if (fd != -1) {
        close(fd);
    }

    return 0;
}

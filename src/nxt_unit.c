
/*
 * Copyright (C) NGINX, Inc.
 */

#include <stdlib.h>

#include "nxt_main.h"
#include "nxt_port_memory_int.h"

#include "nxt_unit.h"
#include "nxt_unit_request.h"
#include "nxt_unit_response.h"

#if (NXT_HAVE_MEMFD_CREATE)
#include <linux/memfd.h>
#endif

typedef struct nxt_unit_impl_s               nxt_unit_impl_t;
typedef struct nxt_unit_mmap_s               nxt_unit_mmap_t;
typedef struct nxt_unit_mmaps_s              nxt_unit_mmaps_t;
typedef struct nxt_unit_process_s            nxt_unit_process_t;
typedef struct nxt_unit_mmap_buf_s           nxt_unit_mmap_buf_t;
typedef struct nxt_unit_recv_msg_s           nxt_unit_recv_msg_t;
typedef struct nxt_unit_ctx_impl_s           nxt_unit_ctx_impl_t;
typedef struct nxt_unit_port_impl_s          nxt_unit_port_impl_t;
typedef struct nxt_unit_request_info_impl_s  nxt_unit_request_info_impl_t;

static nxt_unit_impl_t *nxt_unit_create(nxt_unit_init_t *init);
static void nxt_unit_ctx_init(nxt_unit_impl_t *lib,
    nxt_unit_ctx_impl_t *ctx_impl, void *data);
static int nxt_unit_read_env(nxt_unit_port_t *ready_port,
    nxt_unit_port_t *read_port, int *log_fd, uint32_t *stream);
static int nxt_unit_ready(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id,
    uint32_t stream);
static nxt_unit_request_info_impl_t *nxt_unit_request_info_get(
    nxt_unit_ctx_t *ctx);
static void nxt_unit_request_info_release(nxt_unit_request_info_t *req);
static void nxt_unit_request_info_free(nxt_unit_request_info_impl_t *req);
static nxt_unit_process_t *nxt_unit_msg_get_process(nxt_unit_ctx_t *ctx,
    nxt_unit_recv_msg_t *recv_msg);
static nxt_unit_mmap_buf_t *nxt_unit_mmap_buf_get(nxt_unit_ctx_t *ctx);
static void nxt_unit_mmap_buf_release(nxt_unit_mmap_buf_t *mmap_buf);
static int nxt_unit_mmap_buf_send(nxt_unit_ctx_t *ctx, uint32_t stream,
    nxt_unit_mmap_buf_t *mmap_buf, int last);
static nxt_port_mmap_header_t *nxt_unit_mmap_get(nxt_unit_ctx_t *ctx,
    nxt_unit_process_t *process, nxt_unit_port_id_t *port_id,
    nxt_chunk_id_t *c, int n);
static nxt_unit_mmap_t *nxt_unit_mmap_at(nxt_unit_mmaps_t *mmaps, uint32_t i);
static nxt_port_mmap_header_t *nxt_unit_new_mmap(nxt_unit_ctx_t *ctx,
    nxt_unit_process_t *process, nxt_unit_port_id_t *port_id, int n);
static int nxt_unit_send_mmap(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id,
    int fd);
static int nxt_unit_get_outgoing_buf(nxt_unit_ctx_t *ctx,
    nxt_unit_process_t *process, nxt_unit_port_id_t *port_id, uint32_t size,
    nxt_unit_mmap_buf_t *mmap_buf);
static int nxt_unit_incoming_mmap(nxt_unit_ctx_t *ctx, pid_t pid, int fd);

static void nxt_unit_mmaps_init(nxt_unit_mmaps_t *mmaps);
static void nxt_unit_process_use(nxt_unit_ctx_t *ctx,
    nxt_unit_process_t *process, int i);
static void nxt_unit_mmaps_destroy(nxt_unit_mmaps_t *mmaps);
static nxt_port_mmap_header_t *nxt_unit_get_incoming_mmap(nxt_unit_ctx_t *ctx,
    nxt_unit_process_t *process, uint32_t id);
static int nxt_unit_tracking_read(nxt_unit_ctx_t *ctx,
    nxt_unit_recv_msg_t *recv_msg);
static int nxt_unit_mmap_read(nxt_unit_ctx_t *ctx,
    nxt_unit_recv_msg_t *recv_msg, nxt_queue_t *incoming_buf);
static int nxt_unit_mmap_release(nxt_port_mmap_header_t *hdr, void *start,
    uint32_t size);

static nxt_unit_process_t *nxt_unit_process_get(nxt_unit_ctx_t *ctx,
    pid_t pid);
static nxt_unit_process_t *nxt_unit_process_find(nxt_unit_ctx_t *ctx,
    pid_t pid, int remove);
static nxt_unit_process_t *nxt_unit_process_pop_first(nxt_unit_impl_t *lib);
static int nxt_unit_create_port(nxt_unit_ctx_t *ctx,
    nxt_unit_port_id_t *port_id, int *fd);

static int nxt_unit_send_port(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *dst,
    nxt_unit_port_id_t *new_port, int fd);

static void nxt_unit_remove_port_unsafe(nxt_unit_ctx_t *ctx,
    nxt_unit_port_id_t *port_id, nxt_unit_port_t *r_port,
    nxt_unit_process_t **process);
static void nxt_unit_remove_process(nxt_unit_ctx_t *ctx,
    nxt_unit_process_t *process);

static ssize_t nxt_unit_port_send_default(nxt_unit_ctx_t *ctx,
    nxt_unit_port_id_t *port_id, const void *buf, size_t buf_size,
    const void *oob, size_t oob_size);
static ssize_t nxt_unit_port_recv_default(nxt_unit_ctx_t *ctx,
    nxt_unit_port_id_t *port_id, void *buf, size_t buf_size,
    void *oob, size_t oob_size);

static int nxt_unit_port_hash_add(nxt_lvlhsh_t *port_hash,
    nxt_unit_port_t *port);
static nxt_unit_port_impl_t *nxt_unit_port_hash_find(nxt_lvlhsh_t *port_hash,
    nxt_unit_port_id_t *port_id, int remove);

static char * nxt_unit_snprint_prefix(char *p, char *end, pid_t pid, int level);


struct nxt_unit_mmap_buf_s {
    nxt_unit_buf_t           buf;

    nxt_port_mmap_header_t   *hdr;
    nxt_queue_link_t         link;
    nxt_unit_port_id_t       port_id;
    nxt_unit_request_info_t  *req;
    nxt_unit_ctx_impl_t      *ctx_impl;
};


struct nxt_unit_recv_msg_s {
    nxt_port_msg_t           port_msg;

    void                     *start;
    uint32_t                 size;

    nxt_unit_process_t       *process;
};


typedef enum {
    NXT_UNIT_RS_START           = 0,
    NXT_UNIT_RS_RESPONSE_INIT,
    NXT_UNIT_RS_RESPONSE_HAS_CONTENT,
    NXT_UNIT_RS_RESPONSE_SENT,
    NXT_UNIT_RS_DONE,
} nxt_unit_req_state_t;


struct nxt_unit_request_info_impl_s {
    nxt_unit_request_info_t  req;

    nxt_unit_recv_msg_t      recv_msg;
    nxt_queue_t              outgoing_buf;    /*  of nxt_unit_mmap_buf_t */
    nxt_queue_t              incoming_buf;    /*  of nxt_unit_mmap_buf_t */

    nxt_unit_req_state_t     state;

    nxt_queue_link_t         link;

    char                     extra_data[];
};


struct nxt_unit_ctx_impl_s {
    nxt_unit_ctx_t                ctx;

    nxt_unit_port_id_t            read_port_id;
    int                           read_port_fd;

    nxt_queue_link_t              link;

    nxt_queue_t                   free_buf;  /*  of nxt_unit_mmap_buf_t */

    /*  of nxt_unit_request_info_impl_t */
    nxt_queue_t                   free_req;

    /*  of nxt_unit_request_info_impl_t */
    nxt_queue_t                   active_req;

    nxt_unit_mmap_buf_t           ctx_buf[2];

    nxt_unit_request_info_impl_t  req;
};


struct nxt_unit_impl_s {
    nxt_unit_t               unit;
    nxt_unit_callbacks_t     callbacks;

    uint32_t                 request_data_size;

    pthread_mutex_t          mutex;

    nxt_lvlhsh_t             processes;        /* of nxt_unit_process_t */
    nxt_lvlhsh_t             ports;            /* of nxt_unit_port_impl_t */

    nxt_unit_port_id_t       ready_port_id;

    nxt_queue_t              contexts;         /* of nxt_unit_ctx_impl_t */

    pid_t                    pid;
    int                      log_fd;
    int                      online;

    nxt_unit_ctx_impl_t      main_ctx;
};


struct nxt_unit_port_impl_s {
    nxt_unit_port_t          port;

    nxt_queue_link_t         link;
    nxt_unit_process_t       *process;
};


struct nxt_unit_mmap_s {
    nxt_port_mmap_header_t   *hdr;
};


struct nxt_unit_mmaps_s {
    pthread_mutex_t          mutex;
    uint32_t                 size;
    uint32_t                 cap;
    nxt_unit_mmap_t          *elts;
};


struct nxt_unit_process_s {
    pid_t                    pid;

    nxt_queue_t              ports;

    nxt_unit_mmaps_t         incoming;
    nxt_unit_mmaps_t         outgoing;

    nxt_unit_impl_t          *lib;

    nxt_atomic_t             use_count;

    uint32_t                 next_port_id;
};


/* Explicitly using 32 bit types to avoid possible alignment. */
typedef struct {
    int32_t   pid;
    uint32_t  id;
} nxt_unit_port_hash_id_t;


nxt_unit_ctx_t *
nxt_unit_init(nxt_unit_init_t *init)
{
    int              rc;
    uint32_t         ready_stream;
    nxt_unit_ctx_t   *ctx;
    nxt_unit_impl_t  *lib;
    nxt_unit_port_t  ready_port, read_port;

    lib = nxt_unit_create(init);
    if (nxt_slow_path(lib == NULL)) {
        return NULL;
    }

    if (init->ready_port.id.pid != 0
        && init->ready_stream != 0
        && init->read_port.id.pid != 0)
    {
        ready_port = init->ready_port;
        ready_stream = init->ready_stream;
        read_port = init->read_port;
        lib->log_fd = init->log_fd;

        nxt_unit_port_id_init(&ready_port.id, ready_port.id.pid,
                              ready_port.id.id);
        nxt_unit_port_id_init(&read_port.id, read_port.id.pid,
                              read_port.id.id);
    } else {
        rc = nxt_unit_read_env(&ready_port, &read_port, &lib->log_fd,
                               &ready_stream);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            goto fail;
        }
    }

    ctx = &lib->main_ctx.ctx;

    rc = lib->callbacks.add_port(ctx, &ready_port);
    if (rc != NXT_UNIT_OK) {
        nxt_unit_alert(NULL, "failed to add ready_port");

        goto fail;
    }

    rc = lib->callbacks.add_port(ctx, &read_port);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_alert(NULL, "failed to add read_port");

        goto fail;
    }

    lib->main_ctx.read_port_id = read_port.id;
    lib->ready_port_id = ready_port.id;

    rc = nxt_unit_ready(ctx, &ready_port.id, ready_stream);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_alert(NULL, "failed to send READY message");

        goto fail;
    }

    return ctx;

fail:

    free(lib);

    return NULL;
}


static nxt_unit_impl_t *
nxt_unit_create(nxt_unit_init_t *init)
{
    int                   rc;
    nxt_unit_impl_t       *lib;
    nxt_unit_callbacks_t  *cb;

    lib = malloc(sizeof(nxt_unit_impl_t) + init->request_data_size);
    if (nxt_slow_path(lib == NULL)) {
        nxt_unit_alert(NULL, "failed to allocate unit struct");

        return NULL;
    }

    rc = pthread_mutex_init(&lib->mutex, NULL);
    if (nxt_slow_path(rc != 0)) {
        nxt_unit_alert(NULL, "failed to initialize mutex (%d)", rc);

        goto fail;
    }

    lib->unit.data = init->data;
    lib->callbacks = init->callbacks;

    lib->request_data_size = init->request_data_size;

    lib->processes.slot = NULL;
    lib->ports.slot = NULL;

    lib->pid = getpid();
    lib->log_fd = STDERR_FILENO;
    lib->online = 1;

    nxt_queue_init(&lib->contexts);

    nxt_unit_ctx_init(lib, &lib->main_ctx, init->ctx_data);

    cb = &lib->callbacks;

    if (cb->request_handler == NULL) {
        nxt_unit_alert(NULL, "request_handler is NULL");

        goto fail;
    }

    if (cb->add_port == NULL) {
        cb->add_port = nxt_unit_add_port;
    }

    if (cb->remove_port == NULL) {
        cb->remove_port = nxt_unit_remove_port;
    }

    if (cb->remove_pid == NULL) {
        cb->remove_pid = nxt_unit_remove_pid;
    }

    if (cb->quit == NULL) {
        cb->quit = nxt_unit_quit;
    }

    if (cb->port_send == NULL) {
        cb->port_send = nxt_unit_port_send_default;
    }

    if (cb->port_recv == NULL) {
        cb->port_recv = nxt_unit_port_recv_default;
    }

    return lib;

fail:

    free(lib);

    return NULL;
}


static void
nxt_unit_ctx_init(nxt_unit_impl_t *lib, nxt_unit_ctx_impl_t *ctx_impl,
    void *data)
{
    ctx_impl->ctx.data = data;
    ctx_impl->ctx.unit = &lib->unit;

    nxt_queue_insert_tail(&lib->contexts, &ctx_impl->link);

    nxt_queue_init(&ctx_impl->free_buf);
    nxt_queue_init(&ctx_impl->free_req);
    nxt_queue_init(&ctx_impl->active_req);

    nxt_queue_insert_tail(&ctx_impl->free_buf, &ctx_impl->ctx_buf[0].link);
    nxt_queue_insert_tail(&ctx_impl->free_buf, &ctx_impl->ctx_buf[1].link);
    nxt_queue_insert_tail(&ctx_impl->free_req, &ctx_impl->req.link);

    ctx_impl->req.req.ctx = &ctx_impl->ctx;
    ctx_impl->req.req.unit = &lib->unit;

    ctx_impl->read_port_fd = -1;
}


static int
nxt_unit_read_env(nxt_unit_port_t *ready_port, nxt_unit_port_t *read_port,
    int *log_fd, uint32_t *stream)
{
    int       rc;
    int       ready_fd, read_fd;
    char      *unit_init, *version_end;
    long      version_length;
    int64_t   ready_pid, read_pid;
    uint32_t  ready_stream, ready_id, read_id;

    unit_init = getenv(NXT_UNIT_INIT_ENV);
    if (nxt_slow_path(unit_init == NULL)) {
        nxt_unit_alert(NULL, "%s is not in the current environment",
                       NXT_UNIT_INIT_ENV);

        return NXT_UNIT_ERROR;
    }

    nxt_unit_debug(NULL, "%s='%s'", NXT_UNIT_INIT_ENV, unit_init);

    version_length = nxt_length(NXT_VERSION);

    version_end = strchr(unit_init, ';');
    if (version_end == NULL
        || version_end - unit_init != version_length
        || memcmp(unit_init, NXT_VERSION, version_length) != 0)
    {
        nxt_unit_alert(NULL, "version check error");

        return NXT_UNIT_ERROR;
    }

    rc = sscanf(version_end + 1,
                "%"PRIu32";"
                "%"PRId64",%"PRIu32",%d;"
                "%"PRId64",%"PRIu32",%d;"
                "%d",
                &ready_stream,
                &ready_pid, &ready_id, &ready_fd,
                &read_pid, &read_id, &read_fd,
                log_fd);

    if (nxt_slow_path(rc != 8)) {
        nxt_unit_alert(NULL, "failed to scan variables");

        return NXT_UNIT_ERROR;
    }

    nxt_unit_port_id_init(&ready_port->id, (pid_t) ready_pid, ready_id);

    ready_port->in_fd = -1;
    ready_port->out_fd = ready_fd;
    ready_port->data = NULL;

    nxt_unit_port_id_init(&read_port->id, (pid_t) read_pid, read_id);

    read_port->in_fd = read_fd;
    read_port->out_fd = -1;
    read_port->data = NULL;

    *stream = ready_stream;

    return NXT_UNIT_OK;
}


static int
nxt_unit_ready(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id,
    uint32_t stream)
{
    ssize_t          res;
    nxt_port_msg_t   msg;
    nxt_unit_impl_t  *lib;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    msg.stream = stream;
    msg.pid = lib->pid;
    msg.reply_port = 0;
    msg.type = _NXT_PORT_MSG_PROCESS_READY;
    msg.last = 1;
    msg.mmap = 0;
    msg.nf = 0;
    msg.mf = 0;
    msg.tracking = 0;

    res = lib->callbacks.port_send(ctx, port_id, &msg, sizeof(msg), NULL, 0);
    if (res != sizeof(msg)) {
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


int
nxt_unit_process_msg(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id,
    void *buf, size_t buf_size, void *oob, size_t oob_size)
{
    int                           fd, rc, nb;
    pid_t                         pid;
    nxt_queue_t                   incoming_buf;
    struct cmsghdr                *cm;
    nxt_port_msg_t                *port_msg;
    nxt_unit_impl_t               *lib;
    nxt_unit_port_t               new_port;
    nxt_queue_link_t              *lnk;
    nxt_unit_request_t            *r;
    nxt_unit_mmap_buf_t           *b;
    nxt_unit_recv_msg_t           recv_msg;
    nxt_unit_callbacks_t          *cb;
    nxt_port_msg_new_port_t       *new_port_msg;
    nxt_unit_request_info_t       *req;
    nxt_unit_request_info_impl_t  *req_impl;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    rc = NXT_UNIT_ERROR;
    fd = -1;
    recv_msg.process = NULL;
    port_msg = buf;
    cm = oob;

    if (oob_size >= CMSG_SPACE(sizeof(int))
        && cm->cmsg_len == CMSG_LEN(sizeof(int))
        && cm->cmsg_level == SOL_SOCKET
        && cm->cmsg_type == SCM_RIGHTS)
    {
        memcpy(&fd, CMSG_DATA(cm), sizeof(int));
    }

    nxt_queue_init(&incoming_buf);

    if (nxt_slow_path(buf_size < sizeof(nxt_port_msg_t))) {
        nxt_unit_warn(ctx, "message too small (%d bytes)", (int) buf_size);
        goto fail;
    }

    recv_msg.port_msg = *port_msg;
    recv_msg.start = port_msg + 1;
    recv_msg.size = buf_size - sizeof(nxt_port_msg_t);

    if (nxt_slow_path(port_msg->type >= NXT_PORT_MSG_MAX)) {
        nxt_unit_warn(ctx, "#%"PRIu32": unknown message type (%d)",
                      port_msg->stream, (int) port_msg->type);
        goto fail;
    }

    if (port_msg->tracking && nxt_unit_tracking_read(ctx, &recv_msg) == 0) {
        rc = NXT_UNIT_OK;

        goto fail;
    }

    /* Fragmentation is unsupported. */
    if (nxt_slow_path(port_msg->nf != 0 || port_msg->mf != 0)) {
        nxt_unit_warn(ctx, "#%"PRIu32": fragmented message type (%d)",
                      port_msg->stream, (int) port_msg->type);
        goto fail;
    }

    if (port_msg->mmap) {
        if (nxt_unit_mmap_read(ctx, &recv_msg, &incoming_buf) != NXT_UNIT_OK) {
            goto fail;
        }
    }

    cb = &lib->callbacks;

    switch (port_msg->type) {

    case _NXT_PORT_MSG_QUIT:
        nxt_unit_debug(ctx, "#%"PRIu32": quit", port_msg->stream);

        cb->quit(ctx);
        rc = NXT_UNIT_OK;
        break;

    case _NXT_PORT_MSG_NEW_PORT:
        if (nxt_slow_path(recv_msg.size != sizeof(nxt_port_msg_new_port_t))) {
            nxt_unit_warn(ctx, "#%"PRIu32": new_port: "
                          "invalid message size (%d)",
                          port_msg->stream, (int) recv_msg.size);

            goto fail;
        }

        if (nxt_slow_path(fd < 0)) {
            nxt_unit_alert(ctx, "#%"PRIu32": invalid fd %d for new port",
                           port_msg->stream, fd);

            goto fail;
        }

        new_port_msg = recv_msg.start;

        nxt_unit_debug(ctx, "#%"PRIu32": new_port: %d,%d fd %d",
                       port_msg->stream, (int) new_port_msg->pid,
                       (int) new_port_msg->id, fd);

        nb = 0;

        if (nxt_slow_path(ioctl(fd, FIONBIO, &nb) == -1)) {
            nxt_unit_alert(ctx, "#%"PRIu32": new_port: ioctl(%d, FIONBIO, 0) "
                           "failed: %s (%d)", fd, strerror(errno), errno);

            goto fail;
        }

        nxt_unit_port_id_init(&new_port.id, new_port_msg->pid,
                              new_port_msg->id);

        new_port.in_fd = -1;
        new_port.out_fd = fd;
        new_port.data = NULL;

        fd = -1;

        rc = cb->add_port(ctx, &new_port);
        break;

    case _NXT_PORT_MSG_CHANGE_FILE:
        nxt_unit_debug(ctx, "#%"PRIu32": change_file: fd %d",
                       port_msg->stream, fd);
        break;

    case _NXT_PORT_MSG_MMAP:
        if (nxt_slow_path(fd < 0)) {
            nxt_unit_alert(ctx, "#%"PRIu32": invalid fd %d for mmap",
                           port_msg->stream, fd);

            goto fail;
        }

        rc = nxt_unit_incoming_mmap(ctx, port_msg->pid, fd);
        break;

    case _NXT_PORT_MSG_DATA:
        if (nxt_slow_path(port_msg->mmap == 0)) {
            nxt_unit_warn(ctx, "#%"PRIu32": data is not in shared memory",
                          port_msg->stream);

            goto fail;
        }

        if (nxt_slow_path(recv_msg.size < sizeof(nxt_unit_request_t))) {
            nxt_unit_warn(ctx, "#%"PRIu32": data too short: %d while at least "
                          "%d expected", port_msg->stream, (int) recv_msg.size,
                          (int) sizeof(nxt_unit_request_t));

            goto fail;
        }

        req_impl = nxt_unit_request_info_get(ctx);
        if (nxt_slow_path(req_impl == NULL)) {
            nxt_unit_warn(ctx, "#%"PRIu32": request info allocation failed",
                          port_msg->stream);

            goto fail;
        }

        req = &req_impl->req;

        req->request_port = *port_id;

        nxt_unit_port_id_init(&req->response_port, port_msg->pid,
                              port_msg->reply_port);

        req->request = recv_msg.start;

        lnk = nxt_queue_first(&incoming_buf);
        b = nxt_container_of(lnk, nxt_unit_mmap_buf_t, link);

        req->request_buf = &b->buf;
        req->response = NULL;
        req->response_buf = NULL;

        r = req->request;

        req->content_length = r->content_length;

        req->content_buf = req->request_buf;
        req->content_buf->free = nxt_unit_sptr_get(&r->preread_content);

        /* Move process to req_impl. */
        req_impl->recv_msg = recv_msg;

        recv_msg.process = NULL;

        nxt_queue_init(&req_impl->outgoing_buf);
        nxt_queue_init(&req_impl->incoming_buf);

        nxt_queue_each(b, &incoming_buf, nxt_unit_mmap_buf_t, link)
        {
            b->req = req;
        } nxt_queue_loop;

        nxt_queue_add(&req_impl->incoming_buf, &incoming_buf);
        nxt_queue_init(&incoming_buf);

        req->response_max_fields = 0;
        req_impl->state = NXT_UNIT_RS_START;

        nxt_unit_debug(ctx, "#%"PRIu32": %.*s %.*s (%d)", port_msg->stream,
                       (int) r->method_length, nxt_unit_sptr_get(&r->method),
                       (int) r->target_length, nxt_unit_sptr_get(&r->target),
                       (int) r->content_length);

        cb->request_handler(req);

        rc = NXT_UNIT_OK;
        break;

    case _NXT_PORT_MSG_REMOVE_PID:
        if (nxt_slow_path(recv_msg.size != sizeof(pid))) {
            nxt_unit_warn(ctx, "#%"PRIu32": remove_pid: invalid message size "
                          "(%d != %d)", port_msg->stream, (int) recv_msg.size,
                          (int) sizeof(pid));

            goto fail;
        }

        memcpy(&pid, recv_msg.start, sizeof(pid));

        nxt_unit_debug(ctx, "#%"PRIu32": remove_pid: %d",
                       port_msg->stream, (int) pid);

        cb->remove_pid(ctx, pid);

        rc = NXT_UNIT_OK;
        break;

    default:
        nxt_unit_debug(ctx, "#%"PRIu32": ignore message type: %d",
                       port_msg->stream, (int) port_msg->type);

        goto fail;
    }

fail:

    if (fd != -1) {
        close(fd);
    }

    if (port_msg->mmap) {
        nxt_queue_each(b, &incoming_buf, nxt_unit_mmap_buf_t, link)
        {
            nxt_unit_mmap_release(b->hdr, b->buf.start,
                                  b->buf.end - b->buf.start);

            nxt_unit_mmap_buf_release(b);
        } nxt_queue_loop;
    }

    if (recv_msg.process != NULL) {
        nxt_unit_process_use(ctx, recv_msg.process, -1);
    }

    return rc;
}


static nxt_unit_request_info_impl_t *
nxt_unit_request_info_get(nxt_unit_ctx_t *ctx)
{
    nxt_unit_impl_t               *lib;
    nxt_queue_link_t              *lnk;
    nxt_unit_ctx_impl_t           *ctx_impl;
    nxt_unit_request_info_impl_t  *req_impl;

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    if (nxt_queue_is_empty(&ctx_impl->free_req)) {
        req_impl = malloc(sizeof(nxt_unit_request_info_impl_t)
                          + lib->request_data_size);
        if (nxt_slow_path(req_impl == NULL)) {
            nxt_unit_warn(ctx, "request info allocation failed");

            return NULL;
        }

        req_impl->req.unit = ctx->unit;
        req_impl->req.ctx = ctx;

    } else {
        lnk = nxt_queue_first(&ctx_impl->free_req);
        nxt_queue_remove(lnk);

        req_impl = nxt_container_of(lnk, nxt_unit_request_info_impl_t, link);
    }

    nxt_queue_insert_tail(&ctx_impl->active_req, &req_impl->link);

    req_impl->req.data = lib->request_data_size ? req_impl->extra_data : NULL;

    return req_impl;
}


static void
nxt_unit_request_info_release(nxt_unit_request_info_t *req)
{
    nxt_unit_mmap_buf_t           *b;
    nxt_unit_ctx_impl_t           *ctx_impl;
    nxt_unit_recv_msg_t           *recv_msg;
    nxt_unit_request_info_impl_t  *req_impl;

    ctx_impl = nxt_container_of(req->ctx, nxt_unit_ctx_impl_t, ctx);
    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    req->response = NULL;
    req->response_buf = NULL;

    recv_msg = &req_impl->recv_msg;

    if (recv_msg->process != NULL) {
        nxt_unit_process_use(req->ctx, recv_msg->process, -1);

        recv_msg->process = NULL;
    }

    nxt_queue_each(b, &req_impl->outgoing_buf, nxt_unit_mmap_buf_t, link) {

        nxt_unit_buf_free(&b->buf);

    } nxt_queue_loop;

    nxt_queue_each(b, &req_impl->incoming_buf, nxt_unit_mmap_buf_t, link) {

        nxt_unit_mmap_release(b->hdr, b->buf.start, b->buf.end - b->buf.start);
        nxt_unit_mmap_buf_release(b);

    } nxt_queue_loop;

    nxt_queue_remove(&req_impl->link);

    nxt_queue_insert_tail(&ctx_impl->free_req, &req_impl->link);
}


static void
nxt_unit_request_info_free(nxt_unit_request_info_impl_t *req_impl)
{
    nxt_unit_ctx_impl_t  *ctx_impl;

    ctx_impl = nxt_container_of(req_impl->req.ctx, nxt_unit_ctx_impl_t, ctx);

    nxt_queue_remove(&req_impl->link);

    if (req_impl != &ctx_impl->req) {
        free(req_impl);
    }
}


uint16_t
nxt_unit_field_hash(const char *name, size_t name_length)
{
    u_char      ch;
    uint32_t    hash;
    const char  *p, *end;

    hash = 159406; /* Magic value copied from nxt_http_parse.c */
    end = name + name_length;

    for (p = name; p < end; p++) {
        ch = *p;
        hash = (hash << 4) + hash + nxt_lowcase(ch);
    }

    hash = (hash >> 16) ^ hash;

    return hash;
}


void
nxt_unit_request_group_dup_fields(nxt_unit_request_info_t *req)
{
    uint32_t            i, j;
    nxt_unit_field_t    *fields, f;
    nxt_unit_request_t  *r;

    nxt_unit_req_debug(req, "group_dup_fields");

    r = req->request;
    fields = r->fields;

    for (i = 0; i < r->fields_count; i++) {

        switch (fields[i].hash) {
        case NXT_UNIT_HASH_CONTENT_LENGTH:
            r->content_length_field = i;
            break;

        case NXT_UNIT_HASH_CONTENT_TYPE:
            r->content_type_field = i;
            break;

        case NXT_UNIT_HASH_COOKIE:
            r->cookie_field = i;
            break;
        };

        for (j = i + 1; j < r->fields_count; j++) {
            if (fields[i].hash != fields[j].hash) {
                continue;
            }

            if (j == i + 1) {
                continue;
            }

            f = fields[j];
            f.name.offset += (j - (i + 1)) * sizeof(f);
            f.value.offset += (j - (i + 1)) * sizeof(f);

            while (j > i + 1) {
                fields[j] = fields[j - 1];
                fields[j].name.offset -= sizeof(f);
                fields[j].value.offset -= sizeof(f);
                j--;
            }

            fields[j] = f;

            i++;
        }
    }
}


int
nxt_unit_response_init(nxt_unit_request_info_t *req,
    uint16_t status, uint32_t max_fields_count, uint32_t max_fields_size)
{
    uint32_t                      buf_size;
    nxt_unit_buf_t                *buf;
    nxt_unit_request_info_impl_t  *req_impl;

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    if (nxt_slow_path(req_impl->state >= NXT_UNIT_RS_RESPONSE_SENT)) {
        nxt_unit_req_warn(req, "init: response already sent");

        return NXT_UNIT_ERROR;
    }

    nxt_unit_req_debug(req, "init: %d, max fields %d/%d", (int) status,
                       (int) max_fields_count, (int) max_fields_size);

    if (nxt_slow_path(req_impl->state >= NXT_UNIT_RS_RESPONSE_INIT)) {
        nxt_unit_req_debug(req, "duplicate response init");
    }

    buf_size = sizeof(nxt_unit_response_t)
               + max_fields_count * sizeof(nxt_unit_field_t)
               + max_fields_size;

    if (nxt_slow_path(req->response_buf != NULL)) {
        buf = req->response_buf;

        if (nxt_fast_path(buf_size <= (uint32_t) (buf->end - buf->start))) {
            goto init_response;
        }

        nxt_unit_buf_free(buf);

        req->response_buf = NULL;
        req->response = NULL;
        req->response_max_fields = 0;

        req_impl->state = NXT_UNIT_RS_START;
    }

    buf = nxt_unit_response_buf_alloc(req, buf_size);
    if (nxt_slow_path(buf == NULL)) {
        return NXT_UNIT_ERROR;
    }

init_response:

    memset(buf->start, 0, sizeof(nxt_unit_response_t));

    req->response_buf = buf;

    req->response = (nxt_unit_response_t *) buf->start;
    req->response->status = status;

    buf->free = buf->start + sizeof(nxt_unit_response_t)
                + max_fields_count * sizeof(nxt_unit_field_t);

    req->response_max_fields = max_fields_count;
    req_impl->state = NXT_UNIT_RS_RESPONSE_INIT;

    return NXT_UNIT_OK;
}


int
nxt_unit_response_realloc(nxt_unit_request_info_t *req,
    uint32_t max_fields_count, uint32_t max_fields_size)
{
    char                          *p;
    uint32_t                      i, buf_size;
    nxt_unit_buf_t                *buf;
    nxt_unit_field_t              *f, *src;
    nxt_unit_response_t           *resp;
    nxt_unit_request_info_impl_t  *req_impl;

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    if (nxt_slow_path(req_impl->state < NXT_UNIT_RS_RESPONSE_INIT)) {
        nxt_unit_req_warn(req, "realloc: response not init");

        return NXT_UNIT_ERROR;
    }

    if (nxt_slow_path(req_impl->state >= NXT_UNIT_RS_RESPONSE_SENT)) {
        nxt_unit_req_warn(req, "realloc: response already sent");

        return NXT_UNIT_ERROR;
    }

    if (nxt_slow_path(max_fields_count < req->response->fields_count)) {
        nxt_unit_req_warn(req, "realloc: new max_fields_count is too small");

        return NXT_UNIT_ERROR;
    }

    buf_size = sizeof(nxt_unit_response_t)
               + max_fields_count * sizeof(nxt_unit_field_t)
               + max_fields_size;

    nxt_unit_req_debug(req, "realloc %"PRIu32"", buf_size);

    buf = nxt_unit_response_buf_alloc(req, buf_size);
    if (nxt_slow_path(buf == NULL)) {
        nxt_unit_req_warn(req, "realloc: new buf allocation failed");
        return NXT_UNIT_ERROR;
    }

    resp = (nxt_unit_response_t *) buf->start;

    memset(resp, 0, sizeof(nxt_unit_response_t));

    resp->status = req->response->status;
    resp->content_length = req->response->content_length;

    p = buf->start + max_fields_count * sizeof(nxt_unit_field_t);
    f = resp->fields;

    for (i = 0; i < req->response->fields_count; i++) {
        src = req->response->fields + i;

        if (nxt_slow_path(src->skip != 0)) {
            continue;
        }

        if (nxt_slow_path(src->name_length + src->value_length + 2
                          > (uint32_t) (buf->end - p)))
        {
            nxt_unit_req_warn(req, "realloc: not enough space for field"
                  " #%"PRIu32" (%p), (%"PRIu32" + %"PRIu32") required",
                  i, src, src->name_length, src->value_length);

            goto fail;
        }

        nxt_unit_sptr_set(&f->name, p);
        p = nxt_cpymem(p, nxt_unit_sptr_get(&src->name), src->name_length);
        *p++ = '\0';

        nxt_unit_sptr_set(&f->value, p);
        p = nxt_cpymem(p, nxt_unit_sptr_get(&src->value), src->value_length);
        *p++ = '\0';

        f->hash = src->hash;
        f->skip = 0;
        f->name_length = src->name_length;
        f->value_length = src->value_length;

        resp->fields_count++;
        f++;
    }

    if (req->response->piggyback_content_length > 0) {
        if (nxt_slow_path(req->response->piggyback_content_length
                          > (uint32_t) (buf->end - p)))
        {
            nxt_unit_req_warn(req, "realloc: not enought space for content"
                  " #%"PRIu32", %"PRIu32" required",
                  i, req->response->piggyback_content_length);

            goto fail;
        }

        resp->piggyback_content_length = req->response->piggyback_content_length;

        nxt_unit_sptr_set(&resp->piggyback_content, p);
        p = nxt_cpymem(p, nxt_unit_sptr_get(&req->response->piggyback_content),
                       req->response->piggyback_content_length);
    }

    buf->free = p;

    nxt_unit_buf_free(req->response_buf);

    req->response = resp;
    req->response_buf = buf;
    req->response_max_fields = max_fields_count;

    return NXT_UNIT_OK;

fail:

    nxt_unit_buf_free(buf);

    return NXT_UNIT_ERROR;
}


int
nxt_unit_response_is_init(nxt_unit_request_info_t *req)
{
    nxt_unit_request_info_impl_t  *req_impl;

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    return req_impl->state >= NXT_UNIT_RS_RESPONSE_INIT;
}


int
nxt_unit_response_add_field(nxt_unit_request_info_t *req,
    const char *name, uint8_t name_length,
    const char *value, uint32_t value_length)
{
    nxt_unit_buf_t                *buf;
    nxt_unit_field_t              *f;
    nxt_unit_response_t           *resp;
    nxt_unit_request_info_impl_t  *req_impl;

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    if (nxt_slow_path(req_impl->state != NXT_UNIT_RS_RESPONSE_INIT)) {
        nxt_unit_req_warn(req, "add_field: response not initialized or "
                          "already sent");

        return NXT_UNIT_ERROR;
    }

    resp = req->response;

    if (nxt_slow_path(resp->fields_count >= req->response_max_fields)) {
        nxt_unit_req_warn(req, "add_field: too many response fields");

        return NXT_UNIT_ERROR;
    }

    buf = req->response_buf;

    if (nxt_slow_path(name_length + value_length + 2
                      > (uint32_t) (buf->end - buf->free)))
    {
        nxt_unit_req_warn(req, "add_field: response buffer overflow");

        return NXT_UNIT_ERROR;
    }

    nxt_unit_req_debug(req, "add_field #%"PRIu32": %.*s: %.*s",
                       resp->fields_count,
                       (int) name_length, name,
                       (int) value_length, value);

    f = resp->fields + resp->fields_count;

    nxt_unit_sptr_set(&f->name, buf->free);
    buf->free = nxt_cpymem(buf->free, name, name_length);
    *buf->free++ = '\0';

    nxt_unit_sptr_set(&f->value, buf->free);
    buf->free = nxt_cpymem(buf->free, value, value_length);
    *buf->free++ = '\0';

    f->hash = nxt_unit_field_hash(name, name_length);
    f->skip = 0;
    f->name_length = name_length;
    f->value_length = value_length;

    resp->fields_count++;

    return NXT_UNIT_OK;
}


int
nxt_unit_response_add_content(nxt_unit_request_info_t *req,
    const void* src, uint32_t size)
{
    nxt_unit_buf_t                *buf;
    nxt_unit_response_t           *resp;
    nxt_unit_request_info_impl_t  *req_impl;

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    if (nxt_slow_path(req_impl->state < NXT_UNIT_RS_RESPONSE_INIT)) {
        nxt_unit_req_warn(req, "add_content: response not initialized yet");

        return NXT_UNIT_ERROR;
    }

    if (nxt_slow_path(req_impl->state >= NXT_UNIT_RS_RESPONSE_SENT)) {
        nxt_unit_req_warn(req, "add_content: response already sent");

        return NXT_UNIT_ERROR;
    }

    buf = req->response_buf;

    if (nxt_slow_path(size > (uint32_t) (buf->end - buf->free))) {
        nxt_unit_req_warn(req, "add_content: buffer overflow");

        return NXT_UNIT_ERROR;
    }

    resp = req->response;

    if (resp->piggyback_content_length == 0) {
        nxt_unit_sptr_set(&resp->piggyback_content, buf->free);
        req_impl->state = NXT_UNIT_RS_RESPONSE_HAS_CONTENT;
    }

    resp->piggyback_content_length += size;

    buf->free = nxt_cpymem(buf->free, src, size);

    return NXT_UNIT_OK;
}


int
nxt_unit_response_send(nxt_unit_request_info_t *req)
{
    int                           rc;
    nxt_unit_mmap_buf_t           *mmap_buf;
    nxt_unit_request_info_impl_t  *req_impl;

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    if (nxt_slow_path(req_impl->state < NXT_UNIT_RS_RESPONSE_INIT)) {
        nxt_unit_req_warn(req, "send: response is not initialized yet");

        return NXT_UNIT_ERROR;
    }

    if (nxt_slow_path(req_impl->state >= NXT_UNIT_RS_RESPONSE_SENT)) {
        nxt_unit_req_warn(req, "send: response already sent");

        return NXT_UNIT_ERROR;
    }

    nxt_unit_req_debug(req, "send: %"PRIu32" fields, %d bytes",
                       req->response->fields_count,
                       (int) (req->response_buf->free
                              - req->response_buf->start));

    mmap_buf = nxt_container_of(req->response_buf, nxt_unit_mmap_buf_t, buf);

    rc = nxt_unit_mmap_buf_send(req->ctx,
                                req_impl->recv_msg.port_msg.stream,
                                mmap_buf, 0);
    if (nxt_fast_path(rc == NXT_UNIT_OK)) {
        req->response = NULL;
        req->response_buf = NULL;
        req_impl->state = NXT_UNIT_RS_RESPONSE_SENT;

        nxt_unit_mmap_buf_release(mmap_buf);
    }

    return rc;
}


int
nxt_unit_response_is_sent(nxt_unit_request_info_t *req)
{
    nxt_unit_request_info_impl_t  *req_impl;

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    return req_impl->state >= NXT_UNIT_RS_RESPONSE_SENT;
}


nxt_unit_buf_t *
nxt_unit_response_buf_alloc(nxt_unit_request_info_t *req, uint32_t size)
{
    int                           rc;
    nxt_unit_process_t            *process;
    nxt_unit_mmap_buf_t           *mmap_buf;
    nxt_unit_request_info_impl_t  *req_impl;

    if (nxt_slow_path(size > PORT_MMAP_DATA_SIZE)) {
        nxt_unit_req_warn(req, "response_buf_alloc: "
                          "requested buffer (%"PRIu32") too big", size);

        return NULL;
    }

    nxt_unit_req_debug(req, "response_buf_alloc: %"PRIu32, size);

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    process = nxt_unit_msg_get_process(req->ctx, &req_impl->recv_msg);
    if (nxt_slow_path(process == NULL)) {
        return NULL;
    }

    mmap_buf = nxt_unit_mmap_buf_get(req->ctx);
    if (nxt_slow_path(mmap_buf == NULL)) {
        return NULL;
    }

    mmap_buf->req = req;

    nxt_queue_insert_tail(&req_impl->outgoing_buf, &mmap_buf->link);

    rc = nxt_unit_get_outgoing_buf(req->ctx, process, &req->response_port,
                                   size, mmap_buf);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_mmap_buf_release(mmap_buf);

        return NULL;
    }

    return &mmap_buf->buf;
}


static nxt_unit_process_t *
nxt_unit_msg_get_process(nxt_unit_ctx_t *ctx, nxt_unit_recv_msg_t *recv_msg)
{
    nxt_unit_impl_t  *lib;

    if (recv_msg->process != NULL) {
        return recv_msg->process;
    }

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    pthread_mutex_lock(&lib->mutex);

    recv_msg->process = nxt_unit_process_find(ctx, recv_msg->port_msg.pid, 0);

    pthread_mutex_unlock(&lib->mutex);

    if (recv_msg->process == NULL) {
        nxt_unit_warn(ctx, "#%"PRIu32": process %d not found",
                      recv_msg->port_msg.stream, (int) recv_msg->port_msg.pid);
    }

    return recv_msg->process;
}


static nxt_unit_mmap_buf_t *
nxt_unit_mmap_buf_get(nxt_unit_ctx_t *ctx)
{
    nxt_queue_link_t     *lnk;
    nxt_unit_mmap_buf_t  *mmap_buf;
    nxt_unit_ctx_impl_t  *ctx_impl;

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    if (nxt_queue_is_empty(&ctx_impl->free_buf)) {
        mmap_buf = malloc(sizeof(nxt_unit_mmap_buf_t));
        if (nxt_slow_path(mmap_buf == NULL)) {
            nxt_unit_warn(ctx, "failed to allocate buf");
        }

    } else {
        lnk = nxt_queue_first(&ctx_impl->free_buf);
        nxt_queue_remove(lnk);

        mmap_buf = nxt_container_of(lnk, nxt_unit_mmap_buf_t, link);
    }

    mmap_buf->ctx_impl = ctx_impl;

    return mmap_buf;
}


static void
nxt_unit_mmap_buf_release(nxt_unit_mmap_buf_t *mmap_buf)
{
    nxt_queue_remove(&mmap_buf->link);

    nxt_queue_insert_tail(&mmap_buf->ctx_impl->free_buf, &mmap_buf->link);
}


int
nxt_unit_buf_send(nxt_unit_buf_t *buf)
{
    int                           rc;
    nxt_unit_mmap_buf_t           *mmap_buf;
    nxt_unit_request_info_t       *req;
    nxt_unit_request_info_impl_t  *req_impl;

    mmap_buf = nxt_container_of(buf, nxt_unit_mmap_buf_t, buf);

    req = mmap_buf->req;
    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    nxt_unit_req_debug(req, "buf_send: %d bytes",
                       (int) (buf->free - buf->start));

    if (nxt_slow_path(req_impl->state < NXT_UNIT_RS_RESPONSE_INIT)) {
        nxt_unit_req_warn(req, "buf_send: response not initialized yet");

        return NXT_UNIT_ERROR;
    }

    if (nxt_slow_path(req_impl->state < NXT_UNIT_RS_RESPONSE_SENT)) {
        nxt_unit_req_warn(req, "buf_send: headers not sent yet");

        return NXT_UNIT_ERROR;
    }

    if (nxt_fast_path(buf->free > buf->start)) {
        rc = nxt_unit_mmap_buf_send(req->ctx,
                                    req_impl->recv_msg.port_msg.stream,
                                    mmap_buf, 0);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return rc;
        }
    }

    nxt_unit_mmap_buf_release(mmap_buf);

    return NXT_UNIT_OK;
}


static void
nxt_unit_buf_send_done(nxt_unit_buf_t *buf)
{
    int                           rc;
    nxt_unit_mmap_buf_t           *mmap_buf;
    nxt_unit_request_info_t       *req;
    nxt_unit_request_info_impl_t  *req_impl;

    mmap_buf = nxt_container_of(buf, nxt_unit_mmap_buf_t, buf);

    req = mmap_buf->req;
    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    rc = nxt_unit_mmap_buf_send(req->ctx,
                                req_impl->recv_msg.port_msg.stream,
                                mmap_buf, 1);

    if (nxt_slow_path(rc == NXT_UNIT_OK)) {
        nxt_unit_mmap_buf_release(mmap_buf);

        nxt_unit_request_info_release(req);

    } else {
        nxt_unit_request_done(req, rc);
    }
}


static int
nxt_unit_mmap_buf_send(nxt_unit_ctx_t *ctx, uint32_t stream,
    nxt_unit_mmap_buf_t *mmap_buf, int last)
{
    struct {
        nxt_port_msg_t       msg;
        nxt_port_mmap_msg_t  mmap_msg;
    } m;

    u_char                   *end, *last_used, *first_free;
    ssize_t                  res;
    nxt_chunk_id_t           first_free_chunk;
    nxt_unit_buf_t           *buf;
    nxt_unit_impl_t          *lib;
    nxt_port_mmap_header_t   *hdr;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    buf = &mmap_buf->buf;

    m.mmap_msg.size = buf->free - buf->start;

    m.msg.stream = stream;
    m.msg.pid = lib->pid;
    m.msg.reply_port = 0;
    m.msg.type = _NXT_PORT_MSG_DATA;
    m.msg.last = last != 0;
    m.msg.mmap = m.mmap_msg.size > 0;
    m.msg.nf = 0;
    m.msg.mf = 0;
    m.msg.tracking = 0;

    hdr = mmap_buf->hdr;

    m.mmap_msg.mmap_id = hdr->id;
    m.mmap_msg.chunk_id = nxt_port_mmap_chunk_id(hdr, (u_char *) buf->start);

    nxt_unit_debug(ctx, "#%"PRIu32": send mmap: (%d,%d,%d)",
                   stream,
                   (int) m.mmap_msg.mmap_id,
                   (int) m.mmap_msg.chunk_id,
                   (int) m.mmap_msg.size);

    res = lib->callbacks.port_send(ctx, &mmap_buf->port_id, &m,
                                   m.mmap_msg.size > 0 ? sizeof(m)
                                                       : sizeof(m.msg),
                                   NULL, 0);
    if (nxt_slow_path(res != sizeof(m))) {
        return NXT_UNIT_ERROR;
    }

    if (buf->end - buf->free >= PORT_MMAP_CHUNK_SIZE) {
        last_used = (u_char *) buf->free - 1;

        first_free_chunk = nxt_port_mmap_chunk_id(hdr, last_used) + 1;
        first_free = nxt_port_mmap_chunk_start(hdr, first_free_chunk);
        end = (u_char *) buf->end;

        nxt_unit_mmap_release(hdr, first_free, (uint32_t) (end - first_free));

        buf->end = (char *) first_free;
    }

    return NXT_UNIT_OK;
}


void
nxt_unit_buf_free(nxt_unit_buf_t *buf)
{
    nxt_unit_mmap_buf_t  *mmap_buf;

    mmap_buf = nxt_container_of(buf, nxt_unit_mmap_buf_t, buf);

    nxt_unit_mmap_release(mmap_buf->hdr, buf->start, buf->end - buf->start);

    nxt_unit_mmap_buf_release(mmap_buf);
}


nxt_unit_buf_t *
nxt_unit_buf_next(nxt_unit_buf_t *buf)
{
    nxt_queue_link_t              *lnk;
    nxt_unit_mmap_buf_t           *mmap_buf;
    nxt_unit_request_info_impl_t  *req_impl;

    mmap_buf = nxt_container_of(buf, nxt_unit_mmap_buf_t, buf);
    req_impl = nxt_container_of(mmap_buf->req, nxt_unit_request_info_impl_t,
                                req);

    lnk = &mmap_buf->link;

    if (lnk == nxt_queue_last(&req_impl->incoming_buf)
        || lnk == nxt_queue_last(&req_impl->outgoing_buf))
    {
        return NULL;
    }

    lnk = nxt_queue_next(lnk);
    mmap_buf = nxt_container_of(lnk, nxt_unit_mmap_buf_t, link);

    return &mmap_buf->buf;
}


uint32_t
nxt_unit_buf_max(void)
{
    return PORT_MMAP_DATA_SIZE;
}


uint32_t
nxt_unit_buf_min(void)
{
    return PORT_MMAP_CHUNK_SIZE;
}


int
nxt_unit_response_write(nxt_unit_request_info_t *req, const void *start,
    size_t size)
{
    int                           rc;
    uint32_t                      part_size;
    const char                    *part_start;
    nxt_unit_process_t            *process;
    nxt_unit_mmap_buf_t           mmap_buf;
    nxt_unit_request_info_impl_t  *req_impl;

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    part_start = start;

    /* Check if response is not send yet. */
    if (nxt_slow_path(req->response_buf)) {
        part_size = req->response_buf->end - req->response_buf->free;
        part_size = nxt_min(size, part_size);

        rc = nxt_unit_response_add_content(req, part_start, part_size);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return rc;
        }

        rc = nxt_unit_response_send(req);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return rc;
        }

        size -= part_size;
        part_start += part_size;
    }

    process = nxt_unit_msg_get_process(req->ctx, &req_impl->recv_msg);
    if (nxt_slow_path(process == NULL)) {
        return NXT_UNIT_ERROR;
    }

    while (size > 0) {
        part_size = nxt_min(size, PORT_MMAP_DATA_SIZE);

        rc = nxt_unit_get_outgoing_buf(req->ctx, process, &req->response_port,
                                       part_size, &mmap_buf);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return rc;
        }

        mmap_buf.buf.free = nxt_cpymem(mmap_buf.buf.free,
                                       part_start, part_size);

        rc = nxt_unit_mmap_buf_send(req->ctx,
                                    req_impl->recv_msg.port_msg.stream,
                                    &mmap_buf, 0);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            nxt_unit_mmap_release(mmap_buf.hdr, mmap_buf.buf.start,
                                  mmap_buf.buf.end - mmap_buf.buf.start);

            return rc;
        }

        size -= part_size;
        part_start += part_size;
    }

    return NXT_UNIT_OK;
}


int
nxt_unit_response_write_cb(nxt_unit_request_info_t *req,
    nxt_unit_read_info_t *read_info)
{
    int             rc;
    ssize_t         n;
    nxt_unit_buf_t  *buf;

    /* Check if response is not send yet. */
    if (nxt_slow_path(req->response_buf)) {

        /* Enable content in headers buf. */
        rc = nxt_unit_response_add_content(req, "", 0);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            nxt_unit_req_error(req, "Failed to add piggyback content");

            return rc;
        }

        buf = req->response_buf;

        while (buf->end - buf->free > 0) {
            n = read_info->read(read_info, buf->free, buf->end - buf->free);
            if (nxt_slow_path(n < 0)) {
                nxt_unit_req_error(req, "Read error");

                return NXT_UNIT_ERROR;
            }

            /* Manually increase sizes. */
            buf->free += n;
            req->response->piggyback_content_length += n;

            if (read_info->eof) {
                break;
            }
        }

        rc = nxt_unit_response_send(req);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            nxt_unit_req_error(req, "Failed to send headers with content");

            return rc;
        }

        if (read_info->eof) {
            return NXT_UNIT_OK;
        }
    }

    while (!read_info->eof) {
        nxt_unit_req_debug(req, "write_cb, alloc %"PRIu32"",
                           read_info->buf_size);

        buf = nxt_unit_response_buf_alloc(req, nxt_min(read_info->buf_size,
                                                       PORT_MMAP_DATA_SIZE));
        if (nxt_slow_path(buf == NULL)) {
            nxt_unit_req_error(req, "Failed to allocate buf for content");

            return NXT_UNIT_ERROR;
        }

        while (!read_info->eof && buf->end > buf->free) {
            n = read_info->read(read_info, buf->free, buf->end - buf->free);
            if (nxt_slow_path(n < 0)) {
                nxt_unit_req_error(req, "Read error");

                nxt_unit_buf_free(buf);

                return NXT_UNIT_ERROR;
            }

            buf->free += n;
        }

        rc = nxt_unit_buf_send(buf);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            nxt_unit_req_error(req, "Failed to send content");

            return rc;
        }
    }

    return NXT_UNIT_OK;
}


ssize_t
nxt_unit_request_read(nxt_unit_request_info_t *req, void *dst, size_t size)
{
    u_char          *p;
    size_t          rest, copy, read;
    nxt_unit_buf_t  *buf;

    p = dst;
    rest = size;

    buf = req->content_buf;

    while (buf != NULL) {
        copy = buf->end - buf->free;
        copy = nxt_min(rest, copy);

        p = nxt_cpymem(p, buf->free, copy);

        buf->free += copy;
        rest -= copy;

        if (rest == 0) {
            if (buf->end == buf->free) {
                buf = nxt_unit_buf_next(buf);
            }

            break;
        }

        buf = nxt_unit_buf_next(buf);
    }

    req->content_buf = buf;

    read = size - rest;

    req->content_length -= read;

    return read;
}


void
nxt_unit_request_done(nxt_unit_request_info_t *req, int rc)
{
    ssize_t                       res;
    uint32_t                      size;
    nxt_port_msg_t                msg;
    nxt_unit_impl_t               *lib;
    nxt_unit_request_info_impl_t  *req_impl;

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    nxt_unit_req_debug(req, "done: %d", rc);

    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto skip_response_send;
    }

    if (nxt_slow_path(req_impl->state < NXT_UNIT_RS_RESPONSE_INIT)) {

        size = nxt_length("Content-Type") + nxt_length("text/plain");

        rc = nxt_unit_response_init(req, 200, 1, size);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            goto skip_response_send;
        }

        rc = nxt_unit_response_add_field(req, "Content-Type",
                                   nxt_length("Content-Type"),
                                   "text/plain", nxt_length("text/plain"));
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            goto skip_response_send;
        }
    }

    if (nxt_slow_path(req_impl->state < NXT_UNIT_RS_RESPONSE_SENT)) {

        req_impl->state = NXT_UNIT_RS_RESPONSE_SENT;

        nxt_unit_buf_send_done(req->response_buf);

        return;
    }

skip_response_send:

    lib = nxt_container_of(req->unit, nxt_unit_impl_t, unit);

    msg.stream = req_impl->recv_msg.port_msg.stream;
    msg.pid = lib->pid;
    msg.reply_port = 0;
    msg.type = (rc == NXT_UNIT_OK) ? _NXT_PORT_MSG_DATA
                                   : _NXT_PORT_MSG_RPC_ERROR;
    msg.last = 1;
    msg.mmap = 0;
    msg.nf = 0;
    msg.mf = 0;
    msg.tracking = 0;

    res = lib->callbacks.port_send(req->ctx, &req->response_port,
                                   &msg, sizeof(msg), NULL, 0);
    if (nxt_slow_path(res != sizeof(msg))) {
        nxt_unit_req_alert(req, "last message send failed: %s (%d)",
                           strerror(errno), errno);
    }

    nxt_unit_request_info_release(req);
}


static nxt_port_mmap_header_t *
nxt_unit_mmap_get(nxt_unit_ctx_t *ctx, nxt_unit_process_t *process,
    nxt_unit_port_id_t *port_id, nxt_chunk_id_t *c, int n)
{
    int                     res, nchunks, i;
    nxt_unit_mmap_t         *mm, *mm_end;
    nxt_port_mmap_header_t  *hdr;

    pthread_mutex_lock(&process->outgoing.mutex);

    mm_end = process->outgoing.elts + process->outgoing.size;

    for (mm = process->outgoing.elts; mm < mm_end; mm++) {
        hdr = mm->hdr;

        if (hdr->sent_over != 0xFFFFu && hdr->sent_over != port_id->id) {
            continue;
        }

        *c = 0;

        while (nxt_port_mmap_get_free_chunk(hdr->free_map, c)) {
            nchunks = 1;

            while (nchunks < n) {
                res = nxt_port_mmap_chk_set_chunk_busy(hdr->free_map,
                                                       *c + nchunks);

                if (res == 0) {
                    for (i = 0; i < nchunks; i++) {
                        nxt_port_mmap_set_chunk_free(hdr->free_map, *c + i);
                    }

                    *c += nchunks + 1;
                    nchunks = 0;
                    break;
                }

                nchunks++;
            }

            if (nchunks == n) {
                goto unlock;
            }
        }
    }

    *c = 0;
    hdr = nxt_unit_new_mmap(ctx, process, port_id, n);

unlock:

    pthread_mutex_unlock(&process->outgoing.mutex);

    return hdr;
}


static nxt_unit_mmap_t *
nxt_unit_mmap_at(nxt_unit_mmaps_t *mmaps, uint32_t i)
{
    uint32_t  cap;

    cap = mmaps->cap;

    if (cap == 0) {
        cap = i + 1;
    }

    while (i + 1 > cap) {

        if (cap < 16) {
          cap = cap * 2;

        } else {
          cap = cap + cap / 2;
        }
    }

    if (cap != mmaps->cap) {

        mmaps->elts = realloc(mmaps->elts, cap * sizeof(*mmaps->elts));
        if (nxt_slow_path(mmaps->elts == NULL)) {
            return NULL;
        }

        memset(mmaps->elts + mmaps->cap, 0,
               sizeof(*mmaps->elts) * (cap - mmaps->cap));

        mmaps->cap = cap;
    }

    if (i + 1 > mmaps->size) {
        mmaps->size = i + 1;
    }

    return mmaps->elts + i;
}


static nxt_port_mmap_header_t *
nxt_unit_new_mmap(nxt_unit_ctx_t *ctx, nxt_unit_process_t *process,
    nxt_unit_port_id_t *port_id, int n)
{
    int                     i, fd, rc;
    void                    *mem;
    char                    name[64];
    nxt_unit_mmap_t         *mm;
    nxt_unit_impl_t         *lib;
    nxt_port_mmap_header_t  *hdr;

    lib = process->lib;

    mm = nxt_unit_mmap_at(&process->outgoing, process->outgoing.size);
    if (nxt_slow_path(mm == NULL)) {
        nxt_unit_warn(ctx, "failed to add mmap to outgoing array");

        return NULL;
    }

    snprintf(name, sizeof(name), NXT_SHM_PREFIX "unit.%d.%p",
             lib->pid, (void *) pthread_self());

#if (NXT_HAVE_MEMFD_CREATE)

    fd = syscall(SYS_memfd_create, name, MFD_CLOEXEC);
    if (nxt_slow_path(fd == -1)) {
        nxt_unit_alert(ctx, "memfd_create(%s) failed: %s (%d)", name,
                       strerror(errno), errno);

        goto remove_fail;
    }

    nxt_unit_debug(ctx, "memfd_create(%s): %d", name, fd);

#elif (NXT_HAVE_SHM_OPEN_ANON)

    fd = shm_open(SHM_ANON, O_RDWR, S_IRUSR | S_IWUSR);
    if (nxt_slow_path(fd == -1)) {
        nxt_unit_alert(ctx, "shm_open(SHM_ANON) failed: %s (%d)",
                       strerror(errno), errno);

        goto remove_fail;
    }

#elif (NXT_HAVE_SHM_OPEN)

    /* Just in case. */
    shm_unlink(name);

    fd = shm_open(name, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
    if (nxt_slow_path(fd == -1)) {
        nxt_unit_alert(ctx, "shm_open(%s) failed: %s (%d)", name,
                       strerror(errno), errno);

        goto remove_fail;
    }

    if (nxt_slow_path(shm_unlink(name) == -1)) {
        nxt_unit_warn(ctx, "shm_unlink(%s) failed: %s (%d)", name,
                      strerror(errno), errno);
    }

#else

#error No working shared memory implementation.

#endif

    if (nxt_slow_path(ftruncate(fd, PORT_MMAP_SIZE) == -1)) {
        nxt_unit_alert(ctx, "ftruncate(%d) failed: %s (%d)", fd,
                       strerror(errno), errno);

        goto remove_fail;
    }

    mem = mmap(NULL, PORT_MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (nxt_slow_path(mem == MAP_FAILED)) {
        nxt_unit_alert(ctx, "mmap(%d) failed: %s (%d)", fd,
                       strerror(errno), errno);

        goto remove_fail;
    }

    mm->hdr = mem;
    hdr = mem;

    memset(hdr->free_map, 0xFFU, sizeof(hdr->free_map));
    memset(hdr->free_tracking_map, 0xFFU, sizeof(hdr->free_tracking_map));

    hdr->id = process->outgoing.size - 1;
    hdr->src_pid = lib->pid;
    hdr->dst_pid = process->pid;
    hdr->sent_over = port_id->id;

    /* Mark first n chunk(s) as busy */
    for (i = 0; i < n; i++) {
        nxt_port_mmap_set_chunk_busy(hdr->free_map, i);
    }

    /* Mark as busy chunk followed the last available chunk. */
    nxt_port_mmap_set_chunk_busy(hdr->free_map, PORT_MMAP_CHUNK_COUNT);
    nxt_port_mmap_set_chunk_busy(hdr->free_tracking_map, PORT_MMAP_CHUNK_COUNT);

    pthread_mutex_unlock(&process->outgoing.mutex);

    rc = nxt_unit_send_mmap(ctx, port_id, fd);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        munmap(mem, PORT_MMAP_SIZE);
        hdr = NULL;

    } else {
        nxt_unit_debug(ctx, "new mmap #%"PRIu32" created for %d -> %d",
                       hdr->id, (int) lib->pid, (int) process->pid);
    }

    close(fd);

    pthread_mutex_lock(&process->outgoing.mutex);

    if (nxt_fast_path(hdr != NULL)) {
        return hdr;
    }

remove_fail:

    process->outgoing.size--;

    return NULL;
}


static int
nxt_unit_send_mmap(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id, int fd)
{
    ssize_t          res;
    nxt_port_msg_t   msg;
    nxt_unit_impl_t  *lib;
    union {
        struct cmsghdr  cm;
        char            space[CMSG_SPACE(sizeof(int))];
    } cmsg;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    msg.stream = 0;
    msg.pid = lib->pid;
    msg.reply_port = 0;
    msg.type = _NXT_PORT_MSG_MMAP;
    msg.last = 0;
    msg.mmap = 0;
    msg.nf = 0;
    msg.mf = 0;
    msg.tracking = 0;

    /*
     * Fill all padding fields with 0.
     * Code in Go 1.11 validate cmsghdr using padding field as part of len.
     * See Cmsghdr definition and socketControlMessageHeaderAndData function.
     */
    memset(&cmsg, 0, sizeof(cmsg));

    cmsg.cm.cmsg_len = CMSG_LEN(sizeof(int));
    cmsg.cm.cmsg_level = SOL_SOCKET;
    cmsg.cm.cmsg_type = SCM_RIGHTS;

    /*
     * memcpy() is used instead of simple
     *   *(int *) CMSG_DATA(&cmsg.cm) = fd;
     * because GCC 4.4 with -O2/3/s optimization may issue a warning:
     *   dereferencing type-punned pointer will break strict-aliasing rules
     *
     * Fortunately, GCC with -O1 compiles this nxt_memcpy()
     * in the same simple assignment as in the code above.
     */
    memcpy(CMSG_DATA(&cmsg.cm), &fd, sizeof(int));

    res = lib->callbacks.port_send(ctx, port_id, &msg, sizeof(msg),
                                   &cmsg, sizeof(cmsg));
    if (nxt_slow_path(res != sizeof(msg))) {
        nxt_unit_warn(ctx, "failed to send shm to %d: %s (%d)",
                      (int) port_id->pid, strerror(errno), errno);

        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


static int
nxt_unit_get_outgoing_buf(nxt_unit_ctx_t *ctx, nxt_unit_process_t *process,
    nxt_unit_port_id_t *port_id, uint32_t size,
    nxt_unit_mmap_buf_t *mmap_buf)
{
    uint32_t                nchunks;
    nxt_chunk_id_t          c;
    nxt_port_mmap_header_t  *hdr;

    nchunks = (size + PORT_MMAP_CHUNK_SIZE - 1) / PORT_MMAP_CHUNK_SIZE;

    hdr = nxt_unit_mmap_get(ctx, process, port_id, &c, nchunks);
    if (nxt_slow_path(hdr == NULL)) {
        return NXT_UNIT_ERROR;
    }

    mmap_buf->hdr = hdr;
    mmap_buf->buf.start = (char *) nxt_port_mmap_chunk_start(hdr, c);
    mmap_buf->buf.free = mmap_buf->buf.start;
    mmap_buf->buf.end = mmap_buf->buf.start + nchunks * PORT_MMAP_CHUNK_SIZE;
    mmap_buf->port_id = *port_id;

    nxt_unit_debug(ctx, "outgoing mmap allocation: (%d,%d,%d)",
                  (int) hdr->id, (int) c,
                  (int) (nchunks * PORT_MMAP_CHUNK_SIZE));

    return NXT_UNIT_OK;
}


static int
nxt_unit_incoming_mmap(nxt_unit_ctx_t *ctx, pid_t pid, int fd)
{
    int                      rc;
    void                     *mem;
    struct stat              mmap_stat;
    nxt_unit_mmap_t          *mm;
    nxt_unit_impl_t          *lib;
    nxt_unit_process_t       *process;
    nxt_port_mmap_header_t   *hdr;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    nxt_unit_debug(ctx, "incoming_mmap: fd %d from process %d", fd, (int) pid);

    pthread_mutex_lock(&lib->mutex);

    process = nxt_unit_process_find(ctx, pid, 0);

    pthread_mutex_unlock(&lib->mutex);

    if (nxt_slow_path(process == NULL)) {
        nxt_unit_warn(ctx, "incoming_mmap: process %d not found, fd %d",
                      (int) pid, fd);

        return NXT_UNIT_ERROR;
    }

    rc = NXT_UNIT_ERROR;

    if (fstat(fd, &mmap_stat) == -1) {
        nxt_unit_warn(ctx, "incoming_mmap: fstat(%d) failed: %s (%d)", fd,
                      strerror(errno), errno);

        goto fail;
    }

    mem = mmap(NULL, mmap_stat.st_size, PROT_READ | PROT_WRITE,
               MAP_SHARED, fd, 0);
    if (nxt_slow_path(mem == MAP_FAILED)) {
        nxt_unit_warn(ctx, "incoming_mmap: mmap() failed: %s (%d)",
                      strerror(errno), errno);

        goto fail;
    }

    hdr = mem;

    if (nxt_slow_path(hdr->src_pid != pid || hdr->dst_pid != lib->pid)) {

        nxt_unit_warn(ctx, "incoming_mmap: unexpected pid in mmap header "
                      "detected: %d != %d or %d != %d", (int) hdr->src_pid,
                      (int) pid, (int) hdr->dst_pid, (int) lib->pid);

        munmap(mem, PORT_MMAP_SIZE);

        goto fail;
    }

    pthread_mutex_lock(&process->incoming.mutex);

    mm = nxt_unit_mmap_at(&process->incoming, hdr->id);
    if (nxt_slow_path(mm == NULL)) {
        nxt_unit_warn(ctx, "incoming_mmap: failed to add to incoming array");

        munmap(mem, PORT_MMAP_SIZE);

    } else {
        mm->hdr = hdr;

        hdr->sent_over = 0xFFFFu;

        rc = NXT_UNIT_OK;
    }

    pthread_mutex_unlock(&process->incoming.mutex);

fail:

    nxt_unit_process_use(ctx, process, -1);

    return rc;
}


static void
nxt_unit_mmaps_init(nxt_unit_mmaps_t *mmaps)
{
    pthread_mutex_init(&mmaps->mutex, NULL);

    mmaps->size = 0;
    mmaps->cap = 0;
    mmaps->elts = NULL;
}


static void
nxt_unit_process_use(nxt_unit_ctx_t *ctx, nxt_unit_process_t *process, int i)
{
    long c;

    c = nxt_atomic_fetch_add(&process->use_count, i);

    if (i < 0 && c == -i) {
        nxt_unit_debug(ctx, "destroy process #%d", (int) process->pid);

        nxt_unit_mmaps_destroy(&process->incoming);
        nxt_unit_mmaps_destroy(&process->outgoing);

        free(process);
    }
}


static void
nxt_unit_mmaps_destroy(nxt_unit_mmaps_t *mmaps)
{
    nxt_unit_mmap_t  *mm, *end;

    if (mmaps->elts != NULL) {
        end = mmaps->elts + mmaps->size;

        for (mm = mmaps->elts; mm < end; mm++) {
            munmap(mm->hdr, PORT_MMAP_SIZE);
        }

        free(mmaps->elts);
    }

    pthread_mutex_destroy(&mmaps->mutex);
}


static nxt_port_mmap_header_t *
nxt_unit_get_incoming_mmap(nxt_unit_ctx_t *ctx, nxt_unit_process_t *process,
    uint32_t id)
{
    nxt_port_mmap_header_t  *hdr;

    if (nxt_fast_path(process->incoming.size > id)) {
        hdr = process->incoming.elts[id].hdr;

    } else {
        hdr = NULL;
    }

    return hdr;
}


static int
nxt_unit_tracking_read(nxt_unit_ctx_t *ctx, nxt_unit_recv_msg_t *recv_msg)
{
    int                           rc;
    nxt_chunk_id_t                c;
    nxt_unit_process_t            *process;
    nxt_port_mmap_header_t        *hdr;
    nxt_port_mmap_tracking_msg_t  *tracking_msg;

    if (recv_msg->size < (int) sizeof(nxt_port_mmap_tracking_msg_t)) {
        nxt_unit_warn(ctx, "#%"PRIu32": tracking_read: too small message (%d)",
                      recv_msg->port_msg.stream, (int) recv_msg->size);

        return 0;
    }

    tracking_msg = recv_msg->start;

    recv_msg->start = tracking_msg + 1;
    recv_msg->size -= sizeof(nxt_port_mmap_tracking_msg_t);

    process = nxt_unit_msg_get_process(ctx, recv_msg);
    if (nxt_slow_path(process == NULL)) {
        return 0;
    }

    pthread_mutex_lock(&process->incoming.mutex);

    hdr = nxt_unit_get_incoming_mmap(ctx, process, tracking_msg->mmap_id);
    if (nxt_slow_path(hdr == NULL)) {
        pthread_mutex_unlock(&process->incoming.mutex);

        nxt_unit_warn(ctx, "#%"PRIu32": tracking_read: "
                      "invalid mmap id %d,%"PRIu32,
                      recv_msg->port_msg.stream,
                      (int) process->pid, tracking_msg->mmap_id);

        return 0;
    }

    c = tracking_msg->tracking_id;
    rc = nxt_atomic_cmp_set(hdr->tracking + c, recv_msg->port_msg.stream, 0);

    if (rc == 0) {
        nxt_unit_debug(ctx, "#%"PRIu32": tracking cancelled",
                       recv_msg->port_msg.stream);

        nxt_port_mmap_set_chunk_free(hdr->free_tracking_map, c);
    }

    pthread_mutex_unlock(&process->incoming.mutex);

    return rc;
}


static int
nxt_unit_mmap_read(nxt_unit_ctx_t *ctx, nxt_unit_recv_msg_t *recv_msg,
    nxt_queue_t *incoming_buf)
{
    void                    *start;
    uint32_t                size;
    nxt_unit_process_t      *process;
    nxt_unit_mmap_buf_t     *b;
    nxt_port_mmap_msg_t     *mmap_msg, *end;
    nxt_port_mmap_header_t  *hdr;

    if (nxt_slow_path(recv_msg->size < sizeof(nxt_port_mmap_msg_t))) {
        nxt_unit_warn(ctx, "#%"PRIu32": mmap_read: too small message (%d)",
                      recv_msg->port_msg.stream, (int) recv_msg->size);

        return NXT_UNIT_ERROR;
    }

    process = nxt_unit_msg_get_process(ctx, recv_msg);
    if (nxt_slow_path(process == NULL)) {
        return NXT_UNIT_ERROR;
    }

    mmap_msg = recv_msg->start;
    end = nxt_pointer_to(recv_msg->start, recv_msg->size);

    pthread_mutex_lock(&process->incoming.mutex);

    for (; mmap_msg < end; mmap_msg++) {
        hdr = nxt_unit_get_incoming_mmap(ctx, process, mmap_msg->mmap_id);
        if (nxt_slow_path(hdr == NULL)) {
            pthread_mutex_unlock(&process->incoming.mutex);

            nxt_unit_warn(ctx, "#%"PRIu32": mmap_read: "
                          "invalid mmap id %d,%"PRIu32,
                          recv_msg->port_msg.stream,
                          (int) process->pid, mmap_msg->mmap_id);

            return NXT_UNIT_ERROR;
        }

        start = nxt_port_mmap_chunk_start(hdr, mmap_msg->chunk_id);
        size = mmap_msg->size;

        if (recv_msg->start == mmap_msg) {
            recv_msg->start = start;
            recv_msg->size = size;
        }

        b = nxt_unit_mmap_buf_get(ctx);
        if (nxt_slow_path(b == NULL)) {
            pthread_mutex_unlock(&process->incoming.mutex);

            nxt_unit_warn(ctx, "#%"PRIu32": mmap_read: "
                          "failed to allocate buf",
                          recv_msg->port_msg.stream);

            nxt_unit_mmap_release(hdr, start, size);

            return NXT_UNIT_ERROR;
        }

        nxt_queue_insert_tail(incoming_buf, &b->link);

        b->buf.start = start;
        b->buf.free = start;
        b->buf.end = b->buf.start + size;
        b->hdr = hdr;

        nxt_unit_debug(ctx, "#%"PRIu32": mmap_read: [%p,%d] %d->%d,(%d,%d,%d)",
                       recv_msg->port_msg.stream,
                       start, (int) size,
                       (int) hdr->src_pid, (int) hdr->dst_pid,
                       (int) hdr->id, (int) mmap_msg->chunk_id,
                       (int) mmap_msg->size);
    }

    pthread_mutex_unlock(&process->incoming.mutex);

    return NXT_UNIT_OK;
}


static int
nxt_unit_mmap_release(nxt_port_mmap_header_t *hdr, void *start, uint32_t size)
{
    u_char          *p, *end;
    nxt_chunk_id_t  c;

    memset(start, 0xA5, size);

    p = start;
    end = p + size;
    c = nxt_port_mmap_chunk_id(hdr, p);

    while (p < end) {
        nxt_port_mmap_set_chunk_free(hdr->free_map, c);

        p += PORT_MMAP_CHUNK_SIZE;
        c++;
    }

    return NXT_UNIT_OK;
}


static nxt_int_t
nxt_unit_lvlhsh_pid_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_process_t  *process;

    process = data;

    if (lhq->key.length == sizeof(pid_t)
        && *(pid_t *) lhq->key.start == process->pid)
    {
        return NXT_OK;
    }

    return NXT_DECLINED;
}


static const nxt_lvlhsh_proto_t  lvlhsh_processes_proto  nxt_aligned(64) = {
    NXT_LVLHSH_DEFAULT,
    nxt_unit_lvlhsh_pid_test,
    nxt_lvlhsh_alloc,
    nxt_lvlhsh_free,
};


static inline void
nxt_unit_process_lhq_pid(nxt_lvlhsh_query_t *lhq, pid_t *pid)
{
    lhq->key_hash = nxt_murmur_hash2(pid, sizeof(*pid));
    lhq->key.length = sizeof(*pid);
    lhq->key.start = (u_char *) pid;
    lhq->proto = &lvlhsh_processes_proto;
}


static nxt_unit_process_t *
nxt_unit_process_get(nxt_unit_ctx_t *ctx, pid_t pid)
{
    nxt_unit_impl_t     *lib;
    nxt_unit_process_t  *process;
    nxt_lvlhsh_query_t  lhq;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    nxt_unit_process_lhq_pid(&lhq, &pid);

    if (nxt_lvlhsh_find(&lib->processes, &lhq) == NXT_OK) {
        process = lhq.value;
        nxt_unit_process_use(ctx, process, 1);

        return process;
    }

    process = malloc(sizeof(nxt_unit_process_t));
    if (nxt_slow_path(process == NULL)) {
        nxt_unit_warn(ctx, "failed to allocate process for #%d", (int) pid);

        return NULL;
    }

    process->pid = pid;
    process->use_count = 1;
    process->next_port_id = 0;
    process->lib = lib;

    nxt_queue_init(&process->ports);

    nxt_unit_mmaps_init(&process->incoming);
    nxt_unit_mmaps_init(&process->outgoing);

    lhq.replace = 0;
    lhq.value = process;

    switch (nxt_lvlhsh_insert(&lib->processes, &lhq)) {

    case NXT_OK:
        break;

    default:
        nxt_unit_warn(ctx, "process %d insert failed", (int) pid);

        pthread_mutex_destroy(&process->outgoing.mutex);
        pthread_mutex_destroy(&process->incoming.mutex);
        free(process);
        process = NULL;
        break;
    }

    nxt_unit_process_use(ctx, process, 1);

    return process;
}


static nxt_unit_process_t *
nxt_unit_process_find(nxt_unit_ctx_t *ctx, pid_t pid, int remove)
{
    int                 rc;
    nxt_unit_impl_t     *lib;
    nxt_unit_process_t  *process;
    nxt_lvlhsh_query_t  lhq;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    nxt_unit_process_lhq_pid(&lhq, &pid);

    if (remove) {
        rc = nxt_lvlhsh_delete(&lib->processes, &lhq);

    } else {
        rc = nxt_lvlhsh_find(&lib->processes, &lhq);
    }

    if (rc == NXT_OK) {
        process = lhq.value;

        if (!remove) {
            nxt_unit_process_use(ctx, process, 1);
        }

        return process;
    }

    return NULL;
}


static nxt_unit_process_t *
nxt_unit_process_pop_first(nxt_unit_impl_t *lib)
{
    return nxt_lvlhsh_retrieve(&lib->processes, &lvlhsh_processes_proto, NULL);
}


int
nxt_unit_run(nxt_unit_ctx_t *ctx)
{
    int              rc;
    nxt_unit_impl_t  *lib;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);
    rc = NXT_UNIT_OK;

    while (nxt_fast_path(lib->online)) {
        rc = nxt_unit_run_once(ctx);
    }

    return rc;
}


int
nxt_unit_run_once(nxt_unit_ctx_t *ctx)
{
    int                  rc;
    char                 buf[4096];
    char                 oob[256];
    ssize_t              rsize;
    nxt_unit_impl_t      *lib;
    nxt_unit_ctx_impl_t  *ctx_impl;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);
    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    memset(oob, 0, sizeof(struct cmsghdr));

    if (ctx_impl->read_port_fd != -1) {
        rsize = nxt_unit_port_recv(ctx, ctx_impl->read_port_fd,
                                         buf, sizeof(buf),
                                         oob, sizeof(oob));
    } else {
        rsize = lib->callbacks.port_recv(ctx, &ctx_impl->read_port_id,
                                         buf, sizeof(buf),
                                         oob, sizeof(oob));
    }

    if (nxt_fast_path(rsize > 0)) {
        rc = nxt_unit_process_msg(ctx, &ctx_impl->read_port_id, buf, rsize,
                                  oob, sizeof(oob));
    } else {
        rc = NXT_UNIT_ERROR;
    }

    return rc;
}


void
nxt_unit_done(nxt_unit_ctx_t *ctx)
{
    nxt_unit_impl_t      *lib;
    nxt_unit_process_t   *process;
    nxt_unit_ctx_impl_t  *ctx_impl;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    nxt_queue_each(ctx_impl, &lib->contexts, nxt_unit_ctx_impl_t, link) {

        nxt_unit_ctx_free(&ctx_impl->ctx);

    } nxt_queue_loop;

    for ( ;; ) {
        pthread_mutex_lock(&lib->mutex);

        process = nxt_unit_process_pop_first(lib);
        if (process == NULL) {
            pthread_mutex_unlock(&lib->mutex);

            break;
        }

        nxt_unit_remove_process(ctx, process);
    }

    pthread_mutex_destroy(&lib->mutex);

    free(lib);
}


nxt_unit_ctx_t *
nxt_unit_ctx_alloc(nxt_unit_ctx_t *ctx, void *data)
{
    int                  rc, fd;
    nxt_unit_impl_t      *lib;
    nxt_unit_port_id_t   new_port_id;
    nxt_unit_ctx_impl_t  *new_ctx;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    new_ctx = malloc(sizeof(nxt_unit_ctx_impl_t) + lib->request_data_size);
    if (nxt_slow_path(new_ctx == NULL)) {
        nxt_unit_warn(ctx, "failed to allocate context");

        return NULL;
    }

    rc = nxt_unit_create_port(ctx, &new_port_id, &fd);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        free(new_ctx);

        return NULL;
    }

    rc = nxt_unit_send_port(ctx, &lib->ready_port_id, &new_port_id, fd);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        lib->callbacks.remove_port(ctx, &new_port_id);

        close(fd);

        free(new_ctx);

        return NULL;
    }

    close(fd);

    nxt_unit_ctx_init(lib, new_ctx, data);

    new_ctx->read_port_id = new_port_id;

    return &new_ctx->ctx;
}


void
nxt_unit_ctx_free(nxt_unit_ctx_t *ctx)
{
    nxt_unit_impl_t               *lib;
    nxt_unit_ctx_impl_t           *ctx_impl;
    nxt_unit_mmap_buf_t           *mmap_buf;
    nxt_unit_request_info_impl_t  *req_impl;

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);
    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    nxt_queue_each(req_impl, &ctx_impl->active_req,
                   nxt_unit_request_info_impl_t, link)
    {
        nxt_unit_req_warn(&req_impl->req, "active request on ctx free");

        nxt_unit_request_done(&req_impl->req, NXT_UNIT_ERROR);

    } nxt_queue_loop;

    nxt_queue_remove(&ctx_impl->ctx_buf[0].link);
    nxt_queue_remove(&ctx_impl->ctx_buf[1].link);

    nxt_queue_each(mmap_buf, &ctx_impl->free_buf, nxt_unit_mmap_buf_t, link) {

        nxt_queue_remove(&mmap_buf->link);
        free(mmap_buf);

    } nxt_queue_loop;

    nxt_queue_each(req_impl, &ctx_impl->free_req,
                   nxt_unit_request_info_impl_t, link)
    {
        nxt_unit_request_info_free(req_impl);

    } nxt_queue_loop;

    nxt_queue_remove(&ctx_impl->link);

    if (ctx_impl != &lib->main_ctx) {
        free(ctx_impl);
    }
}


/* SOCK_SEQPACKET is disabled to test SOCK_DGRAM on all platforms. */
#if (0 || NXT_HAVE_AF_UNIX_SOCK_SEQPACKET)
#define NXT_UNIX_SOCKET  SOCK_SEQPACKET
#else
#define NXT_UNIX_SOCKET  SOCK_DGRAM
#endif


void
nxt_unit_port_id_init(nxt_unit_port_id_t *port_id, pid_t pid, uint16_t id)
{
    nxt_unit_port_hash_id_t  port_hash_id;

    port_hash_id.pid = pid;
    port_hash_id.id = id;

    port_id->pid = pid;
    port_id->hash = nxt_murmur_hash2(&port_hash_id, sizeof(port_hash_id));
    port_id->id = id;
}


int
nxt_unit_create_send_port(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *dst,
    nxt_unit_port_id_t *port_id)
{
    int                 rc, fd;
    nxt_unit_impl_t     *lib;
    nxt_unit_port_id_t  new_port_id;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    rc = nxt_unit_create_port(ctx, &new_port_id, &fd);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return rc;
    }

    rc = nxt_unit_send_port(ctx, dst, &new_port_id, fd);

    if (nxt_fast_path(rc == NXT_UNIT_OK)) {
        *port_id = new_port_id;

    } else {
        lib->callbacks.remove_port(ctx, &new_port_id);
    }

    close(fd);

    return rc;
}


static int
nxt_unit_create_port(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id, int *fd)
{
    int                 rc, port_sockets[2];
    nxt_unit_impl_t     *lib;
    nxt_unit_port_t     new_port;
    nxt_unit_process_t  *process;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    rc = socketpair(AF_UNIX, NXT_UNIX_SOCKET, 0, port_sockets);
    if (nxt_slow_path(rc != 0)) {
        nxt_unit_warn(ctx, "create_port: socketpair() failed: %s (%d)",
                      strerror(errno), errno);

        return NXT_UNIT_ERROR;
    }

    nxt_unit_debug(ctx, "create_port: new socketpair: %d->%d",
                   port_sockets[0], port_sockets[1]);

    pthread_mutex_lock(&lib->mutex);

    process = nxt_unit_process_get(ctx, lib->pid);
    if (nxt_slow_path(process == NULL)) {
        pthread_mutex_unlock(&lib->mutex);

        close(port_sockets[0]);
        close(port_sockets[1]);

        return NXT_UNIT_ERROR;
    }

    nxt_unit_port_id_init(&new_port.id, lib->pid, process->next_port_id++);

    new_port.in_fd = port_sockets[0];
    new_port.out_fd = -1;
    new_port.data = NULL;

    pthread_mutex_unlock(&lib->mutex);

    nxt_unit_process_use(ctx, process, -1);

    rc = lib->callbacks.add_port(ctx, &new_port);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_warn(ctx, "create_port: add_port() failed");

        close(port_sockets[0]);
        close(port_sockets[1]);

        return rc;
    }

    *port_id = new_port.id;
    *fd = port_sockets[1];

    return rc;
}


static int
nxt_unit_send_port(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *dst,
    nxt_unit_port_id_t *new_port, int fd)
{
    ssize_t          res;
    nxt_unit_impl_t  *lib;

    struct {
        nxt_port_msg_t            msg;
        nxt_port_msg_new_port_t   new_port;
    } m;

    union {
        struct cmsghdr  cm;
        char            space[CMSG_SPACE(sizeof(int))];
    } cmsg;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    m.msg.stream = 0;
    m.msg.pid = lib->pid;
    m.msg.reply_port = 0;
    m.msg.type = _NXT_PORT_MSG_NEW_PORT;
    m.msg.last = 0;
    m.msg.mmap = 0;
    m.msg.nf = 0;
    m.msg.mf = 0;
    m.msg.tracking = 0;

    m.new_port.id = new_port->id;
    m.new_port.pid = new_port->pid;
    m.new_port.type = NXT_PROCESS_WORKER;
    m.new_port.max_size = 16 * 1024;
    m.new_port.max_share = 64 * 1024;

    memset(&cmsg, 0, sizeof(cmsg));

    cmsg.cm.cmsg_len = CMSG_LEN(sizeof(int));
    cmsg.cm.cmsg_level = SOL_SOCKET;
    cmsg.cm.cmsg_type = SCM_RIGHTS;

    /*
     * memcpy() is used instead of simple
     *   *(int *) CMSG_DATA(&cmsg.cm) = fd;
     * because GCC 4.4 with -O2/3/s optimization may issue a warning:
     *   dereferencing type-punned pointer will break strict-aliasing rules
     *
     * Fortunately, GCC with -O1 compiles this nxt_memcpy()
     * in the same simple assignment as in the code above.
     */
    memcpy(CMSG_DATA(&cmsg.cm), &fd, sizeof(int));

    res = lib->callbacks.port_send(ctx, dst, &m, sizeof(m),
                                   &cmsg, sizeof(cmsg));

    return res == sizeof(m) ? NXT_UNIT_OK : NXT_UNIT_ERROR;
}


int
nxt_unit_add_port(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port)
{
    int                   rc;
    nxt_unit_impl_t       *lib;
    nxt_unit_process_t    *process;
    nxt_unit_port_impl_t  *new_port;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    nxt_unit_debug(ctx, "add_port: %d,%d in_fd %d out_fd %d",
                   port->id.pid, port->id.id,
                   port->in_fd, port->out_fd);

    pthread_mutex_lock(&lib->mutex);

    process = nxt_unit_process_get(ctx, port->id.pid);
    if (nxt_slow_path(process == NULL)) {
        rc = NXT_UNIT_ERROR;
        goto unlock;
    }

    if (port->id.id >= process->next_port_id) {
        process->next_port_id = port->id.id + 1;
    }

    new_port = malloc(sizeof(nxt_unit_port_impl_t));
    if (nxt_slow_path(new_port == NULL)) {
        rc = NXT_UNIT_ERROR;
        goto unlock;
    }

    new_port->port = *port;

    rc = nxt_unit_port_hash_add(&lib->ports, &new_port->port);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto unlock;
    }

    nxt_queue_insert_tail(&process->ports, &new_port->link);

    rc = NXT_UNIT_OK;

    new_port->process = process;

unlock:

    pthread_mutex_unlock(&lib->mutex);

    if (nxt_slow_path(process != NULL && rc != NXT_UNIT_OK)) {
        nxt_unit_process_use(ctx, process, -1);
    }

    return rc;
}


void
nxt_unit_remove_port(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id)
{
    nxt_unit_find_remove_port(ctx, port_id, NULL);
}


void
nxt_unit_find_remove_port(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id,
    nxt_unit_port_t *r_port)
{
    nxt_unit_impl_t     *lib;
    nxt_unit_process_t  *process;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    pthread_mutex_lock(&lib->mutex);

    process = NULL;

    nxt_unit_remove_port_unsafe(ctx, port_id, r_port, &process);

    pthread_mutex_unlock(&lib->mutex);

    if (nxt_slow_path(process != NULL)) {
        nxt_unit_process_use(ctx, process, -1);
    }
}


static void
nxt_unit_remove_port_unsafe(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id,
    nxt_unit_port_t *r_port, nxt_unit_process_t **process)
{
    nxt_unit_impl_t       *lib;
    nxt_unit_port_impl_t  *port;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    port = nxt_unit_port_hash_find(&lib->ports, port_id, 1);
    if (nxt_slow_path(port == NULL)) {
        nxt_unit_debug(ctx, "remove_port: port %d,%d not found",
                       (int) port_id->pid, (int) port_id->id);

        return;
    }

    nxt_unit_debug(ctx, "remove_port: port %d,%d, fds %d,%d, data %p",
                   (int) port_id->pid, (int) port_id->id,
                   port->port.in_fd, port->port.out_fd, port->port.data);

    if (port->port.in_fd != -1) {
        close(port->port.in_fd);
    }

    if (port->port.out_fd != -1) {
        close(port->port.out_fd);
    }

    if (port->process != NULL) {
        nxt_queue_remove(&port->link);
    }

    if (process != NULL) {
        *process = port->process;
    }

    if (r_port != NULL) {
        *r_port = port->port;
    }

    free(port);
}


void
nxt_unit_remove_pid(nxt_unit_ctx_t *ctx, pid_t pid)
{
    nxt_unit_impl_t     *lib;
    nxt_unit_process_t  *process;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    pthread_mutex_lock(&lib->mutex);

    process = nxt_unit_process_find(ctx, pid, 1);
    if (nxt_slow_path(process == NULL)) {
        nxt_unit_debug(ctx, "remove_pid: process %d not found", (int) pid);

        pthread_mutex_unlock(&lib->mutex);

        return;
    }

    nxt_unit_remove_process(ctx, process);
}


static void
nxt_unit_remove_process(nxt_unit_ctx_t *ctx, nxt_unit_process_t *process)
{
    nxt_queue_t           ports;
    nxt_unit_impl_t       *lib;
    nxt_unit_port_impl_t  *port;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    nxt_queue_init(&ports);

    nxt_queue_add(&ports, &process->ports);

    nxt_queue_each(port, &ports, nxt_unit_port_impl_t, link) {

        nxt_unit_process_use(ctx, process, -1);
        port->process = NULL;

        /* Shortcut for default callback. */
        if (lib->callbacks.remove_port == nxt_unit_remove_port) {
            nxt_queue_remove(&port->link);

            nxt_unit_remove_port_unsafe(ctx, &port->port.id, NULL, NULL);
        }

    } nxt_queue_loop;

    pthread_mutex_unlock(&lib->mutex);

    nxt_queue_each(port, &ports, nxt_unit_port_impl_t, link) {

        nxt_queue_remove(&port->link);

        lib->callbacks.remove_port(ctx, &port->port.id);

    } nxt_queue_loop;

    nxt_unit_process_use(ctx, process, -1);
}


void
nxt_unit_quit(nxt_unit_ctx_t *ctx)
{
    nxt_unit_impl_t  *lib;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    lib->online = 0;
}


static ssize_t
nxt_unit_port_send_default(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id,
    const void *buf, size_t buf_size, const void *oob, size_t oob_size)
{
    int                   fd;
    nxt_unit_impl_t       *lib;
    nxt_unit_port_impl_t  *port;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    pthread_mutex_lock(&lib->mutex);

    port = nxt_unit_port_hash_find(&lib->ports, port_id, 0);

    if (nxt_fast_path(port != NULL)) {
        fd = port->port.out_fd;

    } else {
        nxt_unit_warn(ctx, "port_send: port %d,%d not found",
                      (int) port_id->pid, (int) port_id->id);
        fd = -1;
    }

    pthread_mutex_unlock(&lib->mutex);

    if (nxt_slow_path(fd == -1)) {
        if (port != NULL) {
            nxt_unit_warn(ctx, "port_send: port %d,%d: fd == -1",
                          (int) port_id->pid, (int) port_id->id);
        }

        return -1;
    }

    nxt_unit_debug(ctx, "port_send: found port %d,%d fd %d",
                   (int) port_id->pid, (int) port_id->id, fd);

    return nxt_unit_port_send(ctx, fd, buf, buf_size, oob, oob_size);
}


ssize_t
nxt_unit_port_send(nxt_unit_ctx_t *ctx, int fd,
    const void *buf, size_t buf_size, const void *oob, size_t oob_size)
{
    ssize_t        res;
    struct iovec   iov[1];
    struct msghdr  msg;

    iov[0].iov_base = (void *) buf;
    iov[0].iov_len = buf_size;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = (void *) oob;
    msg.msg_controllen = oob_size;

    res = sendmsg(fd, &msg, 0);

    if (nxt_slow_path(res == -1)) {
        nxt_unit_warn(ctx, "port_send(%d, %d) failed: %s (%d)",
                      fd, (int) buf_size, strerror(errno), errno);

    } else {
        nxt_unit_debug(ctx, "port_send(%d, %d): %d", fd, (int) buf_size,
                       (int) res);
    }

    return res;
}


static ssize_t
nxt_unit_port_recv_default(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id,
    void *buf, size_t buf_size, void *oob, size_t oob_size)
{
    int                   fd;
    nxt_unit_impl_t       *lib;
    nxt_unit_ctx_impl_t   *ctx_impl;
    nxt_unit_port_impl_t  *port;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    pthread_mutex_lock(&lib->mutex);

    port = nxt_unit_port_hash_find(&lib->ports, port_id, 0);

    if (nxt_fast_path(port != NULL)) {
        fd = port->port.in_fd;

    } else {
        nxt_unit_debug(ctx, "port_recv: port %d,%d not found",
                       (int) port_id->pid, (int) port_id->id);
        fd = -1;
    }

    pthread_mutex_unlock(&lib->mutex);

    if (nxt_slow_path(fd == -1)) {
        return -1;
    }

    nxt_unit_debug(ctx, "port_recv: found port %d,%d, fd %d",
                   (int) port_id->pid, (int) port_id->id, fd);

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    if (nxt_fast_path(port_id == &ctx_impl->read_port_id)) {
        ctx_impl->read_port_fd = fd;
    }

    return nxt_unit_port_recv(ctx, fd, buf, buf_size, oob, oob_size);
}


ssize_t
nxt_unit_port_recv(nxt_unit_ctx_t *ctx, int fd, void *buf, size_t buf_size,
    void *oob, size_t oob_size)
{
    ssize_t        res;
    struct iovec   iov[1];
    struct msghdr  msg;

    iov[0].iov_base = buf;
    iov[0].iov_len = buf_size;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = oob;
    msg.msg_controllen = oob_size;

    res = recvmsg(fd, &msg, 0);

    if (nxt_slow_path(res == -1)) {
        nxt_unit_warn(ctx, "port_recv(%d) failed: %s (%d)",
                      fd, strerror(errno), errno);

    } else {
        nxt_unit_debug(ctx, "port_recv(%d): %d", fd, (int) res);
    }

    return res;
}


static nxt_int_t
nxt_unit_port_hash_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_unit_port_t          *port;
    nxt_unit_port_hash_id_t  *port_id;

    port = data;
    port_id = (nxt_unit_port_hash_id_t *) lhq->key.start;

    if (lhq->key.length == sizeof(nxt_unit_port_hash_id_t)
        && port_id->pid == port->id.pid
        && port_id->id == port->id.id)
    {
        return NXT_OK;
    }

    return NXT_DECLINED;
}


static const nxt_lvlhsh_proto_t  lvlhsh_ports_proto  nxt_aligned(64) = {
    NXT_LVLHSH_DEFAULT,
    nxt_unit_port_hash_test,
    nxt_lvlhsh_alloc,
    nxt_lvlhsh_free,
};


static inline void
nxt_unit_port_hash_lhq(nxt_lvlhsh_query_t *lhq,
    nxt_unit_port_hash_id_t *port_hash_id,
    nxt_unit_port_id_t *port_id)
{
    port_hash_id->pid = port_id->pid;
    port_hash_id->id = port_id->id;

    if (nxt_fast_path(port_id->hash != 0)) {
        lhq->key_hash = port_id->hash;

    } else {
        lhq->key_hash = nxt_murmur_hash2(port_hash_id, sizeof(*port_hash_id));

        port_id->hash = lhq->key_hash;

        nxt_unit_debug(NULL, "calculate hash for port_id (%d, %d): %04X",
                       (int) port_id->pid, (int) port_id->id,
                       (int) port_id->hash);
    }

    lhq->key.length = sizeof(nxt_unit_port_hash_id_t);
    lhq->key.start = (u_char *) port_hash_id;
    lhq->proto = &lvlhsh_ports_proto;
    lhq->pool = NULL;
}


static int
nxt_unit_port_hash_add(nxt_lvlhsh_t *port_hash, nxt_unit_port_t *port)
{
    nxt_int_t                res;
    nxt_lvlhsh_query_t       lhq;
    nxt_unit_port_hash_id_t  port_hash_id;

    nxt_unit_port_hash_lhq(&lhq, &port_hash_id, &port->id);
    lhq.replace = 0;
    lhq.value = port;

    res = nxt_lvlhsh_insert(port_hash, &lhq);

    switch (res) {

    case NXT_OK:
        return NXT_UNIT_OK;

    default:
        return NXT_UNIT_ERROR;
    }
}


static nxt_unit_port_impl_t *
nxt_unit_port_hash_find(nxt_lvlhsh_t *port_hash, nxt_unit_port_id_t *port_id,
    int remove)
{
    nxt_int_t                res;
    nxt_lvlhsh_query_t       lhq;
    nxt_unit_port_hash_id_t  port_hash_id;

    nxt_unit_port_hash_lhq(&lhq, &port_hash_id, port_id);

    if (remove) {
        res = nxt_lvlhsh_delete(port_hash, &lhq);

    } else {
        res = nxt_lvlhsh_find(port_hash, &lhq);
    }

    switch (res) {

    case NXT_OK:
        return lhq.value;

    default:
        return NULL;
    }
}


void
nxt_unit_log(nxt_unit_ctx_t *ctx, int level, const char *fmt, ...)
{
    int              log_fd, n;
    char             msg[NXT_MAX_ERROR_STR], *p, *end;
    pid_t            pid;
    va_list          ap;
    nxt_unit_impl_t  *lib;

    if (nxt_fast_path(ctx != NULL)) {
        lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

        pid = lib->pid;
        log_fd = lib->log_fd;

    } else {
        pid = getpid();
        log_fd = STDERR_FILENO;
    }

    p = msg;
    end = p + sizeof(msg) - 1;

    p = nxt_unit_snprint_prefix(p, end, pid, level);

    va_start(ap, fmt);
    p += vsnprintf(p, end - p, fmt, ap);
    va_end(ap);

    if (nxt_slow_path(p > end)) {
        memcpy(end - 5, "[...]", 5);
        p = end;
    }

    *p++ = '\n';

    n = write(log_fd, msg, p - msg);
    if (nxt_slow_path(n < 0)) {
        fprintf(stderr, "Failed to write log: %.*s", (int) (p - msg), msg);
    }
}


void
nxt_unit_req_log(nxt_unit_request_info_t *req, int level, const char *fmt, ...)
{
    int                           log_fd, n;
    char                          msg[NXT_MAX_ERROR_STR], *p, *end;
    pid_t                         pid;
    va_list                       ap;
    nxt_unit_impl_t               *lib;
    nxt_unit_request_info_impl_t  *req_impl;

    if (nxt_fast_path(req != NULL)) {
        lib = nxt_container_of(req->ctx->unit, nxt_unit_impl_t, unit);

        pid = lib->pid;
        log_fd = lib->log_fd;

    } else {
        pid = getpid();
        log_fd = STDERR_FILENO;
    }

    p = msg;
    end = p + sizeof(msg) - 1;

    p = nxt_unit_snprint_prefix(p, end, pid, level);

    if (nxt_fast_path(req != NULL)) {
        req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

        p += snprintf(p, end - p,
                      "#%"PRIu32": ", req_impl->recv_msg.port_msg.stream);
    }

    va_start(ap, fmt);
    p += vsnprintf(p, end - p, fmt, ap);
    va_end(ap);

    if (nxt_slow_path(p > end)) {
        memcpy(end - 5, "[...]", 5);
        p = end;
    }

    *p++ = '\n';

    n = write(log_fd, msg, p - msg);
    if (nxt_slow_path(n < 0)) {
        fprintf(stderr, "Failed to write log: %.*s", (int) (p - msg), msg);
    }
}


static const char * nxt_unit_log_levels[] = {
    "alert",
    "error",
    "warn",
    "notice",
    "info",
    "debug",
};


static char *
nxt_unit_snprint_prefix(char *p, char *end, pid_t pid, int level)
{
    struct tm        tm;
    struct timespec  ts;

    (void) clock_gettime(CLOCK_REALTIME, &ts);

#if (NXT_HAVE_LOCALTIME_R)
    (void) localtime_r(&ts.tv_sec, &tm);
#else
    tm = *localtime(&ts.tv_sec);
#endif

    p += snprintf(p, end - p,
                  "%4d/%02d/%02d %02d:%02d:%02d.%03d ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec,
                  (int) ts.tv_nsec / 1000000);

    p += snprintf(p, end - p,
                  "[%s] %d#%"PRIu64" [unit] ", nxt_unit_log_levels[level],
                  (int) pid,
                  (uint64_t) (uintptr_t) nxt_thread_get_tid());

    return p;
}


/* The function required by nxt_lvlhsh_alloc() and nxt_lvlvhsh_free(). */

void *
nxt_memalign(size_t alignment, size_t size)
{
    void        *p;
    nxt_err_t   err;

    err = posix_memalign(&p, alignment, size);

    if (nxt_fast_path(err == 0)) {
        return p;
    }

    return NULL;
}

#if (NXT_DEBUG)

void
nxt_free(void *p)
{
    free(p);
}

#endif

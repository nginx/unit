
/*
 * Copyright (C) NGINX, Inc.
 */

#include "nxt_main.h"
#include "nxt_port_memory_int.h"
#include "nxt_socket_msg.h"
#include "nxt_port_queue.h"
#include "nxt_app_queue.h"

#include "nxt_unit.h"
#include "nxt_unit_request.h"
#include "nxt_unit_response.h"
#include "nxt_unit_websocket.h"

#include "nxt_websocket.h"

#if (NXT_HAVE_MEMFD_CREATE)
#include <linux/memfd.h>
#endif

#define NXT_UNIT_MAX_PLAIN_SIZE  1024
#define NXT_UNIT_LOCAL_BUF_SIZE  \
    (NXT_UNIT_MAX_PLAIN_SIZE + sizeof(nxt_port_msg_t))

enum {
    NXT_QUIT_NORMAL   = 0,
    NXT_QUIT_GRACEFUL = 1,
};

typedef struct nxt_unit_impl_s                  nxt_unit_impl_t;
typedef struct nxt_unit_mmap_s                  nxt_unit_mmap_t;
typedef struct nxt_unit_mmaps_s                 nxt_unit_mmaps_t;
typedef struct nxt_unit_process_s               nxt_unit_process_t;
typedef struct nxt_unit_mmap_buf_s              nxt_unit_mmap_buf_t;
typedef struct nxt_unit_recv_msg_s              nxt_unit_recv_msg_t;
typedef struct nxt_unit_read_buf_s              nxt_unit_read_buf_t;
typedef struct nxt_unit_ctx_impl_s              nxt_unit_ctx_impl_t;
typedef struct nxt_unit_port_impl_s             nxt_unit_port_impl_t;
typedef struct nxt_unit_request_info_impl_s     nxt_unit_request_info_impl_t;
typedef struct nxt_unit_websocket_frame_impl_s  nxt_unit_websocket_frame_impl_t;

static nxt_unit_impl_t *nxt_unit_create(nxt_unit_init_t *init);
static int nxt_unit_ctx_init(nxt_unit_impl_t *lib,
    nxt_unit_ctx_impl_t *ctx_impl, void *data);
nxt_inline void nxt_unit_ctx_use(nxt_unit_ctx_t *ctx);
nxt_inline void nxt_unit_ctx_release(nxt_unit_ctx_t *ctx);
nxt_inline void nxt_unit_lib_use(nxt_unit_impl_t *lib);
nxt_inline void nxt_unit_lib_release(nxt_unit_impl_t *lib);
nxt_inline void nxt_unit_mmap_buf_insert(nxt_unit_mmap_buf_t **head,
    nxt_unit_mmap_buf_t *mmap_buf);
nxt_inline void nxt_unit_mmap_buf_insert_tail(nxt_unit_mmap_buf_t **prev,
    nxt_unit_mmap_buf_t *mmap_buf);
nxt_inline void nxt_unit_mmap_buf_unlink(nxt_unit_mmap_buf_t *mmap_buf);
static int nxt_unit_read_env(nxt_unit_port_t *ready_port,
    nxt_unit_port_t *router_port, nxt_unit_port_t *read_port,
    int *shared_port_fd, int *shared_queue_fd,
    int *log_fd, uint32_t *stream, uint32_t *shm_limit,
    uint32_t *request_limit);
static int nxt_unit_ready(nxt_unit_ctx_t *ctx, int ready_fd, uint32_t stream,
    int queue_fd);
static int nxt_unit_process_msg(nxt_unit_ctx_t *ctx, nxt_unit_read_buf_t *rbuf,
    nxt_unit_request_info_t **preq);
static int nxt_unit_process_new_port(nxt_unit_ctx_t *ctx,
    nxt_unit_recv_msg_t *recv_msg);
static int nxt_unit_ctx_ready(nxt_unit_ctx_t *ctx);
static int nxt_unit_process_req_headers(nxt_unit_ctx_t *ctx,
    nxt_unit_recv_msg_t *recv_msg, nxt_unit_request_info_t **preq);
static int nxt_unit_process_req_body(nxt_unit_ctx_t *ctx,
    nxt_unit_recv_msg_t *recv_msg);
static int nxt_unit_request_check_response_port(nxt_unit_request_info_t *req,
    nxt_unit_port_id_t *port_id);
static int nxt_unit_send_req_headers_ack(nxt_unit_request_info_t *req);
static int nxt_unit_process_websocket(nxt_unit_ctx_t *ctx,
    nxt_unit_recv_msg_t *recv_msg);
static int nxt_unit_process_shm_ack(nxt_unit_ctx_t *ctx);
static nxt_unit_request_info_impl_t *nxt_unit_request_info_get(
    nxt_unit_ctx_t *ctx);
static void nxt_unit_request_info_release(nxt_unit_request_info_t *req);
static void nxt_unit_request_info_free(nxt_unit_request_info_impl_t *req);
static nxt_unit_websocket_frame_impl_t *nxt_unit_websocket_frame_get(
    nxt_unit_ctx_t *ctx);
static void nxt_unit_websocket_frame_release(nxt_unit_websocket_frame_t *ws);
static void nxt_unit_websocket_frame_free(nxt_unit_ctx_t *ctx,
    nxt_unit_websocket_frame_impl_t *ws);
static nxt_unit_mmap_buf_t *nxt_unit_mmap_buf_get(nxt_unit_ctx_t *ctx);
static void nxt_unit_mmap_buf_release(nxt_unit_mmap_buf_t *mmap_buf);
static int nxt_unit_mmap_buf_send(nxt_unit_request_info_t *req,
    nxt_unit_mmap_buf_t *mmap_buf, int last);
static void nxt_unit_mmap_buf_free(nxt_unit_mmap_buf_t *mmap_buf);
static void nxt_unit_free_outgoing_buf(nxt_unit_mmap_buf_t *mmap_buf);
static nxt_unit_read_buf_t *nxt_unit_read_buf_get(nxt_unit_ctx_t *ctx);
static nxt_unit_read_buf_t *nxt_unit_read_buf_get_impl(
    nxt_unit_ctx_impl_t *ctx_impl);
static void nxt_unit_read_buf_release(nxt_unit_ctx_t *ctx,
    nxt_unit_read_buf_t *rbuf);
static nxt_unit_mmap_buf_t *nxt_unit_request_preread(
    nxt_unit_request_info_t *req, size_t size);
static ssize_t nxt_unit_buf_read(nxt_unit_buf_t **b, uint64_t *len, void *dst,
    size_t size);
static nxt_port_mmap_header_t *nxt_unit_mmap_get(nxt_unit_ctx_t *ctx,
    nxt_unit_port_t *port, nxt_chunk_id_t *c, int *n, int min_n);
static int nxt_unit_send_oosm(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port);
static int nxt_unit_wait_shm_ack(nxt_unit_ctx_t *ctx);
static nxt_unit_mmap_t *nxt_unit_mmap_at(nxt_unit_mmaps_t *mmaps, uint32_t i);
static nxt_port_mmap_header_t *nxt_unit_new_mmap(nxt_unit_ctx_t *ctx,
    nxt_unit_port_t *port, int n);
static int nxt_unit_shm_open(nxt_unit_ctx_t *ctx, size_t size);
static int nxt_unit_send_mmap(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port,
    int fd);
static int nxt_unit_get_outgoing_buf(nxt_unit_ctx_t *ctx,
    nxt_unit_port_t *port, uint32_t size,
    uint32_t min_size, nxt_unit_mmap_buf_t *mmap_buf, char *local_buf);
static int nxt_unit_incoming_mmap(nxt_unit_ctx_t *ctx, pid_t pid, int fd);

static void nxt_unit_awake_ctx(nxt_unit_ctx_t *ctx,
    nxt_unit_ctx_impl_t *ctx_impl);
static int nxt_unit_mmaps_init(nxt_unit_mmaps_t *mmaps);
nxt_inline void nxt_unit_process_use(nxt_unit_process_t *process);
nxt_inline void nxt_unit_process_release(nxt_unit_process_t *process);
static void nxt_unit_mmaps_destroy(nxt_unit_mmaps_t *mmaps);
static int nxt_unit_check_rbuf_mmap(nxt_unit_ctx_t *ctx,
    nxt_unit_mmaps_t *mmaps, pid_t pid, uint32_t id,
    nxt_port_mmap_header_t **hdr, nxt_unit_read_buf_t *rbuf);
static int nxt_unit_mmap_read(nxt_unit_ctx_t *ctx,
    nxt_unit_recv_msg_t *recv_msg, nxt_unit_read_buf_t *rbuf);
static int nxt_unit_get_mmap(nxt_unit_ctx_t *ctx, pid_t pid, uint32_t id);
static void nxt_unit_mmap_release(nxt_unit_ctx_t *ctx,
    nxt_port_mmap_header_t *hdr, void *start, uint32_t size);
static int nxt_unit_send_shm_ack(nxt_unit_ctx_t *ctx, pid_t pid);

static nxt_unit_process_t *nxt_unit_process_get(nxt_unit_ctx_t *ctx, pid_t pid);
static nxt_unit_process_t *nxt_unit_process_find(nxt_unit_impl_t *lib,
    pid_t pid, int remove);
static nxt_unit_process_t *nxt_unit_process_pop_first(nxt_unit_impl_t *lib);
static int nxt_unit_run_once_impl(nxt_unit_ctx_t *ctx);
static int nxt_unit_read_buf(nxt_unit_ctx_t *ctx, nxt_unit_read_buf_t *rbuf);
static int nxt_unit_chk_ready(nxt_unit_ctx_t *ctx);
static int nxt_unit_process_pending_rbuf(nxt_unit_ctx_t *ctx);
static void nxt_unit_process_ready_req(nxt_unit_ctx_t *ctx);
nxt_inline int nxt_unit_is_read_queue(nxt_unit_read_buf_t *rbuf);
nxt_inline int nxt_unit_is_read_socket(nxt_unit_read_buf_t *rbuf);
nxt_inline int nxt_unit_is_shm_ack(nxt_unit_read_buf_t *rbuf);
nxt_inline int nxt_unit_is_quit(nxt_unit_read_buf_t *rbuf);
static int nxt_unit_process_port_msg_impl(nxt_unit_ctx_t *ctx,
    nxt_unit_port_t *port);
static void nxt_unit_ctx_free(nxt_unit_ctx_impl_t *ctx_impl);
static nxt_unit_port_t *nxt_unit_create_port(nxt_unit_ctx_t *ctx);

static int nxt_unit_send_port(nxt_unit_ctx_t *ctx, nxt_unit_port_t *dst,
    nxt_unit_port_t *port, int queue_fd);

nxt_inline void nxt_unit_port_use(nxt_unit_port_t *port);
nxt_inline void nxt_unit_port_release(nxt_unit_port_t *port);
static nxt_unit_port_t *nxt_unit_add_port(nxt_unit_ctx_t *ctx,
    nxt_unit_port_t *port, void *queue);
static void nxt_unit_process_awaiting_req(nxt_unit_ctx_t *ctx,
    nxt_queue_t *awaiting_req);
static void nxt_unit_remove_port(nxt_unit_impl_t *lib, nxt_unit_ctx_t *ctx,
    nxt_unit_port_id_t *port_id);
static nxt_unit_port_t *nxt_unit_remove_port_unsafe(nxt_unit_impl_t *lib,
    nxt_unit_port_id_t *port_id);
static void nxt_unit_remove_pid(nxt_unit_impl_t *lib, pid_t pid);
static void nxt_unit_remove_process(nxt_unit_impl_t *lib,
    nxt_unit_process_t *process);
static void nxt_unit_quit(nxt_unit_ctx_t *ctx, uint8_t quit_param);
static int nxt_unit_get_port(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id);
static ssize_t nxt_unit_port_send(nxt_unit_ctx_t *ctx,
    nxt_unit_port_t *port, const void *buf, size_t buf_size,
    const nxt_send_oob_t *oob);
static ssize_t nxt_unit_sendmsg(nxt_unit_ctx_t *ctx, int fd,
    const void *buf, size_t buf_size, const nxt_send_oob_t *oob);
static int nxt_unit_ctx_port_recv(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port,
    nxt_unit_read_buf_t *rbuf);
nxt_inline void nxt_unit_rbuf_cpy(nxt_unit_read_buf_t *dst,
    nxt_unit_read_buf_t *src);
static int nxt_unit_shared_port_recv(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port,
    nxt_unit_read_buf_t *rbuf);
static int nxt_unit_port_recv(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port,
    nxt_unit_read_buf_t *rbuf);
static int nxt_unit_port_queue_recv(nxt_unit_port_t *port,
    nxt_unit_read_buf_t *rbuf);
static int nxt_unit_app_queue_recv(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port,
    nxt_unit_read_buf_t *rbuf);
nxt_inline int nxt_unit_close(int fd);
static int nxt_unit_fd_blocking(int fd);

static int nxt_unit_port_hash_add(nxt_lvlhsh_t *port_hash,
    nxt_unit_port_t *port);
static nxt_unit_port_t *nxt_unit_port_hash_find(nxt_lvlhsh_t *port_hash,
    nxt_unit_port_id_t *port_id, int remove);

static int nxt_unit_request_hash_add(nxt_unit_ctx_t *ctx,
    nxt_unit_request_info_t *req);
static nxt_unit_request_info_t *nxt_unit_request_hash_find(
    nxt_unit_ctx_t *ctx, uint32_t stream, int remove);

static char * nxt_unit_snprint_prefix(char *p, char *end, pid_t pid,
    int level);
static void *nxt_unit_lvlhsh_alloc(void *data, size_t size);
static void nxt_unit_lvlhsh_free(void *data, void *p);
static int nxt_unit_memcasecmp(const void *p1, const void *p2, size_t length);


struct nxt_unit_mmap_buf_s {
    nxt_unit_buf_t           buf;

    nxt_unit_mmap_buf_t      *next;
    nxt_unit_mmap_buf_t      **prev;

    nxt_port_mmap_header_t   *hdr;
    nxt_unit_request_info_t  *req;
    nxt_unit_ctx_impl_t      *ctx_impl;
    char                     *free_ptr;
    char                     *plain_ptr;
};


struct nxt_unit_recv_msg_s {
    uint32_t                 stream;
    nxt_pid_t                pid;
    nxt_port_id_t            reply_port;

    uint8_t                  last;      /* 1 bit */
    uint8_t                  mmap;      /* 1 bit */

    void                     *start;
    uint32_t                 size;

    int                      fd[2];

    nxt_unit_mmap_buf_t      *incoming_buf;
};


typedef enum {
    NXT_UNIT_RS_START           = 0,
    NXT_UNIT_RS_RESPONSE_INIT,
    NXT_UNIT_RS_RESPONSE_HAS_CONTENT,
    NXT_UNIT_RS_RESPONSE_SENT,
    NXT_UNIT_RS_RELEASED,
} nxt_unit_req_state_t;


struct nxt_unit_request_info_impl_s {
    nxt_unit_request_info_t  req;

    uint32_t                 stream;

    nxt_unit_mmap_buf_t      *outgoing_buf;
    nxt_unit_mmap_buf_t      *incoming_buf;

    nxt_unit_req_state_t     state;
    uint8_t                  websocket;
    uint8_t                  in_hash;

    /*  for nxt_unit_ctx_impl_t.free_req or active_req */
    nxt_queue_link_t         link;
    /*  for nxt_unit_port_impl_t.awaiting_req */
    nxt_queue_link_t         port_wait_link;

    char                     extra_data[];
};


struct nxt_unit_websocket_frame_impl_s {
    nxt_unit_websocket_frame_t  ws;

    nxt_unit_mmap_buf_t         *buf;

    nxt_queue_link_t            link;

    nxt_unit_ctx_impl_t         *ctx_impl;
};


struct nxt_unit_read_buf_s {
    nxt_queue_link_t              link;
    nxt_unit_ctx_impl_t           *ctx_impl;
    ssize_t                       size;
    nxt_recv_oob_t                oob;
    char                          buf[16384];
};


struct nxt_unit_ctx_impl_s {
    nxt_unit_ctx_t                ctx;

    nxt_atomic_t                  use_count;
    nxt_atomic_t                  wait_items;

    pthread_mutex_t               mutex;

    nxt_unit_port_t               *read_port;

    nxt_queue_link_t              link;

    nxt_unit_mmap_buf_t           *free_buf;

    /*  of nxt_unit_request_info_impl_t */
    nxt_queue_t                   free_req;

    /*  of nxt_unit_websocket_frame_impl_t */
    nxt_queue_t                   free_ws;

    /*  of nxt_unit_request_info_impl_t */
    nxt_queue_t                   active_req;

    /*  of nxt_unit_request_info_impl_t */
    nxt_lvlhsh_t                  requests;

    /*  of nxt_unit_request_info_impl_t */
    nxt_queue_t                   ready_req;

    /*  of nxt_unit_read_buf_t */
    nxt_queue_t                   pending_rbuf;

    /*  of nxt_unit_read_buf_t */
    nxt_queue_t                   free_rbuf;

    uint8_t                       online;       /* 1 bit */
    uint8_t                       ready;        /* 1 bit */
    uint8_t                       quit_param;

    nxt_unit_mmap_buf_t           ctx_buf[2];
    nxt_unit_read_buf_t           ctx_read_buf;

    nxt_unit_request_info_impl_t  req;
};


struct nxt_unit_mmap_s {
    nxt_port_mmap_header_t   *hdr;
    pthread_t                src_thread;

    /*  of nxt_unit_read_buf_t */
    nxt_queue_t              awaiting_rbuf;
};


struct nxt_unit_mmaps_s {
    pthread_mutex_t          mutex;
    uint32_t                 size;
    uint32_t                 cap;
    nxt_atomic_t             allocated_chunks;
    nxt_unit_mmap_t          *elts;
};


struct nxt_unit_impl_s {
    nxt_unit_t               unit;
    nxt_unit_callbacks_t     callbacks;

    nxt_atomic_t             use_count;
    nxt_atomic_t             request_count;

    uint32_t                 request_data_size;
    uint32_t                 shm_mmap_limit;
    uint32_t                 request_limit;

    pthread_mutex_t          mutex;

    nxt_lvlhsh_t             processes;        /* of nxt_unit_process_t */
    nxt_lvlhsh_t             ports;            /* of nxt_unit_port_impl_t */

    nxt_unit_port_t          *router_port;
    nxt_unit_port_t          *shared_port;

    nxt_queue_t              contexts;         /* of nxt_unit_ctx_impl_t */

    nxt_unit_mmaps_t         incoming;
    nxt_unit_mmaps_t         outgoing;

    pid_t                    pid;
    int                      log_fd;

    nxt_unit_ctx_impl_t      main_ctx;
};


struct nxt_unit_port_impl_s {
    nxt_unit_port_t          port;

    nxt_atomic_t             use_count;

    /*  for nxt_unit_process_t.ports */
    nxt_queue_link_t         link;
    nxt_unit_process_t       *process;

    /*  of nxt_unit_request_info_impl_t */
    nxt_queue_t              awaiting_req;

    int                      ready;

    void                     *queue;

    int                      from_socket;
    nxt_unit_read_buf_t      *socket_rbuf;
};


struct nxt_unit_process_s {
    pid_t                    pid;

    nxt_queue_t              ports;            /* of nxt_unit_port_impl_t */

    nxt_unit_impl_t          *lib;

    nxt_atomic_t             use_count;

    uint32_t                 next_port_id;
};


/* Explicitly using 32 bit types to avoid possible alignment. */
typedef struct {
    int32_t   pid;
    uint32_t  id;
} nxt_unit_port_hash_id_t;


static pid_t  nxt_unit_pid;


nxt_unit_ctx_t *
nxt_unit_init(nxt_unit_init_t *init)
{
    int              rc, queue_fd, shared_queue_fd;
    void             *mem;
    uint32_t         ready_stream, shm_limit, request_limit;
    nxt_unit_ctx_t   *ctx;
    nxt_unit_impl_t  *lib;
    nxt_unit_port_t  ready_port, router_port, read_port, shared_port;

    nxt_unit_pid = getpid();

    lib = nxt_unit_create(init);
    if (nxt_slow_path(lib == NULL)) {
        return NULL;
    }

    queue_fd = -1;
    mem = MAP_FAILED;
    shared_port.out_fd = -1;
    shared_port.data = NULL;

    if (init->ready_port.id.pid != 0
        && init->ready_stream != 0
        && init->read_port.id.pid != 0)
    {
        ready_port = init->ready_port;
        ready_stream = init->ready_stream;
        router_port = init->router_port;
        read_port = init->read_port;
        lib->log_fd = init->log_fd;

        nxt_unit_port_id_init(&ready_port.id, ready_port.id.pid,
                              ready_port.id.id);
        nxt_unit_port_id_init(&router_port.id, router_port.id.pid,
                              router_port.id.id);
        nxt_unit_port_id_init(&read_port.id, read_port.id.pid,
                              read_port.id.id);

        shared_port.in_fd = init->shared_port_fd;
        shared_queue_fd = init->shared_queue_fd;

    } else {
        rc = nxt_unit_read_env(&ready_port, &router_port, &read_port,
                               &shared_port.in_fd, &shared_queue_fd,
                               &lib->log_fd, &ready_stream, &shm_limit,
                               &request_limit);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            goto fail;
        }

        lib->shm_mmap_limit = (shm_limit + PORT_MMAP_DATA_SIZE - 1)
                                / PORT_MMAP_DATA_SIZE;
        lib->request_limit = request_limit;
    }

    if (nxt_slow_path(lib->shm_mmap_limit < 1)) {
        lib->shm_mmap_limit = 1;
    }

    lib->pid = read_port.id.pid;
    nxt_unit_pid = lib->pid;

    ctx = &lib->main_ctx.ctx;

    rc = nxt_unit_fd_blocking(router_port.out_fd);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    lib->router_port = nxt_unit_add_port(ctx, &router_port, NULL);
    if (nxt_slow_path(lib->router_port == NULL)) {
        nxt_unit_alert(NULL, "failed to add router_port");

        goto fail;
    }

    queue_fd = nxt_unit_shm_open(ctx, sizeof(nxt_port_queue_t));
    if (nxt_slow_path(queue_fd == -1)) {
        goto fail;
    }

    mem = mmap(NULL, sizeof(nxt_port_queue_t),
               PROT_READ | PROT_WRITE, MAP_SHARED, queue_fd, 0);
    if (nxt_slow_path(mem == MAP_FAILED)) {
        nxt_unit_alert(ctx, "mmap(%d) failed: %s (%d)", queue_fd,
                       strerror(errno), errno);

        goto fail;
    }

    nxt_port_queue_init(mem);

    rc = nxt_unit_fd_blocking(read_port.in_fd);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    lib->main_ctx.read_port = nxt_unit_add_port(ctx, &read_port, mem);
    if (nxt_slow_path(lib->main_ctx.read_port == NULL)) {
        nxt_unit_alert(NULL, "failed to add read_port");

        goto fail;
    }

    rc = nxt_unit_fd_blocking(ready_port.out_fd);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    nxt_unit_port_id_init(&shared_port.id, read_port.id.pid,
                          NXT_UNIT_SHARED_PORT_ID);

    mem = mmap(NULL, sizeof(nxt_app_queue_t), PROT_READ | PROT_WRITE,
               MAP_SHARED, shared_queue_fd, 0);
    if (nxt_slow_path(mem == MAP_FAILED)) {
        nxt_unit_alert(ctx, "mmap(%d) failed: %s (%d)", shared_queue_fd,
                       strerror(errno), errno);

        goto fail;
    }

    nxt_unit_close(shared_queue_fd);

    lib->shared_port = nxt_unit_add_port(ctx, &shared_port, mem);
    if (nxt_slow_path(lib->shared_port == NULL)) {
        nxt_unit_alert(NULL, "failed to add shared_port");

        goto fail;
    }

    rc = nxt_unit_ready(ctx, ready_port.out_fd, ready_stream, queue_fd);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_alert(NULL, "failed to send READY message");

        goto fail;
    }

    nxt_unit_close(ready_port.out_fd);
    nxt_unit_close(queue_fd);

    return ctx;

fail:

    if (mem != MAP_FAILED) {
        munmap(mem, sizeof(nxt_port_queue_t));
    }

    if (queue_fd != -1) {
        nxt_unit_close(queue_fd);
    }

    nxt_unit_ctx_release(&lib->main_ctx.ctx);

    return NULL;
}


static nxt_unit_impl_t *
nxt_unit_create(nxt_unit_init_t *init)
{
    int              rc;
    nxt_unit_impl_t  *lib;

    if (nxt_slow_path(init->callbacks.request_handler == NULL)) {
        nxt_unit_alert(NULL, "request_handler is NULL");

        return NULL;
    }

    lib = nxt_unit_malloc(NULL,
                          sizeof(nxt_unit_impl_t) + init->request_data_size);
    if (nxt_slow_path(lib == NULL)) {
        nxt_unit_alert(NULL, "failed to allocate unit struct");

        return NULL;
    }

    rc = pthread_mutex_init(&lib->mutex, NULL);
    if (nxt_slow_path(rc != 0)) {
        nxt_unit_alert(NULL, "failed to initialize mutex (%d)", rc);

        goto out_unit_free;
    }

    lib->unit.data = init->data;
    lib->callbacks = init->callbacks;

    lib->request_data_size = init->request_data_size;
    lib->shm_mmap_limit = (init->shm_limit + PORT_MMAP_DATA_SIZE - 1)
                            / PORT_MMAP_DATA_SIZE;
    lib->request_limit = init->request_limit;

    lib->processes.slot = NULL;
    lib->ports.slot = NULL;

    lib->log_fd = STDERR_FILENO;

    nxt_queue_init(&lib->contexts);

    lib->use_count = 0;
    lib->request_count = 0;
    lib->router_port = NULL;
    lib->shared_port = NULL;

    rc = nxt_unit_ctx_init(lib, &lib->main_ctx, init->ctx_data);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto out_mutex_destroy;
    }

    rc = nxt_unit_mmaps_init(&lib->incoming);
    if (nxt_slow_path(rc != 0)) {
        nxt_unit_alert(NULL, "failed to initialize mutex (%d)", rc);

        goto out_ctx_free;
    }

    rc = nxt_unit_mmaps_init(&lib->outgoing);
    if (nxt_slow_path(rc != 0)) {
        nxt_unit_alert(NULL, "failed to initialize mutex (%d)", rc);

        goto out_mmaps_destroy;
    }

    return lib;

out_mmaps_destroy:
    nxt_unit_mmaps_destroy(&lib->incoming);

out_ctx_free:
    nxt_unit_ctx_free(&lib->main_ctx);

out_mutex_destroy:
    pthread_mutex_destroy(&lib->mutex);

out_unit_free:
    nxt_unit_free(NULL, lib);

    return NULL;
}


static int
nxt_unit_ctx_init(nxt_unit_impl_t *lib, nxt_unit_ctx_impl_t *ctx_impl,
    void *data)
{
    int  rc;

    ctx_impl->ctx.data = data;
    ctx_impl->ctx.unit = &lib->unit;

    rc = pthread_mutex_init(&ctx_impl->mutex, NULL);
    if (nxt_slow_path(rc != 0)) {
        nxt_unit_alert(NULL, "failed to initialize mutex (%d)", rc);

        return NXT_UNIT_ERROR;
    }

    nxt_unit_lib_use(lib);

    pthread_mutex_lock(&lib->mutex);

    nxt_queue_insert_tail(&lib->contexts, &ctx_impl->link);

    pthread_mutex_unlock(&lib->mutex);

    ctx_impl->use_count = 1;
    ctx_impl->wait_items = 0;
    ctx_impl->online = 1;
    ctx_impl->ready = 0;
    ctx_impl->quit_param = NXT_QUIT_GRACEFUL;

    nxt_queue_init(&ctx_impl->free_req);
    nxt_queue_init(&ctx_impl->free_ws);
    nxt_queue_init(&ctx_impl->active_req);
    nxt_queue_init(&ctx_impl->ready_req);
    nxt_queue_init(&ctx_impl->pending_rbuf);
    nxt_queue_init(&ctx_impl->free_rbuf);

    ctx_impl->free_buf = NULL;
    nxt_unit_mmap_buf_insert(&ctx_impl->free_buf, &ctx_impl->ctx_buf[1]);
    nxt_unit_mmap_buf_insert(&ctx_impl->free_buf, &ctx_impl->ctx_buf[0]);

    nxt_queue_insert_tail(&ctx_impl->free_req, &ctx_impl->req.link);
    nxt_queue_insert_tail(&ctx_impl->free_rbuf, &ctx_impl->ctx_read_buf.link);

    ctx_impl->ctx_read_buf.ctx_impl = ctx_impl;

    ctx_impl->req.req.ctx = &ctx_impl->ctx;
    ctx_impl->req.req.unit = &lib->unit;

    ctx_impl->read_port = NULL;
    ctx_impl->requests.slot = 0;

    return NXT_UNIT_OK;
}


nxt_inline void
nxt_unit_ctx_use(nxt_unit_ctx_t *ctx)
{
    nxt_unit_ctx_impl_t  *ctx_impl;

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    nxt_atomic_fetch_add(&ctx_impl->use_count, 1);
}


nxt_inline void
nxt_unit_ctx_release(nxt_unit_ctx_t *ctx)
{
    long                 c;
    nxt_unit_ctx_impl_t  *ctx_impl;

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    c = nxt_atomic_fetch_add(&ctx_impl->use_count, -1);

    if (c == 1) {
        nxt_unit_ctx_free(ctx_impl);
    }
}


nxt_inline void
nxt_unit_lib_use(nxt_unit_impl_t *lib)
{
    nxt_atomic_fetch_add(&lib->use_count, 1);
}


nxt_inline void
nxt_unit_lib_release(nxt_unit_impl_t *lib)
{
    long                c;
    nxt_unit_process_t  *process;

    c = nxt_atomic_fetch_add(&lib->use_count, -1);

    if (c == 1) {
        for ( ;; ) {
            pthread_mutex_lock(&lib->mutex);

            process = nxt_unit_process_pop_first(lib);
            if (process == NULL) {
                pthread_mutex_unlock(&lib->mutex);

                break;
            }

            nxt_unit_remove_process(lib, process);
        }

        pthread_mutex_destroy(&lib->mutex);

        if (nxt_fast_path(lib->router_port != NULL)) {
            nxt_unit_port_release(lib->router_port);
        }

        if (nxt_fast_path(lib->shared_port != NULL)) {
            nxt_unit_port_release(lib->shared_port);
        }

        nxt_unit_mmaps_destroy(&lib->incoming);
        nxt_unit_mmaps_destroy(&lib->outgoing);

        nxt_unit_free(NULL, lib);
    }
}


nxt_inline void
nxt_unit_mmap_buf_insert(nxt_unit_mmap_buf_t **head,
    nxt_unit_mmap_buf_t *mmap_buf)
{
    mmap_buf->next = *head;

    if (mmap_buf->next != NULL) {
        mmap_buf->next->prev = &mmap_buf->next;
    }

    *head = mmap_buf;
    mmap_buf->prev = head;
}


nxt_inline void
nxt_unit_mmap_buf_insert_tail(nxt_unit_mmap_buf_t **prev,
    nxt_unit_mmap_buf_t *mmap_buf)
{
    while (*prev != NULL) {
        prev = &(*prev)->next;
    }

    nxt_unit_mmap_buf_insert(prev, mmap_buf);
}


nxt_inline void
nxt_unit_mmap_buf_unlink(nxt_unit_mmap_buf_t *mmap_buf)
{
    nxt_unit_mmap_buf_t  **prev;

    prev = mmap_buf->prev;

    if (mmap_buf->next != NULL) {
        mmap_buf->next->prev = prev;
    }

    if (prev != NULL) {
        *prev = mmap_buf->next;
    }
}


static int
nxt_unit_read_env(nxt_unit_port_t *ready_port, nxt_unit_port_t *router_port,
    nxt_unit_port_t *read_port, int *shared_port_fd, int *shared_queue_fd,
    int *log_fd, uint32_t *stream,
    uint32_t *shm_limit, uint32_t *request_limit)
{
    int       rc;
    int       ready_fd, router_fd, read_in_fd, read_out_fd;
    char      *unit_init, *version_end, *vars;
    size_t    version_length;
    int64_t   ready_pid, router_pid, read_pid;
    uint32_t  ready_stream, router_id, ready_id, read_id;

    unit_init = getenv(NXT_UNIT_INIT_ENV);
    if (nxt_slow_path(unit_init == NULL)) {
        nxt_unit_alert(NULL, "%s is not in the current environment",
                       NXT_UNIT_INIT_ENV);

        return NXT_UNIT_ERROR;
    }

    version_end = strchr(unit_init, ';');
    if (nxt_slow_path(version_end == NULL)) {
        nxt_unit_alert(NULL, "Unit version not found in %s=\"%s\"",
                       NXT_UNIT_INIT_ENV, unit_init);

        return NXT_UNIT_ERROR;
    }

    version_length = version_end - unit_init;

    rc = version_length != nxt_length(NXT_VERSION)
         || memcmp(unit_init, NXT_VERSION, nxt_length(NXT_VERSION));

    if (nxt_slow_path(rc != 0)) {
        nxt_unit_alert(NULL, "versions mismatch: the Unit daemon has version "
                       "%.*s, while the app was compiled with libunit %s",
                       (int) version_length, unit_init, NXT_VERSION);

        return NXT_UNIT_ERROR;
    }

    vars = version_end + 1;

    rc = sscanf(vars,
                "%"PRIu32";"
                "%"PRId64",%"PRIu32",%d;"
                "%"PRId64",%"PRIu32",%d;"
                "%"PRId64",%"PRIu32",%d,%d;"
                "%d,%d;"
                "%d,%"PRIu32",%"PRIu32,
                &ready_stream,
                &ready_pid, &ready_id, &ready_fd,
                &router_pid, &router_id, &router_fd,
                &read_pid, &read_id, &read_in_fd, &read_out_fd,
                shared_port_fd, shared_queue_fd,
                log_fd, shm_limit, request_limit);

    if (nxt_slow_path(rc == EOF)) {
        nxt_unit_alert(NULL, "sscanf(%s) failed: %s (%d) for %s env",
                       vars, strerror(errno), errno, NXT_UNIT_INIT_ENV);

        return NXT_UNIT_ERROR;
    }

    if (nxt_slow_path(rc != 16)) {
        nxt_unit_alert(NULL, "invalid number of variables in %s env: "
                       "found %d of %d in %s", NXT_UNIT_INIT_ENV, rc, 16, vars);

        return NXT_UNIT_ERROR;
    }

    nxt_unit_debug(NULL, "%s='%s'", NXT_UNIT_INIT_ENV, unit_init);

    nxt_unit_port_id_init(&ready_port->id, (pid_t) ready_pid, ready_id);

    ready_port->in_fd = -1;
    ready_port->out_fd = ready_fd;
    ready_port->data = NULL;

    nxt_unit_port_id_init(&router_port->id, (pid_t) router_pid, router_id);

    router_port->in_fd = -1;
    router_port->out_fd = router_fd;
    router_port->data = NULL;

    nxt_unit_port_id_init(&read_port->id, (pid_t) read_pid, read_id);

    read_port->in_fd = read_in_fd;
    read_port->out_fd = read_out_fd;
    read_port->data = NULL;

    *stream = ready_stream;

    return NXT_UNIT_OK;
}


static int
nxt_unit_ready(nxt_unit_ctx_t *ctx, int ready_fd, uint32_t stream, int queue_fd)
{
    ssize_t          res;
    nxt_send_oob_t   oob;
    nxt_port_msg_t   msg;
    nxt_unit_impl_t  *lib;
    int              fds[2] = {queue_fd, -1};

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    msg.stream = stream;
    msg.pid = lib->pid;
    msg.reply_port = 0;
    msg.type = _NXT_PORT_MSG_PROCESS_READY;
    msg.last = 1;
    msg.mmap = 0;
    msg.nf = 0;
    msg.mf = 0;

    nxt_socket_msg_oob_init(&oob, fds);

    res = nxt_unit_sendmsg(ctx, ready_fd, &msg, sizeof(msg), &oob);
    if (res != sizeof(msg)) {
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


static int
nxt_unit_process_msg(nxt_unit_ctx_t *ctx, nxt_unit_read_buf_t *rbuf,
    nxt_unit_request_info_t **preq)
{
    int                  rc;
    pid_t                pid;
    uint8_t              quit_param;
    nxt_port_msg_t       *port_msg;
    nxt_unit_impl_t      *lib;
    nxt_unit_recv_msg_t  recv_msg;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    recv_msg.incoming_buf = NULL;
    recv_msg.fd[0] = -1;
    recv_msg.fd[1] = -1;

    rc = nxt_socket_msg_oob_get_fds(&rbuf->oob, recv_msg.fd);
    if (nxt_slow_path(rc != NXT_OK)) {
        nxt_unit_alert(ctx, "failed to receive file descriptor over cmsg");
        rc = NXT_UNIT_ERROR;
        goto done;
    }

    if (nxt_slow_path(rbuf->size < (ssize_t) sizeof(nxt_port_msg_t))) {
        if (nxt_slow_path(rbuf->size == 0)) {
            nxt_unit_debug(ctx, "read port closed");

            nxt_unit_quit(ctx, NXT_QUIT_GRACEFUL);
            rc = NXT_UNIT_OK;
            goto done;
        }

        nxt_unit_alert(ctx, "message too small (%d bytes)", (int) rbuf->size);

        rc = NXT_UNIT_ERROR;
        goto done;
    }

    port_msg = (nxt_port_msg_t *) rbuf->buf;

    nxt_unit_debug(ctx, "#%"PRIu32": process message %d fd[0] %d fd[1] %d",
                   port_msg->stream, (int) port_msg->type,
                   recv_msg.fd[0], recv_msg.fd[1]);

    recv_msg.stream = port_msg->stream;
    recv_msg.pid = port_msg->pid;
    recv_msg.reply_port = port_msg->reply_port;
    recv_msg.last = port_msg->last;
    recv_msg.mmap = port_msg->mmap;

    recv_msg.start = port_msg + 1;
    recv_msg.size = rbuf->size - sizeof(nxt_port_msg_t);

    if (nxt_slow_path(port_msg->type >= NXT_PORT_MSG_MAX)) {
        nxt_unit_alert(ctx, "#%"PRIu32": unknown message type (%d)",
                       port_msg->stream, (int) port_msg->type);
        rc = NXT_UNIT_ERROR;
        goto done;
    }

    /* Fragmentation is unsupported. */
    if (nxt_slow_path(port_msg->nf != 0 || port_msg->mf != 0)) {
        nxt_unit_alert(ctx, "#%"PRIu32": fragmented message type (%d)",
                       port_msg->stream, (int) port_msg->type);
        rc = NXT_UNIT_ERROR;
        goto done;
    }

    if (port_msg->mmap) {
        rc = nxt_unit_mmap_read(ctx, &recv_msg, rbuf);

        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            if (rc == NXT_UNIT_AGAIN) {
                recv_msg.fd[0] = -1;
                recv_msg.fd[1] = -1;
            }

            goto done;
        }
    }

    switch (port_msg->type) {

    case _NXT_PORT_MSG_RPC_READY:
        rc = NXT_UNIT_OK;
        break;

    case _NXT_PORT_MSG_QUIT:
        if (recv_msg.size == sizeof(quit_param)) {
            memcpy(&quit_param, recv_msg.start, sizeof(quit_param));

        } else {
            quit_param = NXT_QUIT_NORMAL;
        }

        nxt_unit_debug(ctx, "#%"PRIu32": %squit", port_msg->stream,
                       (quit_param == NXT_QUIT_GRACEFUL ? "graceful " : ""));

        nxt_unit_quit(ctx, quit_param);

        rc = NXT_UNIT_OK;
        break;

    case _NXT_PORT_MSG_NEW_PORT:
        rc = nxt_unit_process_new_port(ctx, &recv_msg);
        break;

    case _NXT_PORT_MSG_PORT_ACK:
        rc = nxt_unit_ctx_ready(ctx);
        break;

    case _NXT_PORT_MSG_CHANGE_FILE:
        nxt_unit_debug(ctx, "#%"PRIu32": change_file: fd %d",
                       port_msg->stream, recv_msg.fd[0]);

        if (dup2(recv_msg.fd[0], lib->log_fd) == -1) {
            nxt_unit_alert(ctx, "#%"PRIu32": dup2(%d, %d) failed: %s (%d)",
                           port_msg->stream, recv_msg.fd[0], lib->log_fd,
                           strerror(errno), errno);

            rc = NXT_UNIT_ERROR;
            goto done;
        }

        rc = NXT_UNIT_OK;
        break;

    case _NXT_PORT_MSG_MMAP:
        if (nxt_slow_path(recv_msg.fd[0] < 0)) {
            nxt_unit_alert(ctx, "#%"PRIu32": invalid fd %d for mmap",
                           port_msg->stream, recv_msg.fd[0]);

            rc = NXT_UNIT_ERROR;
            goto done;
        }

        rc = nxt_unit_incoming_mmap(ctx, port_msg->pid, recv_msg.fd[0]);
        break;

    case _NXT_PORT_MSG_REQ_HEADERS:
        rc = nxt_unit_process_req_headers(ctx, &recv_msg, preq);
        break;

    case _NXT_PORT_MSG_REQ_BODY:
        rc = nxt_unit_process_req_body(ctx, &recv_msg);
        break;

    case _NXT_PORT_MSG_WEBSOCKET:
        rc = nxt_unit_process_websocket(ctx, &recv_msg);
        break;

    case _NXT_PORT_MSG_REMOVE_PID:
        if (nxt_slow_path(recv_msg.size != sizeof(pid))) {
            nxt_unit_alert(ctx, "#%"PRIu32": remove_pid: invalid message size "
                           "(%d != %d)", port_msg->stream, (int) recv_msg.size,
                           (int) sizeof(pid));

            rc = NXT_UNIT_ERROR;
            goto done;
        }

        memcpy(&pid, recv_msg.start, sizeof(pid));

        nxt_unit_debug(ctx, "#%"PRIu32": remove_pid: %d",
                       port_msg->stream, (int) pid);

        nxt_unit_remove_pid(lib, pid);

        rc = NXT_UNIT_OK;
        break;

    case _NXT_PORT_MSG_SHM_ACK:
        rc = nxt_unit_process_shm_ack(ctx);
        break;

    default:
        nxt_unit_alert(ctx, "#%"PRIu32": ignore message type: %d",
                       port_msg->stream, (int) port_msg->type);

        rc = NXT_UNIT_ERROR;
        goto done;
    }

done:

    if (recv_msg.fd[0] != -1) {
        nxt_unit_close(recv_msg.fd[0]);
    }

    if (recv_msg.fd[1] != -1) {
        nxt_unit_close(recv_msg.fd[1]);
    }

    while (recv_msg.incoming_buf != NULL) {
        nxt_unit_mmap_buf_free(recv_msg.incoming_buf);
    }

    if (nxt_fast_path(rc != NXT_UNIT_AGAIN)) {
#if (NXT_DEBUG)
        memset(rbuf->buf, 0xAC, rbuf->size);
#endif
        nxt_unit_read_buf_release(ctx, rbuf);
    }

    return rc;
}


static int
nxt_unit_process_new_port(nxt_unit_ctx_t *ctx, nxt_unit_recv_msg_t *recv_msg)
{
    void                     *mem;
    nxt_unit_port_t          new_port, *port;
    nxt_port_msg_new_port_t  *new_port_msg;

    if (nxt_slow_path(recv_msg->size != sizeof(nxt_port_msg_new_port_t))) {
        nxt_unit_warn(ctx, "#%"PRIu32": new_port: "
                      "invalid message size (%d)",
                      recv_msg->stream, (int) recv_msg->size);

        return NXT_UNIT_ERROR;
    }

    if (nxt_slow_path(recv_msg->fd[0] < 0)) {
        nxt_unit_alert(ctx, "#%"PRIu32": invalid fd %d for new port",
                       recv_msg->stream, recv_msg->fd[0]);

        return NXT_UNIT_ERROR;
    }

    new_port_msg = recv_msg->start;

    nxt_unit_debug(ctx, "#%"PRIu32": new_port: port{%d,%d} fd[0] %d fd[1] %d",
                   recv_msg->stream, (int) new_port_msg->pid,
                   (int) new_port_msg->id, recv_msg->fd[0], recv_msg->fd[1]);

    if (nxt_slow_path(nxt_unit_fd_blocking(recv_msg->fd[0]) != NXT_UNIT_OK)) {
        return NXT_UNIT_ERROR;
    }

    nxt_unit_port_id_init(&new_port.id, new_port_msg->pid, new_port_msg->id);

    new_port.in_fd = -1;
    new_port.out_fd = recv_msg->fd[0];

    mem = mmap(NULL, sizeof(nxt_port_queue_t), PROT_READ | PROT_WRITE,
               MAP_SHARED, recv_msg->fd[1], 0);

    if (nxt_slow_path(mem == MAP_FAILED)) {
        nxt_unit_alert(ctx, "mmap(%d) failed: %s (%d)", recv_msg->fd[1],
                       strerror(errno), errno);

        return NXT_UNIT_ERROR;
    }

    new_port.data = NULL;

    recv_msg->fd[0] = -1;

    port = nxt_unit_add_port(ctx, &new_port, mem);
    if (nxt_slow_path(port == NULL)) {
        return NXT_UNIT_ERROR;
    }

    nxt_unit_port_release(port);

    return NXT_UNIT_OK;
}


static int
nxt_unit_ctx_ready(nxt_unit_ctx_t *ctx)
{
    nxt_unit_impl_t      *lib;
    nxt_unit_ctx_impl_t  *ctx_impl;

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    if (nxt_slow_path(ctx_impl->ready)) {
        return NXT_UNIT_OK;
    }

    ctx_impl->ready = 1;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    /* Call ready_handler() only for main context. */
    if (&lib->main_ctx == ctx_impl && lib->callbacks.ready_handler != NULL) {
        return lib->callbacks.ready_handler(ctx);
    }

    if (&lib->main_ctx != ctx_impl) {
        /* Check if the main context is already stopped or quit. */
        if (nxt_slow_path(!lib->main_ctx.ready)) {
            ctx_impl->ready = 0;

            nxt_unit_quit(ctx, lib->main_ctx.quit_param);

            return NXT_UNIT_OK;
        }

        if (lib->callbacks.add_port != NULL) {
            lib->callbacks.add_port(ctx, lib->shared_port);
        }
    }

    return NXT_UNIT_OK;
}


static int
nxt_unit_process_req_headers(nxt_unit_ctx_t *ctx, nxt_unit_recv_msg_t *recv_msg,
    nxt_unit_request_info_t **preq)
{
    int                           res;
    nxt_unit_impl_t               *lib;
    nxt_unit_port_id_t            port_id;
    nxt_unit_request_t            *r;
    nxt_unit_mmap_buf_t           *b;
    nxt_unit_request_info_t       *req;
    nxt_unit_request_info_impl_t  *req_impl;

    if (nxt_slow_path(recv_msg->mmap == 0)) {
        nxt_unit_warn(ctx, "#%"PRIu32": data is not in shared memory",
                      recv_msg->stream);

        return NXT_UNIT_ERROR;
    }

    if (nxt_slow_path(recv_msg->size < sizeof(nxt_unit_request_t))) {
        nxt_unit_warn(ctx, "#%"PRIu32": data too short: %d while at least "
                      "%d expected", recv_msg->stream, (int) recv_msg->size,
                      (int) sizeof(nxt_unit_request_t));

        return NXT_UNIT_ERROR;
    }

    req_impl = nxt_unit_request_info_get(ctx);
    if (nxt_slow_path(req_impl == NULL)) {
        nxt_unit_warn(ctx, "#%"PRIu32": request info allocation failed",
                      recv_msg->stream);

        return NXT_UNIT_ERROR;
    }

    req = &req_impl->req;

    req->request = recv_msg->start;

    b = recv_msg->incoming_buf;

    req->request_buf = &b->buf;
    req->response = NULL;
    req->response_buf = NULL;

    r = req->request;

    req->content_length = r->content_length;

    req->content_buf = req->request_buf;
    req->content_buf->free = nxt_unit_sptr_get(&r->preread_content);

    req_impl->stream = recv_msg->stream;

    req_impl->outgoing_buf = NULL;

    for (b = recv_msg->incoming_buf; b != NULL; b = b->next) {
        b->req = req;
    }

    /* "Move" incoming buffer list to req_impl. */
    req_impl->incoming_buf = recv_msg->incoming_buf;
    req_impl->incoming_buf->prev = &req_impl->incoming_buf;
    recv_msg->incoming_buf = NULL;

    req->content_fd = recv_msg->fd[0];
    recv_msg->fd[0] = -1;

    req->response_max_fields = 0;
    req_impl->state = NXT_UNIT_RS_START;
    req_impl->websocket = 0;
    req_impl->in_hash = 0;

    nxt_unit_debug(ctx, "#%"PRIu32": %.*s %.*s (%d)", recv_msg->stream,
                   (int) r->method_length,
                   (char *) nxt_unit_sptr_get(&r->method),
                   (int) r->target_length,
                   (char *) nxt_unit_sptr_get(&r->target),
                   (int) r->content_length);

    nxt_unit_port_id_init(&port_id, recv_msg->pid, recv_msg->reply_port);

    res = nxt_unit_request_check_response_port(req, &port_id);
    if (nxt_slow_path(res == NXT_UNIT_ERROR)) {
        return NXT_UNIT_ERROR;
    }

    if (nxt_fast_path(res == NXT_UNIT_OK)) {
        res = nxt_unit_send_req_headers_ack(req);
        if (nxt_slow_path(res == NXT_UNIT_ERROR)) {
            nxt_unit_request_done(req, NXT_UNIT_ERROR);

            return NXT_UNIT_ERROR;
        }

        lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

        if (req->content_length
            > (uint64_t) (req->content_buf->end - req->content_buf->free))
        {
            res = nxt_unit_request_hash_add(ctx, req);
            if (nxt_slow_path(res != NXT_UNIT_OK)) {
                nxt_unit_req_warn(req, "failed to add request to hash");

                nxt_unit_request_done(req, NXT_UNIT_ERROR);

                return NXT_UNIT_ERROR;
            }

            /*
             * If application have separate data handler, we may start
             * request processing and process data when it is arrived.
             */
            if (lib->callbacks.data_handler == NULL) {
                return NXT_UNIT_OK;
            }
        }

        if (preq == NULL) {
            lib->callbacks.request_handler(req);

        } else {
            *preq = req;
        }
    }

    return NXT_UNIT_OK;
}


static int
nxt_unit_process_req_body(nxt_unit_ctx_t *ctx, nxt_unit_recv_msg_t *recv_msg)
{
    uint64_t                 l;
    nxt_unit_impl_t          *lib;
    nxt_unit_mmap_buf_t      *b;
    nxt_unit_request_info_t  *req;

    req = nxt_unit_request_hash_find(ctx, recv_msg->stream, recv_msg->last);
    if (req == NULL) {
        return NXT_UNIT_OK;
    }

    l = req->content_buf->end - req->content_buf->free;

    for (b = recv_msg->incoming_buf; b != NULL; b = b->next) {
        b->req = req;
        l += b->buf.end - b->buf.free;
    }

    if (recv_msg->incoming_buf != NULL) {
        b = nxt_container_of(req->content_buf, nxt_unit_mmap_buf_t, buf);

        while (b->next != NULL) {
            b = b->next;
        }

        /* "Move" incoming buffer list to req_impl. */
        b->next = recv_msg->incoming_buf;
        b->next->prev = &b->next;

        recv_msg->incoming_buf = NULL;
    }

    req->content_fd = recv_msg->fd[0];
    recv_msg->fd[0] = -1;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    if (lib->callbacks.data_handler != NULL) {
        lib->callbacks.data_handler(req);

        return NXT_UNIT_OK;
    }

    if (req->content_fd != -1 || l == req->content_length) {
        lib->callbacks.request_handler(req);
    }

    return NXT_UNIT_OK;
}


static int
nxt_unit_request_check_response_port(nxt_unit_request_info_t *req,
    nxt_unit_port_id_t *port_id)
{
    int                           res;
    nxt_unit_ctx_t                *ctx;
    nxt_unit_impl_t               *lib;
    nxt_unit_port_t               *port;
    nxt_unit_process_t            *process;
    nxt_unit_ctx_impl_t           *ctx_impl;
    nxt_unit_port_impl_t          *port_impl;
    nxt_unit_request_info_impl_t  *req_impl;

    ctx = req->ctx;
    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);
    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    pthread_mutex_lock(&lib->mutex);

    port = nxt_unit_port_hash_find(&lib->ports, port_id, 0);

    if (nxt_fast_path(port != NULL)) {
        port_impl = nxt_container_of(port, nxt_unit_port_impl_t, port);
        req->response_port = port;

        if (nxt_fast_path(port_impl->ready)) {
            pthread_mutex_unlock(&lib->mutex);

            nxt_unit_debug(ctx, "check_response_port: found port{%d,%d}",
                           (int) port->id.pid, (int) port->id.id);

            return NXT_UNIT_OK;
        }

        nxt_unit_debug(ctx, "check_response_port: "
                       "port{%d,%d} already requested",
                       (int) port->id.pid, (int) port->id.id);

        req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

        nxt_queue_insert_tail(&port_impl->awaiting_req,
                              &req_impl->port_wait_link);

        pthread_mutex_unlock(&lib->mutex);

        nxt_atomic_fetch_add(&ctx_impl->wait_items, 1);

        return NXT_UNIT_AGAIN;
    }

    port_impl = nxt_unit_malloc(ctx, sizeof(nxt_unit_port_impl_t));
    if (nxt_slow_path(port_impl == NULL)) {
        nxt_unit_alert(ctx, "check_response_port: malloc(%d) failed",
                       (int) sizeof(nxt_unit_port_impl_t));

        pthread_mutex_unlock(&lib->mutex);

        return NXT_UNIT_ERROR;
    }

    port = &port_impl->port;

    port->id = *port_id;
    port->in_fd = -1;
    port->out_fd = -1;
    port->data = NULL;

    res = nxt_unit_port_hash_add(&lib->ports, port);
    if (nxt_slow_path(res != NXT_UNIT_OK)) {
        nxt_unit_alert(ctx, "check_response_port: %d,%d hash_add failed",
                       port->id.pid, port->id.id);

        pthread_mutex_unlock(&lib->mutex);

        nxt_unit_free(ctx, port);

        return NXT_UNIT_ERROR;
    }

    process = nxt_unit_process_find(lib, port_id->pid, 0);
    if (nxt_slow_path(process == NULL)) {
        nxt_unit_alert(ctx, "check_response_port: process %d not found",
                       port->id.pid);

        nxt_unit_port_hash_find(&lib->ports, port_id, 1);

        pthread_mutex_unlock(&lib->mutex);

        nxt_unit_free(ctx, port);

        return NXT_UNIT_ERROR;
    }

    nxt_queue_insert_tail(&process->ports, &port_impl->link);

    port_impl->process = process;
    port_impl->queue = NULL;
    port_impl->from_socket = 0;
    port_impl->socket_rbuf = NULL;

    nxt_queue_init(&port_impl->awaiting_req);

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    nxt_queue_insert_tail(&port_impl->awaiting_req, &req_impl->port_wait_link);

    port_impl->use_count = 2;
    port_impl->ready = 0;

    req->response_port = port;

    pthread_mutex_unlock(&lib->mutex);

    res = nxt_unit_get_port(ctx, port_id);
    if (nxt_slow_path(res == NXT_UNIT_ERROR)) {
        return NXT_UNIT_ERROR;
    }

    nxt_atomic_fetch_add(&ctx_impl->wait_items, 1);

    return NXT_UNIT_AGAIN;
}


static int
nxt_unit_send_req_headers_ack(nxt_unit_request_info_t *req)
{
    ssize_t                       res;
    nxt_port_msg_t                msg;
    nxt_unit_impl_t               *lib;
    nxt_unit_ctx_impl_t           *ctx_impl;
    nxt_unit_request_info_impl_t  *req_impl;

    lib = nxt_container_of(req->ctx->unit, nxt_unit_impl_t, unit);
    ctx_impl = nxt_container_of(req->ctx, nxt_unit_ctx_impl_t, ctx);
    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    memset(&msg, 0, sizeof(nxt_port_msg_t));

    msg.stream = req_impl->stream;
    msg.pid = lib->pid;
    msg.reply_port = ctx_impl->read_port->id.id;
    msg.type = _NXT_PORT_MSG_REQ_HEADERS_ACK;

    res = nxt_unit_port_send(req->ctx, req->response_port,
                             &msg, sizeof(msg), NULL);
    if (nxt_slow_path(res != sizeof(msg))) {
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


static int
nxt_unit_process_websocket(nxt_unit_ctx_t *ctx, nxt_unit_recv_msg_t *recv_msg)
{
    size_t                           hsize;
    nxt_unit_impl_t                  *lib;
    nxt_unit_mmap_buf_t              *b;
    nxt_unit_callbacks_t             *cb;
    nxt_unit_request_info_t          *req;
    nxt_unit_request_info_impl_t     *req_impl;
    nxt_unit_websocket_frame_impl_t  *ws_impl;

    req = nxt_unit_request_hash_find(ctx, recv_msg->stream, recv_msg->last);
    if (nxt_slow_path(req == NULL)) {
        return NXT_UNIT_OK;
    }

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);
    cb = &lib->callbacks;

    if (cb->websocket_handler && recv_msg->size >= 2) {
        ws_impl = nxt_unit_websocket_frame_get(ctx);
        if (nxt_slow_path(ws_impl == NULL)) {
            nxt_unit_warn(ctx, "#%"PRIu32": websocket frame allocation failed",
                          req_impl->stream);

            return NXT_UNIT_ERROR;
        }

        ws_impl->ws.req = req;

        ws_impl->buf = NULL;

        if (recv_msg->mmap) {
            for (b = recv_msg->incoming_buf; b != NULL; b = b->next) {
                b->req = req;
            }

            /* "Move" incoming buffer list to ws_impl. */
            ws_impl->buf = recv_msg->incoming_buf;
            ws_impl->buf->prev = &ws_impl->buf;
            recv_msg->incoming_buf = NULL;

            b = ws_impl->buf;

        } else {
            b = nxt_unit_mmap_buf_get(ctx);
            if (nxt_slow_path(b == NULL)) {
                nxt_unit_alert(ctx, "#%"PRIu32": failed to allocate buf",
                               req_impl->stream);

                nxt_unit_websocket_frame_release(&ws_impl->ws);

                return NXT_UNIT_ERROR;
            }

            b->req = req;
            b->buf.start = recv_msg->start;
            b->buf.free = b->buf.start;
            b->buf.end = b->buf.start + recv_msg->size;

            nxt_unit_mmap_buf_insert(&ws_impl->buf, b);
        }

        ws_impl->ws.header = (void *) b->buf.start;
        ws_impl->ws.payload_len = nxt_websocket_frame_payload_len(
            ws_impl->ws.header);

        hsize = nxt_websocket_frame_header_size(ws_impl->ws.header);

        if (ws_impl->ws.header->mask) {
            ws_impl->ws.mask = (uint8_t *) b->buf.start + hsize - 4;

        } else {
            ws_impl->ws.mask = NULL;
        }

        b->buf.free += hsize;

        ws_impl->ws.content_buf = &b->buf;
        ws_impl->ws.content_length = ws_impl->ws.payload_len;

        nxt_unit_req_debug(req, "websocket_handler: opcode=%d, "
                           "payload_len=%"PRIu64,
                            ws_impl->ws.header->opcode,
                            ws_impl->ws.payload_len);

        cb->websocket_handler(&ws_impl->ws);
    }

    if (recv_msg->last) {
        if (cb->close_handler) {
            nxt_unit_req_debug(req, "close_handler");

            cb->close_handler(req);

        } else {
            nxt_unit_request_done(req, NXT_UNIT_ERROR);
        }
    }

    return NXT_UNIT_OK;
}


static int
nxt_unit_process_shm_ack(nxt_unit_ctx_t *ctx)
{
    nxt_unit_impl_t       *lib;
    nxt_unit_callbacks_t  *cb;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);
    cb = &lib->callbacks;

    if (cb->shm_ack_handler != NULL) {
        cb->shm_ack_handler(ctx);
    }

    return NXT_UNIT_OK;
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

    pthread_mutex_lock(&ctx_impl->mutex);

    if (nxt_queue_is_empty(&ctx_impl->free_req)) {
        pthread_mutex_unlock(&ctx_impl->mutex);

        req_impl = nxt_unit_malloc(ctx, sizeof(nxt_unit_request_info_impl_t)
                                        + lib->request_data_size);
        if (nxt_slow_path(req_impl == NULL)) {
            return NULL;
        }

        req_impl->req.unit = ctx->unit;
        req_impl->req.ctx = ctx;

        pthread_mutex_lock(&ctx_impl->mutex);

    } else {
        lnk = nxt_queue_first(&ctx_impl->free_req);
        nxt_queue_remove(lnk);

        req_impl = nxt_container_of(lnk, nxt_unit_request_info_impl_t, link);
    }

    nxt_queue_insert_tail(&ctx_impl->active_req, &req_impl->link);

    pthread_mutex_unlock(&ctx_impl->mutex);

    req_impl->req.data = lib->request_data_size ? req_impl->extra_data : NULL;

    return req_impl;
}


static void
nxt_unit_request_info_release(nxt_unit_request_info_t *req)
{
    nxt_unit_ctx_t                *ctx;
    nxt_unit_ctx_impl_t           *ctx_impl;
    nxt_unit_request_info_impl_t  *req_impl;

    ctx = req->ctx;
    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);
    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    req->response = NULL;
    req->response_buf = NULL;

    if (req_impl->in_hash) {
        nxt_unit_request_hash_find(req->ctx, req_impl->stream, 1);
    }

    while (req_impl->outgoing_buf != NULL) {
        nxt_unit_mmap_buf_free(req_impl->outgoing_buf);
    }

    while (req_impl->incoming_buf != NULL) {
        nxt_unit_mmap_buf_free(req_impl->incoming_buf);
    }

    if (req->content_fd != -1) {
        nxt_unit_close(req->content_fd);

        req->content_fd = -1;
    }

    if (req->response_port != NULL) {
        nxt_unit_port_release(req->response_port);

        req->response_port = NULL;
    }

    req_impl->state = NXT_UNIT_RS_RELEASED;

    pthread_mutex_lock(&ctx_impl->mutex);

    nxt_queue_remove(&req_impl->link);

    nxt_queue_insert_tail(&ctx_impl->free_req, &req_impl->link);

    pthread_mutex_unlock(&ctx_impl->mutex);

    if (nxt_slow_path(!nxt_unit_chk_ready(ctx))) {
        nxt_unit_quit(ctx, NXT_QUIT_GRACEFUL);
    }
}


static void
nxt_unit_request_info_free(nxt_unit_request_info_impl_t *req_impl)
{
    nxt_unit_ctx_impl_t  *ctx_impl;

    ctx_impl = nxt_container_of(req_impl->req.ctx, nxt_unit_ctx_impl_t, ctx);

    nxt_queue_remove(&req_impl->link);

    if (req_impl != &ctx_impl->req) {
        nxt_unit_free(&ctx_impl->ctx, req_impl);
    }
}


static nxt_unit_websocket_frame_impl_t *
nxt_unit_websocket_frame_get(nxt_unit_ctx_t *ctx)
{
    nxt_queue_link_t                 *lnk;
    nxt_unit_ctx_impl_t              *ctx_impl;
    nxt_unit_websocket_frame_impl_t  *ws_impl;

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    pthread_mutex_lock(&ctx_impl->mutex);

    if (nxt_queue_is_empty(&ctx_impl->free_ws)) {
        pthread_mutex_unlock(&ctx_impl->mutex);

        ws_impl = nxt_unit_malloc(ctx, sizeof(nxt_unit_websocket_frame_impl_t));
        if (nxt_slow_path(ws_impl == NULL)) {
            return NULL;
        }

    } else {
        lnk = nxt_queue_first(&ctx_impl->free_ws);
        nxt_queue_remove(lnk);

        pthread_mutex_unlock(&ctx_impl->mutex);

        ws_impl = nxt_container_of(lnk, nxt_unit_websocket_frame_impl_t, link);
    }

    ws_impl->ctx_impl = ctx_impl;

    return ws_impl;
}


static void
nxt_unit_websocket_frame_release(nxt_unit_websocket_frame_t *ws)
{
    nxt_unit_websocket_frame_impl_t  *ws_impl;

    ws_impl = nxt_container_of(ws, nxt_unit_websocket_frame_impl_t, ws);

    while (ws_impl->buf != NULL) {
        nxt_unit_mmap_buf_free(ws_impl->buf);
    }

    ws->req = NULL;

    pthread_mutex_lock(&ws_impl->ctx_impl->mutex);

    nxt_queue_insert_tail(&ws_impl->ctx_impl->free_ws, &ws_impl->link);

    pthread_mutex_unlock(&ws_impl->ctx_impl->mutex);
}


static void
nxt_unit_websocket_frame_free(nxt_unit_ctx_t *ctx,
    nxt_unit_websocket_frame_impl_t *ws_impl)
{
    nxt_queue_remove(&ws_impl->link);

    nxt_unit_free(ctx, ws_impl);
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
    char                *name;
    uint32_t            i, j;
    nxt_unit_field_t    *fields, f;
    nxt_unit_request_t  *r;

    static const nxt_str_t  content_length = nxt_string("content-length");
    static const nxt_str_t  content_type = nxt_string("content-type");
    static const nxt_str_t  cookie = nxt_string("cookie");

    nxt_unit_req_debug(req, "group_dup_fields");

    r = req->request;
    fields = r->fields;

    for (i = 0; i < r->fields_count; i++) {
        name = nxt_unit_sptr_get(&fields[i].name);

        switch (fields[i].hash) {
        case NXT_UNIT_HASH_CONTENT_LENGTH:
            if (fields[i].name_length == content_length.length
                && nxt_unit_memcasecmp(name, content_length.start,
                                       content_length.length) == 0)
            {
                r->content_length_field = i;
            }

            break;

        case NXT_UNIT_HASH_CONTENT_TYPE:
            if (fields[i].name_length == content_type.length
                && nxt_unit_memcasecmp(name, content_type.start,
                                       content_type.length) == 0)
            {
                r->content_type_field = i;
            }

            break;

        case NXT_UNIT_HASH_COOKIE:
            if (fields[i].name_length == cookie.length
                && nxt_unit_memcasecmp(name, cookie.start,
                                       cookie.length) == 0)
            {
                r->cookie_field = i;
            }

            break;
        }

        for (j = i + 1; j < r->fields_count; j++) {
            if (fields[i].hash != fields[j].hash
                || fields[i].name_length != fields[j].name_length
                || nxt_unit_memcasecmp(name,
                                       nxt_unit_sptr_get(&fields[j].name),
                                       fields[j].name_length) != 0)
            {
                continue;
            }

            f = fields[j];
            f.value.offset += (j - (i + 1)) * sizeof(f);

            while (j > i + 1) {
                fields[j] = fields[j - 1];
                fields[j].name.offset -= sizeof(f);
                fields[j].value.offset -= sizeof(f);
                j--;
            }

            fields[j] = f;

            /* Assign the same name pointer for further grouping simplicity. */
            nxt_unit_sptr_set(&fields[j].name, name);

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

    /*
     * Each field name and value 0-terminated by libunit,
     * this is the reason of '+ 2' below.
     */
    buf_size = sizeof(nxt_unit_response_t)
               + max_fields_count * (sizeof(nxt_unit_field_t) + 2)
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

    /*
     * Each field name and value 0-terminated by libunit,
     * this is the reason of '+ 2' below.
     */
    buf_size = sizeof(nxt_unit_response_t)
               + max_fields_count * (sizeof(nxt_unit_field_t) + 2)
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

    p = buf->start + sizeof(nxt_unit_response_t)
        + max_fields_count * sizeof(nxt_unit_field_t);
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

        resp->piggyback_content_length =
                                       req->response->piggyback_content_length;

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
        nxt_unit_req_warn(req, "add_field: too many response fields (%d)",
                          (int) resp->fields_count);

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

    if (req->request->websocket_handshake && req->response->status == 101) {
        nxt_unit_response_upgrade(req);
    }

    nxt_unit_req_debug(req, "send: %"PRIu32" fields, %d bytes",
                       req->response->fields_count,
                       (int) (req->response_buf->free
                              - req->response_buf->start));

    mmap_buf = nxt_container_of(req->response_buf, nxt_unit_mmap_buf_t, buf);

    rc = nxt_unit_mmap_buf_send(req, mmap_buf, 0);
    if (nxt_fast_path(rc == NXT_UNIT_OK)) {
        req->response = NULL;
        req->response_buf = NULL;
        req_impl->state = NXT_UNIT_RS_RESPONSE_SENT;

        nxt_unit_mmap_buf_free(mmap_buf);
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
    nxt_unit_mmap_buf_t           *mmap_buf;
    nxt_unit_request_info_impl_t  *req_impl;

    if (nxt_slow_path(size > PORT_MMAP_DATA_SIZE)) {
        nxt_unit_req_warn(req, "response_buf_alloc: "
                          "requested buffer (%"PRIu32") too big", size);

        return NULL;
    }

    nxt_unit_req_debug(req, "response_buf_alloc: %"PRIu32, size);

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    mmap_buf = nxt_unit_mmap_buf_get(req->ctx);
    if (nxt_slow_path(mmap_buf == NULL)) {
        nxt_unit_req_alert(req, "response_buf_alloc: failed to allocate buf");

        return NULL;
    }

    mmap_buf->req = req;

    nxt_unit_mmap_buf_insert_tail(&req_impl->outgoing_buf, mmap_buf);

    rc = nxt_unit_get_outgoing_buf(req->ctx, req->response_port,
                                   size, size, mmap_buf,
                                   NULL);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_mmap_buf_release(mmap_buf);

        nxt_unit_req_alert(req, "response_buf_alloc: failed to get out buf");

        return NULL;
    }

    return &mmap_buf->buf;
}


static nxt_unit_mmap_buf_t *
nxt_unit_mmap_buf_get(nxt_unit_ctx_t *ctx)
{
    nxt_unit_mmap_buf_t  *mmap_buf;
    nxt_unit_ctx_impl_t  *ctx_impl;

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    pthread_mutex_lock(&ctx_impl->mutex);

    if (ctx_impl->free_buf == NULL) {
        pthread_mutex_unlock(&ctx_impl->mutex);

        mmap_buf = nxt_unit_malloc(ctx, sizeof(nxt_unit_mmap_buf_t));
        if (nxt_slow_path(mmap_buf == NULL)) {
            return NULL;
        }

    } else {
        mmap_buf = ctx_impl->free_buf;

        nxt_unit_mmap_buf_unlink(mmap_buf);

        pthread_mutex_unlock(&ctx_impl->mutex);
    }

    mmap_buf->ctx_impl = ctx_impl;

    mmap_buf->hdr = NULL;
    mmap_buf->free_ptr = NULL;

    return mmap_buf;
}


static void
nxt_unit_mmap_buf_release(nxt_unit_mmap_buf_t *mmap_buf)
{
    nxt_unit_mmap_buf_unlink(mmap_buf);

    pthread_mutex_lock(&mmap_buf->ctx_impl->mutex);

    nxt_unit_mmap_buf_insert(&mmap_buf->ctx_impl->free_buf, mmap_buf);

    pthread_mutex_unlock(&mmap_buf->ctx_impl->mutex);
}


int
nxt_unit_request_is_websocket_handshake(nxt_unit_request_info_t *req)
{
    return req->request->websocket_handshake;
}


int
nxt_unit_response_upgrade(nxt_unit_request_info_t *req)
{
    int                           rc;
    nxt_unit_request_info_impl_t  *req_impl;

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    if (nxt_slow_path(req_impl->websocket != 0)) {
        nxt_unit_req_debug(req, "upgrade: already upgraded");

        return NXT_UNIT_OK;
    }

    if (nxt_slow_path(req_impl->state < NXT_UNIT_RS_RESPONSE_INIT)) {
        nxt_unit_req_warn(req, "upgrade: response is not initialized yet");

        return NXT_UNIT_ERROR;
    }

    if (nxt_slow_path(req_impl->state >= NXT_UNIT_RS_RESPONSE_SENT)) {
        nxt_unit_req_warn(req, "upgrade: response already sent");

        return NXT_UNIT_ERROR;
    }

    rc = nxt_unit_request_hash_add(req->ctx, req);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_req_warn(req, "upgrade: failed to add request to hash");

        return NXT_UNIT_ERROR;
    }

    req_impl->websocket = 1;

    req->response->status = 101;

    return NXT_UNIT_OK;
}


int
nxt_unit_response_is_websocket(nxt_unit_request_info_t *req)
{
    nxt_unit_request_info_impl_t  *req_impl;

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    return req_impl->websocket;
}


nxt_unit_request_info_t *
nxt_unit_get_request_info_from_data(void *data)
{
    nxt_unit_request_info_impl_t  *req_impl;

    req_impl = nxt_container_of(data, nxt_unit_request_info_impl_t, extra_data);

    return &req_impl->req;
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
        rc = nxt_unit_mmap_buf_send(req, mmap_buf, 0);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return rc;
        }
    }

    nxt_unit_mmap_buf_free(mmap_buf);

    return NXT_UNIT_OK;
}


static void
nxt_unit_buf_send_done(nxt_unit_buf_t *buf)
{
    int                      rc;
    nxt_unit_mmap_buf_t      *mmap_buf;
    nxt_unit_request_info_t  *req;

    mmap_buf = nxt_container_of(buf, nxt_unit_mmap_buf_t, buf);

    req = mmap_buf->req;

    rc = nxt_unit_mmap_buf_send(req, mmap_buf, 1);
    if (nxt_slow_path(rc == NXT_UNIT_OK)) {
        nxt_unit_mmap_buf_free(mmap_buf);

        nxt_unit_request_info_release(req);

    } else {
        nxt_unit_request_done(req, rc);
    }
}


static int
nxt_unit_mmap_buf_send(nxt_unit_request_info_t *req,
    nxt_unit_mmap_buf_t *mmap_buf, int last)
{
    struct {
        nxt_port_msg_t       msg;
        nxt_port_mmap_msg_t  mmap_msg;
    } m;

    int                           rc;
    u_char                        *last_used, *first_free;
    ssize_t                       res;
    nxt_chunk_id_t                first_free_chunk;
    nxt_unit_buf_t                *buf;
    nxt_unit_impl_t               *lib;
    nxt_port_mmap_header_t        *hdr;
    nxt_unit_request_info_impl_t  *req_impl;

    lib = nxt_container_of(req->ctx->unit, nxt_unit_impl_t, unit);
    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    buf = &mmap_buf->buf;
    hdr = mmap_buf->hdr;

    m.mmap_msg.size = buf->free - buf->start;

    m.msg.stream = req_impl->stream;
    m.msg.pid = lib->pid;
    m.msg.reply_port = 0;
    m.msg.type = _NXT_PORT_MSG_DATA;
    m.msg.last = last != 0;
    m.msg.mmap = hdr != NULL && m.mmap_msg.size > 0;
    m.msg.nf = 0;
    m.msg.mf = 0;

    rc = NXT_UNIT_ERROR;

    if (m.msg.mmap) {
        m.mmap_msg.mmap_id = hdr->id;
        m.mmap_msg.chunk_id = nxt_port_mmap_chunk_id(hdr,
                                                     (u_char *) buf->start);

        nxt_unit_debug(req->ctx, "#%"PRIu32": send mmap: (%d,%d,%d)",
                       req_impl->stream,
                       (int) m.mmap_msg.mmap_id,
                       (int) m.mmap_msg.chunk_id,
                       (int) m.mmap_msg.size);

        res = nxt_unit_port_send(req->ctx, req->response_port, &m, sizeof(m),
                                 NULL);
        if (nxt_slow_path(res != sizeof(m))) {
            goto free_buf;
        }

        last_used = (u_char *) buf->free - 1;
        first_free_chunk = nxt_port_mmap_chunk_id(hdr, last_used) + 1;

        if (buf->end - buf->free >= PORT_MMAP_CHUNK_SIZE) {
            first_free = nxt_port_mmap_chunk_start(hdr, first_free_chunk);

            buf->start = (char *) first_free;
            buf->free = buf->start;

            if (buf->end < buf->start) {
                buf->end = buf->start;
            }

        } else {
            buf->start = NULL;
            buf->free = NULL;
            buf->end = NULL;

            mmap_buf->hdr = NULL;
        }

        nxt_atomic_fetch_add(&lib->outgoing.allocated_chunks,
                            (int) m.mmap_msg.chunk_id - (int) first_free_chunk);

        nxt_unit_debug(req->ctx, "allocated_chunks %d",
                       (int) lib->outgoing.allocated_chunks);

    } else {
        if (nxt_slow_path(mmap_buf->plain_ptr == NULL
                          || mmap_buf->plain_ptr > buf->start - sizeof(m.msg)))
        {
            nxt_unit_alert(req->ctx,
                           "#%"PRIu32": failed to send plain memory buffer"
                           ": no space reserved for message header",
                           req_impl->stream);

            goto free_buf;
        }

        memcpy(buf->start - sizeof(m.msg), &m.msg, sizeof(m.msg));

        nxt_unit_debug(req->ctx, "#%"PRIu32": send plain: %d",
                       req_impl->stream,
                       (int) (sizeof(m.msg) + m.mmap_msg.size));

        res = nxt_unit_port_send(req->ctx, req->response_port,
                                 buf->start - sizeof(m.msg),
                                 m.mmap_msg.size + sizeof(m.msg), NULL);

        if (nxt_slow_path(res != (ssize_t) (m.mmap_msg.size + sizeof(m.msg)))) {
            goto free_buf;
        }
    }

    rc = NXT_UNIT_OK;

free_buf:

    nxt_unit_free_outgoing_buf(mmap_buf);

    return rc;
}


void
nxt_unit_buf_free(nxt_unit_buf_t *buf)
{
    nxt_unit_mmap_buf_free(nxt_container_of(buf, nxt_unit_mmap_buf_t, buf));
}


static void
nxt_unit_mmap_buf_free(nxt_unit_mmap_buf_t *mmap_buf)
{
    nxt_unit_free_outgoing_buf(mmap_buf);

    nxt_unit_mmap_buf_release(mmap_buf);
}


static void
nxt_unit_free_outgoing_buf(nxt_unit_mmap_buf_t *mmap_buf)
{
    if (mmap_buf->hdr != NULL) {
        nxt_unit_mmap_release(&mmap_buf->ctx_impl->ctx,
                              mmap_buf->hdr, mmap_buf->buf.start,
                              mmap_buf->buf.end - mmap_buf->buf.start);

        mmap_buf->hdr = NULL;

        return;
    }

    if (mmap_buf->free_ptr != NULL) {
        nxt_unit_free(&mmap_buf->ctx_impl->ctx, mmap_buf->free_ptr);

        mmap_buf->free_ptr = NULL;
    }
}


static nxt_unit_read_buf_t *
nxt_unit_read_buf_get(nxt_unit_ctx_t *ctx)
{
    nxt_unit_ctx_impl_t  *ctx_impl;
    nxt_unit_read_buf_t  *rbuf;

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    pthread_mutex_lock(&ctx_impl->mutex);

    rbuf = nxt_unit_read_buf_get_impl(ctx_impl);

    pthread_mutex_unlock(&ctx_impl->mutex);

    rbuf->oob.size = 0;

    return rbuf;
}


static nxt_unit_read_buf_t *
nxt_unit_read_buf_get_impl(nxt_unit_ctx_impl_t *ctx_impl)
{
    nxt_queue_link_t     *link;
    nxt_unit_read_buf_t  *rbuf;

    if (!nxt_queue_is_empty(&ctx_impl->free_rbuf)) {
        link = nxt_queue_first(&ctx_impl->free_rbuf);
        nxt_queue_remove(link);

        rbuf = nxt_container_of(link, nxt_unit_read_buf_t, link);

        return rbuf;
    }

    rbuf = nxt_unit_malloc(&ctx_impl->ctx, sizeof(nxt_unit_read_buf_t));

    if (nxt_fast_path(rbuf != NULL)) {
        rbuf->ctx_impl = ctx_impl;
    }

    return rbuf;
}


static void
nxt_unit_read_buf_release(nxt_unit_ctx_t *ctx,
    nxt_unit_read_buf_t *rbuf)
{
    nxt_unit_ctx_impl_t  *ctx_impl;

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    pthread_mutex_lock(&ctx_impl->mutex);

    nxt_queue_insert_head(&ctx_impl->free_rbuf, &rbuf->link);

    pthread_mutex_unlock(&ctx_impl->mutex);
}


nxt_unit_buf_t *
nxt_unit_buf_next(nxt_unit_buf_t *buf)
{
    nxt_unit_mmap_buf_t  *mmap_buf;

    mmap_buf = nxt_container_of(buf, nxt_unit_mmap_buf_t, buf);

    if (mmap_buf->next == NULL) {
        return NULL;
    }

    return &mmap_buf->next->buf;
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
    ssize_t  res;

    res = nxt_unit_response_write_nb(req, start, size, size);

    return res < 0 ? -res : NXT_UNIT_OK;
}


ssize_t
nxt_unit_response_write_nb(nxt_unit_request_info_t *req, const void *start,
    size_t size, size_t min_size)
{
    int                           rc;
    ssize_t                       sent;
    uint32_t                      part_size, min_part_size, buf_size;
    const char                    *part_start;
    nxt_unit_mmap_buf_t           mmap_buf;
    nxt_unit_request_info_impl_t  *req_impl;
    char                          local_buf[NXT_UNIT_LOCAL_BUF_SIZE];

    nxt_unit_req_debug(req, "write: %d", (int) size);

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    part_start = start;
    sent = 0;

    if (nxt_slow_path(req_impl->state < NXT_UNIT_RS_RESPONSE_INIT)) {
        nxt_unit_req_alert(req, "write: response not initialized yet");

        return -NXT_UNIT_ERROR;
    }

    /* Check if response is not send yet. */
    if (nxt_slow_path(req->response_buf != NULL)) {
        part_size = req->response_buf->end - req->response_buf->free;
        part_size = nxt_min(size, part_size);

        rc = nxt_unit_response_add_content(req, part_start, part_size);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return -rc;
        }

        rc = nxt_unit_response_send(req);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return -rc;
        }

        size -= part_size;
        part_start += part_size;
        sent += part_size;

        min_size -= nxt_min(min_size, part_size);
    }

    while (size > 0) {
        part_size = nxt_min(size, PORT_MMAP_DATA_SIZE);
        min_part_size = nxt_min(min_size, part_size);
        min_part_size = nxt_min(min_part_size, PORT_MMAP_CHUNK_SIZE);

        rc = nxt_unit_get_outgoing_buf(req->ctx, req->response_port, part_size,
                                       min_part_size, &mmap_buf, local_buf);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return -rc;
        }

        buf_size = mmap_buf.buf.end - mmap_buf.buf.free;
        if (nxt_slow_path(buf_size == 0)) {
            return sent;
        }
        part_size = nxt_min(buf_size, part_size);

        mmap_buf.buf.free = nxt_cpymem(mmap_buf.buf.free,
                                       part_start, part_size);

        rc = nxt_unit_mmap_buf_send(req, &mmap_buf, 0);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return -rc;
        }

        size -= part_size;
        part_start += part_size;
        sent += part_size;

        min_size -= nxt_min(min_size, part_size);
    }

    return sent;
}


int
nxt_unit_response_write_cb(nxt_unit_request_info_t *req,
    nxt_unit_read_info_t *read_info)
{
    int                           rc;
    ssize_t                       n;
    uint32_t                      buf_size;
    nxt_unit_buf_t                *buf;
    nxt_unit_mmap_buf_t           mmap_buf;
    nxt_unit_request_info_impl_t  *req_impl;
    char                          local_buf[NXT_UNIT_LOCAL_BUF_SIZE];

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

    if (nxt_slow_path(req_impl->state < NXT_UNIT_RS_RESPONSE_INIT)) {
        nxt_unit_req_alert(req, "write: response not initialized yet");

        return NXT_UNIT_ERROR;
    }

    /* Check if response is not send yet. */
    if (nxt_slow_path(req->response_buf != NULL)) {

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

        buf_size = nxt_min(read_info->buf_size, PORT_MMAP_DATA_SIZE);

        rc = nxt_unit_get_outgoing_buf(req->ctx, req->response_port,
                                       buf_size, buf_size,
                                       &mmap_buf, local_buf);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return rc;
        }

        buf = &mmap_buf.buf;

        while (!read_info->eof && buf->end > buf->free) {
            n = read_info->read(read_info, buf->free, buf->end - buf->free);
            if (nxt_slow_path(n < 0)) {
                nxt_unit_req_error(req, "Read error");

                nxt_unit_free_outgoing_buf(&mmap_buf);

                return NXT_UNIT_ERROR;
            }

            buf->free += n;
        }

        rc = nxt_unit_mmap_buf_send(req, &mmap_buf, 0);
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
    ssize_t  buf_res, res;

    buf_res = nxt_unit_buf_read(&req->content_buf, &req->content_length,
                                dst, size);

    if (buf_res < (ssize_t) size && req->content_fd != -1) {
        res = read(req->content_fd, dst, size);
        if (nxt_slow_path(res < 0)) {
            nxt_unit_req_alert(req, "failed to read content: %s (%d)",
                               strerror(errno), errno);

            return res;
        }

        if (res < (ssize_t) size) {
            nxt_unit_close(req->content_fd);

            req->content_fd = -1;
        }

        req->content_length -= res;

        dst = nxt_pointer_to(dst, res);

    } else {
        res = 0;
    }

    return buf_res + res;
}


ssize_t
nxt_unit_request_readline_size(nxt_unit_request_info_t *req, size_t max_size)
{
    char                 *p;
    size_t               l_size, b_size;
    nxt_unit_buf_t       *b;
    nxt_unit_mmap_buf_t  *mmap_buf, *preread_buf;

    if (req->content_length == 0) {
        return 0;
    }

    l_size = 0;

    b = req->content_buf;

    while (b != NULL) {
        b_size = b->end - b->free;
        p = memchr(b->free, '\n', b_size);

        if (p != NULL) {
            p++;
            l_size += p - b->free;
            break;
        }

        l_size += b_size;

        if (max_size <= l_size) {
            break;
        }

        mmap_buf = nxt_container_of(b, nxt_unit_mmap_buf_t, buf);
        if (mmap_buf->next == NULL
            && req->content_fd != -1
            && l_size < req->content_length)
        {
            preread_buf = nxt_unit_request_preread(req, 16384);
            if (nxt_slow_path(preread_buf == NULL)) {
                return -1;
            }

            nxt_unit_mmap_buf_insert(&mmap_buf->next, preread_buf);
        }

        b = nxt_unit_buf_next(b);
    }

    return nxt_min(max_size, l_size);
}


static nxt_unit_mmap_buf_t *
nxt_unit_request_preread(nxt_unit_request_info_t *req, size_t size)
{
    ssize_t              res;
    nxt_unit_mmap_buf_t  *mmap_buf;

    if (req->content_fd == -1) {
        nxt_unit_req_alert(req, "preread: content_fd == -1");
        return NULL;
    }

    mmap_buf = nxt_unit_mmap_buf_get(req->ctx);
    if (nxt_slow_path(mmap_buf == NULL)) {
        nxt_unit_req_alert(req, "preread: failed to allocate buf");
        return NULL;
    }

    mmap_buf->free_ptr = nxt_unit_malloc(req->ctx, size);
    if (nxt_slow_path(mmap_buf->free_ptr == NULL)) {
        nxt_unit_req_alert(req, "preread: failed to allocate buf memory");
        nxt_unit_mmap_buf_release(mmap_buf);
        return NULL;
    }

    mmap_buf->plain_ptr = mmap_buf->free_ptr;

    mmap_buf->hdr = NULL;
    mmap_buf->buf.start = mmap_buf->free_ptr;
    mmap_buf->buf.free = mmap_buf->buf.start;
    mmap_buf->buf.end = mmap_buf->buf.start + size;

    res = read(req->content_fd, mmap_buf->free_ptr, size);
    if (res < 0) {
        nxt_unit_req_alert(req, "failed to read content: %s (%d)",
                           strerror(errno), errno);

        nxt_unit_mmap_buf_free(mmap_buf);

        return NULL;
    }

    if (res < (ssize_t) size) {
        nxt_unit_close(req->content_fd);

        req->content_fd = -1;
    }

    nxt_unit_req_debug(req, "preread: read %d", (int) res);

    mmap_buf->buf.end = mmap_buf->buf.free + res;

    return mmap_buf;
}


static ssize_t
nxt_unit_buf_read(nxt_unit_buf_t **b, uint64_t *len, void *dst, size_t size)
{
    u_char          *p;
    size_t          rest, copy, read;
    nxt_unit_buf_t  *buf, *last_buf;

    p = dst;
    rest = size;

    buf = *b;
    last_buf = buf;

    while (buf != NULL) {
        last_buf = buf;

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

    *b = last_buf;

    read = size - rest;

    *len -= read;

    return read;
}


void
nxt_unit_request_done(nxt_unit_request_info_t *req, int rc)
{
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

    msg.stream = req_impl->stream;
    msg.pid = lib->pid;
    msg.reply_port = 0;
    msg.type = (rc == NXT_UNIT_OK) ? _NXT_PORT_MSG_DATA
                                   : _NXT_PORT_MSG_RPC_ERROR;
    msg.last = 1;
    msg.mmap = 0;
    msg.nf = 0;
    msg.mf = 0;

    (void) nxt_unit_port_send(req->ctx, req->response_port,
                              &msg, sizeof(msg), NULL);

    nxt_unit_request_info_release(req);
}


int
nxt_unit_websocket_send(nxt_unit_request_info_t *req, uint8_t opcode,
    uint8_t last, const void *start, size_t size)
{
    const struct iovec  iov = { (void *) start, size };

    return nxt_unit_websocket_sendv(req, opcode, last, &iov, 1);
}


int
nxt_unit_websocket_sendv(nxt_unit_request_info_t *req, uint8_t opcode,
    uint8_t last, const struct iovec *iov, int iovcnt)
{
    int                     i, rc;
    size_t                  l, copy;
    uint32_t                payload_len, buf_size, alloc_size;
    const uint8_t           *b;
    nxt_unit_buf_t          *buf;
    nxt_unit_mmap_buf_t     mmap_buf;
    nxt_websocket_header_t  *wh;
    char                    local_buf[NXT_UNIT_LOCAL_BUF_SIZE];

    payload_len = 0;

    for (i = 0; i < iovcnt; i++) {
        payload_len += iov[i].iov_len;
    }

    buf_size = 10 + payload_len;
    alloc_size = nxt_min(buf_size, PORT_MMAP_DATA_SIZE);

    rc = nxt_unit_get_outgoing_buf(req->ctx, req->response_port,
                                   alloc_size, alloc_size,
                                   &mmap_buf, local_buf);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return rc;
    }

    buf = &mmap_buf.buf;

    buf->start[0] = 0;
    buf->start[1] = 0;

    buf_size -= buf->end - buf->start;

    wh = (void *) buf->free;

    buf->free = nxt_websocket_frame_init(wh, payload_len);
    wh->fin = last;
    wh->opcode = opcode;

    for (i = 0; i < iovcnt; i++) {
        b = iov[i].iov_base;
        l = iov[i].iov_len;

        while (l > 0) {
            copy = buf->end - buf->free;
            copy = nxt_min(l, copy);

            buf->free = nxt_cpymem(buf->free, b, copy);
            b += copy;
            l -= copy;

            if (l > 0) {
                if (nxt_fast_path(buf->free > buf->start)) {
                    rc = nxt_unit_mmap_buf_send(req, &mmap_buf, 0);

                    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
                        return rc;
                    }
                }

                alloc_size = nxt_min(buf_size, PORT_MMAP_DATA_SIZE);

                rc = nxt_unit_get_outgoing_buf(req->ctx, req->response_port,
                                               alloc_size, alloc_size,
                                               &mmap_buf, local_buf);
                if (nxt_slow_path(rc != NXT_UNIT_OK)) {
                    return rc;
                }

                buf_size -= buf->end - buf->start;
            }
        }
    }

    if (buf->free > buf->start) {
        rc = nxt_unit_mmap_buf_send(req, &mmap_buf, 0);
    }

    return rc;
}


ssize_t
nxt_unit_websocket_read(nxt_unit_websocket_frame_t *ws, void *dst,
    size_t size)
{
    ssize_t   res;
    uint8_t   *b;
    uint64_t  i, d;

    res = nxt_unit_buf_read(&ws->content_buf, &ws->content_length,
                            dst, size);

    if (ws->mask == NULL) {
        return res;
    }

    b = dst;
    d = (ws->payload_len - ws->content_length - res) % 4;

    for (i = 0; i < (uint64_t) res; i++) {
        b[i] ^= ws->mask[ (i + d) % 4 ];
    }

    return res;
}


int
nxt_unit_websocket_retain(nxt_unit_websocket_frame_t *ws)
{
    char                             *b;
    size_t                           size, hsize;
    nxt_unit_websocket_frame_impl_t  *ws_impl;

    ws_impl = nxt_container_of(ws, nxt_unit_websocket_frame_impl_t, ws);

    if (ws_impl->buf->free_ptr != NULL || ws_impl->buf->hdr != NULL) {
        return NXT_UNIT_OK;
    }

    size = ws_impl->buf->buf.end - ws_impl->buf->buf.start;

    b = nxt_unit_malloc(ws->req->ctx, size);
    if (nxt_slow_path(b == NULL)) {
        return NXT_UNIT_ERROR;
    }

    memcpy(b, ws_impl->buf->buf.start, size);

    hsize = nxt_websocket_frame_header_size(b);

    ws_impl->buf->buf.start = b;
    ws_impl->buf->buf.free = b + hsize;
    ws_impl->buf->buf.end = b + size;

    ws_impl->buf->free_ptr = b;

    ws_impl->ws.header = (nxt_websocket_header_t *) b;

    if (ws_impl->ws.header->mask) {
        ws_impl->ws.mask = (uint8_t *) b + hsize - 4;

    } else {
        ws_impl->ws.mask = NULL;
    }

    return NXT_UNIT_OK;
}


void
nxt_unit_websocket_done(nxt_unit_websocket_frame_t *ws)
{
    nxt_unit_websocket_frame_release(ws);
}


static nxt_port_mmap_header_t *
nxt_unit_mmap_get(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port,
    nxt_chunk_id_t *c, int *n, int min_n)
{
    int                     res, nchunks, i;
    uint32_t                outgoing_size;
    nxt_unit_mmap_t         *mm, *mm_end;
    nxt_unit_impl_t         *lib;
    nxt_port_mmap_header_t  *hdr;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    pthread_mutex_lock(&lib->outgoing.mutex);

    if (nxt_slow_path(lib->outgoing.elts == NULL)) {
        goto skip;
    }

retry:

    outgoing_size = lib->outgoing.size;

    mm_end = lib->outgoing.elts + outgoing_size;

    for (mm = lib->outgoing.elts; mm < mm_end; mm++) {
        hdr = mm->hdr;

        if (hdr->sent_over != 0xFFFFu
            && (hdr->sent_over != port->id.id
                || mm->src_thread != pthread_self()))
        {
            continue;
        }

        *c = 0;

        while (nxt_port_mmap_get_free_chunk(hdr->free_map, c)) {
            nchunks = 1;

            while (nchunks < *n) {
                res = nxt_port_mmap_chk_set_chunk_busy(hdr->free_map,
                                                       *c + nchunks);

                if (res == 0) {
                    if (nchunks >= min_n) {
                        *n = nchunks;

                        goto unlock;
                    }

                    for (i = 0; i < nchunks; i++) {
                        nxt_port_mmap_set_chunk_free(hdr->free_map, *c + i);
                    }

                    *c += nchunks + 1;
                    nchunks = 0;
                    break;
                }

                nchunks++;
            }

            if (nchunks >= min_n) {
                *n = nchunks;

                goto unlock;
            }
        }

        hdr->oosm = 1;
    }

    if (outgoing_size >= lib->shm_mmap_limit) {
        /* Cannot allocate more shared memory. */
        pthread_mutex_unlock(&lib->outgoing.mutex);

        if (min_n == 0) {
            *n = 0;
        }

        if (nxt_slow_path(lib->outgoing.allocated_chunks + min_n
                          >= lib->shm_mmap_limit * PORT_MMAP_CHUNK_COUNT))
        {
            /* Memory allocated by application, but not send to router. */
            return NULL;
        }

        /* Notify router about OOSM condition. */

        res = nxt_unit_send_oosm(ctx, port);
        if (nxt_slow_path(res != NXT_UNIT_OK)) {
            return NULL;
        }

        /* Return if caller can handle OOSM condition. Non-blocking mode. */

        if (min_n == 0) {
            return NULL;
        }

        nxt_unit_debug(ctx, "oosm: waiting for ACK");

        res = nxt_unit_wait_shm_ack(ctx);
        if (nxt_slow_path(res != NXT_UNIT_OK)) {
            return NULL;
        }

        nxt_unit_debug(ctx, "oosm: retry");

        pthread_mutex_lock(&lib->outgoing.mutex);

        goto retry;
    }

skip:

    *c = 0;
    hdr = nxt_unit_new_mmap(ctx, port, *n);

unlock:

    nxt_atomic_fetch_add(&lib->outgoing.allocated_chunks, *n);

    nxt_unit_debug(ctx, "allocated_chunks %d",
                   (int) lib->outgoing.allocated_chunks);

    pthread_mutex_unlock(&lib->outgoing.mutex);

    return hdr;
}


static int
nxt_unit_send_oosm(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port)
{
    ssize_t          res;
    nxt_port_msg_t   msg;
    nxt_unit_impl_t  *lib;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    msg.stream = 0;
    msg.pid = lib->pid;
    msg.reply_port = 0;
    msg.type = _NXT_PORT_MSG_OOSM;
    msg.last = 0;
    msg.mmap = 0;
    msg.nf = 0;
    msg.mf = 0;

    res = nxt_unit_port_send(ctx, lib->router_port, &msg, sizeof(msg), NULL);
    if (nxt_slow_path(res != sizeof(msg))) {
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


static int
nxt_unit_wait_shm_ack(nxt_unit_ctx_t *ctx)
{
    int                  res;
    nxt_unit_ctx_impl_t  *ctx_impl;
    nxt_unit_read_buf_t  *rbuf;

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    while (1) {
        rbuf = nxt_unit_read_buf_get(ctx);
        if (nxt_slow_path(rbuf == NULL)) {
            return NXT_UNIT_ERROR;
        }

        do {
            res = nxt_unit_ctx_port_recv(ctx, ctx_impl->read_port, rbuf);
        } while (res == NXT_UNIT_AGAIN);

        if (res == NXT_UNIT_ERROR) {
            nxt_unit_read_buf_release(ctx, rbuf);

            return NXT_UNIT_ERROR;
        }

        if (nxt_unit_is_shm_ack(rbuf)) {
            nxt_unit_read_buf_release(ctx, rbuf);
            break;
        }

        pthread_mutex_lock(&ctx_impl->mutex);

        nxt_queue_insert_tail(&ctx_impl->pending_rbuf, &rbuf->link);

        pthread_mutex_unlock(&ctx_impl->mutex);

        if (nxt_unit_is_quit(rbuf)) {
            nxt_unit_debug(ctx, "oosm: quit received");

            return NXT_UNIT_ERROR;
        }
    }

    return NXT_UNIT_OK;
}


static nxt_unit_mmap_t *
nxt_unit_mmap_at(nxt_unit_mmaps_t *mmaps, uint32_t i)
{
    uint32_t         cap, n;
    nxt_unit_mmap_t  *e;

    if (nxt_fast_path(mmaps->size > i)) {
        return mmaps->elts + i;
    }

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

        e = realloc(mmaps->elts, cap * sizeof(nxt_unit_mmap_t));
        if (nxt_slow_path(e == NULL)) {
            return NULL;
        }

        mmaps->elts = e;

        for (n = mmaps->cap; n < cap; n++) {
            e = mmaps->elts + n;

            e->hdr = NULL;
            nxt_queue_init(&e->awaiting_rbuf);
        }

        mmaps->cap = cap;
    }

    if (i + 1 > mmaps->size) {
        mmaps->size = i + 1;
    }

    return mmaps->elts + i;
}


static nxt_port_mmap_header_t *
nxt_unit_new_mmap(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port, int n)
{
    int                     i, fd, rc;
    void                    *mem;
    nxt_unit_mmap_t         *mm;
    nxt_unit_impl_t         *lib;
    nxt_port_mmap_header_t  *hdr;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    mm = nxt_unit_mmap_at(&lib->outgoing, lib->outgoing.size);
    if (nxt_slow_path(mm == NULL)) {
        nxt_unit_alert(ctx, "failed to add mmap to outgoing array");

        return NULL;
    }

    fd = nxt_unit_shm_open(ctx, PORT_MMAP_SIZE);
    if (nxt_slow_path(fd == -1)) {
        goto remove_fail;
    }

    mem = mmap(NULL, PORT_MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (nxt_slow_path(mem == MAP_FAILED)) {
        nxt_unit_alert(ctx, "mmap(%d) failed: %s (%d)", fd,
                       strerror(errno), errno);

        nxt_unit_close(fd);

        goto remove_fail;
    }

    mm->hdr = mem;
    hdr = mem;

    memset(hdr->free_map, 0xFFU, sizeof(hdr->free_map));
    memset(hdr->free_tracking_map, 0xFFU, sizeof(hdr->free_tracking_map));

    hdr->id = lib->outgoing.size - 1;
    hdr->src_pid = lib->pid;
    hdr->dst_pid = port->id.pid;
    hdr->sent_over = port->id.id;
    mm->src_thread = pthread_self();

    /* Mark first n chunk(s) as busy */
    for (i = 0; i < n; i++) {
        nxt_port_mmap_set_chunk_busy(hdr->free_map, i);
    }

    /* Mark as busy chunk followed the last available chunk. */
    nxt_port_mmap_set_chunk_busy(hdr->free_map, PORT_MMAP_CHUNK_COUNT);
    nxt_port_mmap_set_chunk_busy(hdr->free_tracking_map, PORT_MMAP_CHUNK_COUNT);

    pthread_mutex_unlock(&lib->outgoing.mutex);

    rc = nxt_unit_send_mmap(ctx, port, fd);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        munmap(mem, PORT_MMAP_SIZE);
        hdr = NULL;

    } else {
        nxt_unit_debug(ctx, "new mmap #%"PRIu32" created for %d -> %d",
                       hdr->id, (int) lib->pid, (int) port->id.pid);
    }

    nxt_unit_close(fd);

    pthread_mutex_lock(&lib->outgoing.mutex);

    if (nxt_fast_path(hdr != NULL)) {
        return hdr;
    }

remove_fail:

    lib->outgoing.size--;

    return NULL;
}


static int
nxt_unit_shm_open(nxt_unit_ctx_t *ctx, size_t size)
{
    int              fd;

#if (NXT_HAVE_MEMFD_CREATE || NXT_HAVE_SHM_OPEN)
    char             name[64];
    nxt_unit_impl_t  *lib;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);
    snprintf(name, sizeof(name), NXT_SHM_PREFIX "unit.%d.%p",
             lib->pid, (void *) (uintptr_t) pthread_self());
#endif

#if (NXT_HAVE_MEMFD_CREATE)

    fd = syscall(SYS_memfd_create, name, MFD_CLOEXEC);
    if (nxt_slow_path(fd == -1)) {
        nxt_unit_alert(ctx, "memfd_create(%s) failed: %s (%d)", name,
                       strerror(errno), errno);

        return -1;
    }

    nxt_unit_debug(ctx, "memfd_create(%s): %d", name, fd);

#elif (NXT_HAVE_SHM_OPEN_ANON)

    fd = shm_open(SHM_ANON, O_RDWR, S_IRUSR | S_IWUSR);
    if (nxt_slow_path(fd == -1)) {
        nxt_unit_alert(ctx, "shm_open(SHM_ANON) failed: %s (%d)",
                       strerror(errno), errno);

        return -1;
    }

#elif (NXT_HAVE_SHM_OPEN)

    /* Just in case. */
    shm_unlink(name);

    fd = shm_open(name, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
    if (nxt_slow_path(fd == -1)) {
        nxt_unit_alert(ctx, "shm_open(%s) failed: %s (%d)", name,
                       strerror(errno), errno);

        return -1;
    }

    if (nxt_slow_path(shm_unlink(name) == -1)) {
        nxt_unit_alert(ctx, "shm_unlink(%s) failed: %s (%d)", name,
                       strerror(errno), errno);
    }

#else

#error No working shared memory implementation.

#endif

    if (nxt_slow_path(ftruncate(fd, size) == -1)) {
        nxt_unit_alert(ctx, "ftruncate(%d) failed: %s (%d)", fd,
                       strerror(errno), errno);

        nxt_unit_close(fd);

        return -1;
    }

    return fd;
}


static int
nxt_unit_send_mmap(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port, int fd)
{
    ssize_t          res;
    nxt_send_oob_t   oob;
    nxt_port_msg_t   msg;
    nxt_unit_impl_t  *lib;
    int              fds[2] = {fd, -1};

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    msg.stream = 0;
    msg.pid = lib->pid;
    msg.reply_port = 0;
    msg.type = _NXT_PORT_MSG_MMAP;
    msg.last = 0;
    msg.mmap = 0;
    msg.nf = 0;
    msg.mf = 0;

    nxt_socket_msg_oob_init(&oob, fds);

    res = nxt_unit_port_send(ctx, port, &msg, sizeof(msg), &oob);
    if (nxt_slow_path(res != sizeof(msg))) {
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


static int
nxt_unit_get_outgoing_buf(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port,
    uint32_t size, uint32_t min_size,
    nxt_unit_mmap_buf_t *mmap_buf, char *local_buf)
{
    int                     nchunks, min_nchunks;
    nxt_chunk_id_t          c;
    nxt_port_mmap_header_t  *hdr;

    if (size <= NXT_UNIT_MAX_PLAIN_SIZE) {
        if (local_buf != NULL) {
            mmap_buf->free_ptr = NULL;
            mmap_buf->plain_ptr = local_buf;

        } else {
            mmap_buf->free_ptr = nxt_unit_malloc(ctx,
                                                 size + sizeof(nxt_port_msg_t));
            if (nxt_slow_path(mmap_buf->free_ptr == NULL)) {
                return NXT_UNIT_ERROR;
            }

            mmap_buf->plain_ptr = mmap_buf->free_ptr;
        }

        mmap_buf->hdr = NULL;
        mmap_buf->buf.start = mmap_buf->plain_ptr + sizeof(nxt_port_msg_t);
        mmap_buf->buf.free = mmap_buf->buf.start;
        mmap_buf->buf.end = mmap_buf->buf.start + size;

        nxt_unit_debug(ctx, "outgoing plain buffer allocation: (%p, %d)",
                       mmap_buf->buf.start, (int) size);

        return NXT_UNIT_OK;
    }

    nchunks = (size + PORT_MMAP_CHUNK_SIZE - 1) / PORT_MMAP_CHUNK_SIZE;
    min_nchunks = (min_size + PORT_MMAP_CHUNK_SIZE - 1) / PORT_MMAP_CHUNK_SIZE;

    hdr = nxt_unit_mmap_get(ctx, port, &c, &nchunks, min_nchunks);
    if (nxt_slow_path(hdr == NULL)) {
        if (nxt_fast_path(min_nchunks == 0 && nchunks == 0)) {
            mmap_buf->hdr = NULL;
            mmap_buf->buf.start = NULL;
            mmap_buf->buf.free = NULL;
            mmap_buf->buf.end = NULL;
            mmap_buf->free_ptr = NULL;

            return NXT_UNIT_OK;
        }

        return NXT_UNIT_ERROR;
    }

    mmap_buf->hdr = hdr;
    mmap_buf->buf.start = (char *) nxt_port_mmap_chunk_start(hdr, c);
    mmap_buf->buf.free = mmap_buf->buf.start;
    mmap_buf->buf.end = mmap_buf->buf.start + nchunks * PORT_MMAP_CHUNK_SIZE;
    mmap_buf->free_ptr = NULL;
    mmap_buf->ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    nxt_unit_debug(ctx, "outgoing mmap allocation: (%d,%d,%d)",
                  (int) hdr->id, (int) c,
                  (int) (nchunks * PORT_MMAP_CHUNK_SIZE));

    return NXT_UNIT_OK;
}


static int
nxt_unit_incoming_mmap(nxt_unit_ctx_t *ctx, pid_t pid, int fd)
{
    int                     rc;
    void                    *mem;
    nxt_queue_t             awaiting_rbuf;
    struct stat             mmap_stat;
    nxt_unit_mmap_t         *mm;
    nxt_unit_impl_t         *lib;
    nxt_unit_ctx_impl_t     *ctx_impl;
    nxt_unit_read_buf_t     *rbuf;
    nxt_port_mmap_header_t  *hdr;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    nxt_unit_debug(ctx, "incoming_mmap: fd %d from process %d", fd, (int) pid);

    if (fstat(fd, &mmap_stat) == -1) {
        nxt_unit_alert(ctx, "incoming_mmap: fstat(%d) failed: %s (%d)", fd,
                       strerror(errno), errno);

        return NXT_UNIT_ERROR;
    }

    mem = mmap(NULL, mmap_stat.st_size, PROT_READ | PROT_WRITE,
               MAP_SHARED, fd, 0);
    if (nxt_slow_path(mem == MAP_FAILED)) {
        nxt_unit_alert(ctx, "incoming_mmap: mmap() failed: %s (%d)",
                       strerror(errno), errno);

        return NXT_UNIT_ERROR;
    }

    hdr = mem;

    if (nxt_slow_path(hdr->src_pid != pid)) {

        nxt_unit_alert(ctx, "incoming_mmap: unexpected pid in mmap header "
                       "detected: %d != %d or %d != %d", (int) hdr->src_pid,
                       (int) pid, (int) hdr->dst_pid, (int) lib->pid);

        munmap(mem, PORT_MMAP_SIZE);

        return NXT_UNIT_ERROR;
    }

    nxt_queue_init(&awaiting_rbuf);

    pthread_mutex_lock(&lib->incoming.mutex);

    mm = nxt_unit_mmap_at(&lib->incoming, hdr->id);
    if (nxt_slow_path(mm == NULL)) {
        nxt_unit_alert(ctx, "incoming_mmap: failed to add to incoming array");

        munmap(mem, PORT_MMAP_SIZE);

        rc = NXT_UNIT_ERROR;

    } else {
        mm->hdr = hdr;

        hdr->sent_over = 0xFFFFu;

        nxt_queue_add(&awaiting_rbuf, &mm->awaiting_rbuf);
        nxt_queue_init(&mm->awaiting_rbuf);

        rc = NXT_UNIT_OK;
    }

    pthread_mutex_unlock(&lib->incoming.mutex);

    nxt_queue_each(rbuf, &awaiting_rbuf, nxt_unit_read_buf_t, link) {

        ctx_impl = rbuf->ctx_impl;

        pthread_mutex_lock(&ctx_impl->mutex);

        nxt_queue_insert_head(&ctx_impl->pending_rbuf, &rbuf->link);

        pthread_mutex_unlock(&ctx_impl->mutex);

        nxt_atomic_fetch_add(&ctx_impl->wait_items, -1);

        nxt_unit_awake_ctx(ctx, ctx_impl);

    } nxt_queue_loop;

    return rc;
}


static void
nxt_unit_awake_ctx(nxt_unit_ctx_t *ctx, nxt_unit_ctx_impl_t *ctx_impl)
{
    nxt_port_msg_t  msg;

    if (nxt_fast_path(ctx == &ctx_impl->ctx)) {
        return;
    }

    if (nxt_slow_path(ctx_impl->read_port == NULL
                      || ctx_impl->read_port->out_fd == -1))
    {
        nxt_unit_alert(ctx, "target context read_port is NULL or not writable");

        return;
    }

    memset(&msg, 0, sizeof(nxt_port_msg_t));

    msg.type = _NXT_PORT_MSG_RPC_READY;

    (void) nxt_unit_port_send(ctx, ctx_impl->read_port,
                              &msg, sizeof(msg), NULL);
}


static int
nxt_unit_mmaps_init(nxt_unit_mmaps_t *mmaps)
{
    mmaps->size = 0;
    mmaps->cap = 0;
    mmaps->elts = NULL;
    mmaps->allocated_chunks = 0;

    return pthread_mutex_init(&mmaps->mutex, NULL);
}


nxt_inline void
nxt_unit_process_use(nxt_unit_process_t *process)
{
    nxt_atomic_fetch_add(&process->use_count, 1);
}


nxt_inline void
nxt_unit_process_release(nxt_unit_process_t *process)
{
    long c;

    c = nxt_atomic_fetch_add(&process->use_count, -1);

    if (c == 1) {
        nxt_unit_debug(NULL, "destroy process #%d", (int) process->pid);

        nxt_unit_free(NULL, process);
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

        nxt_unit_free(NULL, mmaps->elts);
    }

    pthread_mutex_destroy(&mmaps->mutex);
}


static int
nxt_unit_check_rbuf_mmap(nxt_unit_ctx_t *ctx, nxt_unit_mmaps_t *mmaps,
    pid_t pid, uint32_t id, nxt_port_mmap_header_t **hdr,
    nxt_unit_read_buf_t *rbuf)
{
    int                  res, need_rbuf;
    nxt_unit_mmap_t      *mm;
    nxt_unit_ctx_impl_t  *ctx_impl;

    mm = nxt_unit_mmap_at(mmaps, id);
    if (nxt_slow_path(mm == NULL)) {
        nxt_unit_alert(ctx, "failed to allocate mmap");

        pthread_mutex_unlock(&mmaps->mutex);

        *hdr = NULL;

        return NXT_UNIT_ERROR;
    }

    *hdr = mm->hdr;

    if (nxt_fast_path(*hdr != NULL)) {
        return NXT_UNIT_OK;
    }

    need_rbuf = nxt_queue_is_empty(&mm->awaiting_rbuf);

    nxt_queue_insert_tail(&mm->awaiting_rbuf, &rbuf->link);

    pthread_mutex_unlock(&mmaps->mutex);

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    nxt_atomic_fetch_add(&ctx_impl->wait_items, 1);

    if (need_rbuf) {
        res = nxt_unit_get_mmap(ctx, pid, id);
        if (nxt_slow_path(res == NXT_UNIT_ERROR)) {
            return NXT_UNIT_ERROR;
        }
    }

    return NXT_UNIT_AGAIN;
}


static int
nxt_unit_mmap_read(nxt_unit_ctx_t *ctx, nxt_unit_recv_msg_t *recv_msg,
    nxt_unit_read_buf_t *rbuf)
{
    int                     res;
    void                    *start;
    uint32_t                size;
    nxt_unit_impl_t         *lib;
    nxt_unit_mmaps_t        *mmaps;
    nxt_unit_mmap_buf_t     *b, **incoming_tail;
    nxt_port_mmap_msg_t     *mmap_msg, *end;
    nxt_port_mmap_header_t  *hdr;

    if (nxt_slow_path(recv_msg->size < sizeof(nxt_port_mmap_msg_t))) {
        nxt_unit_warn(ctx, "#%"PRIu32": mmap_read: too small message (%d)",
                      recv_msg->stream, (int) recv_msg->size);

        return NXT_UNIT_ERROR;
    }

    mmap_msg = recv_msg->start;
    end = nxt_pointer_to(recv_msg->start, recv_msg->size);

    incoming_tail = &recv_msg->incoming_buf;

    /* Allocating buffer structures. */
    for (; mmap_msg < end; mmap_msg++) {
        b = nxt_unit_mmap_buf_get(ctx);
        if (nxt_slow_path(b == NULL)) {
            nxt_unit_warn(ctx, "#%"PRIu32": mmap_read: failed to allocate buf",
                          recv_msg->stream);

            while (recv_msg->incoming_buf != NULL) {
                nxt_unit_mmap_buf_release(recv_msg->incoming_buf);
            }

            return NXT_UNIT_ERROR;
        }

        nxt_unit_mmap_buf_insert(incoming_tail, b);
        incoming_tail = &b->next;
    }

    b = recv_msg->incoming_buf;
    mmap_msg = recv_msg->start;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    mmaps = &lib->incoming;

    pthread_mutex_lock(&mmaps->mutex);

    for (; mmap_msg < end; mmap_msg++) {
        res = nxt_unit_check_rbuf_mmap(ctx, mmaps,
                                       recv_msg->pid, mmap_msg->mmap_id,
                                       &hdr, rbuf);

        if (nxt_slow_path(res != NXT_UNIT_OK)) {
            while (recv_msg->incoming_buf != NULL) {
                nxt_unit_mmap_buf_release(recv_msg->incoming_buf);
            }

            return res;
        }

        start = nxt_port_mmap_chunk_start(hdr, mmap_msg->chunk_id);
        size = mmap_msg->size;

        if (recv_msg->start == mmap_msg) {
            recv_msg->start = start;
            recv_msg->size = size;
        }

        b->buf.start = start;
        b->buf.free = start;
        b->buf.end = b->buf.start + size;
        b->hdr = hdr;

        b = b->next;

        nxt_unit_debug(ctx, "#%"PRIu32": mmap_read: [%p,%d] %d->%d,(%d,%d,%d)",
                       recv_msg->stream,
                       start, (int) size,
                       (int) hdr->src_pid, (int) hdr->dst_pid,
                       (int) hdr->id, (int) mmap_msg->chunk_id,
                       (int) mmap_msg->size);
    }

    pthread_mutex_unlock(&mmaps->mutex);

    return NXT_UNIT_OK;
}


static int
nxt_unit_get_mmap(nxt_unit_ctx_t *ctx, pid_t pid, uint32_t id)
{
    ssize_t              res;
    nxt_unit_impl_t      *lib;
    nxt_unit_ctx_impl_t  *ctx_impl;

    struct {
        nxt_port_msg_t           msg;
        nxt_port_msg_get_mmap_t  get_mmap;
    } m;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);
    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    memset(&m.msg, 0, sizeof(nxt_port_msg_t));

    m.msg.pid = lib->pid;
    m.msg.reply_port = ctx_impl->read_port->id.id;
    m.msg.type = _NXT_PORT_MSG_GET_MMAP;

    m.get_mmap.id = id;

    nxt_unit_debug(ctx, "get_mmap: %d %d", (int) pid, (int) id);

    res = nxt_unit_port_send(ctx, lib->router_port, &m, sizeof(m), NULL);
    if (nxt_slow_path(res != sizeof(m))) {
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


static void
nxt_unit_mmap_release(nxt_unit_ctx_t *ctx, nxt_port_mmap_header_t *hdr,
    void *start, uint32_t size)
{
    int              freed_chunks;
    u_char           *p, *end;
    nxt_chunk_id_t   c;
    nxt_unit_impl_t  *lib;

    memset(start, 0xA5, size);

    p = start;
    end = p + size;
    c = nxt_port_mmap_chunk_id(hdr, p);
    freed_chunks = 0;

    while (p < end) {
        nxt_port_mmap_set_chunk_free(hdr->free_map, c);

        p += PORT_MMAP_CHUNK_SIZE;
        c++;
        freed_chunks++;
    }

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    if (hdr->src_pid == lib->pid && freed_chunks != 0) {
        nxt_atomic_fetch_add(&lib->outgoing.allocated_chunks, -freed_chunks);

        nxt_unit_debug(ctx, "allocated_chunks %d",
                       (int) lib->outgoing.allocated_chunks);
    }

    if (hdr->dst_pid == lib->pid
        && freed_chunks != 0
        && nxt_atomic_cmp_set(&hdr->oosm, 1, 0))
    {
        nxt_unit_send_shm_ack(ctx, hdr->src_pid);
    }
}


static int
nxt_unit_send_shm_ack(nxt_unit_ctx_t *ctx, pid_t pid)
{
    ssize_t          res;
    nxt_port_msg_t   msg;
    nxt_unit_impl_t  *lib;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    msg.stream = 0;
    msg.pid = lib->pid;
    msg.reply_port = 0;
    msg.type = _NXT_PORT_MSG_SHM_ACK;
    msg.last = 0;
    msg.mmap = 0;
    msg.nf = 0;
    msg.mf = 0;

    res = nxt_unit_port_send(ctx, lib->router_port, &msg, sizeof(msg), NULL);
    if (nxt_slow_path(res != sizeof(msg))) {
        return NXT_UNIT_ERROR;
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
    nxt_unit_lvlhsh_alloc,
    nxt_unit_lvlhsh_free,
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
        nxt_unit_process_use(process);

        return process;
    }

    process = nxt_unit_malloc(ctx, sizeof(nxt_unit_process_t));
    if (nxt_slow_path(process == NULL)) {
        nxt_unit_alert(ctx, "failed to allocate process for #%d", (int) pid);

        return NULL;
    }

    process->pid = pid;
    process->use_count = 2;
    process->next_port_id = 0;
    process->lib = lib;

    nxt_queue_init(&process->ports);

    lhq.replace = 0;
    lhq.value = process;

    switch (nxt_lvlhsh_insert(&lib->processes, &lhq)) {

    case NXT_OK:
        break;

    default:
        nxt_unit_alert(ctx, "process %d insert failed", (int) pid);

        nxt_unit_free(ctx, process);
        process = NULL;
        break;
    }

    return process;
}


static nxt_unit_process_t *
nxt_unit_process_find(nxt_unit_impl_t *lib, pid_t pid, int remove)
{
    int                 rc;
    nxt_lvlhsh_query_t  lhq;

    nxt_unit_process_lhq_pid(&lhq, &pid);

    if (remove) {
        rc = nxt_lvlhsh_delete(&lib->processes, &lhq);

    } else {
        rc = nxt_lvlhsh_find(&lib->processes, &lhq);
    }

    if (rc == NXT_OK) {
        if (!remove) {
            nxt_unit_process_use(lhq.value);
        }

        return lhq.value;
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
    int                  rc;
    nxt_unit_ctx_impl_t  *ctx_impl;

    nxt_unit_ctx_use(ctx);

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    rc = NXT_UNIT_OK;

    while (nxt_fast_path(ctx_impl->online)) {
        rc = nxt_unit_run_once_impl(ctx);

        if (nxt_slow_path(rc == NXT_UNIT_ERROR)) {
            nxt_unit_quit(ctx, NXT_QUIT_NORMAL);
            break;
        }
    }

    nxt_unit_ctx_release(ctx);

    return rc;
}


int
nxt_unit_run_once(nxt_unit_ctx_t *ctx)
{
    int  rc;

    nxt_unit_ctx_use(ctx);

    rc = nxt_unit_run_once_impl(ctx);

    nxt_unit_ctx_release(ctx);

    return rc;
}


static int
nxt_unit_run_once_impl(nxt_unit_ctx_t *ctx)
{
    int                  rc;
    nxt_unit_read_buf_t  *rbuf;

    rbuf = nxt_unit_read_buf_get(ctx);
    if (nxt_slow_path(rbuf == NULL)) {
        return NXT_UNIT_ERROR;
    }

    rc = nxt_unit_read_buf(ctx, rbuf);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_read_buf_release(ctx, rbuf);

        return rc;
    }

    rc = nxt_unit_process_msg(ctx, rbuf, NULL);
    if (nxt_slow_path(rc == NXT_UNIT_ERROR)) {
        return NXT_UNIT_ERROR;
    }

    rc = nxt_unit_process_pending_rbuf(ctx);
    if (nxt_slow_path(rc == NXT_UNIT_ERROR)) {
        return NXT_UNIT_ERROR;
    }

    nxt_unit_process_ready_req(ctx);

    return rc;
}


static int
nxt_unit_read_buf(nxt_unit_ctx_t *ctx, nxt_unit_read_buf_t *rbuf)
{
    int                   nevents, res, err;
    nxt_uint_t            nfds;
    nxt_unit_impl_t       *lib;
    nxt_unit_ctx_impl_t   *ctx_impl;
    nxt_unit_port_impl_t  *port_impl;
    struct pollfd         fds[2];

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    if (ctx_impl->wait_items > 0 || !nxt_unit_chk_ready(ctx)) {
        return nxt_unit_ctx_port_recv(ctx, ctx_impl->read_port, rbuf);
    }

    port_impl = nxt_container_of(ctx_impl->read_port, nxt_unit_port_impl_t,
                                 port);

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

retry:

    if (port_impl->from_socket == 0) {
        res = nxt_unit_port_queue_recv(ctx_impl->read_port, rbuf);
        if (res == NXT_UNIT_OK) {
            if (nxt_unit_is_read_socket(rbuf)) {
                port_impl->from_socket++;

                nxt_unit_debug(ctx, "port{%d,%d} dequeue 1 read_socket %d",
                               (int) ctx_impl->read_port->id.pid,
                               (int) ctx_impl->read_port->id.id,
                               port_impl->from_socket);

            } else {
                nxt_unit_debug(ctx, "port{%d,%d} dequeue %d",
                               (int) ctx_impl->read_port->id.pid,
                               (int) ctx_impl->read_port->id.id,
                               (int) rbuf->size);

                return NXT_UNIT_OK;
            }
        }
    }

    if (nxt_fast_path(nxt_unit_chk_ready(ctx))) {
        res = nxt_unit_app_queue_recv(ctx, lib->shared_port, rbuf);
        if (res == NXT_UNIT_OK) {
            return NXT_UNIT_OK;
        }

        fds[1].fd = lib->shared_port->in_fd;
        fds[1].events = POLLIN;

        nfds = 2;

    } else {
        nfds = 1;
    }

    fds[0].fd = ctx_impl->read_port->in_fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    fds[1].revents = 0;

    nevents = poll(fds, nfds, -1);
    if (nxt_slow_path(nevents == -1)) {
        err = errno;

        if (err == EINTR) {
            goto retry;
        }

        nxt_unit_alert(ctx, "poll(%d,%d) failed: %s (%d)",
                       fds[0].fd, fds[1].fd, strerror(err), err);

        rbuf->size = -1;

        return (err == EAGAIN) ? NXT_UNIT_AGAIN : NXT_UNIT_ERROR;
    }

    nxt_unit_debug(ctx, "poll(%d,%d): %d, revents [%04X, %04X]",
                   fds[0].fd, fds[1].fd, nevents, fds[0].revents,
                   fds[1].revents);

    if ((fds[0].revents & POLLIN) != 0) {
        res = nxt_unit_ctx_port_recv(ctx, ctx_impl->read_port, rbuf);
        if (res == NXT_UNIT_AGAIN) {
            goto retry;
        }

        return res;
    }

    if ((fds[1].revents & POLLIN) != 0) {
        res = nxt_unit_shared_port_recv(ctx, lib->shared_port, rbuf);
        if (res == NXT_UNIT_AGAIN) {
            goto retry;
        }

        return res;
    }

    nxt_unit_alert(ctx, "poll(%d,%d): %d unexpected revents [%04uXi, %04uXi]",
                   fds[0].fd, fds[1].fd, nevents, fds[0].revents,
                   fds[1].revents);

    return NXT_UNIT_ERROR;
}


static int
nxt_unit_chk_ready(nxt_unit_ctx_t *ctx)
{
    nxt_unit_impl_t      *lib;
    nxt_unit_ctx_impl_t  *ctx_impl;

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);
    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    return (ctx_impl->ready
            && (lib->request_limit == 0
                || lib->request_count < lib->request_limit));
}


static int
nxt_unit_process_pending_rbuf(nxt_unit_ctx_t *ctx)
{
    int                  rc;
    nxt_queue_t          pending_rbuf;
    nxt_unit_ctx_impl_t  *ctx_impl;
    nxt_unit_read_buf_t  *rbuf;

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    pthread_mutex_lock(&ctx_impl->mutex);

    if (nxt_queue_is_empty(&ctx_impl->pending_rbuf)) {
        pthread_mutex_unlock(&ctx_impl->mutex);

        return NXT_UNIT_OK;
    }

    nxt_queue_init(&pending_rbuf);

    nxt_queue_add(&pending_rbuf, &ctx_impl->pending_rbuf);
    nxt_queue_init(&ctx_impl->pending_rbuf);

    pthread_mutex_unlock(&ctx_impl->mutex);

    rc = NXT_UNIT_OK;

    nxt_queue_each(rbuf, &pending_rbuf, nxt_unit_read_buf_t, link) {

        if (nxt_fast_path(rc != NXT_UNIT_ERROR)) {
            rc = nxt_unit_process_msg(&ctx_impl->ctx, rbuf, NULL);

        } else {
            nxt_unit_read_buf_release(ctx, rbuf);
        }

    } nxt_queue_loop;

    if (!ctx_impl->ready) {
        nxt_unit_quit(ctx, NXT_QUIT_GRACEFUL);
    }

    return rc;
}


static void
nxt_unit_process_ready_req(nxt_unit_ctx_t *ctx)
{
    int                           res;
    nxt_queue_t                   ready_req;
    nxt_unit_impl_t               *lib;
    nxt_unit_ctx_impl_t           *ctx_impl;
    nxt_unit_request_info_t       *req;
    nxt_unit_request_info_impl_t  *req_impl;

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    pthread_mutex_lock(&ctx_impl->mutex);

    if (nxt_queue_is_empty(&ctx_impl->ready_req)) {
        pthread_mutex_unlock(&ctx_impl->mutex);

        return;
    }

    nxt_queue_init(&ready_req);

    nxt_queue_add(&ready_req, &ctx_impl->ready_req);
    nxt_queue_init(&ctx_impl->ready_req);

    pthread_mutex_unlock(&ctx_impl->mutex);

    nxt_queue_each(req_impl, &ready_req,
                   nxt_unit_request_info_impl_t, port_wait_link)
    {
        lib = nxt_container_of(ctx_impl->ctx.unit, nxt_unit_impl_t, unit);

        req = &req_impl->req;

        res = nxt_unit_send_req_headers_ack(req);
        if (nxt_slow_path(res != NXT_UNIT_OK)) {
            nxt_unit_request_done(req, NXT_UNIT_ERROR);

            continue;
        }

        if (req->content_length
            > (uint64_t) (req->content_buf->end - req->content_buf->free))
        {
            res = nxt_unit_request_hash_add(ctx, req);
            if (nxt_slow_path(res != NXT_UNIT_OK)) {
                nxt_unit_req_warn(req, "failed to add request to hash");

                nxt_unit_request_done(req, NXT_UNIT_ERROR);

                continue;
            }

            /*
             * If application have separate data handler, we may start
             * request processing and process data when it is arrived.
             */
            if (lib->callbacks.data_handler == NULL) {
                continue;
            }
        }

        lib->callbacks.request_handler(&req_impl->req);

    } nxt_queue_loop;
}


int
nxt_unit_run_ctx(nxt_unit_ctx_t *ctx)
{
    int                  rc;
    nxt_unit_read_buf_t  *rbuf;
    nxt_unit_ctx_impl_t  *ctx_impl;

    nxt_unit_ctx_use(ctx);

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    rc = NXT_UNIT_OK;

    while (nxt_fast_path(ctx_impl->online)) {
        rbuf = nxt_unit_read_buf_get(ctx);
        if (nxt_slow_path(rbuf == NULL)) {
            rc = NXT_UNIT_ERROR;
            break;
        }

    retry:

        rc = nxt_unit_ctx_port_recv(ctx, ctx_impl->read_port, rbuf);
        if (rc == NXT_UNIT_AGAIN) {
            goto retry;
        }

        rc = nxt_unit_process_msg(ctx, rbuf, NULL);
        if (nxt_slow_path(rc == NXT_UNIT_ERROR)) {
            break;
        }

        rc = nxt_unit_process_pending_rbuf(ctx);
        if (nxt_slow_path(rc == NXT_UNIT_ERROR)) {
            break;
        }

        nxt_unit_process_ready_req(ctx);
    }

    nxt_unit_ctx_release(ctx);

    return rc;
}


nxt_inline int
nxt_unit_is_read_queue(nxt_unit_read_buf_t *rbuf)
{
    nxt_port_msg_t  *port_msg;

    if (nxt_fast_path(rbuf->size == (ssize_t) sizeof(nxt_port_msg_t))) {
        port_msg = (nxt_port_msg_t *) rbuf->buf;

        return port_msg->type == _NXT_PORT_MSG_READ_QUEUE;
    }

    return 0;
}


nxt_inline int
nxt_unit_is_read_socket(nxt_unit_read_buf_t *rbuf)
{
    if (nxt_fast_path(rbuf->size == 1)) {
        return rbuf->buf[0] == _NXT_PORT_MSG_READ_SOCKET;
    }

    return 0;
}


nxt_inline int
nxt_unit_is_shm_ack(nxt_unit_read_buf_t *rbuf)
{
    nxt_port_msg_t  *port_msg;

    if (nxt_fast_path(rbuf->size == (ssize_t) sizeof(nxt_port_msg_t))) {
        port_msg = (nxt_port_msg_t *) rbuf->buf;

        return port_msg->type == _NXT_PORT_MSG_SHM_ACK;
    }

    return 0;
}


nxt_inline int
nxt_unit_is_quit(nxt_unit_read_buf_t *rbuf)
{
    nxt_port_msg_t  *port_msg;

    if (nxt_fast_path(rbuf->size == (ssize_t) sizeof(nxt_port_msg_t))) {
        port_msg = (nxt_port_msg_t *) rbuf->buf;

        return port_msg->type == _NXT_PORT_MSG_QUIT;
    }

    return 0;
}


int
nxt_unit_run_shared(nxt_unit_ctx_t *ctx)
{
    int                  rc;
    nxt_unit_impl_t      *lib;
    nxt_unit_read_buf_t  *rbuf;

    nxt_unit_ctx_use(ctx);

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    rc = NXT_UNIT_OK;

    while (nxt_fast_path(nxt_unit_chk_ready(ctx))) {
        rbuf = nxt_unit_read_buf_get(ctx);
        if (nxt_slow_path(rbuf == NULL)) {
            rc = NXT_UNIT_ERROR;
            break;
        }

    retry:

        rc = nxt_unit_shared_port_recv(ctx, lib->shared_port, rbuf);
        if (rc == NXT_UNIT_AGAIN) {
            goto retry;
        }

        if (nxt_slow_path(rc == NXT_UNIT_ERROR)) {
            nxt_unit_read_buf_release(ctx, rbuf);
            break;
        }

        rc = nxt_unit_process_msg(ctx, rbuf, NULL);
        if (nxt_slow_path(rc == NXT_UNIT_ERROR)) {
            break;
        }
    }

    nxt_unit_ctx_release(ctx);

    return rc;
}


nxt_unit_request_info_t *
nxt_unit_dequeue_request(nxt_unit_ctx_t *ctx)
{
    int                      rc;
    nxt_unit_impl_t          *lib;
    nxt_unit_read_buf_t      *rbuf;
    nxt_unit_request_info_t  *req;

    nxt_unit_ctx_use(ctx);

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    req = NULL;

    if (nxt_slow_path(!nxt_unit_chk_ready(ctx))) {
        goto done;
    }

    rbuf = nxt_unit_read_buf_get(ctx);
    if (nxt_slow_path(rbuf == NULL)) {
        goto done;
    }

    rc = nxt_unit_app_queue_recv(ctx, lib->shared_port, rbuf);
    if (rc != NXT_UNIT_OK) {
        nxt_unit_read_buf_release(ctx, rbuf);
        goto done;
    }

    (void) nxt_unit_process_msg(ctx, rbuf, &req);

done:

    nxt_unit_ctx_release(ctx);

    return req;
}


int
nxt_unit_process_port_msg(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port)
{
    int  rc;

    nxt_unit_ctx_use(ctx);

    rc = nxt_unit_process_port_msg_impl(ctx, port);

    nxt_unit_ctx_release(ctx);

    return rc;
}


static int
nxt_unit_process_port_msg_impl(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port)
{
    int                  rc;
    nxt_unit_impl_t      *lib;
    nxt_unit_read_buf_t  *rbuf;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    if (port == lib->shared_port && !nxt_unit_chk_ready(ctx)) {
        return NXT_UNIT_AGAIN;
    }

    rbuf = nxt_unit_read_buf_get(ctx);
    if (nxt_slow_path(rbuf == NULL)) {
        return NXT_UNIT_ERROR;
    }

    if (port == lib->shared_port) {
        rc = nxt_unit_shared_port_recv(ctx, port, rbuf);

    } else {
        rc = nxt_unit_ctx_port_recv(ctx, port, rbuf);
    }

    if (rc != NXT_UNIT_OK) {
        nxt_unit_read_buf_release(ctx, rbuf);
        return rc;
    }

    rc = nxt_unit_process_msg(ctx, rbuf, NULL);
    if (nxt_slow_path(rc == NXT_UNIT_ERROR)) {
        return NXT_UNIT_ERROR;
    }

    rc = nxt_unit_process_pending_rbuf(ctx);
    if (nxt_slow_path(rc == NXT_UNIT_ERROR)) {
        return NXT_UNIT_ERROR;
    }

    nxt_unit_process_ready_req(ctx);

    return rc;
}


void
nxt_unit_done(nxt_unit_ctx_t *ctx)
{
    nxt_unit_ctx_release(ctx);
}


nxt_unit_ctx_t *
nxt_unit_ctx_alloc(nxt_unit_ctx_t *ctx, void *data)
{
    int                   rc, queue_fd;
    void                  *mem;
    nxt_unit_impl_t       *lib;
    nxt_unit_port_t       *port;
    nxt_unit_ctx_impl_t   *new_ctx;
    nxt_unit_port_impl_t  *port_impl;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    new_ctx = nxt_unit_malloc(ctx, sizeof(nxt_unit_ctx_impl_t)
                                   + lib->request_data_size);
    if (nxt_slow_path(new_ctx == NULL)) {
        nxt_unit_alert(ctx, "failed to allocate context");

        return NULL;
    }

    rc = nxt_unit_ctx_init(lib, new_ctx, data);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_free(ctx, new_ctx);

        return NULL;
    }

    queue_fd = -1;

    port = nxt_unit_create_port(&new_ctx->ctx);
    if (nxt_slow_path(port == NULL)) {
        goto fail;
    }

    new_ctx->read_port = port;

    queue_fd = nxt_unit_shm_open(&new_ctx->ctx, sizeof(nxt_port_queue_t));
    if (nxt_slow_path(queue_fd == -1)) {
        goto fail;
    }

    mem = mmap(NULL, sizeof(nxt_port_queue_t),
               PROT_READ | PROT_WRITE, MAP_SHARED, queue_fd, 0);
    if (nxt_slow_path(mem == MAP_FAILED)) {
        nxt_unit_alert(ctx, "mmap(%d) failed: %s (%d)", queue_fd,
                       strerror(errno), errno);

        goto fail;
    }

    nxt_port_queue_init(mem);

    port_impl = nxt_container_of(port, nxt_unit_port_impl_t, port);
    port_impl->queue = mem;

    rc = nxt_unit_send_port(&new_ctx->ctx, lib->router_port, port, queue_fd);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    nxt_unit_close(queue_fd);

    return &new_ctx->ctx;

fail:

    if (queue_fd != -1) {
        nxt_unit_close(queue_fd);
    }

    nxt_unit_ctx_release(&new_ctx->ctx);

    return NULL;
}


static void
nxt_unit_ctx_free(nxt_unit_ctx_impl_t *ctx_impl)
{
    nxt_unit_impl_t                  *lib;
    nxt_unit_mmap_buf_t              *mmap_buf;
    nxt_unit_read_buf_t              *rbuf;
    nxt_unit_request_info_impl_t     *req_impl;
    nxt_unit_websocket_frame_impl_t  *ws_impl;

    lib = nxt_container_of(ctx_impl->ctx.unit, nxt_unit_impl_t, unit);

    nxt_queue_each(req_impl, &ctx_impl->active_req,
                   nxt_unit_request_info_impl_t, link)
    {
        nxt_unit_req_warn(&req_impl->req, "active request on ctx free");

        nxt_unit_request_done(&req_impl->req, NXT_UNIT_ERROR);

    } nxt_queue_loop;

    nxt_unit_mmap_buf_unlink(&ctx_impl->ctx_buf[0]);
    nxt_unit_mmap_buf_unlink(&ctx_impl->ctx_buf[1]);

    while (ctx_impl->free_buf != NULL) {
        mmap_buf = ctx_impl->free_buf;
        nxt_unit_mmap_buf_unlink(mmap_buf);
        nxt_unit_free(&ctx_impl->ctx, mmap_buf);
    }

    nxt_queue_each(req_impl, &ctx_impl->free_req,
                   nxt_unit_request_info_impl_t, link)
    {
        nxt_unit_request_info_free(req_impl);

    } nxt_queue_loop;

    nxt_queue_each(ws_impl, &ctx_impl->free_ws,
                   nxt_unit_websocket_frame_impl_t, link)
    {
        nxt_unit_websocket_frame_free(&ctx_impl->ctx, ws_impl);

    } nxt_queue_loop;

    nxt_queue_each(rbuf, &ctx_impl->free_rbuf, nxt_unit_read_buf_t, link)
    {
        if (rbuf != &ctx_impl->ctx_read_buf) {
            nxt_unit_free(&ctx_impl->ctx, rbuf);
        }
    } nxt_queue_loop;

    pthread_mutex_destroy(&ctx_impl->mutex);

    pthread_mutex_lock(&lib->mutex);

    nxt_queue_remove(&ctx_impl->link);

    pthread_mutex_unlock(&lib->mutex);

    if (nxt_fast_path(ctx_impl->read_port != NULL)) {
        nxt_unit_remove_port(lib, NULL, &ctx_impl->read_port->id);
        nxt_unit_port_release(ctx_impl->read_port);
    }

    if (ctx_impl != &lib->main_ctx) {
        nxt_unit_free(&lib->main_ctx.ctx, ctx_impl);
    }

    nxt_unit_lib_release(lib);
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


static nxt_unit_port_t *
nxt_unit_create_port(nxt_unit_ctx_t *ctx)
{
    int                 rc, port_sockets[2];
    nxt_unit_impl_t     *lib;
    nxt_unit_port_t     new_port, *port;
    nxt_unit_process_t  *process;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    rc = socketpair(AF_UNIX, NXT_UNIX_SOCKET, 0, port_sockets);
    if (nxt_slow_path(rc != 0)) {
        nxt_unit_warn(ctx, "create_port: socketpair() failed: %s (%d)",
                      strerror(errno), errno);

        return NULL;
    }

#if (NXT_HAVE_SOCKOPT_SO_PASSCRED)
    int  enable_creds = 1;

    if (nxt_slow_path(setsockopt(port_sockets[0], SOL_SOCKET, SO_PASSCRED,
                        &enable_creds, sizeof(enable_creds)) == -1))
    {
        nxt_unit_warn(ctx, "failed to set SO_PASSCRED %s", strerror(errno));
        return NULL;
    }

    if (nxt_slow_path(setsockopt(port_sockets[1], SOL_SOCKET, SO_PASSCRED,
                        &enable_creds, sizeof(enable_creds)) == -1))
    {
        nxt_unit_warn(ctx, "failed to set SO_PASSCRED %s", strerror(errno));
        return NULL;
    }
#endif

    nxt_unit_debug(ctx, "create_port: new socketpair: %d->%d",
                   port_sockets[0], port_sockets[1]);

    pthread_mutex_lock(&lib->mutex);

    process = nxt_unit_process_get(ctx, lib->pid);
    if (nxt_slow_path(process == NULL)) {
        pthread_mutex_unlock(&lib->mutex);

        nxt_unit_close(port_sockets[0]);
        nxt_unit_close(port_sockets[1]);

        return NULL;
    }

    nxt_unit_port_id_init(&new_port.id, lib->pid, process->next_port_id++);

    new_port.in_fd = port_sockets[0];
    new_port.out_fd = port_sockets[1];
    new_port.data = NULL;

    pthread_mutex_unlock(&lib->mutex);

    nxt_unit_process_release(process);

    port = nxt_unit_add_port(ctx, &new_port, NULL);
    if (nxt_slow_path(port == NULL)) {
        nxt_unit_close(port_sockets[0]);
        nxt_unit_close(port_sockets[1]);
    }

    return port;
}


static int
nxt_unit_send_port(nxt_unit_ctx_t *ctx, nxt_unit_port_t *dst,
    nxt_unit_port_t *port, int queue_fd)
{
    ssize_t          res;
    nxt_send_oob_t   oob;
    nxt_unit_impl_t  *lib;
    int              fds[2] = { port->out_fd, queue_fd };

    struct {
        nxt_port_msg_t            msg;
        nxt_port_msg_new_port_t   new_port;
    } m;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    m.msg.stream = 0;
    m.msg.pid = lib->pid;
    m.msg.reply_port = 0;
    m.msg.type = _NXT_PORT_MSG_NEW_PORT;
    m.msg.last = 0;
    m.msg.mmap = 0;
    m.msg.nf = 0;
    m.msg.mf = 0;

    m.new_port.id = port->id.id;
    m.new_port.pid = port->id.pid;
    m.new_port.type = NXT_PROCESS_APP;
    m.new_port.max_size = 16 * 1024;
    m.new_port.max_share = 64 * 1024;

    nxt_socket_msg_oob_init(&oob, fds);

    res = nxt_unit_port_send(ctx, dst, &m, sizeof(m), &oob);

    return (res == sizeof(m)) ? NXT_UNIT_OK : NXT_UNIT_ERROR;
}


nxt_inline void nxt_unit_port_use(nxt_unit_port_t *port)
{
    nxt_unit_port_impl_t  *port_impl;

    port_impl = nxt_container_of(port, nxt_unit_port_impl_t, port);

    nxt_atomic_fetch_add(&port_impl->use_count, 1);
}


nxt_inline void nxt_unit_port_release(nxt_unit_port_t *port)
{
    long                  c;
    nxt_unit_port_impl_t  *port_impl;

    port_impl = nxt_container_of(port, nxt_unit_port_impl_t, port);

    c = nxt_atomic_fetch_add(&port_impl->use_count, -1);

    if (c == 1) {
        nxt_unit_debug(NULL, "destroy port{%d,%d} in_fd %d out_fd %d",
                       (int) port->id.pid, (int) port->id.id,
                       port->in_fd, port->out_fd);

        nxt_unit_process_release(port_impl->process);

        if (port->in_fd != -1) {
            nxt_unit_close(port->in_fd);

            port->in_fd = -1;
        }

        if (port->out_fd != -1) {
            nxt_unit_close(port->out_fd);

            port->out_fd = -1;
        }

        if (port_impl->queue != NULL) {
            munmap(port_impl->queue, (port->id.id == NXT_UNIT_SHARED_PORT_ID)
                                     ? sizeof(nxt_app_queue_t)
                                     : sizeof(nxt_port_queue_t));
        }

        nxt_unit_free(NULL, port_impl);
    }
}


static nxt_unit_port_t *
nxt_unit_add_port(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port, void *queue)
{
    int                   rc, ready;
    nxt_queue_t           awaiting_req;
    nxt_unit_impl_t       *lib;
    nxt_unit_port_t       *old_port;
    nxt_unit_process_t    *process;
    nxt_unit_port_impl_t  *new_port, *old_port_impl;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    pthread_mutex_lock(&lib->mutex);

    old_port = nxt_unit_port_hash_find(&lib->ports, &port->id, 0);

    if (nxt_slow_path(old_port != NULL)) {
        nxt_unit_debug(ctx, "add_port: duplicate port{%d,%d} "
                            "in_fd %d out_fd %d queue %p",
                            port->id.pid, port->id.id,
                            port->in_fd, port->out_fd, queue);

        if (old_port->data == NULL) {
            old_port->data = port->data;
            port->data = NULL;
        }

        if (old_port->in_fd == -1) {
            old_port->in_fd = port->in_fd;
            port->in_fd = -1;
        }

        if (port->in_fd != -1) {
            nxt_unit_close(port->in_fd);
            port->in_fd = -1;
        }

        if (old_port->out_fd == -1) {
            old_port->out_fd = port->out_fd;
            port->out_fd = -1;
        }

        if (port->out_fd != -1) {
            nxt_unit_close(port->out_fd);
            port->out_fd = -1;
        }

        *port = *old_port;

        nxt_queue_init(&awaiting_req);

        old_port_impl = nxt_container_of(old_port, nxt_unit_port_impl_t, port);

        if (old_port_impl->queue == NULL) {
            old_port_impl->queue = queue;
        }

        ready = (port->in_fd != -1 || port->out_fd != -1);

        /*
         * Port can be market as 'ready' only after callbacks.add_port() call.
         * Otherwise, request may try to use the port before callback.
         */
        if (lib->callbacks.add_port == NULL && ready) {
            old_port_impl->ready = ready;

            if (!nxt_queue_is_empty(&old_port_impl->awaiting_req)) {
                nxt_queue_add(&awaiting_req, &old_port_impl->awaiting_req);
                nxt_queue_init(&old_port_impl->awaiting_req);
            }
        }

        pthread_mutex_unlock(&lib->mutex);

        if (lib->callbacks.add_port != NULL && ready) {
            lib->callbacks.add_port(ctx, old_port);

            pthread_mutex_lock(&lib->mutex);

            old_port_impl->ready = ready;

            if (!nxt_queue_is_empty(&old_port_impl->awaiting_req)) {
                nxt_queue_add(&awaiting_req, &old_port_impl->awaiting_req);
                nxt_queue_init(&old_port_impl->awaiting_req);
            }

            pthread_mutex_unlock(&lib->mutex);
        }

        nxt_unit_process_awaiting_req(ctx, &awaiting_req);

        return old_port;
    }

    new_port = NULL;
    ready = 0;

    nxt_unit_debug(ctx, "add_port: port{%d,%d} in_fd %d out_fd %d queue %p",
                   port->id.pid, port->id.id,
                   port->in_fd, port->out_fd, queue);

    process = nxt_unit_process_get(ctx, port->id.pid);
    if (nxt_slow_path(process == NULL)) {
        goto unlock;
    }

    if (port->id.id != NXT_UNIT_SHARED_PORT_ID
        && port->id.id >= process->next_port_id)
    {
        process->next_port_id = port->id.id + 1;
    }

    new_port = nxt_unit_malloc(ctx, sizeof(nxt_unit_port_impl_t));
    if (nxt_slow_path(new_port == NULL)) {
        nxt_unit_alert(ctx, "add_port: %d,%d malloc() failed",
                       port->id.pid, port->id.id);

        goto unlock;
    }

    new_port->port = *port;

    rc = nxt_unit_port_hash_add(&lib->ports, &new_port->port);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_alert(ctx, "add_port: %d,%d hash_add failed",
                       port->id.pid, port->id.id);

        nxt_unit_free(ctx, new_port);

        new_port = NULL;

        goto unlock;
    }

    nxt_queue_insert_tail(&process->ports, &new_port->link);

    new_port->use_count = 2;
    new_port->process = process;
    new_port->queue = queue;
    new_port->from_socket = 0;
    new_port->socket_rbuf = NULL;

    nxt_queue_init(&new_port->awaiting_req);

    ready = (port->in_fd != -1 || port->out_fd != -1);

    if (lib->callbacks.add_port == NULL) {
        new_port->ready = ready;

    } else {
        new_port->ready = 0;
    }

    process = NULL;

unlock:

    pthread_mutex_unlock(&lib->mutex);

    if (nxt_slow_path(process != NULL)) {
        nxt_unit_process_release(process);
    }

    if (lib->callbacks.add_port != NULL && new_port != NULL && ready) {
        lib->callbacks.add_port(ctx, &new_port->port);

        nxt_queue_init(&awaiting_req);

        pthread_mutex_lock(&lib->mutex);

        new_port->ready = 1;

        if (!nxt_queue_is_empty(&new_port->awaiting_req)) {
            nxt_queue_add(&awaiting_req, &new_port->awaiting_req);
            nxt_queue_init(&new_port->awaiting_req);
        }

        pthread_mutex_unlock(&lib->mutex);

        nxt_unit_process_awaiting_req(ctx, &awaiting_req);
    }

    return (new_port == NULL) ? NULL : &new_port->port;
}


static void
nxt_unit_process_awaiting_req(nxt_unit_ctx_t *ctx, nxt_queue_t *awaiting_req)
{
    nxt_unit_ctx_impl_t           *ctx_impl;
    nxt_unit_request_info_impl_t  *req_impl;

    nxt_queue_each(req_impl, awaiting_req,
                   nxt_unit_request_info_impl_t, port_wait_link)
    {
        nxt_queue_remove(&req_impl->port_wait_link);

        ctx_impl = nxt_container_of(req_impl->req.ctx, nxt_unit_ctx_impl_t,
                                    ctx);

        pthread_mutex_lock(&ctx_impl->mutex);

        nxt_queue_insert_tail(&ctx_impl->ready_req,
                              &req_impl->port_wait_link);

        pthread_mutex_unlock(&ctx_impl->mutex);

        nxt_atomic_fetch_add(&ctx_impl->wait_items, -1);

        nxt_unit_awake_ctx(ctx, ctx_impl);

    } nxt_queue_loop;
}


static void
nxt_unit_remove_port(nxt_unit_impl_t *lib, nxt_unit_ctx_t *ctx,
    nxt_unit_port_id_t *port_id)
{
    nxt_unit_port_t       *port;
    nxt_unit_port_impl_t  *port_impl;

    pthread_mutex_lock(&lib->mutex);

    port = nxt_unit_remove_port_unsafe(lib, port_id);

    if (nxt_fast_path(port != NULL)) {
        port_impl = nxt_container_of(port, nxt_unit_port_impl_t, port);

        nxt_queue_remove(&port_impl->link);
    }

    pthread_mutex_unlock(&lib->mutex);

    if (lib->callbacks.remove_port != NULL && port != NULL) {
        lib->callbacks.remove_port(&lib->unit, ctx, port);
    }

    if (nxt_fast_path(port != NULL)) {
        nxt_unit_port_release(port);
    }
}


static nxt_unit_port_t *
nxt_unit_remove_port_unsafe(nxt_unit_impl_t *lib, nxt_unit_port_id_t *port_id)
{
    nxt_unit_port_t  *port;

    port = nxt_unit_port_hash_find(&lib->ports, port_id, 1);
    if (nxt_slow_path(port == NULL)) {
        nxt_unit_debug(NULL, "remove_port: port{%d,%d} not found",
                       (int) port_id->pid, (int) port_id->id);

        return NULL;
    }

    nxt_unit_debug(NULL, "remove_port: port{%d,%d}, fds %d,%d, data %p",
                   (int) port_id->pid, (int) port_id->id,
                   port->in_fd, port->out_fd, port->data);

    return port;
}


static void
nxt_unit_remove_pid(nxt_unit_impl_t *lib, pid_t pid)
{
    nxt_unit_process_t  *process;

    pthread_mutex_lock(&lib->mutex);

    process = nxt_unit_process_find(lib, pid, 1);
    if (nxt_slow_path(process == NULL)) {
        nxt_unit_debug(NULL, "remove_pid: process %d not found", (int) pid);

        pthread_mutex_unlock(&lib->mutex);

        return;
    }

    nxt_unit_remove_process(lib, process);

    if (lib->callbacks.remove_pid != NULL) {
        lib->callbacks.remove_pid(&lib->unit, pid);
    }
}


static void
nxt_unit_remove_process(nxt_unit_impl_t *lib, nxt_unit_process_t *process)
{
    nxt_queue_t           ports;
    nxt_unit_port_impl_t  *port;

    nxt_queue_init(&ports);

    nxt_queue_add(&ports, &process->ports);

    nxt_queue_each(port, &ports, nxt_unit_port_impl_t, link) {

        nxt_unit_remove_port_unsafe(lib, &port->port.id);

    } nxt_queue_loop;

    pthread_mutex_unlock(&lib->mutex);

    nxt_queue_each(port, &ports, nxt_unit_port_impl_t, link) {

        nxt_queue_remove(&port->link);

        if (lib->callbacks.remove_port != NULL) {
            lib->callbacks.remove_port(&lib->unit, NULL, &port->port);
        }

        nxt_unit_port_release(&port->port);

    } nxt_queue_loop;

    nxt_unit_process_release(process);
}


static void
nxt_unit_quit(nxt_unit_ctx_t *ctx, uint8_t quit_param)
{
    nxt_bool_t                    skip_graceful_broadcast, quit;
    nxt_unit_impl_t               *lib;
    nxt_unit_ctx_impl_t           *ctx_impl;
    nxt_unit_callbacks_t          *cb;
    nxt_unit_request_info_t       *req;
    nxt_unit_request_info_impl_t  *req_impl;

    struct {
        nxt_port_msg_t            msg;
        uint8_t                   quit_param;
    } nxt_packed m;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);
    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    nxt_unit_debug(ctx, "quit: %d/%d/%d", (int) quit_param, ctx_impl->ready,
                   ctx_impl->online);

    if (nxt_slow_path(!ctx_impl->online)) {
        return;
    }

    skip_graceful_broadcast = quit_param == NXT_QUIT_GRACEFUL
                              && !ctx_impl->ready;

    cb = &lib->callbacks;

    if (nxt_fast_path(ctx_impl->ready)) {
        ctx_impl->ready = 0;

        if (cb->remove_port != NULL) {
            cb->remove_port(&lib->unit, ctx, lib->shared_port);
        }
    }

    if (quit_param == NXT_QUIT_GRACEFUL) {
        pthread_mutex_lock(&ctx_impl->mutex);

        quit = nxt_queue_is_empty(&ctx_impl->active_req)
               && nxt_queue_is_empty(&ctx_impl->pending_rbuf)
               && ctx_impl->wait_items == 0;

        pthread_mutex_unlock(&ctx_impl->mutex);

    } else {
        quit = 1;
        ctx_impl->quit_param = NXT_QUIT_GRACEFUL;
    }

    if (quit) {
        ctx_impl->online = 0;

        if (cb->quit != NULL) {
            cb->quit(ctx);
        }

        nxt_queue_each(req_impl, &ctx_impl->active_req,
                       nxt_unit_request_info_impl_t, link)
        {
            req = &req_impl->req;

            nxt_unit_req_warn(req, "active request on ctx quit");

            if (cb->close_handler) {
                nxt_unit_req_debug(req, "close_handler");

                cb->close_handler(req);

            } else {
                nxt_unit_request_done(req, NXT_UNIT_ERROR);
            }

        } nxt_queue_loop;

        if (nxt_fast_path(ctx_impl->read_port != NULL)) {
            nxt_unit_remove_port(lib, ctx, &ctx_impl->read_port->id);
        }
    }

    if (ctx != &lib->main_ctx.ctx || skip_graceful_broadcast) {
        return;
    }

    memset(&m.msg, 0, sizeof(nxt_port_msg_t));

    m.msg.pid = lib->pid;
    m.msg.type = _NXT_PORT_MSG_QUIT;
    m.quit_param = quit_param;

    pthread_mutex_lock(&lib->mutex);

    nxt_queue_each(ctx_impl, &lib->contexts, nxt_unit_ctx_impl_t, link) {

        if (ctx == &ctx_impl->ctx
            || ctx_impl->read_port == NULL
            || ctx_impl->read_port->out_fd == -1)
        {
            continue;
        }

        (void) nxt_unit_port_send(ctx, ctx_impl->read_port,
                                  &m, sizeof(m), NULL);

    } nxt_queue_loop;

    pthread_mutex_unlock(&lib->mutex);
}


static int
nxt_unit_get_port(nxt_unit_ctx_t *ctx, nxt_unit_port_id_t *port_id)
{
    ssize_t              res;
    nxt_unit_impl_t      *lib;
    nxt_unit_ctx_impl_t  *ctx_impl;

    struct {
        nxt_port_msg_t           msg;
        nxt_port_msg_get_port_t  get_port;
    } m;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);
    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    memset(&m.msg, 0, sizeof(nxt_port_msg_t));

    m.msg.pid = lib->pid;
    m.msg.reply_port = ctx_impl->read_port->id.id;
    m.msg.type = _NXT_PORT_MSG_GET_PORT;

    m.get_port.id = port_id->id;
    m.get_port.pid = port_id->pid;

    nxt_unit_debug(ctx, "get_port: %d %d", (int) port_id->pid,
                   (int) port_id->id);

    res = nxt_unit_port_send(ctx, lib->router_port, &m, sizeof(m), NULL);
    if (nxt_slow_path(res != sizeof(m))) {
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


static ssize_t
nxt_unit_port_send(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port,
    const void *buf, size_t buf_size, const nxt_send_oob_t *oob)
{
    int                   notify;
    ssize_t               ret;
    nxt_int_t             rc;
    nxt_port_msg_t        msg;
    nxt_unit_impl_t       *lib;
    nxt_unit_port_impl_t  *port_impl;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    port_impl = nxt_container_of(port, nxt_unit_port_impl_t, port);
    if (port_impl->queue != NULL && (oob == NULL || oob->size == 0)
        && buf_size <= NXT_PORT_QUEUE_MSG_SIZE)
    {
        rc = nxt_port_queue_send(port_impl->queue, buf, buf_size, &notify);
        if (nxt_slow_path(rc != NXT_OK)) {
            nxt_unit_alert(ctx, "port_send: port %d,%d queue overflow",
                           (int) port->id.pid, (int) port->id.id);

            return -1;
        }

        nxt_unit_debug(ctx, "port{%d,%d} enqueue %d notify %d",
                       (int) port->id.pid, (int) port->id.id,
                       (int) buf_size, notify);

        if (notify) {
            memcpy(&msg, buf, sizeof(nxt_port_msg_t));

            msg.type = _NXT_PORT_MSG_READ_QUEUE;

            if (lib->callbacks.port_send == NULL) {
                ret = nxt_unit_sendmsg(ctx, port->out_fd, &msg,
                                       sizeof(nxt_port_msg_t), NULL);

                nxt_unit_debug(ctx, "port{%d,%d} send %d read_queue",
                               (int) port->id.pid, (int) port->id.id,
                               (int) ret);

            } else {
                ret = lib->callbacks.port_send(ctx, port, &msg,
                                               sizeof(nxt_port_msg_t), NULL, 0);

                nxt_unit_debug(ctx, "port{%d,%d} sendcb %d read_queue",
                               (int) port->id.pid, (int) port->id.id,
                               (int) ret);
            }

        }

        return buf_size;
    }

    if (port_impl->queue != NULL) {
        msg.type = _NXT_PORT_MSG_READ_SOCKET;

        rc = nxt_port_queue_send(port_impl->queue, &msg.type, 1, &notify);
        if (nxt_slow_path(rc != NXT_OK)) {
            nxt_unit_alert(ctx, "port_send: port %d,%d queue overflow",
                           (int) port->id.pid, (int) port->id.id);

            return -1;
        }

        nxt_unit_debug(ctx, "port{%d,%d} enqueue 1 read_socket notify %d",
                       (int) port->id.pid, (int) port->id.id, notify);
    }

    if (lib->callbacks.port_send != NULL) {
        ret = lib->callbacks.port_send(ctx, port, buf, buf_size,
                                       oob != NULL ? oob->buf : NULL,
                                       oob != NULL ? oob->size : 0);

        nxt_unit_debug(ctx, "port{%d,%d} sendcb %d",
                       (int) port->id.pid, (int) port->id.id,
                       (int) ret);

    } else {
        ret = nxt_unit_sendmsg(ctx, port->out_fd, buf, buf_size, oob);

        nxt_unit_debug(ctx, "port{%d,%d} sendmsg %d",
                       (int) port->id.pid, (int) port->id.id,
                       (int) ret);
    }

    return ret;
}


static ssize_t
nxt_unit_sendmsg(nxt_unit_ctx_t *ctx, int fd,
    const void *buf, size_t buf_size, const nxt_send_oob_t *oob)
{
    int            err;
    ssize_t        n;
    struct iovec   iov[1];

    iov[0].iov_base = (void *) buf;
    iov[0].iov_len = buf_size;

retry:

    n = nxt_sendmsg(fd, iov, 1, oob);

    if (nxt_slow_path(n == -1)) {
        err = errno;

        if (err == EINTR) {
            goto retry;
        }

        /*
         * FIXME: This should be "alert" after router graceful shutdown
         * implementation.
         */
        nxt_unit_warn(ctx, "sendmsg(%d, %d) failed: %s (%d)",
                      fd, (int) buf_size, strerror(err), err);

    } else {
        nxt_unit_debug(ctx, "sendmsg(%d, %d, %d): %d", fd, (int) buf_size,
                       (oob != NULL ? (int) oob->size : 0), (int) n);
    }

    return n;
}


static int
nxt_unit_ctx_port_recv(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port,
    nxt_unit_read_buf_t *rbuf)
{
    int                   res, read;
    nxt_unit_port_impl_t  *port_impl;

    port_impl = nxt_container_of(port, nxt_unit_port_impl_t, port);

    read = 0;

retry:

    if (port_impl->from_socket > 0) {
        if (port_impl->socket_rbuf != NULL
            && port_impl->socket_rbuf->size > 0)
        {
            port_impl->from_socket--;

            nxt_unit_rbuf_cpy(rbuf, port_impl->socket_rbuf);
            port_impl->socket_rbuf->size = 0;

            nxt_unit_debug(ctx, "port{%d,%d} use suspended message %d",
                           (int) port->id.pid, (int) port->id.id,
                           (int) rbuf->size);

            return NXT_UNIT_OK;
        }

    } else {
        res = nxt_unit_port_queue_recv(port, rbuf);

        if (res == NXT_UNIT_OK) {
            if (nxt_unit_is_read_socket(rbuf)) {
                port_impl->from_socket++;

                nxt_unit_debug(ctx, "port{%d,%d} dequeue 1 read_socket %d",
                               (int) port->id.pid, (int) port->id.id,
                               port_impl->from_socket);

                goto retry;
            }

            nxt_unit_debug(ctx, "port{%d,%d} dequeue %d",
                           (int) port->id.pid, (int) port->id.id,
                           (int) rbuf->size);

            return NXT_UNIT_OK;
        }
    }

    if (read) {
        return NXT_UNIT_AGAIN;
    }

    res = nxt_unit_port_recv(ctx, port, rbuf);
    if (nxt_slow_path(res == NXT_UNIT_ERROR)) {
        return NXT_UNIT_ERROR;
    }

    read = 1;

    if (nxt_unit_is_read_queue(rbuf)) {
        nxt_unit_debug(ctx, "port{%d,%d} recv %d read_queue",
                       (int) port->id.pid, (int) port->id.id, (int) rbuf->size);

        goto retry;
    }

    nxt_unit_debug(ctx, "port{%d,%d} recvmsg %d",
                   (int) port->id.pid, (int) port->id.id,
                   (int) rbuf->size);

    if (res == NXT_UNIT_AGAIN) {
        return NXT_UNIT_AGAIN;
    }

    if (port_impl->from_socket > 0) {
        port_impl->from_socket--;

        return NXT_UNIT_OK;
    }

    nxt_unit_debug(ctx, "port{%d,%d} suspend message %d",
                   (int) port->id.pid, (int) port->id.id,
                   (int) rbuf->size);

    if (port_impl->socket_rbuf == NULL) {
        port_impl->socket_rbuf = nxt_unit_read_buf_get(ctx);

        if (nxt_slow_path(port_impl->socket_rbuf == NULL)) {
            return NXT_UNIT_ERROR;
        }

        port_impl->socket_rbuf->size = 0;
    }

    if (port_impl->socket_rbuf->size > 0) {
        nxt_unit_alert(ctx, "too many port socket messages");

        return NXT_UNIT_ERROR;
    }

    nxt_unit_rbuf_cpy(port_impl->socket_rbuf, rbuf);

    rbuf->oob.size = 0;

    goto retry;
}


nxt_inline void
nxt_unit_rbuf_cpy(nxt_unit_read_buf_t *dst, nxt_unit_read_buf_t *src)
{
    memcpy(dst->buf, src->buf, src->size);
    dst->size = src->size;
    dst->oob.size = src->oob.size;
    memcpy(dst->oob.buf, src->oob.buf, src->oob.size);
}


static int
nxt_unit_shared_port_recv(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port,
    nxt_unit_read_buf_t *rbuf)
{
    int                   res;
    nxt_unit_port_impl_t  *port_impl;

    port_impl = nxt_container_of(port, nxt_unit_port_impl_t, port);

retry:

    res = nxt_unit_app_queue_recv(ctx, port, rbuf);

    if (res == NXT_UNIT_OK) {
        return NXT_UNIT_OK;
    }

    if (res == NXT_UNIT_AGAIN) {
        res = nxt_unit_port_recv(ctx, port, rbuf);
        if (nxt_slow_path(res == NXT_UNIT_ERROR)) {
            return NXT_UNIT_ERROR;
        }

        if (nxt_unit_is_read_queue(rbuf)) {
            nxt_app_queue_notification_received(port_impl->queue);

            nxt_unit_debug(ctx, "port{%d,%d} recv %d read_queue",
                           (int) port->id.pid, (int) port->id.id, (int) rbuf->size);

            goto retry;
        }
    }

    return res;
}


static int
nxt_unit_port_recv(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port,
    nxt_unit_read_buf_t *rbuf)
{
    int              fd, err;
    size_t           oob_size;
    struct iovec     iov[1];
    nxt_unit_impl_t  *lib;

    lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

    if (lib->callbacks.port_recv != NULL) {
        oob_size = sizeof(rbuf->oob.buf);

        rbuf->size = lib->callbacks.port_recv(ctx, port,
                                              rbuf->buf, sizeof(rbuf->buf),
                                              rbuf->oob.buf, &oob_size);

        nxt_unit_debug(ctx, "port{%d,%d} recvcb %d",
                       (int) port->id.pid, (int) port->id.id, (int) rbuf->size);

        if (nxt_slow_path(rbuf->size < 0)) {
            return NXT_UNIT_ERROR;
        }

        rbuf->oob.size = oob_size;
        return NXT_UNIT_OK;
    }

    iov[0].iov_base = rbuf->buf;
    iov[0].iov_len = sizeof(rbuf->buf);

    fd = port->in_fd;

retry:

    rbuf->size = nxt_recvmsg(fd, iov, 1, &rbuf->oob);

    if (nxt_slow_path(rbuf->size == -1)) {
        err = errno;

        if (err == EINTR) {
            goto retry;
        }

        if (err == EAGAIN) {
            nxt_unit_debug(ctx, "recvmsg(%d) failed: %s (%d)",
                           fd, strerror(err), err);

            return NXT_UNIT_AGAIN;
        }

        nxt_unit_alert(ctx, "recvmsg(%d) failed: %s (%d)",
                       fd, strerror(err), err);

        return NXT_UNIT_ERROR;
    }

    nxt_unit_debug(ctx, "recvmsg(%d): %d", fd, (int) rbuf->size);

    return NXT_UNIT_OK;
}


static int
nxt_unit_port_queue_recv(nxt_unit_port_t *port, nxt_unit_read_buf_t *rbuf)
{
    nxt_unit_port_impl_t  *port_impl;

    port_impl = nxt_container_of(port, nxt_unit_port_impl_t, port);

    rbuf->size = nxt_port_queue_recv(port_impl->queue, rbuf->buf);

    return (rbuf->size == -1) ? NXT_UNIT_AGAIN : NXT_UNIT_OK;
}


static int
nxt_unit_app_queue_recv(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port,
    nxt_unit_read_buf_t *rbuf)
{
    uint32_t              cookie;
    nxt_port_msg_t        *port_msg;
    nxt_app_queue_t       *queue;
    nxt_unit_impl_t       *lib;
    nxt_unit_port_impl_t  *port_impl;

    struct {
        nxt_port_msg_t    msg;
        uint8_t           quit_param;
    } nxt_packed m;

    port_impl = nxt_container_of(port, nxt_unit_port_impl_t, port);
    queue = port_impl->queue;

retry:

    rbuf->size = nxt_app_queue_recv(queue, rbuf->buf, &cookie);

    nxt_unit_debug(NULL, "app_queue_recv: %d", (int) rbuf->size);

    if (rbuf->size >= (ssize_t) sizeof(nxt_port_msg_t)) {
        port_msg = (nxt_port_msg_t *) rbuf->buf;

        if (nxt_app_queue_cancel(queue, cookie, port_msg->stream)) {
            lib = nxt_container_of(ctx->unit, nxt_unit_impl_t, unit);

            if (lib->request_limit != 0) {
                nxt_atomic_fetch_add(&lib->request_count, 1);

                if (nxt_slow_path(lib->request_count >= lib->request_limit)) {
                    nxt_unit_debug(ctx, "request limit reached");

                    memset(&m.msg, 0, sizeof(nxt_port_msg_t));

                    m.msg.pid = lib->pid;
                    m.msg.type = _NXT_PORT_MSG_QUIT;
                    m.quit_param = NXT_QUIT_GRACEFUL;

                    (void) nxt_unit_port_send(ctx, lib->main_ctx.read_port,
                                              &m, sizeof(m), NULL);
                }
            }

            return NXT_UNIT_OK;
        }

        nxt_unit_debug(NULL, "app_queue_recv: message cancelled");

        goto retry;
    }

    return (rbuf->size == -1) ? NXT_UNIT_AGAIN : NXT_UNIT_OK;
}


nxt_inline int
nxt_unit_close(int fd)
{
    int  res;

    res = close(fd);

    if (nxt_slow_path(res == -1)) {
        nxt_unit_alert(NULL, "close(%d) failed: %s (%d)",
                       fd, strerror(errno), errno);

    } else {
        nxt_unit_debug(NULL, "close(%d): %d", fd, res);
    }

    return res;
}


static int
nxt_unit_fd_blocking(int fd)
{
    int  nb;

    nb = 0;

    if (nxt_slow_path(ioctl(fd, FIONBIO, &nb) == -1)) {
        nxt_unit_alert(NULL, "ioctl(%d, FIONBIO, 0) failed: %s (%d)",
                       fd, strerror(errno), errno);

        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
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
    nxt_unit_lvlhsh_alloc,
    nxt_unit_lvlhsh_free,
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


static nxt_unit_port_t *
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
        if (!remove) {
            nxt_unit_port_use(lhq.value);
        }

        return lhq.value;

    default:
        return NULL;
    }
}


static nxt_int_t
nxt_unit_request_hash_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    return NXT_OK;
}


static const nxt_lvlhsh_proto_t  lvlhsh_requests_proto  nxt_aligned(64) = {
    NXT_LVLHSH_DEFAULT,
    nxt_unit_request_hash_test,
    nxt_unit_lvlhsh_alloc,
    nxt_unit_lvlhsh_free,
};


static int
nxt_unit_request_hash_add(nxt_unit_ctx_t *ctx,
    nxt_unit_request_info_t *req)
{
    uint32_t                      *stream;
    nxt_int_t                     res;
    nxt_lvlhsh_query_t            lhq;
    nxt_unit_ctx_impl_t           *ctx_impl;
    nxt_unit_request_info_impl_t  *req_impl;

    req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);
    if (req_impl->in_hash) {
        return NXT_UNIT_OK;
    }

    stream = &req_impl->stream;

    lhq.key_hash = nxt_murmur_hash2(stream, sizeof(*stream));
    lhq.key.length = sizeof(*stream);
    lhq.key.start = (u_char *) stream;
    lhq.proto = &lvlhsh_requests_proto;
    lhq.pool = NULL;
    lhq.replace = 0;
    lhq.value = req_impl;

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    pthread_mutex_lock(&ctx_impl->mutex);

    res = nxt_lvlhsh_insert(&ctx_impl->requests, &lhq);

    pthread_mutex_unlock(&ctx_impl->mutex);

    switch (res) {

    case NXT_OK:
        req_impl->in_hash = 1;
        return NXT_UNIT_OK;

    default:
        return NXT_UNIT_ERROR;
    }
}


static nxt_unit_request_info_t *
nxt_unit_request_hash_find(nxt_unit_ctx_t *ctx, uint32_t stream, int remove)
{
    nxt_int_t                     res;
    nxt_lvlhsh_query_t            lhq;
    nxt_unit_ctx_impl_t           *ctx_impl;
    nxt_unit_request_info_impl_t  *req_impl;

    lhq.key_hash = nxt_murmur_hash2(&stream, sizeof(stream));
    lhq.key.length = sizeof(stream);
    lhq.key.start = (u_char *) &stream;
    lhq.proto = &lvlhsh_requests_proto;
    lhq.pool = NULL;

    ctx_impl = nxt_container_of(ctx, nxt_unit_ctx_impl_t, ctx);

    pthread_mutex_lock(&ctx_impl->mutex);

    if (remove) {
        res = nxt_lvlhsh_delete(&ctx_impl->requests, &lhq);

    } else {
        res = nxt_lvlhsh_find(&ctx_impl->requests, &lhq);
    }

    pthread_mutex_unlock(&ctx_impl->mutex);

    switch (res) {

    case NXT_OK:
        req_impl = nxt_container_of(lhq.value, nxt_unit_request_info_impl_t,
                                    req);
        if (remove) {
            req_impl->in_hash = 0;
        }

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
        pid = nxt_unit_pid;
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
        pid = nxt_unit_pid;
        log_fd = STDERR_FILENO;
    }

    p = msg;
    end = p + sizeof(msg) - 1;

    p = nxt_unit_snprint_prefix(p, end, pid, level);

    if (nxt_fast_path(req != NULL)) {
        req_impl = nxt_container_of(req, nxt_unit_request_info_impl_t, req);

        p += snprintf(p, end - p, "#%"PRIu32": ", req_impl->stream);
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

#if (NXT_DEBUG)
    p += snprintf(p, end - p,
                  "%4d/%02d/%02d %02d:%02d:%02d.%03d ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec,
                  (int) ts.tv_nsec / 1000000);
#else
    p += snprintf(p, end - p,
                  "%4d/%02d/%02d %02d:%02d:%02d ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
#endif

    p += snprintf(p, end - p,
                  "[%s] %d#%"PRIu64" [unit] ", nxt_unit_log_levels[level],
                  (int) pid,
                  (uint64_t) (uintptr_t) nxt_thread_get_tid());

    return p;
}


static void *
nxt_unit_lvlhsh_alloc(void *data, size_t size)
{
    int   err;
    void  *p;

    err = posix_memalign(&p, size, size);

    if (nxt_fast_path(err == 0)) {
        nxt_unit_debug(NULL, "posix_memalign(%d, %d): %p",
                       (int) size, (int) size, p);
        return p;
    }

    nxt_unit_alert(NULL, "posix_memalign(%d, %d) failed: %s (%d)",
                   (int) size, (int) size, strerror(err), err);
    return NULL;
}


static void
nxt_unit_lvlhsh_free(void *data, void *p)
{
    nxt_unit_free(NULL, p);
}


void *
nxt_unit_malloc(nxt_unit_ctx_t *ctx, size_t size)
{
    void  *p;

    p = malloc(size);

    if (nxt_fast_path(p != NULL)) {
#if (NXT_DEBUG_ALLOC)
        nxt_unit_debug(ctx, "malloc(%d): %p", (int) size, p);
#endif

    } else {
        nxt_unit_alert(ctx, "malloc(%d) failed: %s (%d)",
                       (int) size, strerror(errno), errno);
    }

    return p;
}


void
nxt_unit_free(nxt_unit_ctx_t *ctx, void *p)
{
#if (NXT_DEBUG_ALLOC)
    nxt_unit_debug(ctx, "free(%p)", p);
#endif

    free(p);
}


static int
nxt_unit_memcasecmp(const void *p1, const void *p2, size_t length)
{
    u_char        c1, c2;
    nxt_int_t     n;
    const u_char  *s1, *s2;

    s1 = p1;
    s2 = p2;

    while (length-- != 0) {
        c1 = *s1++;
        c2 = *s2++;

        c1 = nxt_lowcase(c1);
        c2 = nxt_lowcase(c2);

        n = c1 - c2;

        if (n != 0) {
            return n;
        }
    }

    return 0;
}

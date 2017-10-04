
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PORT_H_INCLUDED_
#define _NXT_PORT_H_INCLUDED_


struct nxt_port_handlers_s {
    /* RPC responses. */
    nxt_port_handler_t  rpc_ready;
    nxt_port_handler_t  rpc_error;

    /* Main process RPC requests. */
    nxt_port_handler_t  start_worker;
    nxt_port_handler_t  socket;
    nxt_port_handler_t  modules;
    nxt_port_handler_t  conf_store;

    /* File descriptor exchange. */
    nxt_port_handler_t  change_file;
    nxt_port_handler_t  new_port;
    nxt_port_handler_t  mmap;

    /* New process ready. */
    nxt_port_handler_t  process_ready;

    /* Process exit/crash notification. */
    nxt_port_handler_t  remove_pid;

    /* Stop process command. */
    nxt_port_handler_t  quit;

    /* Various data. */
    nxt_port_handler_t  data;
};


#define nxt_port_handler_idx(name)                                            \
    ( &((nxt_port_handlers_t *) 0)->name - (nxt_port_handler_t *) 0)


typedef enum {
    NXT_PORT_MSG_LAST           = 0x100,
    NXT_PORT_MSG_CLOSE_FD       = 0x200,
    NXT_PORT_MSG_SYNC           = 0x400,

    NXT_PORT_MSG_MASK           = 0xFF,

    _NXT_PORT_MSG_RPC_READY     = nxt_port_handler_idx(rpc_ready),
    _NXT_PORT_MSG_RPC_ERROR     = nxt_port_handler_idx(rpc_error),

    _NXT_PORT_MSG_START_WORKER  = nxt_port_handler_idx(start_worker),
    _NXT_PORT_MSG_SOCKET        = nxt_port_handler_idx(socket),
    _NXT_PORT_MSG_MODULES       = nxt_port_handler_idx(modules),
    _NXT_PORT_MSG_CONF_STORE    = nxt_port_handler_idx(conf_store),

    _NXT_PORT_MSG_CHANGE_FILE   = nxt_port_handler_idx(change_file),
    _NXT_PORT_MSG_NEW_PORT      = nxt_port_handler_idx(new_port),
    _NXT_PORT_MSG_MMAP          = nxt_port_handler_idx(mmap),

    _NXT_PORT_MSG_PROCESS_READY = nxt_port_handler_idx(process_ready),
    _NXT_PORT_MSG_REMOVE_PID    = nxt_port_handler_idx(remove_pid),
    _NXT_PORT_MSG_QUIT          = nxt_port_handler_idx(quit),

    _NXT_PORT_MSG_DATA          = nxt_port_handler_idx(data),

    NXT_PORT_MSG_MAX            = sizeof(nxt_port_handlers_t) /
                                      sizeof(nxt_port_handler_t),

    NXT_PORT_MSG_RPC_READY      = _NXT_PORT_MSG_RPC_READY,
    NXT_PORT_MSG_RPC_READY_LAST = _NXT_PORT_MSG_RPC_READY | NXT_PORT_MSG_LAST,
    NXT_PORT_MSG_RPC_ERROR      = _NXT_PORT_MSG_RPC_ERROR | NXT_PORT_MSG_LAST,

    NXT_PORT_MSG_START_WORKER   = _NXT_PORT_MSG_START_WORKER |
                                  NXT_PORT_MSG_LAST,
    NXT_PORT_MSG_SOCKET         = _NXT_PORT_MSG_SOCKET | NXT_PORT_MSG_LAST,
    NXT_PORT_MSG_MODULES        = _NXT_PORT_MSG_MODULES | NXT_PORT_MSG_LAST,
    NXT_PORT_MSG_CONF_STORE     = _NXT_PORT_MSG_CONF_STORE | NXT_PORT_MSG_LAST,

    NXT_PORT_MSG_CHANGE_FILE    = _NXT_PORT_MSG_CHANGE_FILE | NXT_PORT_MSG_LAST,
    NXT_PORT_MSG_NEW_PORT       = _NXT_PORT_MSG_NEW_PORT | NXT_PORT_MSG_LAST,
    NXT_PORT_MSG_MMAP           = _NXT_PORT_MSG_MMAP | NXT_PORT_MSG_LAST |
                                  NXT_PORT_MSG_CLOSE_FD | NXT_PORT_MSG_SYNC,

    NXT_PORT_MSG_PROCESS_READY  = _NXT_PORT_MSG_PROCESS_READY |
                                  NXT_PORT_MSG_LAST,
    NXT_PORT_MSG_QUIT           = _NXT_PORT_MSG_QUIT | NXT_PORT_MSG_LAST,
    NXT_PORT_MSG_REMOVE_PID     = _NXT_PORT_MSG_REMOVE_PID | NXT_PORT_MSG_LAST,

    NXT_PORT_MSG_DATA           = _NXT_PORT_MSG_DATA,
    NXT_PORT_MSG_DATA_LAST      = _NXT_PORT_MSG_DATA | NXT_PORT_MSG_LAST,
} nxt_port_msg_type_t;


/* Passed as a first iov chunk. */
typedef struct {
    uint32_t             stream;
    nxt_pid_t            pid;
    nxt_port_id_t        reply_port;

    uint8_t              type;
    uint8_t              last;      /* 1 bit */

    /* Message data send using mmap, next chunk is a nxt_port_mmap_msg_t. */
    uint8_t              mmap;      /* 1 bit */

    uint8_t              nf;
    uint8_t              mf;
} nxt_port_msg_t;


typedef struct {
    nxt_queue_link_t    link;
    nxt_buf_t           *buf;
    size_t              share;
    nxt_fd_t            fd;
    nxt_bool_t          close_fd;
    nxt_port_msg_t      port_msg;

    nxt_work_t          work;
} nxt_port_send_msg_t;


struct nxt_port_recv_msg_s {
    nxt_fd_t            fd;
    nxt_buf_t           *buf;
    nxt_port_t          *port;
    nxt_port_msg_t      port_msg;
    size_t              size;
    union {
        nxt_port_t      *new_port;
        nxt_pid_t       removed_pid;
        void            *data;
    } u;
};

typedef struct nxt_app_s  nxt_app_t;

struct nxt_port_s {
    nxt_fd_event_t      socket;

    nxt_queue_link_t    link;       /* for nxt_process_t.ports */
    nxt_process_t       *process;

    nxt_queue_link_t    app_link;   /* for nxt_app_t.ports */
    nxt_app_t           *app;

    nxt_queue_t         messages;   /* of nxt_port_send_msg_t */
    nxt_thread_mutex_t  write_mutex;

    /* Maximum size of message part. */
    uint32_t            max_size;
    /* Maximum interleave of message parts. */
    uint32_t            max_share;

    uint32_t            app_requests;
    uint32_t            app_responses;

    nxt_port_handler_t  handler;
    nxt_port_handler_t  *data;

    nxt_mp_t            *mem_pool;
    nxt_event_engine_t  *engine;

    nxt_buf_t           *free_bufs;
    nxt_socket_t        pair[2];

    nxt_port_id_t       id;
    nxt_pid_t           pid;

    nxt_lvlhsh_t        rpc_streams; /* stream to nxt_port_rpc_reg_t */
    nxt_lvlhsh_t        rpc_peers;   /* peer to queue of nxt_port_rpc_reg_t */

    nxt_lvlhsh_t        frags;

    nxt_atomic_t        use_count;

    nxt_process_type_t  type;

    struct iovec        *iov;
    void                *mmsg_buf;
};


typedef struct {
    nxt_port_id_t       id;
    nxt_pid_t           pid;
    size_t              max_size;
    size_t              max_share;
    nxt_process_type_t  type:8;
} nxt_port_msg_new_port_t;


/*
 * nxt_port_data_t size is allocation size
 * which enables effective reuse of memory pool cache.
 */
typedef union {
    nxt_buf_t                buf;
    nxt_port_msg_new_port_t  new_port;
} nxt_port_data_t;


typedef void (*nxt_port_post_handler_t)(nxt_task_t *task, nxt_port_t *port,
    void *data);

nxt_port_t *nxt_port_new(nxt_task_t *task, nxt_port_id_t id, nxt_pid_t pid,
    nxt_process_type_t type);

nxt_port_id_t nxt_port_get_next_id(void);
void nxt_port_reset_next_id(void);

nxt_int_t nxt_port_socket_init(nxt_task_t *task, nxt_port_t *port,
    size_t max_size);
void nxt_port_destroy(nxt_port_t *port);
void nxt_port_close(nxt_task_t *task, nxt_port_t *port);
void nxt_port_write_enable(nxt_task_t *task, nxt_port_t *port);
void nxt_port_write_close(nxt_port_t *port);
void nxt_port_read_enable(nxt_task_t *task, nxt_port_t *port);
void nxt_port_read_close(nxt_port_t *port);
nxt_int_t nxt_port_socket_write(nxt_task_t *task, nxt_port_t *port,
    nxt_uint_t type, nxt_fd_t fd, uint32_t stream, nxt_port_id_t reply_port,
    nxt_buf_t *b);

void nxt_port_enable(nxt_task_t *task, nxt_port_t *port,
    nxt_port_handlers_t *handlers);
void nxt_port_send_new_port(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_port_t *port, uint32_t stream);
nxt_int_t nxt_port_send_port(nxt_task_t *task, nxt_port_t *port,
    nxt_port_t *new_port, uint32_t stream);
void nxt_port_change_log_file(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_uint_t slot, nxt_fd_t fd);

void nxt_port_quit_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_port_new_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_port_process_ready_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_port_change_log_file_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
void nxt_port_mmap_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_port_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_port_remove_pid_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_port_empty_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);

nxt_int_t nxt_port_post(nxt_task_t *task, nxt_port_t *port,
    nxt_port_post_handler_t handler, void *data);
void nxt_port_use(nxt_task_t *task, nxt_port_t *port, int i);

#endif /* _NXT_PORT_H_INCLUDED_ */

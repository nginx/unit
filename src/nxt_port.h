
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
    nxt_port_handler_t  start_process;
    nxt_port_handler_t  socket;
    nxt_port_handler_t  socket_unlink;
    nxt_port_handler_t  modules;
    nxt_port_handler_t  conf_store;
    nxt_port_handler_t  cert_get;
    nxt_port_handler_t  cert_delete;
    nxt_port_handler_t  script_get;
    nxt_port_handler_t  script_delete;
    nxt_port_handler_t  access_log;

    /* File descriptor exchange. */
    nxt_port_handler_t  change_file;
    nxt_port_handler_t  new_port;
    nxt_port_handler_t  get_port;
    nxt_port_handler_t  port_ack;
    nxt_port_handler_t  mmap;
    nxt_port_handler_t  get_mmap;

    /* New process */
    nxt_port_handler_t  process_created;
    nxt_port_handler_t  process_ready;
    nxt_port_handler_t  whoami;

    /* Process exit/crash notification. */
    nxt_port_handler_t  remove_pid;

    /* Stop process command. */
    nxt_port_handler_t  quit;

    /* Request headers. */
    nxt_port_handler_t  req_headers;
    nxt_port_handler_t  req_headers_ack;
    nxt_port_handler_t  req_body;

    /* Websocket frame. */
    nxt_port_handler_t  websocket_frame;

    /* Various data. */
    nxt_port_handler_t  data;
    nxt_port_handler_t  app_restart;

    /* Status report. */
    nxt_port_handler_t  status;

    nxt_port_handler_t  oosm;
    nxt_port_handler_t  shm_ack;
    nxt_port_handler_t  read_queue;
    nxt_port_handler_t  read_socket;
};


#define nxt_port_handler_idx(name)                                            \
    ( offsetof(nxt_port_handlers_t, name) / sizeof(nxt_port_handler_t) )

#define nxt_msg_last(handler)                                                 \
    (handler | NXT_PORT_MSG_LAST)

typedef enum {
    NXT_PORT_MSG_LAST             = 0x100,
    NXT_PORT_MSG_CLOSE_FD         = 0x200,
    NXT_PORT_MSG_SYNC             = 0x400,

    NXT_PORT_MSG_MASK             = 0xFF,

    _NXT_PORT_MSG_RPC_READY       = nxt_port_handler_idx(rpc_ready),
    _NXT_PORT_MSG_RPC_ERROR       = nxt_port_handler_idx(rpc_error),

    _NXT_PORT_MSG_START_PROCESS   = nxt_port_handler_idx(start_process),
    _NXT_PORT_MSG_SOCKET          = nxt_port_handler_idx(socket),
    _NXT_PORT_MSG_SOCKET_UNLINK   = nxt_port_handler_idx(socket_unlink),
    _NXT_PORT_MSG_MODULES         = nxt_port_handler_idx(modules),
    _NXT_PORT_MSG_CONF_STORE      = nxt_port_handler_idx(conf_store),
    _NXT_PORT_MSG_CERT_GET        = nxt_port_handler_idx(cert_get),
    _NXT_PORT_MSG_CERT_DELETE     = nxt_port_handler_idx(cert_delete),
    _NXT_PORT_MSG_SCRIPT_GET      = nxt_port_handler_idx(script_get),
    _NXT_PORT_MSG_SCRIPT_DELETE   = nxt_port_handler_idx(script_delete),
    _NXT_PORT_MSG_ACCESS_LOG      = nxt_port_handler_idx(access_log),

    _NXT_PORT_MSG_CHANGE_FILE     = nxt_port_handler_idx(change_file),
    _NXT_PORT_MSG_NEW_PORT        = nxt_port_handler_idx(new_port),
    _NXT_PORT_MSG_GET_PORT        = nxt_port_handler_idx(get_port),
    _NXT_PORT_MSG_PORT_ACK        = nxt_port_handler_idx(port_ack),
    _NXT_PORT_MSG_MMAP            = nxt_port_handler_idx(mmap),
    _NXT_PORT_MSG_GET_MMAP        = nxt_port_handler_idx(get_mmap),

    _NXT_PORT_MSG_PROCESS_CREATED = nxt_port_handler_idx(process_created),
    _NXT_PORT_MSG_PROCESS_READY   = nxt_port_handler_idx(process_ready),
    _NXT_PORT_MSG_WHOAMI          = nxt_port_handler_idx(whoami),
    _NXT_PORT_MSG_REMOVE_PID      = nxt_port_handler_idx(remove_pid),
    _NXT_PORT_MSG_QUIT            = nxt_port_handler_idx(quit),

    _NXT_PORT_MSG_REQ_HEADERS     = nxt_port_handler_idx(req_headers),
    _NXT_PORT_MSG_REQ_HEADERS_ACK = nxt_port_handler_idx(req_headers_ack),
    _NXT_PORT_MSG_REQ_BODY        = nxt_port_handler_idx(req_body),
    _NXT_PORT_MSG_WEBSOCKET       = nxt_port_handler_idx(websocket_frame),

    _NXT_PORT_MSG_DATA            = nxt_port_handler_idx(data),
    _NXT_PORT_MSG_APP_RESTART     = nxt_port_handler_idx(app_restart),
    _NXT_PORT_MSG_STATUS          = nxt_port_handler_idx(status),

    _NXT_PORT_MSG_OOSM            = nxt_port_handler_idx(oosm),
    _NXT_PORT_MSG_SHM_ACK         = nxt_port_handler_idx(shm_ack),
    _NXT_PORT_MSG_READ_QUEUE      = nxt_port_handler_idx(read_queue),
    _NXT_PORT_MSG_READ_SOCKET     = nxt_port_handler_idx(read_socket),

    NXT_PORT_MSG_MAX              = sizeof(nxt_port_handlers_t)
                                    / sizeof(nxt_port_handler_t),

    NXT_PORT_MSG_RPC_READY        = _NXT_PORT_MSG_RPC_READY,
    NXT_PORT_MSG_RPC_READY_LAST   = nxt_msg_last(_NXT_PORT_MSG_RPC_READY),
    NXT_PORT_MSG_RPC_ERROR        = nxt_msg_last(_NXT_PORT_MSG_RPC_ERROR),
    NXT_PORT_MSG_START_PROCESS    = nxt_msg_last(_NXT_PORT_MSG_START_PROCESS),
    NXT_PORT_MSG_SOCKET           = nxt_msg_last(_NXT_PORT_MSG_SOCKET),
    NXT_PORT_MSG_SOCKET_UNLINK    = nxt_msg_last(_NXT_PORT_MSG_SOCKET_UNLINK),
    NXT_PORT_MSG_MODULES          = nxt_msg_last(_NXT_PORT_MSG_MODULES),
    NXT_PORT_MSG_CONF_STORE       = nxt_msg_last(_NXT_PORT_MSG_CONF_STORE),
    NXT_PORT_MSG_CERT_GET         = nxt_msg_last(_NXT_PORT_MSG_CERT_GET),
    NXT_PORT_MSG_CERT_DELETE      = nxt_msg_last(_NXT_PORT_MSG_CERT_DELETE),
    NXT_PORT_MSG_SCRIPT_GET       = nxt_msg_last(_NXT_PORT_MSG_SCRIPT_GET),
    NXT_PORT_MSG_SCRIPT_DELETE    = nxt_msg_last(_NXT_PORT_MSG_SCRIPT_DELETE),
    NXT_PORT_MSG_ACCESS_LOG       = nxt_msg_last(_NXT_PORT_MSG_ACCESS_LOG),
    NXT_PORT_MSG_CHANGE_FILE      = nxt_msg_last(_NXT_PORT_MSG_CHANGE_FILE),
    NXT_PORT_MSG_NEW_PORT         = nxt_msg_last(_NXT_PORT_MSG_NEW_PORT),
    NXT_PORT_MSG_GET_PORT         = nxt_msg_last(_NXT_PORT_MSG_GET_PORT),
    NXT_PORT_MSG_PORT_ACK         = nxt_msg_last(_NXT_PORT_MSG_PORT_ACK),
    NXT_PORT_MSG_MMAP             = nxt_msg_last(_NXT_PORT_MSG_MMAP)
                                    | NXT_PORT_MSG_SYNC,
    NXT_PORT_MSG_GET_MMAP         = nxt_msg_last(_NXT_PORT_MSG_GET_MMAP),

    NXT_PORT_MSG_PROCESS_CREATED  = nxt_msg_last(_NXT_PORT_MSG_PROCESS_CREATED),
    NXT_PORT_MSG_PROCESS_READY    = nxt_msg_last(_NXT_PORT_MSG_PROCESS_READY),
    NXT_PORT_MSG_WHOAMI           = nxt_msg_last(_NXT_PORT_MSG_WHOAMI),
    NXT_PORT_MSG_QUIT             = nxt_msg_last(_NXT_PORT_MSG_QUIT),
    NXT_PORT_MSG_REMOVE_PID       = nxt_msg_last(_NXT_PORT_MSG_REMOVE_PID),

    NXT_PORT_MSG_REQ_HEADERS      = _NXT_PORT_MSG_REQ_HEADERS,
    NXT_PORT_MSG_REQ_BODY         = _NXT_PORT_MSG_REQ_BODY,
    NXT_PORT_MSG_WEBSOCKET        = _NXT_PORT_MSG_WEBSOCKET,
    NXT_PORT_MSG_WEBSOCKET_LAST   = nxt_msg_last(_NXT_PORT_MSG_WEBSOCKET),

    NXT_PORT_MSG_DATA             = _NXT_PORT_MSG_DATA,
    NXT_PORT_MSG_DATA_LAST        = nxt_msg_last(_NXT_PORT_MSG_DATA),
    NXT_PORT_MSG_APP_RESTART      = nxt_msg_last(_NXT_PORT_MSG_APP_RESTART),
    NXT_PORT_MSG_STATUS           = nxt_msg_last(_NXT_PORT_MSG_STATUS),

    NXT_PORT_MSG_OOSM             = nxt_msg_last(_NXT_PORT_MSG_OOSM),
    NXT_PORT_MSG_SHM_ACK          = nxt_msg_last(_NXT_PORT_MSG_SHM_ACK),
    NXT_PORT_MSG_READ_QUEUE       = _NXT_PORT_MSG_READ_QUEUE,
    NXT_PORT_MSG_READ_SOCKET      = _NXT_PORT_MSG_READ_SOCKET,
} nxt_port_msg_type_t;


/* Passed as a first iov chunk. */
typedef struct {
    uint32_t             stream;

    nxt_pid_t            pid;       /* not used on Linux and FreeBSD */

    nxt_port_id_t        reply_port;

    uint8_t              type;

    /* Last message for this stream. */
    uint8_t              last;      /* 1 bit */

    /* Message data send using mmap, next chunk is a nxt_port_mmap_msg_t. */
    uint8_t              mmap;      /* 1 bit */

    /* Non-First fragment in fragmented message sequence. */
    uint8_t              nf;        /* 1 bit */

    /* More Fragments followed. */
    uint8_t              mf;        /* 1 bit */
} nxt_port_msg_t;


typedef struct {
    nxt_queue_link_t    link;
    nxt_buf_t           *buf;
    size_t              share;
    nxt_fd_t            fd[2];
    nxt_port_msg_t      port_msg;
    uint8_t             close_fd;   /* 1 bit */
    uint8_t             allocated;  /* 1 bit */
} nxt_port_send_msg_t;

#if (NXT_HAVE_UCRED) || (NXT_HAVE_MSGHDR_CMSGCRED)
#define NXT_USE_CMSG_PID    1
#endif

struct nxt_port_recv_msg_s {
    nxt_fd_t            fd[2];
    nxt_buf_t           *buf;
    nxt_port_t          *port;
    nxt_port_msg_t      port_msg;
    size_t              size;
#if (NXT_USE_CMSG_PID)
    nxt_pid_t           cmsg_pid;
#endif
    nxt_bool_t          cancelled;
    union {
        nxt_port_t      *new_port;
        nxt_pid_t       removed_pid;
        void            *data;
    } u;
};


#if (NXT_USE_CMSG_PID)
#define nxt_recv_msg_cmsg_pid(msg)      ((msg)->cmsg_pid)
#define nxt_recv_msg_cmsg_pid_ref(msg)  (&(msg)->cmsg_pid)
#else
#define nxt_recv_msg_cmsg_pid(msg)      ((msg)->port_msg.pid)
#define nxt_recv_msg_cmsg_pid_ref(msg)  (NULL)
#endif

typedef struct nxt_app_s  nxt_app_t;

struct nxt_port_s {
    nxt_fd_event_t      socket;

    nxt_queue_link_t    link;       /* for nxt_process_t.ports */
    nxt_process_t       *process;

    nxt_queue_link_t    app_link;   /* for nxt_app_t.ports */
    nxt_app_t           *app;
    nxt_port_t          *main_app_port;

    nxt_queue_link_t    idle_link;  /* for nxt_app_t.idle_ports */
    nxt_msec_t          idle_start;

    nxt_queue_t         messages;   /* of nxt_port_send_msg_t */
    nxt_thread_mutex_t  write_mutex;

    /* Maximum size of message part. */
    uint32_t            max_size;
    /* Maximum interleave of message parts. */
    uint32_t            max_share;

    uint32_t            active_websockets;
    uint32_t            active_requests;

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

    nxt_fd_t            queue_fd;
    void                *queue;

    void                *socket_msg;
    int                 from_socket;
};


typedef struct {
    nxt_port_id_t       id;
    nxt_pid_t           pid;
    size_t              max_size;
    size_t              max_share;
    nxt_process_type_t  type:8;
} nxt_port_msg_new_port_t;


typedef struct {
    nxt_port_id_t       id;
    nxt_pid_t           pid;
} nxt_port_msg_get_port_t;


typedef struct {
    uint32_t            id;
} nxt_port_msg_get_mmap_t;


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
nxt_int_t nxt_port_socket_write2(nxt_task_t *task, nxt_port_t *port,
    nxt_uint_t type, nxt_fd_t fd, nxt_fd_t fd2, uint32_t stream,
    nxt_port_id_t reply_port, nxt_buf_t *b);

nxt_inline nxt_int_t
nxt_port_socket_write(nxt_task_t *task, nxt_port_t *port,
    nxt_uint_t type, nxt_fd_t fd, uint32_t stream, nxt_port_id_t reply_port,
    nxt_buf_t *b)
{
    return nxt_port_socket_write2(task, port, type, fd, -1, stream, reply_port,
                                  b);
}

void nxt_port_enable(nxt_task_t *task, nxt_port_t *port,
    const nxt_port_handlers_t *handlers);
nxt_int_t nxt_port_send_port(nxt_task_t *task, nxt_port_t *port,
    nxt_port_t *new_port, uint32_t stream);
void nxt_port_change_log_file(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_uint_t slot, nxt_fd_t fd);
void nxt_port_remove_notify_others(nxt_task_t *task, nxt_process_t *process);

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

nxt_inline void nxt_port_inc_use(nxt_port_t *port)
{
    nxt_atomic_fetch_add(&port->use_count, 1);
}

#endif /* _NXT_PORT_H_INCLUDED_ */

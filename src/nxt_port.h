
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PORT_H_INCLUDED_
#define _NXT_PORT_H_INCLUDED_


typedef enum {
    NXT_PORT_MSG_QUIT = 0,
    NXT_PORT_MSG_NEW_PORT,
    NXT_PORT_MSG_CHANGE_FILE,
    NXT_PORT_MSG_MMAP,
    NXT_PORT_MSG_DATA,
    NXT_PORT_MSG_REMOVE_PID,
    NXT_PORT_MSG_READY,

    NXT_PORT_MSG_MAX,
} nxt_port_msg_type_t;


/* Passed as a first iov chunk. */
typedef struct {
    uint32_t             stream;
    nxt_pid_t            pid;
    nxt_port_id_t        reply_port;

    nxt_port_msg_type_t  type:8;
    uint8_t              last;      /* 1 bit */

    /* Message data send using mmap, next chunk is a nxt_port_mmap_msg_t. */
    uint8_t              mmap;      /* 1 bit */
} NXT_PACKED nxt_port_msg_t;


typedef struct {
    nxt_queue_link_t    link;
    nxt_buf_t           *buf;
    size_t              share;
    nxt_fd_t            fd;
    nxt_port_msg_t      port_msg;

    nxt_work_t          work;
    nxt_event_engine_t  *engine;
    nxt_mp_t            *mem_pool;
} nxt_port_send_msg_t;


struct nxt_port_recv_msg_s {
    nxt_fd_t            fd;
    nxt_buf_t           *buf;
    nxt_port_t          *port;
    nxt_port_msg_t      port_msg;
    size_t              size;
    nxt_port_t          *new_port;
};

typedef struct nxt_app_s  nxt_app_t;

struct nxt_port_s {
    nxt_fd_event_t      socket;

    nxt_queue_link_t    link;       /* for nxt_process_t.ports */
    nxt_process_t       *process;

    nxt_queue_link_t    app_link;   /* for nxt_app_t.ports */
    nxt_app_t           *app;

    nxt_queue_t         messages;   /* of nxt_port_send_msg_t */

    /* Maximum size of message part. */
    uint32_t            max_size;
    /* Maximum interleave of message parts. */
    uint32_t            max_share;
    uint32_t            app_req_id;

    nxt_port_handler_t  handler;
    nxt_port_handler_t  *data;

    nxt_mp_t            *mem_pool;
    nxt_event_engine_t  *engine;

    nxt_buf_t           *free_bufs;
    nxt_socket_t        pair[2];

    nxt_port_id_t       id;
    nxt_pid_t           pid;

    nxt_process_type_t  type;
    nxt_work_t          work;
};


typedef struct {
    nxt_port_id_t       id;
    nxt_pid_t           pid;
    size_t              max_size;
    size_t              max_share;
    nxt_process_type_t  type:8;
} NXT_PACKED nxt_port_msg_new_port_t;


/*
 * nxt_port_data_t size is allocation size
 * which enables effective reuse of memory pool cache.
 */
typedef union {
    nxt_buf_t                buf;
    nxt_port_msg_new_port_t  new_port;
} nxt_port_data_t;


nxt_port_t *nxt_port_new(nxt_port_id_t id, nxt_pid_t pid,
    nxt_process_type_t type);
nxt_bool_t nxt_port_release(nxt_port_t *port);

nxt_port_id_t nxt_port_get_next_id(void);
void nxt_port_reset_next_id(void);

nxt_int_t nxt_port_socket_init(nxt_task_t *task, nxt_port_t *port,
    size_t max_size);
void nxt_port_destroy(nxt_port_t *port);
void nxt_port_write_enable(nxt_task_t *task, nxt_port_t *port);
void nxt_port_write_close(nxt_port_t *port);
void nxt_port_read_enable(nxt_task_t *task, nxt_port_t *port);
void nxt_port_read_close(nxt_port_t *port);
nxt_int_t nxt_port_socket_write(nxt_task_t *task, nxt_port_t *port,
    nxt_uint_t type, nxt_fd_t fd, uint32_t stream, nxt_port_id_t reply_port,
    nxt_buf_t *b);

void nxt_port_enable(nxt_task_t *task, nxt_port_t *port,
    nxt_port_handler_t *handlers);
void nxt_port_write(nxt_task_t *task, nxt_runtime_t *rt, nxt_uint_t type,
    nxt_fd_t fd, uint32_t stream, nxt_buf_t *b);
void nxt_port_send_new_port(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_port_t *port, uint32_t stream);
nxt_int_t nxt_port_send_port(nxt_task_t *task, nxt_port_t *port,
    nxt_port_t *new_port, uint32_t stream);
void nxt_port_change_log_file(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_uint_t slot, nxt_fd_t fd);

void nxt_port_quit_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_port_new_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_port_ready_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_port_change_log_file_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
void nxt_port_mmap_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_port_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_port_remove_pid_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_port_empty_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);


#endif /* _NXT_PORT_H_INCLUDED_ */

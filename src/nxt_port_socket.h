
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PORT_SOCKET_H_INCLUDED_
#define _NXT_PORT_SOCKET_H_INCLUDED_


typedef struct {
    uint32_t            stream;

    uint16_t            type;
    uint8_t             last;      /* 1 bit */
} nxt_port_msg_t;


typedef struct {
    nxt_queue_link_t    link;
    nxt_buf_t           *buf;
    size_t              share;
    nxt_fd_t            fd;
    nxt_port_msg_t      port_msg;
} nxt_port_send_msg_t;


typedef struct nxt_port_recv_msg_s  nxt_port_recv_msg_t;
typedef void (*nxt_port_handler_t)(nxt_task_t *task, nxt_port_recv_msg_t *msg);


typedef struct {
    /* Must be the first field. */
    nxt_fd_event_t      socket;

    nxt_task_t          task;

    nxt_queue_t         messages;   /* of nxt_port_send_msg_t */

    /* Maximum size of message part. */
    uint32_t            max_size;
    /* Maximum interleave of message parts. */
    uint32_t            max_share;

    nxt_port_handler_t  handler;
    void                *data;

    nxt_mem_pool_t      *mem_pool;
    nxt_buf_t           *free_bufs;
    nxt_socket_t        pair[2];
} nxt_port_t;


struct nxt_port_recv_msg_s {
    uint32_t            stream;
    uint16_t            type;

    nxt_fd_t            fd;
    nxt_buf_t           *buf;
    nxt_port_t          *port;
};


NXT_EXPORT nxt_port_t *nxt_port_alloc(void);
NXT_EXPORT nxt_port_t *nxt_port_create(size_t bufsize);
NXT_EXPORT void nxt_port_destroy(nxt_port_t *port);
NXT_EXPORT void nxt_port_write_enable(nxt_task_t *task, nxt_port_t *port);
NXT_EXPORT void nxt_port_write_close(nxt_port_t *port);
NXT_EXPORT void nxt_port_read_enable(nxt_task_t *task, nxt_port_t *port);
NXT_EXPORT void nxt_port_read_close(nxt_port_t *port);
NXT_EXPORT nxt_int_t nxt_port_write(nxt_task_t *task, nxt_port_t *port,
    nxt_uint_t type, nxt_fd_t fd, uint32_t stream, nxt_buf_t *b);


#endif /* _NXT_PORT_SOCKET_H_INCLUDED_ */

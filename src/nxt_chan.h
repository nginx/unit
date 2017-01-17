
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIX_CHAN_H_INCLUDED_
#define _NXT_UNIX_CHAN_H_INCLUDED_


typedef struct {
    uint32_t            stream;

    uint16_t            type;
    uint8_t             last;      /* 1 bit */
} nxt_chan_msg_t;


typedef struct {
    nxt_queue_link_t    link;
    nxt_buf_t           *buf;
    size_t              share;
    nxt_fd_t            fd;
    nxt_chan_msg_t      chan_msg;
} nxt_chan_send_msg_t;


typedef struct nxt_chan_recv_msg_s  nxt_chan_recv_msg_t;
typedef void (*nxt_chan_handler_t)(nxt_thread_t *thr, nxt_chan_recv_msg_t *msg);


typedef struct {
    /* Must be the first field. */
    nxt_event_fd_t      socket;

    nxt_queue_t         messages;   /* of nxt_chan_send_msg_t */

    /* Maximum size of message part. */
    uint32_t            max_size;
    /* Maximum interleave of message parts. */
    uint32_t            max_share;

    nxt_chan_handler_t  handler;
    void                *data;

    nxt_mem_pool_t      *mem_pool;
    nxt_buf_t           *free_bufs;
    nxt_socket_t        pair[2];
} nxt_chan_t;


struct nxt_chan_recv_msg_s {
    uint32_t            stream;
    uint16_t            type;

    nxt_fd_t            fd;
    nxt_buf_t           *buf;
    nxt_chan_t          *chan;
};


NXT_EXPORT nxt_chan_t *nxt_chan_alloc(void);
NXT_EXPORT nxt_chan_t *nxt_chan_create(size_t bufsize);
NXT_EXPORT void nxt_chan_destroy(nxt_chan_t *chan);
NXT_EXPORT void nxt_chan_write_enable(nxt_thread_t *thr, nxt_chan_t *chan);
NXT_EXPORT void nxt_chan_write_close(nxt_chan_t *chan);
NXT_EXPORT void nxt_chan_read_enable(nxt_thread_t *thr, nxt_chan_t *chan);
NXT_EXPORT void nxt_chan_read_close(nxt_chan_t *chan);
NXT_EXPORT nxt_int_t nxt_chan_write(nxt_chan_t *chan, nxt_uint_t type,
    nxt_fd_t fd, uint32_t stream, nxt_buf_t *b);


#endif /* _NXT_UNIX_CHAN_H_INCLUDED_ */


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_SENDBUF_H_INCLUDED_
#define _NXT_SENDBUF_H_INCLUDED_


/*
 * The sendbuf interface is intended to send a buffer chain to a connection.
 * It uses sendfile interface if available.  Otherwise it can send only
 * memory buffers, so file buffers must be read in memory in advance.
 *
 * The sendbuf interface sets c->socket.write_ready to appropriate state
 * and returns:
 *
 *   N > 0      if sendbuf sent N bytes.
 *
 *   0          if sendbuf was interrupted (EINTR and so on),
 *              or sendbuf sent previously buffered data,
 *              or single sync buffer has been encountered.
 *              In all these cases sendbuf is ready to continue
 *              operation, unless c->socket.write_ready is cleared.
 *
 *   NXT_AGAIN  if sendbuf did not send any bytes.
 *
 *   NXT_ERROR  if there was erorr.
 *
 * The sendbuf limit is size_t type since size_t is large enough and many
 * sendfile implementations do not support anyway sending more than size_t
 * at once.  The limit support is located at the sendbuf level otherwise
 * an additional limited chain must be created on each sendbuf call.
 */


typedef struct {
    nxt_buf_t     *buf;
    void          *tls;
    nxt_socket_t  socket;
    nxt_err_t     error;
    nxt_off_t     sent;
    size_t        size;
    size_t        limit;

    uint8_t       ready;   /* 1 bit */
    uint8_t       once;    /* 1 bit */
    uint8_t       sync;    /* 1 bit */
    uint8_t       last;    /* 1 bit */
} nxt_sendbuf_t;


typedef struct {
    nxt_buf_t    *buf;
    nxt_iobuf_t  *iobuf;
    nxt_uint_t   niov;

    uint32_t     nmax;
    uint8_t      sync;   /* 1 bit */
    uint8_t      last;   /* 1 bit */
    uint8_t      limit_reached;
    uint8_t      nmax_reached;

    size_t       size;
    size_t       limit;
} nxt_sendbuf_coalesce_t;


#if (NXT_HAVE_LINUX_SENDFILE)
#define NXT_HAVE_SENDFILE  1
ssize_t nxt_linux_event_conn_io_sendfile(nxt_conn_t *c, nxt_buf_t *b,
    size_t limit);
#endif

#if (NXT_HAVE_FREEBSD_SENDFILE)
#define NXT_HAVE_SENDFILE  1
ssize_t nxt_freebsd_event_conn_io_sendfile(nxt_conn_t *c, nxt_buf_t *b,
    size_t limit);
#endif

#if (NXT_HAVE_SOLARIS_SENDFILEV)
#define NXT_HAVE_SENDFILE  1
ssize_t nxt_solaris_event_conn_io_sendfilev(nxt_conn_t *c, nxt_buf_t *b,
    size_t limit);
#endif

#if (NXT_HAVE_MACOSX_SENDFILE)
#define NXT_HAVE_SENDFILE  1
ssize_t nxt_macosx_event_conn_io_sendfile(nxt_conn_t *c, nxt_buf_t *b,
    size_t limit);
#endif

#if (NXT_HAVE_AIX_SEND_FILE)
#define NXT_HAVE_SENDFILE  1
ssize_t nxt_aix_event_conn_io_send_file(nxt_conn_t *c, nxt_buf_t *b,
    size_t limit);
#endif

#if (NXT_HAVE_HPUX_SENDFILE)
#define NXT_HAVE_SENDFILE  1
ssize_t nxt_hpux_event_conn_io_sendfile(nxt_conn_t *c, nxt_buf_t *b,
    size_t limit);
#endif

ssize_t nxt_event_conn_io_sendbuf(nxt_conn_t *c, nxt_buf_t *b,
    size_t limit);


nxt_uint_t nxt_sendbuf_mem_coalesce0(nxt_task_t *task, nxt_sendbuf_t *sb,
    struct iovec *iov, nxt_uint_t niov_max);
nxt_uint_t nxt_sendbuf_mem_coalesce(nxt_task_t *task,
    nxt_sendbuf_coalesce_t *sb);
size_t nxt_sendbuf_file_coalesce(nxt_sendbuf_coalesce_t *sb);

/*
 * Auxiliary nxt_sendbuf_copy_coalesce() interface copies small memory
 * buffers into internal buffer before output.  It is intended for
 * SSL/TLS libraries which lack vector I/O interface yet add noticeable
 * overhead to each SSL/TLS record.
 */
ssize_t nxt_sendbuf_copy_coalesce(nxt_conn_t *c, nxt_buf_mem_t *bm,
    nxt_buf_t *b, size_t limit);

nxt_buf_t *nxt_sendbuf_update(nxt_buf_t *b, size_t sent);
nxt_buf_t *nxt_sendbuf_completion(nxt_task_t *task, nxt_work_queue_t *wq,
    nxt_buf_t *b);
void nxt_sendbuf_drain(nxt_task_t *task, nxt_work_queue_t *wq, nxt_buf_t *b);


#endif /* _NXT_SENDBUF_H_INCLUDED_ */

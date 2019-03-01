
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_CONN_H_INCLUDED_
#define _NXT_CONN_H_INCLUDED_


typedef ssize_t (*nxt_conn_io_read_t)(nxt_conn_t *c);
typedef nxt_msec_t (*nxt_conn_timer_value_t)(nxt_conn_t *c, uintptr_t data);


typedef struct {
    nxt_work_handler_t            ready_handler;
    nxt_work_handler_t            close_handler;
    nxt_work_handler_t            error_handler;

    nxt_conn_io_read_t            io_read_handler;

    nxt_work_handler_t            timer_handler;
    nxt_conn_timer_value_t        timer_value;
    uintptr_t                     timer_data;

    uint8_t                       timer_autoreset;
} nxt_conn_state_t;


typedef struct {
    double                        average;
    size_t                        limit;
    size_t                        limit_after;
    size_t                        max_limit;
    nxt_msec_t                    last;
} nxt_event_write_rate_t;


typedef struct {

    nxt_work_handler_t            connect;
    nxt_work_handler_t            accept;

    /*
     * The read() with NULL c->read buffer waits readiness of a connection
     * to avoid allocation of read buffer if the connection will time out
     * or will be closed with error.  The kqueue-specific read() can also
     * detect case if a client did not sent anything and has just closed the
     * connection without errors.  In the latter case state's close_handler
     * is called.
     */
    nxt_work_handler_t            read;

    ssize_t                       (*recvbuf)(nxt_conn_t *c, nxt_buf_t *b);

    ssize_t                       (*recv)(nxt_conn_t *c, void *buf,
                                      size_t size, nxt_uint_t flags);

    /* The write() is an interface to write a buffer chain. */
    nxt_work_handler_t            write;

    /*
     * The sendbuf() is an interface for OS-specific sendfile
     * implementations or simple writev().
     */
    ssize_t                       (*sendbuf)(nxt_task_t *task,
                                       nxt_sendbuf_t *sb);
    /*
     * The sendbuf() is an interface for OS-specific sendfile
     * implementations or simple writev().
     */
    ssize_t                       (*old_sendbuf)(nxt_conn_t *c, nxt_buf_t *b,
                                      size_t limit);
    /*
     * The writev() is an interface to write several nxt_iobuf_t buffers.
     */
    ssize_t                       (*writev)(nxt_conn_t *c,
                                      nxt_iobuf_t *iob, nxt_uint_t niob);
    /*
     * The send() is an interface to write a single buffer.  SSL/TLS
     * libraries' send() interface handles also the libraries' errors.
     */
    ssize_t                       (*send)(nxt_conn_t *c, void *buf,
                                      size_t size);

    nxt_work_handler_t            shutdown;
} nxt_conn_io_t;


/*
 * The nxt_listen_event_t is separated from nxt_listen_socket_t
 * because nxt_listen_socket_t is one per process whilst each worker
 * thread uses own nxt_listen_event_t.
 */
typedef struct {
    /* Must be the first field. */
    nxt_fd_event_t                socket;

    nxt_task_t                    task;

    uint32_t                      ready;
    uint32_t                      batch;
    uint32_t                      count;

    /* An accept() interface is cached to minimize memory accesses. */
    nxt_work_handler_t            accept;

    nxt_listen_socket_t           *listen;
    nxt_conn_t                    *next;   /* STUB */
    nxt_work_queue_t              *work_queue;

    nxt_timer_t                   timer;

    nxt_queue_link_t              link;
} nxt_listen_event_t;


struct nxt_conn_s {
    /*
     * Must be the first field, since nxt_fd_event_t
     * and nxt_conn_t are used interchangeably.
     */
    nxt_fd_event_t                socket;

    nxt_buf_t                     *read;
    const nxt_conn_state_t        *read_state;
    nxt_work_queue_t              *read_work_queue;
    nxt_timer_t                   read_timer;

    nxt_buf_t                     *write;
    const nxt_conn_state_t        *write_state;
    nxt_work_queue_t              *write_work_queue;
    nxt_event_write_rate_t        *rate;
    nxt_timer_t                   write_timer;

    nxt_off_t                     sent;
    uint32_t                      max_chunk;
    uint32_t                      nbytes;

    nxt_conn_io_t                 *io;

    union {
#if (NXT_TLS)
        void                      *tls;
#endif
        nxt_thread_pool_t         *thread_pool;
    } u;

    nxt_mp_t                      *mem_pool;

    nxt_task_t                    task;
    nxt_log_t                     log;

    nxt_listen_event_t            *listen;

    nxt_sockaddr_t                *remote;
    nxt_sockaddr_t                *local;
    const char                    *action;

    uint8_t                       block_read;   /* 1 bit */
    uint8_t                       block_write;  /* 1 bit */
    uint8_t                       delayed;      /* 1 bit */

#define NXT_CONN_SENDFILE_OFF     0
#define NXT_CONN_SENDFILE_ON      1
#define NXT_CONN_SENDFILE_UNSET   3

    uint8_t                       sendfile;     /* 2 bits */
    uint8_t                       tcp_nodelay;  /* 1 bit */

    nxt_queue_link_t              link;
};


#define nxt_conn_timer_init(ev, c, wq)                                        \
    do {                                                                      \
        (ev)->work_queue = (wq);                                              \
        (ev)->log = &(c)->log;                                                \
        (ev)->bias = NXT_TIMER_DEFAULT_BIAS;                                  \
    } while (0)


#define nxt_read_timer_conn(ev)                                               \
    nxt_timer_data(ev, nxt_conn_t, read_timer)


#define nxt_write_timer_conn(ev)                                              \
    nxt_timer_data(ev, nxt_conn_t, write_timer)


#if (NXT_HAVE_UNIX_DOMAIN)

#define nxt_conn_tcp_nodelay_on(task, c)                                      \
    do {                                                                      \
        nxt_int_t  ret;                                                       \
                                                                              \
        if ((c)->remote->u.sockaddr.sa_family != AF_UNIX) {                   \
            ret = nxt_socket_setsockopt(task, (c)->socket.fd, IPPROTO_TCP,    \
                                        TCP_NODELAY, 1);                      \
                                                                              \
            (c)->tcp_nodelay = (ret == NXT_OK);                               \
        }                                                                     \
    } while (0)


#else

#define nxt_conn_tcp_nodelay_on(task, c)                                      \
    do {                                                                      \
        nxt_int_t  ret;                                                       \
                                                                              \
        ret = nxt_socket_setsockopt(task, (c)->socket.fd, IPPROTO_TCP,        \
                                    TCP_NODELAY, 1);                          \
                                                                              \
        (c)->tcp_nodelay = (ret == NXT_OK);                                   \
    } while (0)

#endif


NXT_EXPORT nxt_conn_t *nxt_conn_create(nxt_mp_t *mp, nxt_task_t *task);
NXT_EXPORT void nxt_conn_free(nxt_task_t *task, nxt_conn_t *c);
NXT_EXPORT void nxt_conn_close(nxt_event_engine_t *engine, nxt_conn_t *c);

NXT_EXPORT void nxt_conn_timer(nxt_event_engine_t *engine, nxt_conn_t *c,
    const nxt_conn_state_t *state, nxt_timer_t *tev);
NXT_EXPORT void nxt_conn_work_queue_set(nxt_conn_t *c, nxt_work_queue_t *wq);
NXT_EXPORT nxt_sockaddr_t *nxt_conn_local_addr(nxt_task_t *task,
    nxt_conn_t *c);

void nxt_conn_sys_socket(nxt_task_t *task, void *obj, void *data);
void nxt_conn_io_connect(nxt_task_t *task, void *obj, void *data);
nxt_int_t nxt_conn_socket(nxt_task_t *task, nxt_conn_t *c);
void nxt_conn_connect_test(nxt_task_t *task, void *obj, void *data);
void nxt_conn_connect_error(nxt_task_t *task, void *obj, void *data);

NXT_EXPORT nxt_listen_event_t *nxt_listen_event(nxt_task_t *task,
    nxt_listen_socket_t *ls);
void nxt_conn_io_accept(nxt_task_t *task, void *obj, void *data);
NXT_EXPORT void nxt_conn_accept(nxt_task_t *task, nxt_listen_event_t *lev,
    nxt_conn_t *c);
void nxt_conn_accept_error(nxt_task_t *task, nxt_listen_event_t *lev,
    const char *accept_syscall, nxt_err_t err);

void nxt_conn_wait(nxt_conn_t *c);

void nxt_conn_io_read(nxt_task_t *task, void *obj, void *data);
ssize_t nxt_conn_io_recvbuf(nxt_conn_t *c, nxt_buf_t *b);
ssize_t nxt_conn_io_recv(nxt_conn_t *c, void *buf, size_t size,
    nxt_uint_t flags);

void nxt_conn_io_write(nxt_task_t *task, void *obj, void *data);
ssize_t nxt_conn_io_sendbuf(nxt_task_t *task, nxt_sendbuf_t *sb);
ssize_t nxt_conn_io_writev(nxt_task_t *task, nxt_sendbuf_t *sb,
    nxt_iobuf_t *iob, nxt_uint_t niob);
ssize_t nxt_conn_io_send(nxt_task_t *task, nxt_sendbuf_t *sb, void *buf,
    size_t size);

size_t nxt_event_conn_write_limit(nxt_conn_t *c);
nxt_bool_t nxt_event_conn_write_delayed(nxt_event_engine_t *engine,
    nxt_conn_t *c, size_t sent);
ssize_t nxt_event_conn_io_writev(nxt_conn_t *c, nxt_iobuf_t *iob,
    nxt_uint_t niob);
ssize_t nxt_event_conn_io_send(nxt_conn_t *c, void *buf, size_t size);

NXT_EXPORT void nxt_event_conn_job_sendfile(nxt_task_t *task,
    nxt_conn_t *c);


#define nxt_conn_connect(engine, c)                                           \
    nxt_work_queue_add(&engine->socket_work_queue, nxt_conn_sys_socket,       \
                       c->socket.task, c, c->socket.data)


#define nxt_conn_read(engine, c)                                              \
    do {                                                                      \
        nxt_event_engine_t  *e = engine;                                      \
                                                                              \
        c->socket.read_work_queue = &e->read_work_queue;                      \
                                                                              \
        nxt_work_queue_add(&e->read_work_queue, c->io->read,                  \
                           c->socket.task, c, c->socket.data);                \
    } while (0)


#define nxt_conn_write(engine, c)                                             \
    do {                                                                      \
        nxt_event_engine_t  *e = engine;                                      \
                                                                              \
        c->socket.write_work_queue = &e->write_work_queue;                    \
                                                                              \
        nxt_work_queue_add(&e->write_work_queue, c->io->write,                \
                           c->socket.task, c, c->socket.data);                \
    } while (0)


extern nxt_conn_io_t             nxt_unix_conn_io;


typedef struct {
    /*
     * Client and peer connections are not embedded because already
     * existent connections can be switched to the event connection proxy.
     */
    nxt_conn_t                   *client;
    nxt_conn_t                   *peer;
    nxt_buf_t                    *client_buffer;
    nxt_buf_t                    *peer_buffer;

    size_t                       client_buffer_size;
    size_t                       peer_buffer_size;

    nxt_msec_t                   client_wait_timeout;
    nxt_msec_t                   connect_timeout;
    nxt_msec_t                   reconnect_timeout;
    nxt_msec_t                   peer_wait_timeout;
    nxt_msec_t                   client_write_timeout;
    nxt_msec_t                   peer_write_timeout;

    uint8_t                      connected;  /* 1 bit */
    uint8_t                      delayed;    /* 1 bit */
    uint8_t                      retries;    /* 8 bits */
    uint8_t                      retain;     /* 2 bits */

    nxt_work_handler_t           completion_handler;
} nxt_conn_proxy_t;


NXT_EXPORT nxt_conn_proxy_t *nxt_conn_proxy_create(nxt_conn_t *c);
NXT_EXPORT void nxt_conn_proxy(nxt_task_t *task, nxt_conn_proxy_t *p);


/* STUB */
#define nxt_event_conn_t         nxt_conn_t
#define nxt_event_conn_state_t   nxt_conn_state_t
#define nxt_event_conn_proxy_t   nxt_conn_proxy_t
#define nxt_event_conn_read      nxt_conn_read
#define nxt_event_conn_write     nxt_conn_write
#define nxt_event_conn_close     nxt_conn_close


#endif /* _NXT_CONN_H_INCLUDED_ */

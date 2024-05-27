
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_EVENT_ENGINE_H_INCLUDED_
#define _NXT_EVENT_ENGINE_H_INCLUDED_

/*
 * An event interface is kernel interface such as kqueue, epoll, etc.
 * intended to get event notifications about file descriptor state,
 * signals, etc.
 */

#define NXT_FILE_EVENTS           1
#define NXT_NO_FILE_EVENTS        0

#define NXT_SIGNAL_EVENTS         1
#define NXT_NO_SIGNAL_EVENTS      0


typedef struct {

    /* The canonical event set name. */
    const char                    *name;

    /*
     * Create an event set.  The mchanges argument is a maximum number of
     * changes to send to the kernel.  The mevents argument is a maximum
     * number of events to retrieve from the kernel at once, if underlying
     * event facility supports batch operations.
     */
    nxt_int_t                     (*create)(nxt_event_engine_t *engine,
                                      nxt_uint_t mchanges, nxt_uint_t mevents);

    /* Close and free an event set. */
    void                          (*free)(nxt_event_engine_t *engine);

    /*
     * Add a file descriptor to an event set and enable the most
     * effective read and write event notification method provided
     * by underlying event facility.
     */
    void                          (*enable)(nxt_event_engine_t *engine,
                                      nxt_fd_event_t *ev);

    /* Disable file descriptor event notifications. */
    void                          (*disable)(nxt_event_engine_t *engine,
                                      nxt_fd_event_t *ev);

    /*
     * Delete a file descriptor from an event set.  A possible usage
     * is a moving of the file descriptor from one event set to another.
     */
    void                          (*delete)(nxt_event_engine_t *engine,
                                      nxt_fd_event_t *ev);

    /*
     * Delete a file descriptor from an event set before closing the
     * file descriptor.  The most event facilities such as Linux epoll,
     * BSD kqueue, Solaris event ports, AIX pollset, and HP-UX /dev/poll
     * delete a file descriptor automatically on the file descriptor close.
     * Some facilities such as Solaris /dev/poll require to delete a file
     * descriptor explicitly.
     */
    nxt_bool_t                    (*close)(nxt_event_engine_t *engine,
                                      nxt_fd_event_t *ev);

    /*
     * Add a file descriptor to an event set and enable the most effective
     * read event notification method provided by underlying event facility.
     */
    void                          (*enable_read)(nxt_event_engine_t *engine,
                                      nxt_fd_event_t *ev);

    /*
     * Add a file descriptor to an event set and enable the most effective
     * write event notification method provided by underlying event facility.
     */
    void                          (*enable_write)(nxt_event_engine_t *engine,
                                      nxt_fd_event_t *ev);

    /* Disable file descriptor read event notifications. */
    void                          (*disable_read)(nxt_event_engine_t *engine,
                                      nxt_fd_event_t *ev);

    /* Disable file descriptor write event notifications. */
    void                          (*disable_write)(nxt_event_engine_t *engine,
                                      nxt_fd_event_t *ev);

    /* Block file descriptor read event notifications. */
    void                          (*block_read)(nxt_event_engine_t *engine,
                                      nxt_fd_event_t *ev);

    /* Block file descriptor write event notifications. */
    void                          (*block_write)(nxt_event_engine_t *engine,
                                      nxt_fd_event_t *ev);

    /*
     * Add a file descriptor to an event set and enable an oneshot
     * read event notification method.
     */
    void                          (*oneshot_read)(nxt_event_engine_t *engine,
                                      nxt_fd_event_t *ev);

    /*
     * Add a file descriptor to an event set and enable an oneshot
     * write event notification method.
     */
    void                          (*oneshot_write)(nxt_event_engine_t *engine,
                                      nxt_fd_event_t *ev);

    /*
     * Add a listening socket descriptor to an event set and enable
     * a level-triggered read event notification method.
     */
    void                          (*enable_accept)(nxt_event_engine_t *engine,
                                      nxt_fd_event_t *ev);

    /*
     * Add a file to an event set and enable a file change notification
     * events.
     */
    void                          (*enable_file)(nxt_event_engine_t *engine,
                                      nxt_file_event_t *ev);

    /*
     * Delete a file from an event set before closing the file descriptor.
     */
    void                          (*close_file)(nxt_event_engine_t *engine,
                                      nxt_file_event_t *ev);

    /*
     * Enable post event notifications and set a post handler to handle
     * the zero signal.
     */
    nxt_int_t                     (*enable_post)(nxt_event_engine_t *engine,
                                      nxt_work_handler_t handler);

    /*
     * Signal an event set.  If a signal number is non-zero then
     * a signal handler added to the event set is called.  This is
     * a way to route Unix signals to an event engine if underlying
     * event facility does not support signal events.
     *
     * If a signal number is zero, then the post_handler of the event
     * set is called.  This has no relation to Unix signals but is
     * a way to wake up the event set to process works posted to
     * the event engine locked work queue.
     */
    void                          (*signal)(nxt_event_engine_t *engine,
                                      nxt_uint_t signo);

    /* Poll an event set for new event notifications. */
    void                          (*poll)(nxt_event_engine_t *engine,
                                      nxt_msec_t timeout);

    /* I/O operations suitable to underlying event facility. */
    nxt_conn_io_t                 *io;

    /* True if an event facility supports file change event notifications. */
    uint8_t                       file_support;   /* 1 bit */

    /* True if an event facility supports signal event notifications. */
    uint8_t                       signal_support;  /* 1 bit */
} nxt_event_interface_t;


#if (NXT_HAVE_KQUEUE)

typedef struct {
    int                           fd;
    int                           nchanges;
    int                           mchanges;
    int                           mevents;
    nxt_pid_t                     pid;

    nxt_work_handler_t            post_handler;

    struct kevent                 *changes;
    struct kevent                 *events;
} nxt_kqueue_engine_t;

extern const nxt_event_interface_t  nxt_kqueue_engine;

#endif


#if (NXT_HAVE_EPOLL)

typedef struct {
    int                           op;
    struct epoll_event            event;
} nxt_epoll_change_t;


typedef struct {
    int                           fd;
    uint32_t                      mode;
    nxt_uint_t                    nchanges;
    nxt_uint_t                    mchanges;
    int                           mevents;

    uint8_t                       error;  /* 1 bit */

    nxt_epoll_change_t            *changes;
    struct epoll_event            *events;

#if (NXT_HAVE_EVENTFD)
    nxt_work_handler_t            post_handler;
    nxt_fd_event_t                eventfd;
    uint32_t                      neventfd;
#endif

#if (NXT_HAVE_SIGNALFD)
    nxt_fd_event_t                signalfd;
#endif
} nxt_epoll_engine_t;


extern const nxt_event_interface_t  nxt_epoll_edge_engine;
extern const nxt_event_interface_t  nxt_epoll_level_engine;

#endif


#if (NXT_HAVE_EVENTPORT)

typedef struct {
    int                           events;
    nxt_fd_event_t                *event;
} nxt_eventport_change_t;


typedef struct {
    int                           fd;
    nxt_uint_t                    nchanges;
    nxt_uint_t                    mchanges;
    u_int                         mevents;

    nxt_eventport_change_t        *changes;
    port_event_t                  *events;

    nxt_work_handler_t            post_handler;
    nxt_work_handler_t            signal_handler;
} nxt_eventport_engine_t;

extern const nxt_event_interface_t  nxt_eventport_engine;

#endif


#if (NXT_HAVE_DEVPOLL)

typedef struct {
    uint8_t                       op;
    short                         events;
    nxt_fd_event_t                *event;
} nxt_devpoll_change_t;


typedef struct {
    int                           fd;
    int                           nchanges;
    int                           mchanges;
    int                           mevents;

    nxt_devpoll_change_t          *changes;
    struct pollfd                 *write_changes;
    struct pollfd                 *events;
    nxt_lvlhsh_t                  fd_hash;
} nxt_devpoll_engine_t;

extern const nxt_event_interface_t  nxt_devpoll_engine;

#endif


#if (NXT_HAVE_POLLSET)

typedef struct {
    uint8_t                       op;
    uint8_t                       cmd;
    short                         events;
    nxt_fd_event_t                *event;
} nxt_pollset_change_t;


typedef struct {
    pollset_t                     ps;
    int                           nchanges;
    int                           mchanges;
    int                           mevents;

    nxt_pollset_change_t          *changes;
    struct poll_ctl               *write_changes;
    struct pollfd                 *events;
    nxt_lvlhsh_t                  fd_hash;
} nxt_pollset_engine_t;

extern const nxt_event_interface_t  nxt_pollset_engine;

#endif


typedef struct {
    uint8_t                       op;
    short                         events;
    nxt_fd_event_t                *event;
} nxt_poll_change_t;


typedef struct {
    nxt_uint_t                    max_nfds;
    nxt_uint_t                    nfds;

    nxt_uint_t                    nchanges;
    nxt_uint_t                    mchanges;

    nxt_poll_change_t             *changes;
    struct pollfd                 *set;

    nxt_lvlhsh_t                  fd_hash;
} nxt_poll_engine_t;

extern const nxt_event_interface_t  nxt_poll_engine;


typedef struct {
    int                           nfds;
    uint32_t                      update_nfds;  /* 1 bit */

    nxt_fd_event_t                **events;

    fd_set                        main_read_fd_set;
    fd_set                        main_write_fd_set;
    fd_set                        work_read_fd_set;
    fd_set                        work_write_fd_set;
} nxt_select_engine_t;

extern const nxt_event_interface_t  nxt_select_engine;


nxt_int_t nxt_fd_event_hash_add(nxt_lvlhsh_t *lvlhsh, nxt_fd_t fd,
    nxt_fd_event_t *ev);
void *nxt_fd_event_hash_get(nxt_task_t *task, nxt_lvlhsh_t *lvlhsh,
    nxt_fd_t fd);
void nxt_fd_event_hash_delete(nxt_task_t *task, nxt_lvlhsh_t *lvlhsh,
    nxt_fd_t fd, nxt_bool_t ignore);
void nxt_fd_event_hash_destroy(nxt_lvlhsh_t *lvlhsh);


#define nxt_fd_event_disable(engine, ev)                                      \
    (engine)->event.disable(engine, ev)


#define nxt_fd_event_delete(engine, ev)                                       \
    (engine)->event.delete(engine, ev)


#define nxt_fd_event_close(engine, ev)                                        \
    (engine)->event.close(engine, ev)


#define nxt_fd_event_enable_read(engine, ev)                                  \
    (engine)->event.enable_read(engine, ev)


#define nxt_fd_event_enable_write(engine, ev)                                 \
    (engine)->event.enable_write(engine, ev)


#define nxt_fd_event_disable_read(engine, ev)                                 \
    (engine)->event.disable_read(engine, ev)


#define nxt_fd_event_disable_write(engine, ev)                                \
    (engine)->event.disable_write(engine, ev)


#define nxt_fd_event_block_read(engine, ev)                                   \
    do {                                                                      \
        if (nxt_fd_event_is_active((ev)->read)) {                             \
            (engine)->event.block_read(engine, ev);                           \
        }                                                                     \
    } while (0)


#define nxt_fd_event_block_write(engine, ev)                                  \
    do {                                                                      \
        if (nxt_fd_event_is_active((ev)->write)) {                            \
            (engine)->event.block_write(engine, ev);                          \
        }                                                                     \
    } while (0)


#define nxt_fd_event_oneshot_read(engine, ev)                                 \
    (engine)->event.oneshot_read(engine, ev)


#define nxt_fd_event_oneshot_write(engine, ev)                                \
    (engine)->event.oneshot_write(engine, ev)


#define nxt_fd_event_enable_accept(engine, ev)                                \
    (engine)->event.enable_accept(engine, ev)


#define NXT_ENGINE_FIBERS      1


typedef struct {
    nxt_fd_t                   fds[2];
    nxt_fd_event_t             event;
} nxt_event_engine_pipe_t;


struct nxt_event_engine_s {
    nxt_task_t                 task;

    union {
        nxt_poll_engine_t      poll;
        nxt_select_engine_t    select;

#if (NXT_HAVE_KQUEUE)
        nxt_kqueue_engine_t    kqueue;
#endif
#if (NXT_HAVE_EPOLL)
        nxt_epoll_engine_t     epoll;
#endif
#if (NXT_HAVE_EVENTPORT)
        nxt_eventport_engine_t eventport;
#endif
#if (NXT_HAVE_DEVPOLL)
        nxt_devpoll_engine_t   devpoll;
#endif
#if (NXT_HAVE_POLLSET)
        nxt_pollset_engine_t   pollset;
#endif
    } u;

    nxt_timers_t               timers;

    nxt_work_queue_cache_t     work_queue_cache;
    nxt_work_queue_t           *current_work_queue;
    nxt_work_queue_t           fast_work_queue;
    nxt_work_queue_t           accept_work_queue;
    nxt_work_queue_t           read_work_queue;
    nxt_work_queue_t           socket_work_queue;
    nxt_work_queue_t           connect_work_queue;
    nxt_work_queue_t           write_work_queue;
    nxt_work_queue_t           shutdown_work_queue;
    nxt_work_queue_t           close_work_queue;

    nxt_locked_work_queue_t    locked_work_queue;

    nxt_event_interface_t      event;

    /*
     * A pipe to pass event signals to the engine, if the engine's
     * underlying event facility does not support user events.
     */
    nxt_event_engine_pipe_t    *pipe;

    nxt_event_signals_t        *signals;

    nxt_fiber_main_t           *fibers;

    /* The engine ID, the main engine has ID 0. */
    uint32_t                   id;

    uint8_t                    shutdown;  /* 1 bit */

    uint32_t                   batch;
    uint32_t                   connections;
    uint32_t                   max_connections;

    nxt_port_t                 *port;
    nxt_mp_t                   *mem_pool;
    nxt_queue_t                joints;
    nxt_queue_t                listen_connections;
    nxt_queue_t                idle_connections;
    nxt_array_t                *mem_cache;

    nxt_atomic_uint_t          accepted_conns_cnt;
    nxt_atomic_uint_t          idle_conns_cnt;
    nxt_atomic_uint_t          closed_conns_cnt;
    nxt_atomic_uint_t          requests_cnt;

    nxt_queue_link_t           link;
    // STUB: router link
    nxt_queue_link_t           link0;
};


NXT_EXPORT nxt_event_engine_t *nxt_event_engine_create(nxt_task_t *task,
    const nxt_event_interface_t *interface, const nxt_sig_event_t *signals,
    nxt_uint_t flags, nxt_uint_t batch);
NXT_EXPORT nxt_int_t nxt_event_engine_change(nxt_event_engine_t *engine,
    const nxt_event_interface_t *interface, nxt_uint_t batch);
NXT_EXPORT void nxt_event_engine_free(nxt_event_engine_t *engine);
NXT_EXPORT void nxt_event_engine_start(nxt_event_engine_t *engine);

NXT_EXPORT void nxt_event_engine_post(nxt_event_engine_t *engine,
    nxt_work_t *work);
NXT_EXPORT void nxt_event_engine_signal(nxt_event_engine_t *engine,
    nxt_uint_t signo);

#define NXT_EVENT_ENGINE_NO_MEM_HINT  255

void *nxt_event_engine_mem_alloc(nxt_event_engine_t *engine, uint8_t *hint,
    size_t size);
void nxt_event_engine_mem_free(nxt_event_engine_t *engine, uint8_t hint,
    void *p, size_t size);
void *nxt_event_engine_buf_mem_alloc(nxt_event_engine_t *engine, size_t size);
void nxt_event_engine_buf_mem_free(nxt_event_engine_t *engine, nxt_buf_t *b);
void nxt_event_engine_buf_mem_completion(nxt_task_t *task, void *obj,
    void *data);


nxt_inline nxt_event_engine_t *
nxt_thread_event_engine(void)
{
    nxt_thread_t  *thr;

    thr = nxt_thread();
    return thr->engine;
}

#if (NXT_DEBUG)

NXT_EXPORT void nxt_event_engine_thread_adopt(nxt_event_engine_t *engine);

#else

#define nxt_event_engine_thread_adopt(_engine)

#endif


#endif /* _NXT_EVENT_ENGINE_H_INCLUDED_ */

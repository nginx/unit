
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_EVENT_SET_H_INCLUDED_
#define _NXT_EVENT_SET_H_INCLUDED_


/*
 * An event facility is kernel interface such as kqueue, epoll, etc.
 * intended to get event notifications about file descriptor state,
 * signals, etc.
 *
 * An event set provides generic interface to underlying event facility.
 * Although event set and event facility are closely coupled with an event
 * engine, nevertheless they are separated from an event engine to allow
 * to add one event facility to another if underlying event facility allows
 * this (Linux epoll, BSD kqueue, Solaris eventport).
 */

typedef union nxt_event_set_u     nxt_event_set_t;


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
    nxt_event_set_t               *(*create)(nxt_event_signals_t *signals,
                                      nxt_uint_t mchanges, nxt_uint_t mevents);

    /* Close and free an event set. */
    void                          (*free)(nxt_event_set_t *data);

    /*
     * Add a file descriptor to an event set and enable the most
     * effective read and write event notification method provided
     * by underlying event facility.
     */
    void                          (*enable)(nxt_event_set_t *event_set,
                                      nxt_event_fd_t *ev);

    /* Disable file descriptor event notifications. */
    void                          (*disable)(nxt_event_set_t *event_set,
                                      nxt_event_fd_t *ev);

    /*
     * Delete a file descriptor from an event set.  A possible usage
     * is a moving of the file descriptor from one event set to another.
     */
    void                          (*delete)(nxt_event_set_t *event_set,
                                      nxt_event_fd_t *ev);

    /*
     * Delete a file descriptor from an event set before closing the
     * file descriptor.  The most event facilities such as Linux epoll,
     * BSD kqueue, Solaris event ports, AIX pollset, and HP-UX /dev/poll
     * delete a file descriptor automatically on the file descriptor close.
     * Some facilities such as Solaris /dev/poll require to delete a file
     * descriptor explicitly.
     */
    void                          (*close)(nxt_event_set_t *event_set,
                                      nxt_event_fd_t *ev);

    /*
     * Add a file descriptor to an event set and enable the most effective
     * read event notification method provided by underlying event facility.
     */
    void                          (*enable_read)(nxt_event_set_t *event_set,
                                      nxt_event_fd_t *ev);

    /*
     * Add a file descriptor to an event set and enable the most effective
     * write event notification method provided by underlying event facility.
     */
    void                          (*enable_write)(nxt_event_set_t *event_set,
                                      nxt_event_fd_t *ev);

    /* Disable file descriptor read event notifications. */
    void                          (*disable_read)(nxt_event_set_t *event_set,
                                      nxt_event_fd_t *ev);

    /* Disable file descriptor write event notifications. */
    void                          (*disable_write)(nxt_event_set_t *event_set,
                                      nxt_event_fd_t *ev);

    /* Block file descriptor read event notifications. */
    void                          (*block_read)(nxt_event_set_t *event_set,
                                      nxt_event_fd_t *ev);

    /* Block file descriptor write event notifications. */
    void                          (*block_write)(nxt_event_set_t *event_set,
                                      nxt_event_fd_t *ev);

    /*
     * Add a file descriptor to an event set and enable an oneshot
     * read event notification method.
     */
    void                          (*oneshot_read)(nxt_event_set_t *event_set,
                                      nxt_event_fd_t *ev);

    /*
     * Add a file descriptor to an event set and enable an oneshot
     * write event notification method.
     */
    void                          (*oneshot_write)(nxt_event_set_t *event_set,
                                      nxt_event_fd_t *ev);

    /*
     * Add a listening socket descriptor to an event set and enable
     * a level-triggered read event notification method.
     */
    void                          (*enable_accept)(nxt_event_set_t *event_set,
                                      nxt_event_fd_t *ev);

    /*
     * Add a file to an event set and enable a file change notification
     * events.
     */
    void                          (*enable_file)(nxt_event_set_t *event_set,
                                      nxt_event_file_t *fev);

    /*
     * Delete a file from an event set before closing the file descriptor.
     */
    void                          (*close_file)(nxt_event_set_t *event_set,
                                      nxt_event_file_t *fev);

    /*
     * Enable post event notifications and set a post handler to handle
     * the zero signal.
     */
    nxt_int_t                     (*enable_post)(nxt_event_set_t *event_set,
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
    void                          (*signal)(nxt_event_set_t *event_set,
                                      nxt_uint_t signo);

    /* Poll an event set for new event notifications. */
    void                          (*poll)(nxt_task_t *task,
                                      nxt_event_set_t *event_set,
                                      nxt_msec_t timeout);

    /* I/O operations suitable to underlying event facility. */
    nxt_event_conn_io_t           *io;

    /* True if an event facility supports file change event notifications. */
    uint8_t                       file_support;   /* 1 bit */

    /* True if an event facility supports signal event notifications. */
    uint8_t                       signal_support;  /* 1 bit */
} nxt_event_set_ops_t;


#if (NXT_HAVE_KQUEUE)

typedef struct {
    int                           kqueue;
    int                           nchanges;
    int                           mchanges;
    int                           mevents;
    nxt_pid_t                     pid;

    nxt_work_handler_t            post_handler;

    struct kevent                 *changes;
    struct kevent                 *events;
} nxt_kqueue_event_set_t;

extern const nxt_event_set_ops_t  nxt_kqueue_event_set;

#endif


#if (NXT_HAVE_EPOLL)

typedef struct {
    int                           op;
    /*
     * Although file descriptor can be obtained using pointer to a
     * nxt_event_fd_t stored in event.data.ptr, nevertheless storing
     * the descriptor right here avoid cache miss.  Besides this costs
     * no space because event.data must be anyway aligned to 64 bits.
     */
    nxt_socket_t                  fd;

    struct epoll_event            event;
} nxt_epoll_change_t;


typedef struct {
    int                           epoll;
    uint32_t                      mode;
    nxt_uint_t                    nchanges;
    nxt_uint_t                    mchanges;
    int                           mevents;

    nxt_epoll_change_t            *changes;
    struct epoll_event            *events;

#if (NXT_HAVE_EVENTFD)
    nxt_work_handler_t            post_handler;
    nxt_event_fd_t                eventfd;
    uint32_t                      neventfd;
#endif

#if (NXT_HAVE_SIGNALFD)
    nxt_event_fd_t                signalfd;
#endif
} nxt_epoll_event_set_t;


extern const nxt_event_set_ops_t  nxt_epoll_edge_event_set;
extern const nxt_event_set_ops_t  nxt_epoll_level_event_set;

#endif


#if (NXT_HAVE_EVENTPORT)

typedef struct {
    /*
     * Although file descriptor can be obtained using pointer to a
     * nxt_event_fd_t, nevertheless storing the descriptor right here
     * avoid cache miss.  Besides this costs no space on 64-bit platform.
     */
    nxt_socket_t                  fd;

    int                           events;
    nxt_event_fd_t                *event;
} nxt_eventport_change_t;


typedef struct {
    int                           port;
    nxt_uint_t                    nchanges;
    nxt_uint_t                    mchanges;
    u_int                         mevents;

    nxt_eventport_change_t        *changes;
    port_event_t                  *events;

    nxt_work_handler_t            post_handler;
    nxt_work_handler_t            signal_handler;
} nxt_eventport_event_set_t;

extern const nxt_event_set_ops_t  nxt_eventport_event_set;

#endif


#if (NXT_HAVE_DEVPOLL)

typedef struct {
    uint8_t                       op;
    short                         events;

    /* A file descriptor stored because nxt_event_fd_t may be already freed. */
    nxt_socket_t                  fd;

    nxt_event_fd_t                *event;
} nxt_devpoll_change_t;


typedef struct {
    int                           devpoll;
    int                           nchanges;
    int                           mchanges;
    int                           mevents;

    nxt_devpoll_change_t          *devpoll_changes;
    struct pollfd                 *changes;
    struct pollfd                 *events;
    nxt_lvlhsh_t                  fd_hash;
} nxt_devpoll_event_set_t;

extern const nxt_event_set_ops_t  nxt_devpoll_event_set;

#endif


#if (NXT_HAVE_POLLSET)

typedef struct {
    uint8_t                       op;
    uint8_t                       cmd;
    short                         events;

    /* A file descriptor stored because nxt_event_fd_t may be already freed. */
    nxt_socket_t                  fd;

    nxt_event_fd_t                *event;
} nxt_pollset_change_t;


typedef struct {
    pollset_t                     pollset;
    int                           nchanges;
    int                           mchanges;
    int                           mevents;

    nxt_pollset_change_t          *pollset_changes;
    struct poll_ctl               *changes;
    struct pollfd                 *events;
    nxt_lvlhsh_t                  fd_hash;
} nxt_pollset_event_set_t;

extern const nxt_event_set_ops_t  nxt_pollset_event_set;

#endif


typedef struct {
    uint8_t                       op;
    short                         events;

    /* A file descriptor stored because nxt_event_fd_t may be already freed. */
    nxt_socket_t                  fd;

    nxt_event_fd_t                *event;
} nxt_poll_change_t;


typedef struct {
    nxt_uint_t                    max_nfds;
    nxt_uint_t                    nfds;

    nxt_uint_t                    nchanges;
    nxt_uint_t                    mchanges;

    nxt_poll_change_t             *changes;
    struct pollfd                 *poll_set;

    nxt_lvlhsh_t                  fd_hash;
} nxt_poll_event_set_t;

extern const nxt_event_set_ops_t  nxt_poll_event_set;


typedef struct {
    int                           nfds;
    uint32_t                      update_nfds;  /* 1 bit */

    nxt_event_fd_t                **events;

    fd_set                        main_read_fd_set;
    fd_set                        main_write_fd_set;
    fd_set                        work_read_fd_set;
    fd_set                        work_write_fd_set;
} nxt_select_event_set_t;

extern const nxt_event_set_ops_t  nxt_select_event_set;


union nxt_event_set_u {
#if (NXT_HAVE_KQUEUE)
    nxt_kqueue_event_set_t     kqueue;
#endif
#if (NXT_HAVE_EPOLL)
    nxt_epoll_event_set_t      epoll;
#endif
#if (NXT_HAVE_EVENTPORT)
    nxt_eventport_event_set_t  eventport;
#endif
#if (NXT_HAVE_DEVPOLL)
    nxt_devpoll_event_set_t    devpoll;
#endif
#if (NXT_HAVE_POLLSET)
    nxt_pollset_event_set_t    pollset;
#endif
    nxt_poll_event_set_t       poll;
    nxt_select_event_set_t     select;
};


nxt_int_t nxt_event_set_fd_hash_add(nxt_lvlhsh_t *lh, nxt_fd_t fd,
    nxt_event_fd_t *ev);
void *nxt_event_set_fd_hash_get(nxt_lvlhsh_t *lh, nxt_fd_t fd);
void nxt_event_set_fd_hash_delete(nxt_lvlhsh_t *lh, nxt_fd_t fd,
    nxt_bool_t ignore);
void nxt_event_set_fd_hash_destroy(nxt_lvlhsh_t *lh);


#define                                                                       \
nxt_event_fd_disable(engine, ev)                                              \
    (engine)->event->disable((engine)->event_set, ev)


#define                                                                       \
nxt_event_fd_close(engine, ev)                                                \
    (engine)->event->close((engine)->event_set, ev)


#define                                                                       \
nxt_event_fd_enable_read(engine, ev)                                          \
    (engine)->event->enable_read((engine)->event_set, ev)


#define                                                                       \
nxt_event_fd_enable_write(engine, ev)                                         \
    (engine)->event->enable_write((engine)->event_set, ev)


#define                                                                       \
nxt_event_fd_disable_read(engine, ev)                                         \
    (engine)->event->disable_read((engine)->event_set, ev)


#define                                                                       \
nxt_event_fd_disable_write(engine, ev)                                        \
    (engine)->event->disable_write((engine)->event_set, ev)


#define                                                                       \
nxt_event_fd_block_read(engine, ev)                                           \
    do {                                                                      \
        if (nxt_event_fd_is_active((ev)->read)) {                             \
            (engine)->event->block_read((engine)->event_set, ev);             \
        }                                                                     \
    } while (0)


#define                                                                       \
nxt_event_fd_block_write(engine, ev)                                          \
    do {                                                                      \
        if (nxt_event_fd_is_active((ev)->write)) {                            \
            (engine)->event->block_write((engine)->event_set, ev);            \
        }                                                                     \
    } while (0)


#define                                                                       \
nxt_event_fd_oneshot_read(engine, ev)                                         \
    (engine)->event->oneshot_read((engine)->event_set, ev)


#define                                                                       \
nxt_event_fd_oneshot_write(engine, ev)                                        \
    (engine)->event->oneshot_write((engine)->event_set, ev)


#define                                                                       \
nxt_event_fd_enable_accept(engine, ev)                                        \
    (engine)->event->enable_accept((engine)->event_set, ev)


#endif /* _NXT_EVENT_SET_H_INCLUDED_ */


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_FD_EVENT_H_INCLUDED_
#define _NXT_FD_EVENT_H_INCLUDED_


typedef enum {
    /* A completely inactive event. */
    NXT_EVENT_INACTIVE = 0,

    /*
     * An event presents in the kernel but disabled after oneshot.
     * Used by epoll.
     */
    NXT_EVENT_DISABLED,

    /*
     * An event is active in the kernel but blocked by application.
     * Used by kqueue, epoll, eventport, devpoll, and pollset.
     */
    NXT_EVENT_BLOCKED,

    /*
     * An active oneshot event.
     * Used by epoll, devpoll, pollset, poll, and select.
     */
    NXT_EVENT_ONESHOT,

    /* An active level-triggered event.  Used by eventport. */
    NXT_EVENT_LEVEL,

    /*
     * An active default event.  The event type depends on interface:
     *    edge-triggered for kqueue, and modern epoll;
     *    level-triggered for old epoll, devpoll, pollset, poll, and select;
     *    oneshot for kqueue and eventport.
     */
    NXT_EVENT_DEFAULT,
    NXT_EVENT_ACTIVE = NXT_EVENT_DEFAULT,
} nxt_fd_event_state_t;


#define nxt_fd_event_is_disabled(state)                                       \
    ((state) < NXT_EVENT_ONESHOT)


#define nxt_fd_event_is_active(state)                                         \
    ((state) >= NXT_EVENT_ONESHOT)


struct nxt_fd_event_s {
    void                    *data;

    /* Both are int's. */
    nxt_socket_t            fd;
    nxt_err_t               error;

    /* The flags should also be prefetched by nxt_work_queue_pop(). */

#if (NXT_64BIT)
    nxt_fd_event_state_t      read:8;       /* 3 bits. */
    nxt_fd_event_state_t      write:8;      /* 3 bits. */
    uint8_t                   read_ready;
    uint8_t                   write_ready;
    uint8_t                   changing;
    uint8_t                   closed;
    uint8_t                   timedout;
    uint8_t                   shutdown:1;
#if (NXT_HAVE_EPOLL)
    uint8_t                   epoll_eof:1;
    uint8_t                   epoll_error:1;
#endif
#if (NXT_HAVE_KQUEUE)
    uint8_t                   kq_eof:1;
#endif

#else /* NXT_32BIT */
    nxt_fd_event_state_t      read:3;
    nxt_fd_event_state_t      write:3;
    uint8_t                   read_ready:1;
    uint8_t                   write_ready:1;
    uint8_t                   changing:1;
    uint8_t                   closed:1;
    uint8_t                   timedout:1;
    uint8_t                   shutdown:1;
#if (NXT_HAVE_EPOLL)
    uint8_t                   epoll_eof:1;
    uint8_t                   epoll_error:1;
#endif
#if (NXT_HAVE_KQUEUE)
    uint8_t                   kq_eof:1;
#endif
#endif /* NXT_64BIT */

#if (NXT_HAVE_KQUEUE)
    /* nxt_err_t is int. */
    nxt_err_t               kq_errno;
    /* struct kevent.data is intptr_t, however int32_t is enough. */
    int32_t                 kq_available;
#endif

    nxt_task_t              *task;

    nxt_work_queue_t        *read_work_queue;
    nxt_work_handler_t      read_handler;
    nxt_work_queue_t        *write_work_queue;
    nxt_work_handler_t      write_handler;
    nxt_work_handler_t      error_handler;

    nxt_log_t               *log;
};


#endif /* _NXT_FD_EVENT_H_INCLUDED_ */

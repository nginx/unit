
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */


#ifndef _NXT_UNIX_TEST_BUILD_H_INCLUDED_
#define _NXT_UNIX_TEST_BUILD_H_INCLUDED_


#if (NXT_TEST_BUILD_EPOLL)

#define NXT_HAVE_EPOLL       1
#define NXT_HAVE_EPOLL_EDGE  1
#define NXT_HAVE_EVENTFD     1
#define NXT_HAVE_SIGNALFD    1
#define NXT_HAVE_ACCEPT4     1

/* Linux epoll declarations */

#define EPOLLIN        0x00000001
#define EPOLLPRI       0x00000002
#define EPOLLOUT       0x00000004
#define EPOLLERR       0x00000008
#define EPOLLHUP       0x00000010
#define EPOLLRDNORM    0x00000040
#define EPOLLRDBAND    0x00000080
#define EPOLLWRNORM    00000x0100
#define EPOLLWRBAND    0x00000200
#define EPOLLMSG       0x00000400
#define EPOLLRDHUP     0x00002000

#define EPOLLET        0x80000000
#define EPOLLONESHOT   0x40000000

#define EPOLL_CTL_ADD  1
#define EPOLL_CTL_DEL  2
#define EPOLL_CTL_MOD  3

#define EFD_SEMAPHORE  1
#define EFD_NONBLOCK   04000


typedef union epoll_data {
    void               *ptr;
    int                fd;
    uint32_t           u32;
    uint64_t           u64;
} epoll_data_t;


struct epoll_event {
    uint32_t           events;
    epoll_data_t       data;
};


struct signalfd_siginfo {
    uint32_t           ssi_signo;   /* Signal number */
    int32_t            ssi_errno;   /* Error number (unused) */
    int32_t            ssi_code;    /* Signal code */
    uint32_t           ssi_pid;     /* PID of sender */
    uint32_t           ssi_uid;     /* Real UID of sender */
    int32_t            ssi_fd;      /* File descriptor (SIGIO) */
    uint32_t           ssi_tid;     /* Kernel timer ID (POSIX timers) */
    uint32_t           ssi_band;    /* Band event (SIGIO) */
    uint32_t           ssi_overrun; /* POSIX timer overrun count */
    uint32_t           ssi_trapno;  /* Trap number that caused signal */
    int32_t            ssi_status;  /* Exit status or signal (SIGCHLD) */
    int32_t            ssi_int;     /* Integer sent by sigqueue(2) */
    uint64_t           ssi_ptr;     /* Pointer sent by sigqueue(2) */
    uint64_t           ssi_utime;   /* User CPU time consumed (SIGCHLD) */
    uint64_t           ssi_stime;   /* System CPU time consumed (SIGCHLD) */
    uint64_t           ssi_addr;    /* Address that generated signal
                                       (for hardware-generated signals) */
    uint8_t            pad[8];      /* Pad size to 128 bytes (allow for
                                       additional fields in the future) */
};


int epoll_create(int size);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout);

int eventfd(u_int initval, int flags);
int signalfd(int fd, const sigset_t *mask, int flags);

#define SOCK_NONBLOCK  04000

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);

#endif


#if (NXT_TEST_BUILD_EVENTPORT)

#include <poll.h>

#define NXT_HAVE_EVENTPORT  1

#define ushort_t  u_short
#define uint_t    u_int

/* Solaris eventport declarations */

#define PORT_SOURCE_AIO    1
#define PORT_SOURCE_TIMER  2
#define PORT_SOURCE_USER   3
#define PORT_SOURCE_FD     4
#define PORT_SOURCE_ALERT  5
#define PORT_SOURCE_MQ     6
#define PORT_SOURCE_FILE   7

#ifndef ETIME
#define ETIME              62
#endif


typedef struct {
    int                    portev_events;  /* event data is source specific */
    ushort_t               portev_source;  /* event source */
    ushort_t               portev_pad;     /* port internal use */
    uintptr_t              portev_object;  /* source specific object */
    void                   *portev_user;   /* user cookie */
} port_event_t;


typedef struct timespec  timespec_t;
typedef struct timespec  timestruc_t;


typedef struct file_obj {
    timestruc_t            fo_atime;       /* Access time from stat(2) */
    timestruc_t            fo_mtime;       /* Modification time from stat(2) */
    timestruc_t            fo_ctime;       /* Change time from stat(2) */
    uintptr_t              fo_pad[3];      /* For future expansion */
    char                   *fo_name;       /* Null terminated file name */
} file_obj_t;


int port_create(void);
int port_associate(int port, int source, uintptr_t object, int events,
    void *user);
int port_dissociate(int port, int source, uintptr_t object);
int port_send(int port, int events, void *user);
int port_getn(int port, port_event_t list[], uint_t max, uint_t *nget,
    const timespec_t *timeout);

#endif


#if (NXT_TEST_BUILD_DEVPOLL)

#define NXT_HAVE_DEVPOLL  1

#include <poll.h>
#include <sys/ioctl.h>

/* Solaris /dev/poll declarations */

#define POLLREMOVE      0x0800
#define DP_POLL         0xD001
#define DP_ISPOLLED     0xD002


struct dvpoll {
    struct pollfd       *dp_fds;
    int                 dp_nfds;
    int                 dp_timeout;
};

#endif


#if (NXT_TEST_BUILD_POLLSET)

#define NXT_HAVE_POLLSET  1

#include <poll.h>

/* AIX pollset declarations */

#define PS_ADD          0x0
#define PS_MOD          0x1
#define PS_DELETE       0x2


typedef int             pollset_t;

struct poll_ctl {
    short               cmd;
    short               events;
    int                 fd;
};


pollset_t pollset_create(int maxfd);
int pollset_destroy(pollset_t ps);
int pollset_query(pollset_t ps, struct pollfd *pollfd_query);
int pollset_ctl(pollset_t ps, struct poll_ctl *pollctl_array, int array_length);
int pollset_poll(pollset_t ps, struct pollfd *polldata_array, int array_length,
    int timeout);

#endif


#if (NXT_TEST_BUILD_FREEBSD_SENDFILE || NXT_TEST_BUILD_MACOSX_SENDFILE)

#if !(NXT_FREEBSD) && !(NXT_MACOSX)

struct sf_hdtr {
    struct iovec  *headers;
    int           hdr_cnt;
    struct iovec  *trailers;
    int           trl_cnt;
};

#endif

#endif


#if (NXT_TEST_BUILD_SOLARIS_SENDFILEV)

/* Solaris declarations */

typedef struct sendfilevec {
    int     sfv_fd;
    u_int   sfv_flag;
    off_t   sfv_off;
    size_t  sfv_len;
} sendfilevec_t;

#define SFV_FD_SELF  -2

ssize_t sendfilev(int fd, const struct sendfilevec *vec, int sfvcnt,
    size_t *xferred);

#endif


#if (NXT_TEST_BUILD_AIX_SEND_FILE)

#ifndef uint_t
#define uint_t    u_int
#endif

struct sf_parms {
    void      *header_data;
    uint_t    header_length;

    int       file_descriptor;
    uint64_t  file_size;
    uint64_t  file_offset;
    int64_t   file_bytes;

    void      *trailer_data;
    uint_t    trailer_length;

    uint64_t  bytes_sent;
};

#define SF_CLOSE       0x00000001  /* close the socket after completion */
#define SF_REUSE       0x00000002  /* reuse socket. not supported */
#define SF_DONT_CACHE  0x00000004  /* don't apply network buffer cache */
#define SF_SYNC_CACHE  0x00000008  /* sync/update network buffer cache */

ssize_t send_file(int *s, struct sf_parms *sf_iobuf, uint_t flags);

#endif


#endif /* _NXT_UNIX_TEST_BUILD_H_INCLUDED_ */

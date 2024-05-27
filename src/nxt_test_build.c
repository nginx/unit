
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */


#include <nxt_main.h>


#if (NXT_TEST_BUILD_EPOLL)

int
epoll_create(int size)
{
    return -1;
}


int
epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return -1;
}


int
epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout)
{
    return -1;
}

int
eventfd(u_int initval, int flags)
{
    return -1;
}


int
signalfd(int fd, const sigset_t *mask, int flags)
{
    return -1;
}


int
accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    return -1;
}

#endif


#if (NXT_TEST_BUILD_EVENTPORT)

int
port_create(void)
{
    return -1;
}


int
port_associate(int port, int source, uintptr_t object, int events, void *user)
{
    return -1;
}


int
port_dissociate(int port, int source, uintptr_t object)
{
    return -1;
}


int
port_send(int port, int events, void *user)
{
    return -1;
}


int port_getn(int port, port_event_t list[], uint_t max, uint_t *nget,
    const timespec_t *timeout)
{
    return -1;
}

#endif


#if (NXT_TEST_BUILD_POLLSET)

pollset_t
pollset_create(int maxfd)
{
    return -1;
}


int
pollset_destroy(pollset_t ps)
{
    return -1;
}


int
pollset_query(pollset_t ps, struct pollfd *pollfd_query)
{
    return -1;
}


int
pollset_ctl(pollset_t ps, struct poll_ctl *pollctl_array, int array_length)
{
    return -1;
}


int
pollset_poll(pollset_t ps, struct pollfd *polldata_array, int array_length,
    int timeout)
{
    return -1;
}

#endif


#if (NXT_TEST_BUILD_SOLARIS_SENDFILEV)

ssize_t sendfilev(int fd, const struct sendfilevec *vec,
    int sfvcnt, size_t *xferred)
{
    return -1;
}

#endif


#if (NXT_TEST_BUILD_AIX_SEND_FILE)

ssize_t send_file(int *s, struct sf_parms *sf_iobuf, uint_t flags)
{
    return -1;
}

#endif

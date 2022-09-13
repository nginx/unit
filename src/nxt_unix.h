
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */


#ifndef _NXT_UNIX_H_INCLUDED_
#define _NXT_UNIX_H_INCLUDED_


#if (NXT_LINUX)

#ifdef _FORTIFY_SOURCE
/*
 * _FORTIFY_SOURCE
 *     may call sigaltstack() while _longjmp() checking;
 *     may cause _longjmp() to fail with message:
 *         "longjmp() causes uninitialized stack frame";
 *     does not allow to use "(void) write()";
 *     does surplus checks.
 */
#undef _FORTIFY_SOURCE
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE                 /* pread(), pwrite(), gethostname(). */
#endif

#define _FILE_OFFSET_BITS  64

#include <malloc.h>                 /* malloc_usable_size(). */
#include <sys/syscall.h>            /* syscall(SYS_gettid). */

#if (__GLIBC__ >= 2 && __GLIBC_MINOR__ >= 4)
/*
 * POSIX semaphores using NPTL atomic/futex operations
 * were introduced during glibc 2.3 development time.
 */
#define NXT_HAVE_SEM_TRYWAIT_FAST  1
#endif

#endif /* NXT_LINUX */


#if (NXT_FREEBSD)

#if (NXT_HAVE_MALLOC_USABLE_SIZE)
#include <malloc_np.h>              /* malloc_usable_size(). */
#endif

#if (__FreeBSD_version >= 900007)
/* POSIX semaphores using atomic/umtx. */
#define NXT_HAVE_SEM_TRYWAIT_FAST  1
#endif

#endif /* NXT_FREEBSD */


#if (NXT_SOLARIS)

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS  64       /* Must be before <sys/types.h>. */
#endif

#ifndef _REENTRANT                  /* May be set by "-mt" options. */
#define _REENTRANT                  /* Thread safe errno. */
#endif

#ifndef _POSIX_PTHREAD_SEMANTICS
#define _POSIX_PTHREAD_SEMANTICS    /* 2 arguments in sigwait(). */
#endif

/*
 * Solaris provides two sockets API:
 *
 * 1) 4.3BSD sockets (int instead of socklen_t in accept(), etc.;
 *    struct msghdr.msg_accrights) in libsocket;
 * 2) X/Open sockets (socklen_t, struct msghdr.msg_control) with __xnet_
 *    function name prefix in libxnet and libsocket.
 */

/* Enable X/Open sockets API. */
#define _XOPEN_SOURCE
#define _XOPEN_SOURCE_EXTENDED  1
/* Enable Solaris extensions disabled by _XOPEN_SOURCE. */
#ifndef __EXTENSIONS__
#define __EXTENSIONS__
#endif

#endif /* NXT_SOLARIS */


#if (NXT_MACOSX)

#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE            /* pthread_threadid_np(), mach_port_t. */
#endif

#include <mach/mach_time.h>         /* mach_absolute_time(). */
#include <malloc/malloc.h>          /* malloc_size(). */

#endif /* NXT_MACOSX */


#if (NXT_AIX)

#define _THREAD_SAFE                /* Must before any include. */

#endif /* NXT_AIX */


#if (NXT_HPUX)

#define _FILE_OFFSET_BITS  64

/*
 * HP-UX provides three sockets API:
 *
 * 1) 4.3BSD sockets (int instead of socklen_t in accept(), etc.;
 *    struct msghdr.msg_accrights) in libc;
 * 2) X/Open sockets (socklen_t, struct msghdr.msg_control) with _xpg_
 *    function name prefix in libc;
 * 3) and X/Open sockets (socklen_t, struct msghdr.msg_control) in libxnet.
 */

/* Enable X/Open sockets API. */
#define _XOPEN_SOURCE
#define _XOPEN_SOURCE_EXTENDED
/* Enable static function wrappers for _xpg_ X/Open sockets API in libc. */
#define _HPUX_ALT_XOPEN_SOCKET_API

#include <sys/mpctl.h>

#if (NXT_HAVE_HG_GETHRTIME)
#include <sys/mercury.h>
#endif

#endif /* NXT_HPUX */


#if (NXT_HAVE_ALLOCA_H)
#include <alloca.h>
#endif
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pwd.h>
#include <semaphore.h>
#include <setjmp.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stddef.h>                 /* offsetof() */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#if (NXT_HAVE_SYS_FILIO_H)
#include <sys/filio.h>              /* FIONBIO */
#endif
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>              /* MAXPATHLEN */
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#if (NXT_HAVE_UNIX_DOMAIN)
#include <sys/un.h>
#endif
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#if (NXT_HAVE_EPOLL)
#include <sys/epoll.h>

#ifdef EPOLLRDHUP
/*
 * Epoll edge-tiggered mode is pretty much useless without EPOLLRDHUP support.
 */
#define NXT_HAVE_EPOLL_EDGE  1
#endif

#endif

#if (NXT_HAVE_SIGNALFD)
#include <sys/signalfd.h>
#endif

#if (NXT_HAVE_EVENTFD)
#include <sys/eventfd.h>
#endif

#if (NXT_HAVE_KQUEUE)
#include <sys/event.h>
#endif

#if (NXT_HAVE_EVENTPORT)
#include <port.h>
#endif

#if (NXT_HAVE_DEVPOLL)
#include <sys/devpoll.h>
#endif

#if (NXT_HAVE_POLLSET)
#include <sys/pollset.h>
#endif

#if (NXT_HAVE_LINUX_SENDFILE)
#include <sys/sendfile.h>
#endif

#if (NXT_HAVE_SOLARIS_SENDFILEV)
#include <sys/sendfile.h>
#endif

#if (NXT_HAVE_GETRANDOM)
#include <sys/random.h>             /* getrandom(). */
#elif (NXT_HAVE_LINUX_SYS_GETRANDOM)
#include <linux/random.h>           /* SYS_getrandom. */
#elif (NXT_HAVE_GETENTROPY_SYS_RANDOM)
#include <sys/random.h>             /* getentropy(). */
#endif

#if (NXT_HAVE_ISOLATION_ROOTFS)
#include <sys/mount.h>
#endif

#if (NXT_HAVE_OPENAT2)
#include <linux/openat2.h>
#endif

#if (NXT_TEST_BUILD)
#include <nxt_test_build.h>
#endif


/*
 * On Linux IOV_MAX is 1024.  Linux uses kernel stack for 8 iovec's
 * to avoid kernel allocation/deallocation.
 *
 * On FreeBSD IOV_MAX is 1024.  FreeBSD used kernel stack for 8 iovec's
 * to avoid kernel allocation/deallocation until FreeBSD 5.2.
 * FreeBSD 5.2 and later do not use stack at all.
 *
 * On Solaris IOV_MAX is 16 and Solaris uses only kernel stack.
 *
 * On MacOSX IOV_MAX is 1024.  MacOSX used kernel stack for 8 iovec's
 * to avoid kernel allocation/deallocation until MacOSX 10.4 (Tiger).
 * MacOSX 10.4 and later do not use stack at all.
 *
 * On NetBSD, OpenBSD, and DragonFlyBSD IOV_MAX is 1024.  All these OSes
 * uses kernel stack for 8 iovec's to avoid kernel allocation/deallocation.
 *
 * On AIX and HP-UX IOV_MAX is 16.
 */
#define NXT_IOBUF_MAX  8


typedef struct iovec   nxt_iobuf_t;

#define nxt_iobuf_data(iob)                                                   \
    (iob)->iov_base

#define nxt_iobuf_size(iob)                                                   \
    (iob)->iov_len

#define nxt_iobuf_set(iob, p, size)                                           \
    do {                                                                      \
        (iob)->iov_base = (void *) p;                                         \
        (iob)->iov_len = size;                                                \
    } while (0)

#define nxt_iobuf_add(iob, size)                                              \
    (iob)->iov_len += size


#endif /* _NXT_UNIX_H_INCLUDED_ */

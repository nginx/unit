
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIX_THREAD_ID_H_INCLUDED_
#define _NXT_UNIX_THREAD_ID_H_INCLUDED_


#if (NXT_LINUX)

typedef pid_t      nxt_tid_t;

#elif (NXT_FREEBSD)

typedef uint32_t   nxt_tid_t;

#elif (NXT_SOLARIS)

typedef pthread_t  nxt_tid_t;

#elif (NXT_MACOSX)

typedef uint64_t   nxt_tid_t;

#elif (NXT_AIX)

typedef tid_t      nxt_tid_t;

#elif (NXT_HPUX)

typedef pthread_t  nxt_tid_t;

#else

typedef pthread_t  nxt_tid_t;

#endif


NXT_EXPORT nxt_tid_t nxt_thread_tid(nxt_thread_t *thr);


/*
 * On Linux pthread_t is unsigned long integer.
 * On FreeBSD, MacOSX, NetBSD, and OpenBSD pthread_t is pointer to a struct.
 * On Solaris and AIX pthread_t is unsigned integer.
 * On HP-UX pthread_t is int.
 * On Cygwin pthread_t is pointer to void.
 * On z/OS pthread_t is "struct { char __[0x08]; }".
 */
typedef pthread_t  nxt_thread_handle_t;


#define                                                                       \
nxt_thread_handle_clear(th)                                                   \
    th = (pthread_t) 0

#define                                                                       \
nxt_thread_handle_equal(th0, th1)                                             \
    pthread_equal(th0, th1)


#endif /* _NXT_UNIX_THREAD_ID_H_INCLUDED_ */

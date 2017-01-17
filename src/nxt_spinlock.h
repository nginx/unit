
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIX_SPINLOCK_H_INCLUDED_
#define _NXT_UNIX_SPINLOCK_H_INCLUDED_


#if (NXT_THREADS)

#if (NXT_HAVE_MACOSX_SPINLOCK)

#include <libkern/OSAtomic.h>

typedef OSSpinLock    nxt_thread_spinlock_t;

#define                                                                       \
nxt_thread_spin_init(ncpu, count)

#else

typedef nxt_atomic_t  nxt_thread_spinlock_t;

NXT_EXPORT void nxt_thread_spin_init(nxt_uint_t ncpu, nxt_uint_t count);

#endif


NXT_EXPORT void nxt_thread_spin_lock(nxt_thread_spinlock_t *lock);
NXT_EXPORT nxt_bool_t nxt_thread_spin_trylock(nxt_thread_spinlock_t *lock);
NXT_EXPORT void nxt_thread_spin_unlock(nxt_thread_spinlock_t *lock);


#else /* !(NXT_THREADS) */


typedef nxt_atomic_t  nxt_thread_spinlock_t;

#define                                                                       \
nxt_thread_spin_init(ncpu, count)

#define                                                                       \
nxt_thread_spin_lock(lock)

#define                                                                       \
nxt_thread_spin_trylock(lock)                                                 \
    1

#define                                                                       \
nxt_thread_spin_unlock(lock)

#endif


#endif /* _NXT_UNIX_SPINLOCK_H_INCLUDED_ */

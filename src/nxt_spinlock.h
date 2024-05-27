
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIX_SPINLOCK_H_INCLUDED_
#define _NXT_UNIX_SPINLOCK_H_INCLUDED_


typedef nxt_atomic_t  nxt_thread_spinlock_t;

NXT_EXPORT void nxt_thread_spin_init(nxt_uint_t ncpu, nxt_uint_t count);
NXT_EXPORT void nxt_thread_spin_lock(nxt_thread_spinlock_t *lock);
NXT_EXPORT nxt_bool_t nxt_thread_spin_trylock(nxt_thread_spinlock_t *lock);
NXT_EXPORT void nxt_thread_spin_unlock(nxt_thread_spinlock_t *lock);


#endif /* _NXT_UNIX_SPINLOCK_H_INCLUDED_ */

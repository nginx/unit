
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_ATOMIC_H_INCLUDED_
#define _NXT_ATOMIC_H_INCLUDED_


/*
 * nxt_atomic_try_lock() must set an acquire barrier on lock.
 * nxt_atomic_xchg() must set an acquire barrier.
 * nxt_atomic_release() must set a release barrier.
 */

#if (NXT_HAVE_GCC_ATOMIC) /* GCC 4.1 builtin atomic operations */

typedef intptr_t                    nxt_atomic_int_t;
typedef uintptr_t                   nxt_atomic_uint_t;
typedef volatile nxt_atomic_uint_t  nxt_atomic_t;

/*
 * __sync_bool_compare_and_swap() is a full barrier.
 * __sync_lock_test_and_set() is an acquire barrier.
 * __sync_lock_release() is a release barrier.
 */

#define nxt_atomic_cmp_set(lock, cmp, set)                                    \
    __sync_bool_compare_and_swap(lock, cmp, set)


#define nxt_atomic_xchg(lock, set)                                            \
    __sync_lock_test_and_set(lock, set)


#define nxt_atomic_fetch_add(value, add)                                      \
    __sync_fetch_and_add(value, add)


#define nxt_atomic_try_lock(lock)                                             \
    nxt_atomic_cmp_set(lock, 0, 1)


#define nxt_atomic_release(lock)                                              \
    __sync_lock_release(lock)


#define nxt_atomic_or_fetch(ptr, val)                                         \
    __sync_or_and_fetch(ptr, val)


#define nxt_atomic_and_fetch(ptr, val)                                        \
    __sync_and_and_fetch(ptr, val)


#if (__i386__ || __i386 || __amd64__ || __amd64)
#define nxt_cpu_pause()                                                       \
    __asm__ ("pause")

#elif (__aarch64__ || __arm64__)
#define nxt_cpu_pause()                                                       \
    __asm__ ("isb")

#else
#define nxt_cpu_pause()
#endif


/* elif (NXT_HAVE_MACOSX_ATOMIC) */

/*
 * The atomic(3) interface has been introduced in MacOS 10.4 (Tiger) and
 * extended in 10.5 (Leopard).  However its support is omitted because:
 *
 * 1) the interface is still incomplete:
 *    *) there are OSAtomicAdd32Barrier() and OSAtomicAdd64Barrier()
 *       but no OSAtomicAddLongBarrier();
 *    *) there is no interface for XCHG operation.
 *
 * 2) the interface is tuned for non-SMP systems due to omission of the
 *    LOCK prefix on single CPU system but nowadays MacOSX systems are at
 *    least dual core.  Thus these indirect calls just add overhead as
 *    compared with inlined atomic operations which are supported by GCC
 *    and Clang in modern MacOSX systems.
 */


#endif /* NXT_HAVE_GCC_ATOMIC */


#endif /* _NXT_ATOMIC_H_INCLUDED_ */

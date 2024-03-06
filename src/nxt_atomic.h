
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


#elif (NXT_HAVE_SOLARIS_ATOMIC) /* Solaris 10 */

#include <atomic.h>

typedef long                        nxt_atomic_int_t;
typedef ulong_t                     nxt_atomic_uint_t;
typedef volatile nxt_atomic_uint_t  nxt_atomic_t;


#define nxt_atomic_cmp_set(lock, cmp, set)                                    \
    (atomic_cas_ulong(lock, cmp, set) == (ulong_t) cmp)


#define nxt_atomic_xchg(lock, set)                                            \
    atomic_add_swap(lock, set)


#define nxt_atomic_fetch_add(value, add)                                      \
    (atomic_add_long_nv(value, add) - add)


#define nxt_atomic_or_fetch(ptr, val)                                         \
    atomic_or_ulong_nv(ptr, val)


#define nxt_atomic_and_fetch(ptr, val)                                        \
    atomic_and_ulong_nv(ptr, val)


/*
 * Solaris uses SPARC Total Store Order model.  In this model:
 * 1) Each atomic load-store instruction behaves as if it were followed by
 *    #LoadLoad, #LoadStore, and #StoreStore barriers.
 * 2) Each load instruction behaves as if it were followed by
 *    #LoadLoad and #LoadStore barriers.
 * 3) Each store instruction behaves as if it were followed by
 *    #StoreStore barrier.
 *
 * In X86_64 atomic instructions set a full barrier and usual instructions
 * set implicit #LoadLoad, #LoadStore, and #StoreStore barriers.
 *
 * An acquire barrier requires at least #LoadLoad and #LoadStore barriers
 * and they are provided by atomic load-store instruction.
 *
 * A release barrier requires at least #LoadStore and #StoreStore barriers,
 * so a lock release does not require an explicit barrier: all load
 * instructions in critical section is followed by implicit #LoadStore
 * barrier and all store instructions are followed by implicit #StoreStore
 * barrier.
 */

#define nxt_atomic_try_lock(lock)                                             \
    nxt_atomic_cmp_set(lock, 0, 1)


#define nxt_atomic_release(lock)                                              \
    *lock = 0;


/*
 * The "rep; nop" is used instead of "pause" to omit the "[ PAUSE ]" hardware
 * capability added by linker since Solaris ld.so.1 does not know about it:
 *
 *   ld.so.1: ...: fatal: hardware capability unsupported: 0x2000 [ PAUSE ]
 */

#if (__i386__ || __i386 || __amd64__ || __amd64)
#define nxt_cpu_pause()                                                       \
    __asm__ ("rep; nop")

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

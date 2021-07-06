
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

#define                                                                       \
nxt_atomic_cmp_set(lock, cmp, set)                                            \
    __sync_bool_compare_and_swap(lock, cmp, set)


#define                                                                       \
nxt_atomic_xchg(lock, set)                                                    \
    __sync_lock_test_and_set(lock, set)


#define                                                                       \
nxt_atomic_fetch_add(value, add)                                              \
    __sync_fetch_and_add(value, add)


#define                                                                       \
nxt_atomic_try_lock(lock)                                                     \
    nxt_atomic_cmp_set(lock, 0, 1)


#define                                                                       \
nxt_atomic_release(lock)                                                      \
    __sync_lock_release(lock)


#define nxt_atomic_or_fetch(ptr, val)                                         \
    __sync_or_and_fetch(ptr, val)


#define nxt_atomic_and_fetch(ptr, val)                                        \
    __sync_and_and_fetch(ptr, val)


#if (__i386__ || __i386 || __amd64__ || __amd64)
#define                                                                       \
nxt_cpu_pause()                                                               \
    __asm__ ("pause")

#elif __aarch64__
#define                                                                       \
nxt_cpu_pause()                                                               \
   __asm__ ("yield")

#else
#define                                                                       \
nxt_cpu_pause()
#endif


#elif (NXT_HAVE_SOLARIS_ATOMIC) /* Solaris 10 */

#include <atomic.h>

typedef long                        nxt_atomic_int_t;
typedef ulong_t                     nxt_atomic_uint_t;
typedef volatile nxt_atomic_uint_t  nxt_atomic_t;


#define                                                                       \
nxt_atomic_cmp_set(lock, cmp, set)                                            \
    (atomic_cas_ulong(lock, cmp, set) == (ulong_t) cmp)


#define                                                                       \
nxt_atomic_xchg(lock, set)                                                    \
    atomic_add_swap(lock, set)


#define                                                                       \
nxt_atomic_fetch_add(value, add)                                              \
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

#define                                                                       \
nxt_atomic_try_lock(lock)                                                     \
    nxt_atomic_cmp_set(lock, 0, 1)


#define                                                                       \
nxt_atomic_release(lock)                                                      \
    *lock = 0;


/*
 * The "rep; nop" is used instead of "pause" to omit the "[ PAUSE ]" hardware
 * capability added by linker since Solaris ld.so.1 does not know about it:
 *
 *   ld.so.1: ...: fatal: hardware capability unsupported: 0x2000 [ PAUSE ]
 */

#if (__i386__ || __i386 || __amd64__ || __amd64)
#define                                                                       \
nxt_cpu_pause()                                                               \
    __asm__ ("rep; nop")

#else
#define                                                                       \
nxt_cpu_pause()
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


#elif (NXT_HAVE_XLC_ATOMIC) /* XL C/C++ V8.0 for AIX */

#if (NXT_64BIT)

typedef long                        nxt_atomic_int_t;
typedef unsigned long               nxt_atomic_uint_t;
typedef volatile nxt_atomic_int_t   nxt_atomic_t;


nxt_inline nxt_bool_t
nxt_atomic_cmp_set(nxt_atomic_t *lock, nxt_atomic_int_t cmp,
    nxt_atomic_int_t set)
{
    nxt_atomic_int_t  old;

    old = cmp;

    return __compare_and_swaplp(lock, &old, set);
}


#define                                                                       \
nxt_atomic_xchg(lock, set)                                                    \
    __fetch_and_swaplp(lock, set)


#define                                                                       \
nxt_atomic_fetch_add(value, add)                                              \
    __fetch_and_addlp(value, add)


#else /* NXT_32BIT */

typedef int                         nxt_atomic_int_t;
typedef unsigned int                nxt_atomic_uint_t;
typedef volatile nxt_atomic_int_t   nxt_atomic_t;


nxt_inline nxt_bool_t
nxt_atomic_cmp_set(nxt_atomic_t *lock, nxt_atomic_int_t cmp,
    nxt_atomic_int_t set)
{
    nxt_atomic_int_t  old;

    old = cmp;

    return __compare_and_swap(lock, &old, set);
}


#define                                                                       \
nxt_atomic_xchg(lock, set)                                                    \
    __fetch_and_swap(lock, set)


#define                                                                       \
nxt_atomic_fetch_add(value, add)                                              \
    __fetch_and_add(value, add)


#endif /* NXT_32BIT*/


/*
 * __lwsync() is a "lwsync" instruction that sets #LoadLoad, #LoadStore,
 * and #StoreStore barrier.
 *
 * __compare_and_swap() is a pair of "ldarx" and "stdcx" instructions.
 * A "lwsync" does not set #StoreLoad barrier so it can not be used after
 * this pair since a next load inside critical section can be performed
 * after the "ldarx" instruction but before the "stdcx" instruction.
 * However, this next load instruction will load correct data because
 * otherwise the "ldarx/stdcx" pair will fail and this data will be
 * discarded.  Nevertheless, the "isync" instruction is used for sure.
 *
 * A full barrier can be set with __sync(), a "sync" instruction, but there
 * is also a faster __isync(), an "isync" instruction.  This instruction is
 * not a memory barrier but an instruction barrier.  An "isync" instruction
 * causes the processor to complete execution of all previous instructions
 * and then to discard instructions (which may have begun execution) following
 * the "isync".  After the "isync" is executed, the following instructions
 * then begin execution.  The "isync" is used to ensure that the loads
 * following entry into a critical section are not performed (because of
 * aggressive out-of-order or speculative execution in the processor) until
 * the lock is granted.
 */

nxt_inline nxt_bool_t
nxt_atomic_try_lock(nxt_atomic_t *lock)
{
    if (nxt_atomic_cmp_set(lock, 0, 1)) {
        __isync();
        return 1;
    }

    return 0;
}


#define                                                                       \
nxt_atomic_release(lock)                                                      \
    do { __lwsync(); *lock = 0; } while (0)


#define                                                                       \
nxt_cpu_pause()


#endif /* NXT_HAVE_XLC_ATOMIC */


#endif /* _NXT_ATOMIC_H_INCLUDED_ */

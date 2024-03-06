
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_TYPES_H_INCLUDED_
#define _NXT_TYPES_H_INCLUDED_


/*
 * nxt_int_t corresponds to the most efficient integer type,
 * an architecture word.  It is usually the long type,
 * but on Win64 the long is int32_t, so pointer size suits better.
 * nxt_int_t must be no less than int32_t.
 */

#if (__amd64__)
/*
 * AMD64 64-bit multiplication and division operations
 * are slower and 64-bit instructions are longer.
 */
#define NXT_INT_T_SIZE       4
typedef int                  nxt_int_t;
typedef u_int                nxt_uint_t;

#else
#define NXT_INT_T_SIZE       NXT_PTR_SIZE
typedef intptr_t             nxt_int_t;
typedef uintptr_t            nxt_uint_t;
#endif


typedef nxt_uint_t           nxt_bool_t;


/*
 * nxt_off_t corresponds to OS's off_t, a file offset type.
 * Although Linux, Solaris, and HP-UX define both off_t and off64_t,
 * setting _FILE_OFFSET_BITS to 64 defines off_t as off64_t.
 */
typedef off_t                nxt_off_t;


/*
 * nxt_time_t corresponds to OS's time_t, time in seconds.  nxt_time_t is
 * a signed integer.  OS's time_t may be an integer or real-floating type,
 * though it is usually a signed 32-bit or 64-bit integer depending on
 * platform bit count.  There are however exceptions, e.g., time_t is:
 *   32-bit on 64-bit NetBSD prior to 6.0 version;
 *   64-bit on 32-bit NetBSD 6.0;
 *   32-bit on 64-bit OpenBSD;
 *   64-bit in Linux x32 ABI;
 */
#if (NXT_QNX)
/*
 * QNX defines time_t as uint32_t.
 * Y2038 fix: "typedef int64_t  nxt_time_t".
 */
typedef int32_t              nxt_time_t;

#else
/* Y2038, if time_t is 32-bit integer. */
typedef time_t               nxt_time_t;
#endif


#if (NXT_PTR_SIZE == 8)
#define NXT_64BIT            1
#define NXT_32BIT            0

#else
#define NXT_64BIT            0
#define NXT_32BIT            1
#endif


#define NXT_INT64_T_LEN      nxt_length("-9223372036854775808")
#define NXT_INT32_T_LEN      nxt_length("-2147483648")

#define NXT_INT64_T_HEXLEN   nxt_length("FFFFFFFFFFFFFFFF")
#define NXT_INT32_T_HEXLEN   nxt_length("FFFFFFFF")

#define NXT_INT64_T_MAX      0x7FFFFFFFFFFFFFFFLL
#define NXT_INT32_T_MAX      0x7FFFFFFF


#if (NXT_INT_T_SIZE == 8)
#define NXT_INT_T_LEN        NXT_INT64_T_LEN
#define NXT_INT_T_HEXLEN     NXT_INT64_T_HEXLEN
#define NXT_INT_T_MAX        NXT_INT64_T_MAX

#else
#define NXT_INT_T_LEN        NXT_INT32_T_LEN
#define NXT_INT_T_HEXLEN     NXT_INT32_T_HEXLEN
#define NXT_INT_T_MAX        NXT_INT32_T_MAX
#endif


#if (NXT_64BIT)
#define NXT_ATOMIC_T_LEN     NXT_INT64_T_LEN
#define NXT_ATOMIC_T_HEXLEN  NXT_INT64_T_HEXLEN
#define NXT_ATOMIC_T_MAX     NXT_INT64_T_MAX

#else
#define NXT_ATOMIC_T_LEN     NXT_INT32_T_LEN
#define NXT_ATOMIC_T_HEXLEN  NXT_INT32_T_HEXLEN
#define NXT_ATOMIC_T_MAX     NXT_INT32_T_MAX
#endif


#if (NXT_OFF_T_SIZE == 8)
typedef uint64_t             nxt_uoff_t;
#define NXT_OFF_T_LEN        NXT_INT64_T_LEN
#define NXT_OFF_T_HEXLEN     NXT_INT64_T_HEXLEN
#define NXT_OFF_T_MAX        NXT_INT64_T_MAX

#else
typedef uint32_t             nxt_uoff_t;
#define NXT_OFF_T_LEN        NXT_INT32_T_LEN
#define NXT_OFF_T_HEXLEN     NXT_INT32_T_HEXLEN
#define NXT_OFF_T_MAX        NXT_INT32_T_MAX
#endif


#if (NXT_SIZE_T_SIZE == 8)
#define NXT_SIZE_T_LEN       NXT_INT64_T_LEN
#define NXT_SIZE_T_HEXLEN    NXT_INT64_T_HEXLEN
#define NXT_SIZE_T_MAX       NXT_INT64_T_MAX

#else
#define NXT_SIZE_T_LEN       NXT_INT32_T_LEN
#define NXT_SIZE_T_HEXLEN    NXT_INT32_T_HEXLEN
#define NXT_SIZE_T_MAX       NXT_INT32_T_MAX
#endif


#if (NXT_TIME_T_SIZE == 8)
#define NXT_TIME_T_LEN       NXT_INT64_T_LEN
#define NXT_TIME_T_HEXLEN    NXT_INT64_T_HEXLEN
#define NXT_TIME_T_MAX       NXT_INT64_T_MAX

#else
#define NXT_TIME_T_LEN       NXT_INT32_T_LEN
#define NXT_TIME_T_HEXLEN    NXT_INT32_T_HEXLEN
#define NXT_TIME_T_MAX       NXT_INT32_T_MAX
#endif


#endif /* _NXT_TYPES_H_INCLUDED_ */

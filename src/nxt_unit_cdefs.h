/*
 * Copyright (C) 2019-2023, Alejandro Colomar <alx@kernel.org>
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIT_CDEFS_H_INCLUDED_
#define _NXT_UNIT_CDEFS_H_INCLUDED_


#include <stddef.h>


#define nxt_max(a, b)            (((a) > (b)) ? (a) : (b))
#define nxt_min(a, b)            (((a) < (b)) ? (a) : (b))


#define nxt_swap(ap, bp)                                                      \
    do {                                                                      \
        __auto_type   ap_ = (ap);                                             \
        __auto_type   bp_ = (bp);                                             \
        typeof(*ap_)  tmp_;                                                   \
                                                                              \
        _Static_assert(nxt_is_same_typeof(ap_, bp_), "");                     \
                                                                              \
        tmp_ = *ap_;                                                          \
        *ap_ = *bp_;                                                          \
        *bp_ = tmp_;                                                          \
    } while (0)


#define nxt_sizeof_array(a)      (sizeof(a) + nxt_must_be_array(a))
#define nxt_nitems(a)            (nxt_sizeof_array(a) / sizeof((a)[0]))
#define nxt_memberof(T, member)  ((T){}.member)

#define nxt_sizeof_incomplete(x)                                              \
    (                                                                         \
        sizeof(                                                               \
            struct {                                                          \
                max_align_t  a;                                               \
                typeof(x)    inc;                                             \
            }                                                                 \
        )                                                                     \
        - sizeof(max_align_t)                                                 \
    )

#define nxt_sizeof_fam0(T, fam)                                               \
    (sizeof(nxt_memberof(T, fam[0])) + nxt_must_be_fam(T, fam))

#define nxt_sizeof_fam(T, fam, n)                                             \
    (nxt_sizeof_fam0(T, fam) * (n))

#define nxt_offsetof_fam(T, fam, n)                                           \
    (offsetof(T, fam) + nxt_sizeof_fam(T, fam, n))

#define nxt_sizeof_struct(T, fam, n)                                          \
    nxt_max(sizeof(T), nxt_offsetof_fam(T, fam, n))


#define nxt_is_near_end(T, m)     (offsetof(T, m) > (sizeof(T) - _Alignof(T)))
#define nxt_is_zero_sizeof(z)     (nxt_sizeof_incomplete(z) == 0)
#define nxt_is_same_type(a, b)    __builtin_types_compatible_p(a, b)
#define nxt_is_same_typeof(a, b)  nxt_is_same_type(typeof(a), typeof(b))
#define nxt_is_array(a)           (!nxt_is_same_typeof(a, &(a)[0]))


#define nxt_must_be(e)                                                        \
    (                                                                         \
        0 * (int) sizeof(                                                     \
            struct {                                                          \
                _Static_assert(e, "");                                        \
                int ISO_C_forbids_a_struct_with_no_members_;                  \
            }                                                                 \
        )                                                                     \
    )


#define nxt_must_be_array(a)        nxt_must_be(nxt_is_array(a))
#define nxt_must_be_zero_sizeof(z)  nxt_must_be(nxt_is_zero_sizeof(z))
#define nxt_must_be_near_end(T, m)  nxt_must_be(nxt_is_near_end(T, m))

#define nxt_must_be_fam(T, fam)                                               \
    (nxt_must_be_array(nxt_memberof(T, fam))                                  \
     + nxt_must_be_zero_sizeof(nxt_memberof(T, fam))                          \
     + nxt_must_be_near_end(T, fam))


#endif /* _NXT_UNIT_CDEFS_H_INCLUDED_ */

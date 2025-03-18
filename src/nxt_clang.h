
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_CLANG_H_INCLUDED_
#define _NXT_CLANG_H_INCLUDED_


#define nxt_inline     static inline __attribute__((always_inline))
#define nxt_noinline   __attribute__((noinline))
#define nxt_cdecl


#if (NXT_CLANG)

/* Any __asm__ directive disables loop vectorization in GCC and Clang. */
#define nxt_pragma_loop_disable_vectorization                                 \
    __asm__("")

#else

#define nxt_pragma_loop_disable_vectorization

#endif


#if (NXT_HAVE_BUILTIN_EXPECT)

#define nxt_expect(c, x)                                                      \
    __builtin_expect((long) (x), (c))

#define nxt_fast_path(x)                                                      \
    nxt_expect(1, x)

#define nxt_slow_path(x)                                                      \
    nxt_expect(0, x)


#else

#define nxt_expect(c, x)                                                      \
    (x)

#define nxt_fast_path(x)                                                      \
    (x)

#define nxt_slow_path(x)                                                      \
    (x)

#endif


#if (NXT_HAVE_BUILTIN_UNREACHABLE)

#define nxt_unreachable()                                                     \
    __builtin_unreachable()

#else

#define nxt_unreachable()

#endif


#if (NXT_HAVE_BUILTIN_PREFETCH)

#define nxt_prefetch(a)                                                       \
    __builtin_prefetch(a)

#else

#define nxt_prefetch(a)

#endif


#if (NXT_HAVE_GCC_ATTRIBUTE_VISIBILITY)

#define NXT_EXPORT         __attribute__((visibility("default")))

#else

#define NXT_EXPORT

#endif


#if (NXT_HAVE_GCC_ATTRIBUTE_MALLOC)

#define NXT_MALLOC_LIKE    __attribute__((__malloc__))

#else

#define NXT_MALLOC_LIKE

#endif


#if (NXT_HAVE_GCC_ATTRIBUTE_ALIGNED)

#define nxt_aligned(x)     __attribute__((aligned(x)))

#else

#define nxt_aligned(x)

#endif


#if (NXT_HAVE_GCC_ATTRIBUTE_PACKED)

#define nxt_packed         __attribute__((__packed__))

#else

#define nxt_packed

#endif


#if (NXT_HAVE_GCC_ATTRIBUTE_UNUSED)

#define NXT_MAYBE_UNUSED         __attribute__((__unused__))

#else

#define NXT_MAYBE_UNUSED

#endif


#if (NXT_HAVE_GCC_ATTRIBUTE_NONSTRING)

#define NXT_NONSTRING      __attribute__((__nonstring__))

#else

#define NXT_NONSTRING

#endif


#if (NXT_HAVE_BUILTIN_POPCOUNT)

#define nxt_popcount       __builtin_popcount

#else

nxt_inline int
nxt_popcount(unsigned int x)
{
    int  count;

    for (count = 0; x != 0; count++) {
        x &= x - 1;
    }

    return count;
}

#endif


#ifndef NXT_ALIGNMENT

#if (NXT_SOLARIS)
#define NXT_ALIGNMENT      _POINTER_ALIGNMENT     /* x86_64: 8,   i386: 4    */
                                                  /* sparcv9: 8,  sparcv8: 4 */
#elif (__i386__ || __i386)
#define NXT_ALIGNMENT      4

#elif (__arm__)
#define NXT_ALIGNMENT      8         /* 32-bit ARM may use 64-bit load/store */

#elif (__ia64__)
#define NXT_ALIGNMENT      8         /* long long */

#else
#define NXT_ALIGNMENT      NXT_PTR_SIZE
#endif

#endif


#ifndef NXT_MAX_ALIGNMENT

#if (NXT_SOLARIS)
#define NXT_MAX_ALIGNMENT  _MAX_ALIGNMENT        /* x86_64: 16,   i386: 4    */
                                                 /* sparcv9: 16,  sparcv8: 8 */
#elif (__i386__ || __i386)
#define NXT_MAX_ALIGNMENT  4

#elif (__arm__)
#define NXT_MAX_ALIGNMENT  16

#elif (__ia64__)
#define NXT_MAX_ALIGNMENT  16

#else
#define NXT_MAX_ALIGNMENT  16
#endif

#endif


#define nxt_alloca(size)                                                      \
    alloca(size)


#define nxt_container_of(p, type, field)                                      \
    (type *) ((u_char *) (p) - offsetof(type, field))


#define nxt_pointer_to(p, offset)                                             \
    ((void *) ((char *) (p) + (offset)))


#define nxt_value_at(type, p, offset)                                         \
    *(type *) ((u_char *) p + offset)


#define nxt_nitems(x)                                                         \
    (sizeof(x) / sizeof((x)[0]))


/* GCC and Clang use __builtin_abs() instead of libc abs(). */

#define nxt_abs(val)                                                          \
    abs(val)


#define nxt_max(val1, val2)                                                   \
    ((val1 < val2) ? (val2) : (val1))


#define nxt_min(val1, val2)                                                   \
    ((val1 > val2) ? (val2) : (val1))


#define nxt_bswap32(val)                                                      \
    (   ((val)               >> 24)                                           \
     | (((val) & 0x00FF0000) >>  8)                                           \
     | (((val) & 0x0000FF00) <<  8)                                           \
     |  ((val)               << 24))


#define nxt_is_power_of_two(value)                                            \
    ((((value) - 1) & (value)) == 0)


#define nxt_align_size(d, a)                                                  \
    (((d) + ((size_t) (a) - 1)) & ~((size_t) (a) - 1))


#define nxt_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) (a) - 1))                     \
                  & ~((uintptr_t) (a) - 1))

#define nxt_trunc_ptr(p, a)                                                   \
    (u_char *) ((uintptr_t) (p) & ~((uintptr_t) (a) - 1))


#define nxt_length(s)                                                         \
    (nxt_nitems(s) - 1)


#endif /* _NXT_CLANG_H_INCLUDED_ */

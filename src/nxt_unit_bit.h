/*
 * Copyright (C) 2022-2023, Alejandro Colomar <alx@kernel.org>
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIT_BIT_H_INCLUDED_
#define _NXT_UNIT_BIT_H_INCLUDED_


#include <limits.h>


/* C23 <stdbit.h> stuff */
nxt_inline unsigned long nxt_bit_ceil_ul(unsigned long x);
nxt_inline unsigned long nxt_bit_ceil_wrap_ul(unsigned long x);
nxt_inline int nxt_bit_width_ul(unsigned long x);
nxt_inline int nxt_leading_zeros_ul(unsigned long x);
nxt_inline int nxt_trailing_zeros_ul(unsigned long x);


nxt_inline unsigned long
nxt_bit_ceil_ul(unsigned long x)
{
    return 1 + (ULONG_MAX >> nxt_leading_zeros_ul(x));
}


nxt_inline unsigned long
nxt_bit_ceil_wrap_ul(unsigned long x)
{
    return (x == 0) ? 0 : nxt_bit_ceil_ul(x);
}


nxt_inline int
nxt_bit_width_ul(unsigned long x)
{
    return (x == 0) ? 0 : nxt_trailing_zeros_ul(nxt_bit_ceil_ul(x));
}


nxt_inline int
nxt_leading_zeros_ul(unsigned long x)
{
    if (x == 0) {
        return sizeof(unsigned long) * CHAR_BIT;
    }

    return __builtin_clzl(x);
}


nxt_inline int
nxt_trailing_zeros_ul(unsigned long x)
{
    if (x == 0) {
        return sizeof(unsigned long) * CHAR_BIT;
    }

    return __builtin_ctzl(x);
}


#endif /* _NXT_UNIT_BIT_H_INCLUDED_ */

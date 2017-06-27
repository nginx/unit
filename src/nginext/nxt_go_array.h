
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_GO_ARRAY_H_INCLUDED_
#define _NXT_GO_ARRAY_H_INCLUDED_


#include <nxt_array.h>

void nxt_go_array_init(nxt_array_t *array, nxt_uint_t n, size_t size);

void *nxt_go_array_add(nxt_array_t *array);

nxt_inline void *
nxt_go_array_zero_add(nxt_array_t *array)
{
    void  *p;

    p = nxt_go_array_add(array);

    if (nxt_fast_path(p != NULL)) {
        nxt_memzero(p, array->size);
    }

    return p;
}

#define                                                                       \
nxt_go_array_at(array, n)                                                     \
    nxt_pointer_to((array)->elts, (array)->size * (n))


#endif /* _NXT_GO_ARRAY_H_INCLUDED_ */

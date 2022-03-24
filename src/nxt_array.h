
/*
 * Copyright (C) Evgenii Sokolov
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_ARRAY_H_INCLUDED_
#define _NXT_ARRAY_H_INCLUDED_


typedef struct {
    void                *elts;
    nxt_uint_t          nelts;
    nxt_uint_t          size;
    nxt_uint_t          nalloc;
    nxt_mp_t            *mem_pool;
} nxt_array_t;


NXT_EXPORT nxt_array_t *nxt_array_create(nxt_mp_t *mp, nxt_uint_t n,
                                         size_t size);
NXT_EXPORT void nxt_array_destroy(nxt_array_t *array);
NXT_EXPORT void *nxt_array_add(nxt_array_t *array);
NXT_EXPORT void *nxt_array_zero_add(nxt_array_t *array);
NXT_EXPORT void nxt_array_del(nxt_array_t *array, void *elt);
NXT_EXPORT void nxt_array_del_last(nxt_array_t *array);
NXT_EXPORT nxt_array_t *nxt_array_copy(nxt_mp_t *mp,
                                       nxt_array_t *array);


#define                                                                       \
nxt_array_pointer_to_index(array, index)                                      \
    nxt_pointer_to((array)->elts, (array)->size * (index))


#define                                                                       \
nxt_array_pointer_to_last(array)                                              \
    nxt_pointer_to((array)->elts, (array)->size * ((array)->nelts - 1))


#define                                                                       \
nxt_array_reset(array)                                                        \
    (array)->nelts = 0;


#define                                                                       \
nxt_array_is_empty(array)                                                     \
    ((array)->nelts == 0)


#endif /* _NXT_ARRAY_H_INCLUDED_ */

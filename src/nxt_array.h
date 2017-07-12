
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_ARRAY_H_INCLUDED_
#define _NXT_ARRAY_H_INCLUDED_


typedef struct {
    void      *elts;
    /* nelts has uint32_t type because it is used most often. */
    uint32_t  nelts;
    uint16_t  size;
    uint16_t  nalloc;
    nxt_mp_t  *mem_pool;
} nxt_array_t;


NXT_EXPORT nxt_array_t *nxt_array_create(nxt_mp_t *mp, nxt_uint_t n,
    size_t size);
NXT_EXPORT void nxt_array_destroy(nxt_array_t *array);
NXT_EXPORT void *nxt_array_add(nxt_array_t *array);
NXT_EXPORT void *nxt_array_zero_add(nxt_array_t *array);
NXT_EXPORT void nxt_array_remove(nxt_array_t *array, void *elt);


#define                                                                       \
nxt_array_last(array)                                                         \
    nxt_pointer_to((array)->elts, (array)->size * ((array)->nelts - 1))


#define                                                                       \
nxt_array_reset(array)                                                        \
    (array)->nelts = 0;


#define                                                                       \
nxt_array_is_empty(array)                                                     \
    ((array)->nelts == 0)


nxt_inline void *
nxt_array_remove_last(nxt_array_t *array)
{
    array->nelts--;
    return nxt_pointer_to(array->elts, array->size * array->nelts);
}


#endif /* _NXT_ARRAY_H_INCLUDED_ */

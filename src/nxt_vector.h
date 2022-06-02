
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_VECTOR_H_INCLUDED_
#define _NXT_VECTOR_H_INCLUDED_


typedef enum {
    NXT_VECTOR_INITED = 0,
    NXT_VECTOR_DESCRETE,
    NXT_VECTOR_EMBEDDED,
} nxt_vector_type_t;


typedef struct {
    void               *start;
    /*
     * A vector can hold no more than 65536 items.
     * The item size is no more than 64K.
     */
    uint16_t           items;
    uint16_t           avalaible;
    uint16_t           item_size;
    nxt_vector_type_t  type:8;
} nxt_vector_t;


NXT_EXPORT nxt_vector_t *nxt_vector_create(nxt_uint_t items, size_t item_size,
    const nxt_mem_proto_t *proto, void *pool);
NXT_EXPORT void *nxt_vector_init(nxt_vector_t *vector, nxt_uint_t items,
    size_t item_size, const nxt_mem_proto_t *proto, void *pool);
NXT_EXPORT void nxt_vector_destroy(nxt_vector_t *vector,
    const nxt_mem_proto_t *proto, void *pool);
NXT_EXPORT void *nxt_vector_add(nxt_vector_t *vector,
    const nxt_mem_proto_t *proto, void *pool);
NXT_EXPORT void *nxt_vector_zero_add(nxt_vector_t *vector,
    const nxt_mem_proto_t *proto, void *pool);
NXT_EXPORT void nxt_vector_remove(nxt_vector_t *vector, void *item);


#define nxt_vector_last(vector)                                               \
    nxt_pointer_to((vector)->start,                                           \
                   (vector)->item_size * ((vector)->items - 1))


#define nxt_vector_reset(vector)                                              \
    (vector)->items = 0;


#define nxt_vector_is_empty(vector)                                           \
    ((vector)->items == 0)


nxt_inline void *
nxt_vector_remove_last(nxt_vector_t *vector)
{
    vector->items--;
    return nxt_pointer_to(vector->start, vector->item_size * vector->items);
}


#endif /* _NXT_VECTOR_H_INCLUDED_ */

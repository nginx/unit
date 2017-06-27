
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


nxt_vector_t *
nxt_vector_create(nxt_uint_t items, size_t item_size,
    const nxt_mem_proto_t *proto, void *pool)
{
    nxt_vector_t  *vector;

    vector = proto->alloc(pool, sizeof(nxt_vector_t) + items * item_size);

    if (nxt_fast_path(vector != NULL)) {
        vector->start = nxt_pointer_to(vector, sizeof(nxt_vector_t));
        vector->items = 0;
        vector->item_size = item_size;
        vector->avalaible = items;
        vector->type = NXT_VECTOR_EMBEDDED;
    }

    return vector;
}


void *
nxt_vector_init(nxt_vector_t *vector, nxt_uint_t items, size_t item_size,
    const nxt_mem_proto_t *proto, void *pool)
{
    vector->start = proto->alloc(pool, items * item_size);

    if (nxt_fast_path(vector->start != NULL)) {
        vector->items = 0;
        vector->item_size = item_size;
        vector->avalaible = items;
        vector->type = NXT_VECTOR_INITED;
    }

    return vector->start;
}


void
nxt_vector_destroy(nxt_vector_t *vector, const nxt_mem_proto_t *proto,
    void *pool)
{
    switch (vector->type) {

    case NXT_VECTOR_INITED:
        proto->free(pool, vector->start);
#if (NXT_DEBUG)
        vector->start = NULL;
        vector->items = 0;
        vector->avalaible = 0;
#endif
        break;

    case NXT_VECTOR_DESCRETE:
        proto->free(pool, vector->start);

        /* Fall through. */

    case NXT_VECTOR_EMBEDDED:
        proto->free(pool, vector);
        break;
    }
}


void *
nxt_vector_add(nxt_vector_t *vector, const nxt_mem_proto_t *proto, void *pool)
{
    void      *item, *start, *old;
    size_t    size;
    uint32_t  n;

    n = vector->avalaible;

    if (n == vector->items) {

        if (n < 16) {
            /* Allocate new vector twice as much as current. */
            n *= 2;

        } else {
            /* Allocate new vector half as much as current. */
            n += n / 2;
        }

        size = n * vector->item_size;

        start = proto->alloc(pool, size);
        if (nxt_slow_path(start == NULL)) {
            return NULL;
        }

        vector->avalaible = n;
        old = vector->start;
        vector->start = start;

        nxt_memcpy(start, old, size);

        if (vector->type == NXT_VECTOR_EMBEDDED) {
            vector->type = NXT_VECTOR_DESCRETE;

        } else {
            proto->free(pool, old);
        }
    }

    item = nxt_pointer_to(vector->start, vector->item_size * vector->items);

    vector->items++;

    return item;
}


void *
nxt_vector_zero_add(nxt_vector_t *vector, const nxt_mem_proto_t *proto,
    void *pool)
{
    void  *item;

    item = nxt_vector_add(vector, proto, pool);

    if (nxt_fast_path(item != NULL)) {
        nxt_memzero(item, vector->item_size);
    }

    return item;
}


void
nxt_vector_remove(nxt_vector_t *vector, void *item)
{
    u_char    *next, *last, *end;
    uint32_t  item_size;

    item_size = vector->item_size;
    end = nxt_pointer_to(vector->start, item_size * vector->items);
    last = end - item_size;

    if (item != last) {
        next = nxt_pointer_to(item, item_size);

        nxt_memmove(item, next, end - next);
    }

    vector->items--;
}

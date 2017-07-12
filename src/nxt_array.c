
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


nxt_array_t *
nxt_array_create(nxt_mp_t *mp, nxt_uint_t n, size_t size)
{
    nxt_array_t  *array;

    array = nxt_mp_alloc(mp, sizeof(nxt_array_t) + n * size);

    if (nxt_slow_path(array == NULL)) {
        return NULL;
    }

    array->elts = nxt_pointer_to(array, sizeof(nxt_array_t));
    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
    array->mem_pool = mp;

    return array;
}


void
nxt_array_destroy(nxt_array_t *array)
{
    if (array->elts != nxt_pointer_to(array, sizeof(nxt_array_t))) {
        nxt_mp_free(array->mem_pool, array->elts);
    }

    nxt_mp_free(array->mem_pool, array);
}


void *
nxt_array_add(nxt_array_t *array)
{
    void      *p;
    uint32_t  nalloc, new_alloc;

    nalloc = array->nalloc;

    if (array->nelts == nalloc) {

        if (nalloc < 16) {
            /* Allocate new array twice larger than current. */
            new_alloc = nalloc * 2;

        } else {
            /* Allocate new array 1.5 times larger than current. */
            new_alloc = nalloc + nalloc / 2;
        }

        p = nxt_mp_alloc(array->mem_pool, array->size * new_alloc);

        if (nxt_slow_path(p == NULL)) {
            return NULL;
        }

        nxt_memcpy(p, array->elts, array->size * nalloc);

        if (array->elts != nxt_pointer_to(array, sizeof(nxt_array_t))) {
            nxt_mp_free(array->mem_pool, array->elts);
        }

        array->elts = p;
        array->nalloc = new_alloc;
    }

    p = nxt_pointer_to(array->elts, array->size * array->nelts);
    array->nelts++;

    return p;
}


void *
nxt_array_zero_add(nxt_array_t *array)
{
    void  *p;

    p = nxt_array_add(array);

    if (nxt_fast_path(p != NULL)) {
        nxt_memzero(p, array->size);
    }

    return p;
}


void
nxt_array_remove(nxt_array_t *array, void *elt)
{
    void  *last;

    last = nxt_array_last(array);

    if (elt != last) {
        nxt_memcpy(elt, last, array->size);
    }

    array->nelts--;
}

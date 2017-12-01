
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#include <stdint.h>
#include <sys/types.h>

#include <nxt_main.h>

#include "nxt_go_array.h"

void
nxt_go_array_init(nxt_array_t *array, nxt_uint_t n, size_t size)
{
    array->elts = malloc(n * size);

    if (nxt_slow_path(n != 0 && array->elts == NULL)) {
        return;
    }

    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
    array->mem_pool = NULL;
}

void *
nxt_go_array_add(nxt_array_t *array)
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

        p = realloc(array->elts, array->size * new_alloc);

        if (nxt_slow_path(p == NULL)) {
            return NULL;
        }

        array->elts = p;
        array->nalloc = new_alloc;
    }

    p = nxt_pointer_to(array->elts, array->size * array->nelts);
    array->nelts++;

    return p;
}


/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


nxt_list_t *
nxt_list_create(nxt_mp_t *mp, nxt_uint_t n, size_t size)
{
    nxt_list_t  *list;

    list = nxt_mp_get(mp, sizeof(nxt_list_t) + n * size);

    if (nxt_fast_path(list != NULL)) {
        list->last = &list->part;
        list->size = size;
        list->nalloc = n;
        list->mem_pool = mp;
        list->part.next = NULL;
        list->part.nelts = 0;
    }

    return list;
}


void *
nxt_list_add(nxt_list_t *list)
{
    void             *elt;
    nxt_list_part_t  *last;

    last = list->last;

    if (last->nelts == list->nalloc) {

        /* The last list part is filled up, allocating a new list part. */

        last = nxt_mp_get(list->mem_pool,
                          sizeof(nxt_list_part_t) + list->nalloc * list->size);

        if (nxt_slow_path(last == NULL)) {
            return NULL;
        }

        last->next = NULL;
        last->nelts = 0;

        list->last->next = last;
        list->last = last;
    }

    elt = nxt_pointer_to(nxt_list_data(last), last->nelts * list->size);
    last->nelts++;

    return elt;
}


void *
nxt_list_zero_add(nxt_list_t *list)
{
    void  *p;

    p = nxt_list_add(list);

    if (nxt_fast_path(p != NULL)) {
        nxt_memzero(p, list->size);
    }

    return p;
}


void *
nxt_list_next(nxt_list_t *list, nxt_list_next_t *next)
{
    if (next->part != NULL) {
        next->elt++;

        if (next->elt < next->part->nelts) {
            return nxt_list_next_value(list, next);
        }

        next->part = next->part->next;

        if (next->part != NULL) {
            next->elt = 0;
            return nxt_list_data(next->part);
        }

    } else {
        next->part = nxt_list_part(list);
        /*
         * The first list part is allocated together with
         * a nxt_list_t itself and it may never be NULL.
         */
        if (next->part->nelts != 0) {
            return nxt_list_data(next->part);
        }

    }

    return NULL;
}

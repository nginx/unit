
/*
 * Copyright (C) Evgenii Sokolov
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void nxt_array_elts_copy(void **dst_elts, nxt_array_t *src_array);
static nxt_uint_t nxt_array_calc_alloc(nxt_uint_t nelts);
static void *nxt_array_elts_realloc(nxt_array_t *array,
                                    nxt_uint_t nalloc);


/*
 * nxt_array_create - Create a new array and return a pointer to it.
 */
nxt_array_t *
nxt_array_create(nxt_mp_t *mp, nxt_uint_t arr_size, size_t elt_size)
{
    nxt_uint_t     nalloc;
    nxt_array_t    *array;
    void           *elts;

    array = nxt_mp_alloc(mp, sizeof(nxt_array_t));

    if (nxt_slow_path(array == NULL)) {
        return NULL;
    }

    nalloc = nxt_array_calc_alloc(arr_size);
    elts = nxt_mp_alloc(mp, elt_size * nalloc);

    if (nxt_slow_path(elts == NULL)) {
        return NULL;
    }

    array->elts = elts;
    array->nelts = 0;
    array->size = elt_size;
    array->nalloc = nalloc;
    array->mem_pool = mp;

    return array;
}


/*
 * nxt_array_destroy - Destroy the existing array.
 */
void
nxt_array_destroy(nxt_array_t *array)
{
    if (nxt_fast_path(array != NULL)) {

        array->nelts = 0;

        (void) nxt_mp_free(array->mem_pool, array->elts);
        (void) nxt_mp_free(array->mem_pool, array);

    }
}


/*
 * nxt_array_add - Add an element to the existing array.
 */
void *
nxt_array_add(nxt_array_t *array)
{
    if (nxt_fast_path(array != NULL)) {

        nxt_uint_t    nalloc;
        void          *elt, *elts;

        if (array->nelts == array->nalloc) {

            nalloc = nxt_array_calc_alloc(array->nelts);
            elts = nxt_array_elts_realloc(array, nalloc);

            if (nxt_slow_path(elts == NULL)) {
                return NULL;
            }

        }

        elt = nxt_pointer_to(array->elts, array->size * array->nelts);

        array->nelts++;

        return elt;

    } else {
        return NULL;
    }
}


/*
 * nxt_array_zero_add - Add an element to the existing array,
 * fill with zeros.
 */
void *
nxt_array_zero_add(nxt_array_t *array)
{
    if (nxt_fast_path(array != NULL)) {

        void    *elt;

        elt = nxt_array_add(array);

        if (nxt_fast_path(elt != NULL)) {

            (void) nxt_memzero(elt, array->size);

        }

        return elt;

    } else {
        return NULL;
    }
}


/*
 * nxt_array_del - Delete the specified element in the array.
 */
void
nxt_array_del(nxt_array_t *array, void *elt)
{
    if (nxt_fast_path(array != NULL)) {

        void    *last;

        last = nxt_array_pointer_to_last(array);

        if (elt != last) {
            (void) nxt_memcpy(elt, last, array->size);
        }

        (void) nxt_array_del_last(array);

    }
}


/*
 * nxt_array_del_last - Delete the last element from
 * the existing array.
 */
void
nxt_array_del_last(nxt_array_t *array)
{
    if (nxt_fast_path(array != NULL)) {

        array->nelts--;

    }
}


/*
 * nxt_array_copy - Copies the existing array to a new one
 * and returns a pointer to it.
 */
nxt_array_t *
nxt_array_copy(nxt_mp_t *mp, nxt_array_t *array)
{
    if (nxt_fast_path(array != NULL)) {

        nxt_array_t    *new_array;

        new_array = nxt_array_create(mp, array->nelts, array->size);

        if (nxt_slow_path(new_array == NULL)) {
            return NULL;
        }

        (void) nxt_array_elts_copy(new_array->elts, array);

        new_array->nelts = array->nelts;

        return new_array;

    } else {
        return NULL;
    }
}


/*
 * nxt_array_elts_copy - Copy existing elements from source
 * to destination array.
 */
static void
nxt_array_elts_copy(void **dst_elts, nxt_array_t *src_array)
{
    (void) nxt_memcpy(dst_elts, src_array->elts,
                      src_array->size * src_array->nelts);
}


/*
 * nxt_array_calc_alloc - Calculate the required size
 * of the memory area for the specified number of elements.
 */
static nxt_uint_t
nxt_array_calc_alloc(nxt_uint_t nelts)
{
    nxt_uint_t    nalloc;

    if (nelts <= 16) {

        nalloc = (nelts == 0) ? 2 : nelts * 2;

    } else {

        nalloc = nelts + nelts / 2;

    }

    return nalloc;
}


/*
 * nxt_array_elts_realloc - Reallocate the allocated memory
 * for the array elements and return a pointer to the new block.
 */
static void *
nxt_array_elts_realloc(nxt_array_t *array, nxt_uint_t nalloc)
{
    void    **old_elts, *new_elts;

    old_elts = array->elts;
    new_elts = nxt_mp_alloc(array->mem_pool, array->size * nalloc);

    if (nxt_slow_path(new_elts == NULL)) {
        return NULL;
    }

    (void) nxt_array_elts_copy(new_elts, array);

    array->elts = new_elts;
    array->nalloc = nalloc;

    (void) nxt_mp_free(array->mem_pool, old_elts);

    return new_elts;
}

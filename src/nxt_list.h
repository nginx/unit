
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_LIST_H_INCLUDED_
#define _NXT_LIST_H_INCLUDED_


typedef struct nxt_list_part_s  nxt_list_part_t;

struct nxt_list_part_s {
    nxt_list_part_t             *next;
    uintptr_t                   nelts;
    char                        data[];
};


typedef struct {
    nxt_list_part_t             *last;
#if (NXT_64BIT)
    uint32_t                    size;
    uint32_t                    nalloc;
#else
    uint16_t                    size;
    uint16_t                    nalloc;
#endif
    nxt_mp_t                    *mem_pool;
    nxt_list_part_t             part;
} nxt_list_t;


typedef struct {
    nxt_list_part_t             *part;
    uintptr_t                   elt;
} nxt_list_next_t;


#define                                                                       \
nxt_list_part(list)                                                           \
    (&(list)->part)


#define                                                                       \
nxt_list_data(part)                                                           \
    ((void *) part->data)


#define                                                                       \
nxt_list_first(list)                                                          \
    nxt_list_data(nxt_list_part(list))


nxt_inline void *
nxt_list_elt(nxt_list_t *list, nxt_uint_t n)
{
    nxt_list_part_t  *part;

    if (nxt_fast_path((list) != NULL)) {
        part = nxt_list_part(list);

        while (part != NULL) {
            if (n < (nxt_uint_t) part->nelts) {
                return nxt_pointer_to(nxt_list_data(part), n * (list)->size);
            }

            n -= (nxt_uint_t) part->nelts;
            part = part->next;
        }
    }

    return NULL;
}


#define nxt_list_each(elt, list)                                              \
    do {                                                                      \
        if (nxt_fast_path((list) != NULL)) {                                  \
            void             *_end;                                           \
            nxt_list_part_t  *_part = nxt_list_part(list);                    \
                                                                              \
            do {                                                              \
                elt = nxt_list_data(_part);                                   \
                                                                              \
                for (_end = (elt + _part->nelts); elt != _end; elt++) {       \

#define nxt_list_loop                                                         \
                }                                                             \
                                                                              \
                _part = _part->next;                                          \
                                                                              \
            } while (_part != NULL);                                          \
        }                                                                     \
    } while (0)


NXT_EXPORT nxt_list_t *nxt_list_create(nxt_mp_t *mp, nxt_uint_t n, size_t size);
NXT_EXPORT void *nxt_list_add(nxt_list_t *list);
NXT_EXPORT void *nxt_list_zero_add(nxt_list_t *list);

NXT_EXPORT void *nxt_list_next(nxt_list_t *list, nxt_list_next_t *next);


#define                                                                       \
nxt_list_next_value(list, next)                                               \
    (nxt_pointer_to(nxt_list_data((next)->part), (next)->elt * (list)->size))


nxt_inline nxt_uint_t
nxt_list_nelts(nxt_list_t *list)
{
    nxt_uint_t       n;
    nxt_list_part_t  *part;

    n = 0;

    if (nxt_fast_path((list) != NULL)) {
        part = nxt_list_part(list);

        do {
            n += (nxt_uint_t) part->nelts;
            part = part->next;
        } while (part != NULL);
    }

    return n;
}


#endif /* _NXT_LIST_H_INCLUDED_ */

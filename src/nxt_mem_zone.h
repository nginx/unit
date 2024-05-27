
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_MEM_ZONE_H_INCLUDED_
#define _NXT_MEM_ZONE_H_INCLUDED_


typedef struct nxt_mem_zone_s  nxt_mem_zone_t;


NXT_EXPORT nxt_mem_zone_t *nxt_mem_zone_init(u_char *start, size_t zone_size,
    nxt_uint_t page_size);

#define nxt_mem_zone_alloc(zone, size)                                        \
    nxt_mem_zone_align((zone), 1, (size))

NXT_EXPORT void *nxt_mem_zone_align(nxt_mem_zone_t *zone, size_t alignment,
    size_t size)
    NXT_MALLOC_LIKE;
NXT_EXPORT void *nxt_mem_zone_zalloc(nxt_mem_zone_t *zone, size_t size)
    NXT_MALLOC_LIKE;
NXT_EXPORT void nxt_mem_zone_free(nxt_mem_zone_t *zone, void *p);


#endif /* _NXT_MEM_ZONE_H_INCLUDED_ */

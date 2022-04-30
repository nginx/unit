
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_BUF_POOL_H_INCLUDED_
#define _NXT_BUF_POOL_H_INCLUDED_


/*
 * nxt_buf_pool_t is intended to allocate up to the "max" number
 * memory, memory/file, or mmap/file buffers.  A size of the buffers
 * is set in the "size" field.  The size however can be overridden in
 * nxt_buf_pool_XXX_alloc() by the "size" argument if the argument is
 * not zero and lesser than or equal to the "size" field multiplied
 * by 1.25.  The "flags" field is passed as the nxt_mem_buf() flags.
 */

typedef struct {
    nxt_buf_t       *current;
    nxt_buf_t       *free;
    nxt_mp_t        *mem_pool;

    uint16_t        num;
    uint16_t        max;

    uint32_t        size;

    uint8_t         flags;     /* 2 bits */
    uint8_t         destroy;   /* 1 bit */
    uint8_t         mmap;      /* 1 bit */
} nxt_buf_pool_t;


NXT_EXPORT nxt_int_t nxt_buf_pool_mem_alloc(nxt_buf_pool_t *bp, size_t size);
NXT_EXPORT nxt_int_t nxt_buf_pool_file_alloc(nxt_buf_pool_t *bp, size_t size);
NXT_EXPORT nxt_int_t nxt_buf_pool_mmap_alloc(nxt_buf_pool_t *bp, size_t size);
NXT_EXPORT void nxt_buf_pool_free(nxt_buf_pool_t *bp, nxt_buf_t *b);
NXT_EXPORT void nxt_buf_pool_destroy(nxt_buf_pool_t *bp);


/* There is ready free buffer. */

#define nxt_buf_pool_ready(bp)                                                \
    ((bp)->free != NULL                                                       \
     || ((bp)->current != NULL                                                \
         && (bp)->current->mem.free < (bp)->current->mem.end))


/* A free buffer is allowed to be allocated. */

#define nxt_buf_pool_obtainable(bp)                                           \
    ((bp)->num < (bp)->max)


/* There is ready free buffer or it is allowed to be allocated. */

#define nxt_buf_pool_available(bp)                                            \
    (nxt_buf_pool_obtainable(bp) || nxt_buf_pool_ready(bp))


/* Reserve allocation of "n" free buffers as they were allocated. */

#define nxt_buf_pool_reserve(bp, n)                                           \
    (bp)->num += (n)


/* Release a reservation. */

#define nxt_buf_pool_release(bp, n)                                           \
    (bp)->num -= (n)


#endif /* _NXT_BUF_POOL_H_INCLUDED_ */

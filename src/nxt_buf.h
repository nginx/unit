
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_BUF_H_INCLUDED_
#define _NXT_BUF_H_INCLUDED_


/*
 * There are four types of buffers.  They are different sizes, so they
 * should be allocated by appropriate nxt_buf_XXX_alloc() function.
 *
 * 1) Memory-only buffers, their size is less than nxt_buf_t size, it
 *    is equal to offsetof(nxt_buf_t, file_pos), that is it is nxt_buf_t
 *    without file and mmap part.  The buffers are frequently used, so
 *    the reduction allows to save 20-32 bytes depending on platform.
 *
 * 2) Memory/file buffers, on Unix their size is exactly nxt_buf_t size,
 *    since nxt_mem_map_file_ctx_t() is empty macro.  On Windows the size
 *    equals offsetof(nxt_buf_t, mmap), that is it is nxt_buf_t without
 *    memory map context part.  The buffers can contain both memory and
 *    file pointers at once, or only memory or file pointers.
 *
 * 3) Memory mapped buffers are similar to the memory/file buffers.  Their
 *    size is exactly nxt_buf_t size.  The buffers can contain both memory
 *    and file pointers at once, or only memory or file pointers.  If a
 *    buffer is not currently mapped in memory, its mapping size is stored
 *    in the mem.end field and available via nxt_buf_mem_size() macro.
 *
 * 4) Sync buffers, their size is the same size as memory-only buffers
 *    size.  A sync buffer can be smaller but for memory pool cache
 *    purpose it is better to allocate it as frequently used memory-only
 *    buffer.  The buffers are used to synchronize pipeline processing
 *    completion, because data buffers in the pipeline can be completed
 *    and freed before their final output will even be passed to a peer.
 *    For this purpose a sync buffer is allocated with the stop flag which
 *    stops buffer chain completion processing on the sync buffer in
 *    nxt_sendbuf_update() and nxt_sendbuf_completion().
 *    Clearing the stop flag allows to continue completion processing.
 *
 *    The last flag means the end of the output and must be set only
 *    in a sync buffer.  The last flag is not permitted in memory and
 *    file buffers since it requires special handling while conversion
 *    one buffer to another.
 *
 *    The nxt_buf_used_size() macro treats a sync buffer as a memory-only
 *    buffer which has NULL pointers, thus the buffer content size is zero.
 *    If allocated size of sync buffer would be lesser than memory-only
 *    buffer, then the special memory flag would be required because
 *    currently presence of memory part is indicated by non-NULL pointer
 *    to a content in memory.
 *
 *    All types of buffers can have the flush flag that means the buffer
 *    should be sent as much as possible.
 */

typedef struct {
    u_char                  *pos;
    u_char                  *free;
    u_char                  *start;
    u_char                  *end;
} nxt_buf_mem_t;


struct nxt_buf_s {
    void                    *data;
    nxt_work_handler_t      completion_handler;
    void                    *parent;

    /*
     * The next link, flags, and nxt_buf_mem_t should
     * reside together to improve cache locality.
     */
    nxt_buf_t               *next;

    uint32_t                retain;

    uint8_t                 is_file;     /* 1 bit */

    uint16_t                is_mmap:1;
    uint16_t                is_port_mmap:1;

    uint16_t                is_sync:1;
    uint16_t                is_nobuf:1;
    uint16_t                is_flush:1;
    uint16_t                is_last:1;
    uint16_t                is_port_mmap_sent:1;
    uint16_t                is_ts:1;

    nxt_buf_mem_t           mem;

    /* The file and mmap parts are not allocated by nxt_buf_mem_alloc(). */
    nxt_file_t              *file;
    nxt_off_t               file_pos;
    nxt_off_t               file_end;

    /* The mmap part is not allocated by nxt_buf_file_alloc(). */
    nxt_mem_map_file_ctx_t  (mmap)
};


#define NXT_BUF_SYNC_SIZE       offsetof(nxt_buf_t, mem.free)
#define NXT_BUF_MEM_SIZE        offsetof(nxt_buf_t, file)
#define NXT_BUF_FILE_SIZE       sizeof(nxt_buf_t)
#define NXT_BUF_MMAP_SIZE       NXT_BUF_FILE_SIZE
#define NXT_BUF_PORT_MMAP_SIZE  NXT_BUF_MEM_SIZE


#define NXT_BUF_SYNC_NOBUF  1
#define NXT_BUF_SYNC_FLUSH  2
#define NXT_BUF_SYNC_LAST   4


#define                                                                       \
nxt_buf_is_mem(b)                                                             \
    ((b)->mem.pos != NULL)


#define                                                                       \
nxt_buf_is_file(b)                                                            \
    ((b)->is_file)

#define                                                                       \
nxt_buf_set_file(b)                                                           \
    (b)->is_file = 1

#define                                                                       \
nxt_buf_clear_file(b)                                                         \
    (b)->is_file = 0


#define                                                                       \
nxt_buf_is_mmap(b)                                                            \
    ((b)->is_mmap)

#define                                                                       \
nxt_buf_set_mmap(b)                                                           \
    (b)->is_mmap = 1

#define                                                                       \
nxt_buf_clear_mmap(b)                                                         \
    (b)->is_mmap = 0


#define                                                                       \
nxt_buf_is_port_mmap(b)                                                       \
    ((b)->is_port_mmap)

#define                                                                       \
nxt_buf_set_port_mmap(b)                                                      \
    (b)->is_port_mmap = 1

#define                                                                       \
nxt_buf_clear_port_mmap(b)                                                    \
    (b)->is_port_mmap = 0


#define                                                                       \
nxt_buf_is_sync(b)                                                            \
    ((b)->is_sync)

#define                                                                       \
nxt_buf_set_sync(b)                                                           \
    (b)->is_sync = 1

#define                                                                       \
nxt_buf_clear_sync(b)                                                         \
    (b)->is_sync = 0


#define                                                                       \
nxt_buf_is_nobuf(b)                                                           \
    ((b)->is_nobuf)

#define                                                                       \
nxt_buf_set_nobuf(b)                                                          \
    (b)->is_nobuf = 1

#define                                                                       \
nxt_buf_clear_nobuf(b)                                                        \
    (b)->is_nobuf = 0


#define                                                                       \
nxt_buf_is_flush(b)                                                           \
    ((b)->is_flush)

#define                                                                       \
nxt_buf_set_flush(b)                                                          \
    (b)->is_flush = 1

#define                                                                       \
nxt_buf_clear_flush(b)                                                        \
    (b)->is_flush = 0


#define                                                                       \
nxt_buf_is_last(b)                                                            \
    ((b)->is_last)

#define                                                                       \
nxt_buf_set_last(b)                                                           \
    (b)->is_last = 1

#define                                                                       \
nxt_buf_clear_last(b)                                                         \
    (b)->is_last = 0


#define                                                                       \
nxt_buf_mem_set_size(bm, size)                                                \
    do {                                                                      \
        (bm)->start = 0;                                                      \
        (bm)->end = (void *) size;                                            \
    } while (0)


#define                                                                       \
nxt_buf_mem_size(bm)                                                          \
    ((bm)->end - (bm)->start)


#define                                                                       \
nxt_buf_mem_used_size(bm)                                                     \
    ((bm)->free - (bm)->pos)


#define                                                                       \
nxt_buf_mem_free_size(bm)                                                     \
    ((bm)->end - (bm)->free)


#define                                                                       \
nxt_buf_used_size(b)                                                          \
    (nxt_buf_is_file(b) ? (b)->file_end - (b)->file_pos:                      \
                          nxt_buf_mem_used_size(&(b)->mem))


NXT_EXPORT void nxt_buf_mem_init(nxt_buf_t *b, void *start, size_t size);
NXT_EXPORT nxt_buf_t *nxt_buf_mem_alloc(nxt_mp_t *mp, size_t size,
    nxt_uint_t flags);
NXT_EXPORT nxt_buf_t *nxt_buf_mem_ts_alloc(nxt_task_t *task, nxt_mp_t *mp,
    size_t size);
NXT_EXPORT nxt_buf_t *nxt_buf_file_alloc(nxt_mp_t *mp, size_t size,
    nxt_uint_t flags);
NXT_EXPORT nxt_buf_t *nxt_buf_mmap_alloc(nxt_mp_t *mp, size_t size);
NXT_EXPORT nxt_buf_t *nxt_buf_sync_alloc(nxt_mp_t *mp, nxt_uint_t flags);

NXT_EXPORT nxt_int_t nxt_buf_ts_handle(nxt_task_t *task, void *obj, void *data);

NXT_EXPORT nxt_buf_t *nxt_buf_make_plain(nxt_mp_t *mp, nxt_buf_t *src,
    size_t size);

nxt_inline nxt_buf_t *
nxt_buf_chk_make_plain(nxt_mp_t *mp, nxt_buf_t *src, size_t size)
{
    if (nxt_slow_path(src != NULL && src->next != NULL)) {
        return nxt_buf_make_plain(mp, src, size);
    }

    return src;
}

#define                                                                       \
nxt_buf_free(mp, b)                                                           \
    nxt_mp_free((mp), (b))


NXT_EXPORT void nxt_buf_chain_add(nxt_buf_t **head, nxt_buf_t *in);
NXT_EXPORT size_t nxt_buf_chain_length(nxt_buf_t *b);

nxt_inline nxt_buf_t *
nxt_buf_cpy(nxt_buf_t *b, const void *src, size_t length)
{
    nxt_memcpy(b->mem.free, src, length);
    b->mem.free += length;

    return b;
}

nxt_inline nxt_buf_t *
nxt_buf_cpystr(nxt_buf_t *b, const nxt_str_t *str)
{
    return nxt_buf_cpy(b, str->start, str->length);
}


#endif /* _NXT_BUF_H_INCLIDED_ */

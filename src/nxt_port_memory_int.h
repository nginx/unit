
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PORT_MEMORY_INT_H_INCLUDED_
#define _NXT_PORT_MEMORY_INT_H_INCLUDED_


#include <stdint.h>
#include <nxt_atomic.h>


#ifdef NXT_MMAP_TINY_CHUNK

#define PORT_MMAP_CHUNK_SIZE    16
#define PORT_MMAP_HEADER_SIZE   1024
#define PORT_MMAP_DATA_SIZE     1024

#else

#define PORT_MMAP_CHUNK_SIZE    (1024 * 16)
#define PORT_MMAP_HEADER_SIZE   (1024 * 4)
#define PORT_MMAP_DATA_SIZE     (1024 * 1024 * 10)

#endif


#define PORT_MMAP_SIZE          (PORT_MMAP_HEADER_SIZE + PORT_MMAP_DATA_SIZE)
#define PORT_MMAP_CHUNK_COUNT   (PORT_MMAP_DATA_SIZE / PORT_MMAP_CHUNK_SIZE)


typedef uint32_t  nxt_chunk_id_t;

typedef nxt_atomic_uint_t  nxt_free_map_t;

#define FREE_BITS (sizeof(nxt_free_map_t) * 8)

#define FREE_IDX(nchunk) ((nchunk) / FREE_BITS)

#define FREE_MASK(nchunk)                                                     \
    ( 1ULL << ( (nchunk) % FREE_BITS ) )

#define MAX_FREE_IDX FREE_IDX(PORT_MMAP_CHUNK_COUNT)


/* Mapped at the start of shared memory segment. */
struct nxt_port_mmap_header_s {
    uint32_t        id;
    nxt_pid_t       src_pid; /* For sanity check. */
    nxt_pid_t       dst_pid; /* For sanity check. */
    nxt_port_id_t   sent_over;
    nxt_atomic_t    oosm;
    nxt_free_map_t  free_map[MAX_FREE_IDX];
    nxt_free_map_t  free_map_padding;
    nxt_free_map_t  free_tracking_map[MAX_FREE_IDX];
    nxt_free_map_t  free_tracking_map_padding;
    nxt_atomic_t    tracking[PORT_MMAP_CHUNK_COUNT];
};


struct nxt_port_mmap_handler_s {
    nxt_port_mmap_header_t  *hdr;
    nxt_atomic_t            use_count;
    nxt_fd_t                fd;
};

/*
 * Element of nxt_process_t.incoming/outgoing, shared memory segment
 * descriptor.
 */
struct nxt_port_mmap_s {
    nxt_port_mmap_handler_t  *mmap_handler;
};

typedef struct nxt_port_mmap_msg_s nxt_port_mmap_msg_t;

/* Passed as a second iov chunk when 'mmap' bit in nxt_port_msg_t is 1. */
struct nxt_port_mmap_msg_s {
    uint32_t            mmap_id;    /* Mmap index in nxt_process_t.outgoing. */
    nxt_chunk_id_t      chunk_id;   /* Mmap chunk index. */
    uint32_t            size;       /* Payload data size. */
};


nxt_inline nxt_bool_t
nxt_port_mmap_get_free_chunk(nxt_free_map_t *m, nxt_chunk_id_t *c);

#define nxt_port_mmap_get_chunk_busy(m, c)                                    \
    ((m[FREE_IDX(c)] & FREE_MASK(c)) == 0)

nxt_inline void
nxt_port_mmap_set_chunk_busy(nxt_free_map_t *m, nxt_chunk_id_t c);

nxt_inline nxt_bool_t
nxt_port_mmap_chk_set_chunk_busy(nxt_free_map_t *m, nxt_chunk_id_t c);

nxt_inline void
nxt_port_mmap_set_chunk_free(nxt_free_map_t *m, nxt_chunk_id_t c);

nxt_inline nxt_chunk_id_t
nxt_port_mmap_chunk_id(nxt_port_mmap_header_t *hdr, const u_char *p)
{
    u_char  *mm_start;

    mm_start = (u_char *) hdr;

    return ((p - mm_start) - PORT_MMAP_HEADER_SIZE) / PORT_MMAP_CHUNK_SIZE;
}


nxt_inline u_char *
nxt_port_mmap_chunk_start(nxt_port_mmap_header_t *hdr, nxt_chunk_id_t c)
{
    u_char  *mm_start;

    mm_start = (u_char *) hdr;

    return mm_start + PORT_MMAP_HEADER_SIZE + c * PORT_MMAP_CHUNK_SIZE;
}


nxt_inline nxt_bool_t
nxt_port_mmap_get_free_chunk(nxt_free_map_t *m, nxt_chunk_id_t *c)
{
    const nxt_free_map_t  default_mask = (nxt_free_map_t) -1;

    int             ffs;
    size_t          i, start;
    nxt_chunk_id_t  chunk;
    nxt_free_map_t  bits, mask;

    start = FREE_IDX(*c);
    mask = default_mask << ((*c) % FREE_BITS);

    for (i = start; i < MAX_FREE_IDX; i++) {
        bits = m[i] & mask;
        mask = default_mask;

        if (bits == 0) {
            continue;
        }

        ffs = __builtin_ffsll(bits);
        if (ffs != 0) {
            chunk = i * FREE_BITS + ffs - 1;

            if (nxt_port_mmap_chk_set_chunk_busy(m, chunk)) {
                *c = chunk;
                return 1;
            }
        }
    }

    return 0;
}


nxt_inline void
nxt_port_mmap_set_chunk_busy(nxt_free_map_t *m, nxt_chunk_id_t c)
{
    nxt_atomic_and_fetch(m + FREE_IDX(c), ~FREE_MASK(c));
}


nxt_inline nxt_bool_t
nxt_port_mmap_chk_set_chunk_busy(nxt_free_map_t *m, nxt_chunk_id_t c)
{
    nxt_free_map_t  *f;
    nxt_free_map_t  free_val, busy_val;

    f = m + FREE_IDX(c);

    while ( (*f & FREE_MASK(c)) != 0 ) {

        free_val = *f | FREE_MASK(c);
        busy_val = free_val & ~FREE_MASK(c);

        if (nxt_atomic_cmp_set(f, free_val, busy_val) != 0) {
            return 1;
        }
    }

    return 0;
}


nxt_inline void
nxt_port_mmap_set_chunk_free(nxt_free_map_t *m, nxt_chunk_id_t c)
{
    nxt_atomic_or_fetch(m + FREE_IDX(c), FREE_MASK(c));
}


#endif /* _NXT_PORT_MEMORY_INT_H_INCLUDED_ */

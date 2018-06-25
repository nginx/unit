
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UPSTREAM_SOURCE_H_INCLUDED_
#define _NXT_UPSTREAM_SOURCE_H_INCLUDED_


typedef struct {
    uint32_t                           hash;

    unsigned                           value_len:23;
    unsigned                           skip:1;
    unsigned                           name_len:8;

    u_char                             *value_start;
    u_char                             *name_start;
} nxt_name_value_t;


typedef struct {
    nxt_list_t                         *list;
    nxt_lvlhsh_t                       hash;

    uint16_t                           status;    /* 16 bits */

    nxt_off_t                          content_length;
} nxt_upstream_header_in_t;


typedef nxt_int_t (*nxt_upstream_name_value_handler_t)(
    nxt_upstream_source_t *us, nxt_name_value_t *nv);


typedef struct {
    nxt_upstream_name_value_handler_t  handler;

    uint8_t                            len;
    /*
     * A name is inlined to test it with one memory access.
     * The struct size is aligned to 32 bytes.
     */
#if (NXT_64BIT)
    u_char                             name[23];
#else
    u_char                             name[27];
#endif
} nxt_upstream_name_value_t;


struct nxt_upstream_source_s {
    nxt_upstream_peer_t                *peer;

    const nxt_upstream_state_t         *state;

    void                               *protocol_source;
    void                               *data;
    nxt_work_queue_t                   *work_queue;

    nxt_buf_pool_t                     buffers;

    nxt_lvlhsh_t                       header_hash;
    nxt_stream_source_t                *stream;
};


#define NXT_UPSTREAM_NAME_VALUE_MIN_SIZE                                      \
    offsetof(nxt_http_upstream_header_t, name)

#define nxt_upstream_name_value(s)   nxt_length(s), s


NXT_EXPORT nxt_int_t nxt_upstream_header_hash_add(nxt_mp_t *mp,
    nxt_lvlhsh_t *lh, const nxt_upstream_name_value_t *unv, nxt_uint_t n);
NXT_EXPORT nxt_int_t nxt_upstream_name_value_ignore(nxt_upstream_source_t *us,
    nxt_name_value_t *nv);

NXT_EXPORT extern const nxt_lvlhsh_proto_t  nxt_upstream_header_hash_proto;


#endif /* _NXT_UPSTREAM_SOURCE_H_INCLUDED_ */

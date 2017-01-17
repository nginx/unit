
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_HTTP_PARSE_H_INCLUDED_
#define _NXT_HTTP_PARSE_H_INCLUDED_


typedef struct {
    uint8_t                  state;
    uint8_t                  http_version;

    uint32_t                 code;

    u_char                   *start;
    u_char                   *end;
} nxt_http_status_parse_t;


nxt_int_t nxt_http_status_parse(nxt_http_status_parse_t *sp, nxt_buf_mem_t *b);


typedef struct {
    uint32_t                 header_hash;

    uint8_t                  state;
    uint8_t                  underscore;      /* 1 bit */
    uint8_t                  invalid_header;  /* 1 bit */
    uint8_t                  upstream;        /* 1 bit */

    u_char                   *header_start;
    u_char                   *header_end;
    u_char                   *header_name_start;
    u_char                   *header_name_end;
} nxt_http_header_parse_t;


NXT_EXPORT nxt_int_t nxt_http_header_parse(nxt_http_header_parse_t *hp,
    nxt_buf_mem_t *b);


typedef struct {
    u_char                   *start;
    u_char                   *end;
} nxt_http_header_part_t;


typedef struct {
    nxt_array_t              *parts;  /* of nxt_http_header_part_t */
    nxt_mem_pool_t           *mem_pool;

    nxt_http_header_parse_t  parse;
} nxt_http_split_header_parse_t;


nxt_int_t nxt_http_split_header_parse(nxt_http_split_header_parse_t *shp,
    nxt_buf_mem_t *b);


typedef struct {
    u_char                   *pos;
    nxt_mem_pool_t           *mem_pool;

    uint64_t                 chunk_size;

    uint8_t                  state;
    uint8_t                  last;         /* 1 bit */
    uint8_t                  chunk_error;  /* 1 bit */
    uint8_t                  error;        /* 1 bit */
} nxt_http_chunk_parse_t;


NXT_EXPORT nxt_buf_t *nxt_http_chunk_parse(nxt_http_chunk_parse_t *hcp,
    nxt_buf_t *in);


#endif /* _NXT_HTTP_PARSE_H_INCLUDED_ */

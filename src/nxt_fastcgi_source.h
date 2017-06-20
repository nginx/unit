
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_FASTCGI_SOURCE_H_INCLUDED_
#define _NXT_FASTCGI_SOURCE_H_INCLUDED_


#define NXT_FASTCGI_BEGIN_REQUEST        1
#define NXT_FASTCGI_ABORT_REQUEST        2
#define NXT_FASTCGI_END_REQUEST          3
#define NXT_FASTCGI_PARAMS               4
#define NXT_FASTCGI_STDIN                5
#define NXT_FASTCGI_STDOUT               6
#define NXT_FASTCGI_STDERR               7
#define NXT_FASTCGI_DATA                 8


typedef struct nxt_fastcgi_parse_s       nxt_fastcgi_parse_t;

struct nxt_fastcgi_parse_s {
    u_char                               *pos;

    uint16_t                             length;         /* 16 bits */
    uint8_t                              padding;
    uint8_t                              type;

    uint8_t                              state;
    uint8_t                              fastcgi_error;  /* 1 bit */
    uint8_t                              error;          /* 1 bit */
    uint8_t                              done;           /* 1 bit */

    /* FastCGI stdout and stderr buffer chains. */
    nxt_buf_t                            *out[2];

    nxt_buf_t                            *(*last_buf)(nxt_fastcgi_parse_t *fp);
    void                                 *data;
    nxt_mp_t                             *mem_pool;
};


typedef struct {
    nxt_fastcgi_parse_t                  parse;
    nxt_source_hook_t                    next;
} nxt_fastcgi_source_record_t;


typedef struct {
    nxt_str_t                            name;
    nxt_str_t                            value;
    uintptr_t                            data[3];
} nxt_fastcgi_source_request_t;


typedef struct nxt_fastcgi_source_s  nxt_fastcgi_source_t;
typedef nxt_int_t (*nxt_fastcgi_source_request_create_t)(
    nxt_fastcgi_source_t *fs);


struct nxt_fastcgi_source_s {
    nxt_source_hook_t                    query;
    nxt_source_hook_t                    *next;

    nxt_upstream_source_t                *upstream;

    nxt_fastcgi_source_request_create_t  request_create;

    nxt_upstream_header_in_t             header_in;

    nxt_buf_t                            *rest;

    uint32_t                             state;  /* 2 bits */

    nxt_fastcgi_source_record_t          record;

    union {
        nxt_fastcgi_source_request_t     request;
    } u;
};


NXT_EXPORT void nxt_fastcgi_source_handler(nxt_task_t *task,
    nxt_upstream_source_t *us,
    nxt_fastcgi_source_request_create_t request_create);
NXT_EXPORT nxt_int_t nxt_fastcgi_source_hash_create(nxt_mp_t *mp,
    nxt_lvlhsh_t *lh);
void nxt_fastcgi_record_parse(nxt_task_t *task, nxt_fastcgi_parse_t *fp,
    nxt_buf_t *in);


#endif /* _NXT_FASTCGI_SOURCE_H_INCLUDED_ */

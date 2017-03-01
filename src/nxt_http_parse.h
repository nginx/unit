
/*
 * Copyright (C) NGINX, Inc.
 * Copyright (C) Valentin V. Bartenev
 */

#ifndef _NXT_HTTP_PARSER_H_INCLUDED_
#define _NXT_HTTP_PARSER_H_INCLUDED_


typedef struct nxt_http_request_parse_s  nxt_http_request_parse_t;
typedef struct nxt_http_fields_hash_s    nxt_http_fields_hash_t;

typedef nxt_int_t (*nxt_http_field_handler_t)(void *ctx, nxt_str_t *name,
                                              nxt_str_t *value, uintptr_t data);


typedef union {
   u_char    str[8];
   uint64_t  ui64;
} nxt_http_ver_t;


struct nxt_http_request_parse_s {
    nxt_int_t               (*handler)(nxt_http_request_parse_t *rp,
                                       u_char **pos, u_char *end);

    size_t                  offset;

    nxt_str_t               method;

    u_char                  *target_start;
    u_char                  *target_end;
    u_char                  *exten_start;
    u_char                  *args_start;

    nxt_http_ver_t          version;

    union {
        uint8_t             str[32];
        uint64_t            ui64[4];
    } field_name_key;

    nxt_str_t               field_name;
    nxt_str_t               field_value;

    nxt_http_fields_hash_t  *hash;
    void                    *ctx;

    /* target with "/." */
    unsigned                complex_target:1;
    /* target with "%" */
    unsigned                quoted_target:1;
    /* target with " " */
    unsigned                space_in_target:1;
    /* target with "+" */
    unsigned                plus_in_target:1;
};


typedef struct {
    nxt_str_t                 name;
    nxt_http_field_handler_t  handler;
    uintptr_t                 data;
} nxt_http_fields_t;


nxt_int_t nxt_http_parse_request(nxt_http_request_parse_t *rp,
    nxt_buf_mem_t *b);
nxt_http_fields_hash_t *nxt_http_fields_hash(nxt_http_fields_t *fields,
    nxt_mem_pool_t *mp);


#endif /* _NXT_HTTP_PARSER_H_INCLUDED_ */

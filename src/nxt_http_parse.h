
/*
 * Copyright (C) NGINX, Inc.
 * Copyright (C) Valentin V. Bartenev
 */

#ifndef _NXT_HTTP_PARSER_H_INCLUDED_
#define _NXT_HTTP_PARSER_H_INCLUDED_


typedef struct nxt_http_request_parse_s  nxt_http_request_parse_t;
typedef struct nxt_http_field_s          nxt_http_field_t;
typedef struct nxt_http_fields_hash_s    nxt_http_fields_hash_t;


typedef union {
   u_char                     str[8];
   uint64_t                   ui64;
} nxt_http_ver_t;


struct nxt_http_request_parse_s {
    nxt_int_t                 (*handler)(nxt_http_request_parse_t *rp,
                                         u_char **pos, u_char *end);

    size_t                    offset;

    nxt_str_t                 method;

    u_char                    *target_start;
    u_char                    *target_end;
    u_char                    *exten_start;
    u_char                    *args_start;

    nxt_str_t                 path;
    nxt_str_t                 args;
    nxt_str_t                 exten;

    nxt_http_ver_t            version;

    union {
        uint8_t               str[32];
        uint64_t              ui64[4];
    } field_key;

    nxt_str_t                 field_name;
    nxt_str_t                 field_value;

    nxt_http_fields_hash_t    *fields_hash;

    nxt_list_t                *fields;
    nxt_mp_t                  *mem_pool;

    /* target with "/." */
    unsigned                  complex_target:1;
    /* target with "%" */
    unsigned                  quoted_target:1;
    /* target with " " */
    unsigned                  space_in_target:1;
    /* target with "+" */
    unsigned                  plus_in_target:1;
};


typedef nxt_int_t (*nxt_http_field_handler_t)(void *ctx,
                                              nxt_http_field_t *field,
                                              nxt_log_t *log);


typedef struct {
    nxt_str_t                 name;
    nxt_http_field_handler_t  handler;
    uintptr_t                 data;
} nxt_http_fields_hash_entry_t;


struct nxt_http_field_s {
    nxt_str_t                 name;
    nxt_str_t                 value;
    nxt_http_field_handler_t  handler;
    uintptr_t                 data;
};


nxt_inline nxt_int_t
nxt_http_parse_request_init(nxt_http_request_parse_t *rp, nxt_mp_t *mp)
{
    rp->mem_pool = mp;

    rp->fields = nxt_list_create(mp, 8, sizeof(nxt_http_field_t));
    if (nxt_slow_path(rp->fields == NULL)){
        return NXT_ERROR;
    }

    return NXT_OK;
}


nxt_int_t nxt_http_parse_request(nxt_http_request_parse_t *rp,
    nxt_buf_mem_t *b);

nxt_http_fields_hash_t *nxt_http_fields_hash_create(
    nxt_http_fields_hash_entry_t *entries, nxt_mp_t *mp);
nxt_int_t nxt_http_fields_process(nxt_list_t *fields, void *ctx,
                                  nxt_log_t *log);


#endif /* _NXT_HTTP_PARSER_H_INCLUDED_ */

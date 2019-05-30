
/*
 * Copyright (C) NGINX, Inc.
 * Copyright (C) Valentin V. Bartenev
 */

#ifndef _NXT_HTTP_PARSER_H_INCLUDED_
#define _NXT_HTTP_PARSER_H_INCLUDED_


typedef enum {
    NXT_HTTP_PARSE_INVALID = 1,
    NXT_HTTP_PARSE_UNSUPPORTED_VERSION,
    NXT_HTTP_PARSE_TOO_LARGE_FIELD,
} nxt_http_parse_error_t;


typedef struct nxt_http_request_parse_s  nxt_http_request_parse_t;
typedef struct nxt_http_field_s          nxt_http_field_t;
typedef struct nxt_http_fields_hash_s    nxt_http_fields_hash_t;


typedef union {
    u_char                    str[8];
    uint64_t                  ui64;

    struct {
        u_char                prefix[5];
        u_char                major;
        u_char                point;
        u_char                minor;
    } s;
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

    nxt_list_t                *fields;
    nxt_mp_t                  *mem_pool;

    nxt_str_t                 field_name;
    nxt_str_t                 field_value;

    uint32_t                  field_hash;

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
                                              uintptr_t data);


typedef struct {
    nxt_str_t                 name;
    nxt_http_field_handler_t  handler;
    uintptr_t                 data;
} nxt_http_field_proc_t;


struct nxt_http_field_s {
    uint16_t                  hash;
    uint8_t                   skip;             /* 1 bit */
    uint8_t                   name_length;
    uint32_t                  value_length;
    u_char                    *name;
    u_char                    *value;
};


#define NXT_HTTP_FIELD_HASH_INIT        159406U
#define nxt_http_field_hash_char(h, c)  (((h) << 4) + (h) + (c))
#define nxt_http_field_hash_end(h)      (((h) >> 16) ^ (h))


nxt_int_t nxt_http_parse_request_init(nxt_http_request_parse_t *rp,
    nxt_mp_t *mp);
nxt_int_t nxt_http_parse_request(nxt_http_request_parse_t *rp,
    nxt_buf_mem_t *b);
nxt_int_t nxt_http_parse_fields(nxt_http_request_parse_t *rp,
    nxt_buf_mem_t *b);

nxt_int_t nxt_http_fields_hash(nxt_lvlhsh_t *hash, nxt_mp_t *mp,
    nxt_http_field_proc_t items[], nxt_uint_t count);
nxt_uint_t nxt_http_fields_hash_collisions(nxt_lvlhsh_t *hash, nxt_mp_t *mp,
    nxt_http_field_proc_t items[], nxt_uint_t count, nxt_bool_t level);
nxt_int_t nxt_http_fields_process(nxt_list_t *fields, nxt_lvlhsh_t *hash,
    void *ctx);


#endif /* _NXT_HTTP_PARSER_H_INCLUDED_ */

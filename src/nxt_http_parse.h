
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
    u_char                    str[8] NXT_NONSTRING;
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
                                         u_char **pos, const u_char *end);

    nxt_str_t                 method;

    u_char                    *target_start;
    u_char                    *target_end;
    u_char                    *request_line_end;

    nxt_str_t                 path;
    nxt_str_t                 args;

    nxt_http_ver_t            version;

    nxt_list_t                *fields;
    nxt_mp_t                  *mem_pool;

    nxt_str_t                 field_name;
    nxt_str_t                 field_value;

    uint32_t                  field_hash;

    uint8_t                   skip_field;             /* 1 bit */
    uint8_t                   discard_unsafe_fields;  /* 1 bit */

    /* target with "/." */
    uint8_t                   complex_target;         /* 1 bit */
    /* target with "%" */
    uint8_t                   quoted_target;          /* 1 bit */
#if 0
    /* target with " " */
    uint8_t                   space_in_target;        /* 1 bit */
#endif
    /* Preserve encoded '/' (%2F) and '%' (%25). */
    uint8_t                   encoded_slashes;        /* 1 bit */
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
    uint8_t                   skip:1;
    uint8_t                   hopbyhop:1;
    uint8_t                   name_length;
    uint32_t                  value_length;
    u_char                    *name;
    u_char                    *value;
};


typedef struct {
    nxt_mp_t                  *mem_pool;
    uint64_t                  chunk_size;
    uint8_t                   state;
    uint8_t                   last;         /* 1 bit */
    uint8_t                   chunk_error;  /* 1 bit */
    uint8_t                   error;        /* 1 bit */
} nxt_http_chunk_parse_t;


#define NXT_HTTP_FIELD_HASH_INIT        159406U
#define nxt_http_field_hash_char(h, c)  (((h) << 4) + (h) + (c))
#define nxt_http_field_hash_end(h)      (((h) >> 16) ^ (h))


nxt_int_t nxt_http_parse_request_init(nxt_http_request_parse_t *rp,
    nxt_mp_t *mp);
nxt_int_t nxt_http_parse_request(nxt_http_request_parse_t *rp,
    nxt_buf_mem_t *b);
nxt_int_t nxt_http_parse_fields(nxt_http_request_parse_t *rp,
    nxt_buf_mem_t *b);

nxt_int_t nxt_http_fields_hash(nxt_lvlhsh_t *hash,
    nxt_http_field_proc_t items[], nxt_uint_t count);
nxt_uint_t nxt_http_fields_hash_collisions(nxt_lvlhsh_t *hash,
    nxt_http_field_proc_t items[], nxt_uint_t count, nxt_bool_t level);
nxt_int_t nxt_http_fields_process(nxt_list_t *fields, nxt_lvlhsh_t *hash,
    void *ctx);

nxt_int_t nxt_http_parse_complex_target(nxt_http_request_parse_t *rp);
nxt_buf_t *nxt_http_chunk_parse(nxt_task_t *task, nxt_http_chunk_parse_t *hcp,
    nxt_buf_t *in);


extern const nxt_lvlhsh_proto_t  nxt_http_fields_hash_proto;

nxt_inline nxt_int_t
nxt_http_field_process(nxt_http_field_t *field, nxt_lvlhsh_t *hash, void *ctx)
{
    nxt_lvlhsh_query_t     lhq;
    nxt_http_field_proc_t  *proc;

    lhq.proto = &nxt_http_fields_hash_proto;

    lhq.key_hash = field->hash;
    lhq.key.length = field->name_length;
    lhq.key.start = field->name;

    if (nxt_lvlhsh_find(hash, &lhq) != NXT_OK) {
        return NXT_OK;
    }

    proc = lhq.value;

    return proc->handler(ctx, field, proc->data);
}


#endif /* _NXT_HTTP_PARSER_H_INCLUDED_ */

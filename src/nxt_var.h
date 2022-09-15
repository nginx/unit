
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_VAR_H_INCLUDED_
#define _NXT_VAR_H_INCLUDED_


typedef struct nxt_var_s        nxt_var_t;
typedef struct nxt_var_query_s  nxt_var_query_t;


typedef nxt_int_t (*nxt_var_handler_t)(nxt_task_t *task,
                                       nxt_str_t *str,
                                       void *ctx, uint16_t field);

typedef int64_t (*nxt_var_field_hash_t)(nxt_mp_t *mp, nxt_str_t *str);

typedef struct {
    nxt_str_t               name;
    nxt_var_handler_t       handler;
    nxt_var_field_hash_t    field_hash;
    uint32_t                index;
} nxt_var_decl_t;


typedef struct {
    nxt_str_t               name;
    uint16_t                hash;
    uint32_t                index;
} nxt_var_field_t;


typedef enum {
    NXT_VAR_STRZ       = 1 << 0,
    NXT_VAR_LOGGING    = 1 << 1,
} nxt_var_flags_t;


nxt_inline nxt_bool_t
nxt_is_var(nxt_str_t *str)
{
    return (nxt_memchr(str->start, '$', str->length) != NULL);
}


nxt_int_t nxt_var_register(nxt_var_decl_t *decl, size_t n);
nxt_int_t nxt_var_index_init(void);

nxt_var_field_t *nxt_var_field_get(nxt_array_t *fields, uint16_t index);

nxt_var_t *nxt_var_compile(nxt_str_t *str, nxt_mp_t *mp, nxt_array_t *fields,
    nxt_var_flags_t flags);
nxt_int_t nxt_var_test(nxt_str_t *str, nxt_array_t *fields, u_char *error);

nxt_bool_t nxt_var_is_const(nxt_var_t *var);
void nxt_var_raw(nxt_var_t *var, nxt_str_t *str);

nxt_int_t nxt_var_query_init(nxt_var_query_t **query_p, void *ctx,
    nxt_mp_t *mp);
void nxt_var_query(nxt_task_t *task, nxt_var_query_t *query,
    nxt_var_t *var, nxt_str_t *str);
void nxt_var_query_resolve(nxt_task_t *task, nxt_var_query_t *query, void *data,
    nxt_work_handler_t ready, nxt_work_handler_t error);
void nxt_var_query_handle(nxt_task_t *task, nxt_var_query_t *query,
    nxt_bool_t failed);


#endif /* _NXT_VAR_H_INCLUDED_ */

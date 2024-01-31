
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_VAR_H_INCLUDED_
#define _NXT_VAR_H_INCLUDED_


typedef struct nxt_var_s        nxt_var_t;
typedef struct nxt_var_query_s  nxt_var_query_t;


typedef nxt_int_t (*nxt_var_handler_t)(nxt_task_t *task,
                                       nxt_str_t *str,
                                       void *ctx, void *data);

typedef int64_t (*nxt_var_field_hash_t)(nxt_mp_t *mp, nxt_str_t *str);

typedef struct {
    nxt_str_t               name;
    nxt_var_handler_t       handler;
    uint8_t                 cacheable;  /* 1 bit */
} nxt_var_decl_t;


typedef struct {
    nxt_str_t               *name;
    nxt_var_handler_t       handler;
    void                    *data;
    uint32_t                index;
    uint8_t                 cacheable;  /* 1 bit */
} nxt_var_ref_t;


typedef struct {
    nxt_str_t               name;
    uint16_t                hash;
} nxt_var_field_t;


typedef struct {
    nxt_mp_t                *pool;
    nxt_lvlhsh_t            hash;
    nxt_str_t               *spare;
} nxt_var_cache_t;


nxt_int_t nxt_var_register(nxt_var_decl_t *decl, size_t n);
nxt_int_t nxt_var_index_init(void);

nxt_var_field_t *nxt_var_field_get(nxt_array_t *fields, uint16_t index);
nxt_var_field_t *nxt_var_field_new(nxt_mp_t *mp, nxt_str_t *name,
    uint32_t hash);

nxt_var_t *nxt_var_compile(nxt_tstr_state_t *state, nxt_str_t *str);
nxt_int_t nxt_var_test(nxt_tstr_state_t *state, nxt_str_t *str, u_char *error);

nxt_int_t nxt_var_interpreter(nxt_task_t *task, nxt_tstr_state_t *state,
    nxt_var_cache_t *cache, nxt_var_t *var, nxt_str_t *str, void *ctx,
    nxt_bool_t logging);
nxt_str_t *nxt_var_get(nxt_task_t *task, nxt_tstr_state_t *state,
    nxt_var_cache_t *cache, nxt_str_t *name, void *ctx);

nxt_int_t nxt_http_unknown_var_ref(nxt_mp_t *mp, nxt_var_ref_t *ref,
    nxt_str_t *name);


#endif /* _NXT_VAR_H_INCLUDED_ */

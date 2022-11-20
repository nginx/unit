
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_TSTR_H_INCLUDED_
#define _NXT_TSTR_H_INCLUDED_


typedef struct nxt_tstr_s        nxt_tstr_t;
typedef struct nxt_tstr_query_s  nxt_tstr_query_t;


typedef struct {
    nxt_mp_t            *pool;
    nxt_array_t         *var_fields;
} nxt_tstr_state_t;


typedef enum {
    NXT_TSTR_STRZ       = 1 << 0,
    NXT_TSTR_LOGGING    = 1 << 1,
} nxt_tstr_flags_t;


nxt_tstr_state_t *nxt_tstr_state_new(nxt_mp_t *mp);
nxt_tstr_t *nxt_tstr_compile(nxt_tstr_state_t *state, nxt_str_t *str,
    nxt_tstr_flags_t flags);
nxt_int_t nxt_tstr_test(nxt_tstr_state_t *state, nxt_str_t *str, u_char *error);

nxt_bool_t nxt_tstr_is_const(nxt_tstr_t *tstr);
void nxt_tstr_str(nxt_tstr_t *tstr, nxt_str_t *str);

nxt_int_t nxt_tstr_query_init(nxt_tstr_query_t **query_p,
    nxt_tstr_state_t *state, nxt_var_cache_t *cache, void *ctx,
    nxt_mp_t *mp);
void nxt_tstr_query(nxt_task_t *task, nxt_tstr_query_t *query, nxt_tstr_t *tstr,
    nxt_str_t *val);
void nxt_tstr_query_resolve(nxt_task_t *task, nxt_tstr_query_t *query,
    void *data, nxt_work_handler_t ready, nxt_work_handler_t error);
void nxt_tstr_query_handle(nxt_task_t *task, nxt_tstr_query_t *query,
    nxt_bool_t failed);


#endif /* _NXT_TSTR_H_INCLUDED_ */

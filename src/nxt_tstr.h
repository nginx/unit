
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_TSTR_H_INCLUDED_
#define _NXT_TSTR_H_INCLUDED_


#include <nxt_js.h>

typedef struct nxt_tstr_s        nxt_tstr_t;
typedef struct nxt_tstr_query_s  nxt_tstr_query_t;


struct nxt_tstr_state_s {
    nxt_mp_t            *pool;
    nxt_array_t         *var_refs;
#if (NXT_HAVE_NJS)
    nxt_js_conf_t       *jcf;
#endif
    uint8_t             test;  /* 1 bit */
};


typedef struct {
    nxt_var_cache_t     var;
#if (NXT_HAVE_NJS)
    nxt_js_cache_t      js;
#endif
} nxt_tstr_cache_t;


typedef enum {
    NXT_TSTR_STRZ       = 1 << 0,
    NXT_TSTR_LOGGING    = 1 << 1,
} nxt_tstr_flags_t;


nxt_tstr_state_t *nxt_tstr_state_new(nxt_mp_t *mp, nxt_bool_t test);
nxt_tstr_t *nxt_tstr_compile(nxt_tstr_state_t *state, nxt_str_t *str,
    nxt_tstr_flags_t flags);
nxt_int_t nxt_tstr_test(nxt_tstr_state_t *state, nxt_str_t *str, u_char *error);
nxt_int_t nxt_tstr_state_done(nxt_tstr_state_t *state, u_char *error);
void nxt_tstr_state_release(nxt_tstr_state_t *state);

nxt_bool_t nxt_tstr_is_const(nxt_tstr_t *tstr);
void nxt_tstr_str(nxt_tstr_t *tstr, nxt_str_t *str);

nxt_int_t nxt_tstr_query_init(nxt_tstr_query_t **query_p,
    nxt_tstr_state_t *state, nxt_tstr_cache_t *cache, void *ctx,
    nxt_mp_t *mp);
void nxt_tstr_query(nxt_task_t *task, nxt_tstr_query_t *query, nxt_tstr_t *tstr,
    nxt_str_t *val);
nxt_bool_t nxt_tstr_query_failed(nxt_tstr_query_t *query);
void nxt_tstr_query_resolve(nxt_task_t *task, nxt_tstr_query_t *query,
    void *data, nxt_work_handler_t ready, nxt_work_handler_t error);
void nxt_tstr_query_handle(nxt_task_t *task, nxt_tstr_query_t *query,
    nxt_bool_t failed);
void nxt_tstr_query_release(nxt_tstr_query_t *query);


nxt_inline nxt_bool_t
nxt_is_tstr(nxt_str_t *str)
{
    u_char  *p;

    p = memchr(str->start, '`', str->length);
    if (p != NULL) {
        return 1;
    }

    p = memchr(str->start, '$', str->length);
    if (p != NULL) {
        return 1;
    }

    return 0;
}


#endif /* _NXT_TSTR_H_INCLUDED_ */

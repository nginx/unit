/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>

typedef enum {
    NXT_TSTR_CONST = 0,
    NXT_TSTR_VAR,
#if (NXT_HAVE_NJS)
    NXT_TSTR_JS,
#endif
} nxt_tstr_type_t;

struct nxt_tstr_s {
    nxt_str_t str;

    union {
        nxt_var_t *var;
#if (NXT_HAVE_NJS)
        nxt_js_t *js;
#endif
    } u;

    nxt_tstr_flags_t flags;
    nxt_tstr_type_t  type;
};

struct nxt_tstr_query_s {
    nxt_mp_t *pool;

    nxt_tstr_state_t *state;
    nxt_tstr_cache_t *cache;

    void *ctx;
    void *data;
};

#define nxt_tstr_is_js(str) nxt_strchr_start(str, '`')

nxt_tstr_state_t *
nxt_tstr_state_new(nxt_mp_t *mp, nxt_bool_t test)
{
    nxt_tstr_state_t *state;

    state = nxt_mp_get(mp, sizeof(nxt_tstr_state_t));
    if (nxt_slow_path(state == NULL)) {
        return NULL;
    }

    state->pool     = mp;
    state->test     = test;

    state->var_refs = nxt_array_create(mp, 4, sizeof(nxt_var_ref_t));
    if (nxt_slow_path(state->var_refs == NULL)) {
        return NULL;
    }

#if (NXT_HAVE_NJS)
    state->jcf = nxt_js_conf_new(mp, test);
    if (nxt_slow_path(state->jcf == NULL)) {
        return NULL;
    }
#endif

    return state;
}

nxt_tstr_t *
nxt_tstr_compile(nxt_tstr_state_t *state, const nxt_str_t *str,
                 nxt_tstr_flags_t flags)
{
    u_char     *p;
    nxt_tstr_t *tstr;
    nxt_bool_t  strz, newline;

    strz    = (flags & NXT_TSTR_STRZ) != 0;
    newline = (flags & NXT_TSTR_NEWLINE) != 0;

    tstr    = nxt_mp_get(state->pool, sizeof(nxt_tstr_t));
    if (nxt_slow_path(tstr == NULL)) {
        return NULL;
    }

    tstr->str.length = str->length + newline + strz;

    tstr->str.start  = nxt_mp_nget(state->pool, tstr->str.length);
    if (nxt_slow_path(tstr->str.start == NULL)) {
        return NULL;
    }

    p = nxt_cpymem(tstr->str.start, str->start, str->length);

    if (newline) {
        *p++ = '\n';
    }

    if (strz) {
        *p = '\0';
    }

    tstr->flags = flags;

    if (nxt_tstr_is_js(str)) {
#if (NXT_HAVE_NJS)

        nxt_str_t tpl;

        tstr->type = NXT_TSTR_JS;

        nxt_tstr_str(tstr, &tpl);

        tstr->u.js = nxt_js_add_tpl(state->jcf, &tpl, flags);
        if (nxt_slow_path(tstr->u.js == NULL)) {
            return NULL;
        }

#endif

    } else {
        p = memchr(str->start, '$', str->length);

        if (p != NULL) {
            tstr->type  = NXT_TSTR_VAR;

            tstr->u.var = nxt_var_compile(state, &tstr->str);
            if (nxt_slow_path(tstr->u.var == NULL)) {
                return NULL;
            }

        } else {
            tstr->type = NXT_TSTR_CONST;
        }
    }

    return tstr;
}

nxt_int_t
nxt_tstr_test(nxt_tstr_state_t *state, nxt_str_t *str, u_char *error)
{
    u_char *p;

    if (nxt_tstr_is_js(str)) {
#if (NXT_HAVE_NJS)
        return nxt_js_test(state->jcf, str, error);

#else
        nxt_sprintf(error, error + NXT_MAX_ERROR_STR,
                    "Unit is built without support of njs: "
                    "\"--njs\" ./configure option is missing.%Z");
        return NXT_ERROR;
#endif

    } else {
        p = memchr(str->start, '$', str->length);

        if (p != NULL) {
            return nxt_var_test(state, str, error);
        }
    }

    return NXT_OK;
}

nxt_int_t
nxt_tstr_state_done(nxt_tstr_state_t *state, u_char *error)
{
#if (NXT_HAVE_NJS)
    if (!state->test) {
        nxt_int_t ret;

        ret = nxt_js_compile(state->jcf);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }
    }
#endif

    return NXT_OK;
}

void
nxt_tstr_state_release(nxt_tstr_state_t *state)
{
#if (NXT_HAVE_NJS)
    nxt_js_conf_release(state->jcf);
#endif
}

nxt_int_t
nxt_tstr_cond_compile(nxt_tstr_state_t *state, nxt_str_t *str,
                      nxt_tstr_cond_t *cond)
{
    if (str->length > 0 && str->start[0] == '!') {
        cond->negate = 1;

        str->start++;
        str->length--;
    }

    cond->expr = nxt_tstr_compile(state, str, 0);
    if (nxt_slow_path(cond->expr == NULL)) {
        return NXT_ERROR;
    }

    return NXT_OK;
}

nxt_bool_t
nxt_tstr_is_const(nxt_tstr_t *tstr)
{
    return (tstr->type == NXT_TSTR_CONST);
}

void
nxt_tstr_str(nxt_tstr_t *tstr, nxt_str_t *str)
{
    *str = tstr->str;

    if (tstr->flags & NXT_TSTR_STRZ) {
        str->length--;
    }
}

nxt_int_t
nxt_tstr_query_init(nxt_tstr_query_t **query_p, nxt_tstr_state_t *state,
                    nxt_tstr_cache_t *cache, void *ctx, nxt_mp_t *mp)
{
    nxt_tstr_query_t *query;

    query = *query_p;

    if (*query_p == NULL) {
        query = nxt_mp_zget(mp, sizeof(nxt_tstr_query_t));
        if (nxt_slow_path(query == NULL)) {
            return NXT_ERROR;
        }
    }

    query->pool  = mp;
    query->state = state;
    query->cache = cache;
    query->ctx   = ctx;

    *query_p     = query;

    return NXT_OK;
}

nxt_int_t
nxt_tstr_query(nxt_task_t *task, nxt_tstr_query_t *query, nxt_tstr_t *tstr,
               nxt_str_t *val)
{
    nxt_int_t ret;

    if (nxt_tstr_is_const(tstr)) {
        nxt_tstr_str(tstr, val);
        return NXT_OK;
    }

    if (tstr->type == NXT_TSTR_VAR) {
        ret = nxt_var_interpreter(task, query->state, &query->cache->var,
                                  tstr->u.var, val, query->ctx,
                                  tstr->flags & NXT_TSTR_LOGGING);

        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }

    } else {
#if (NXT_HAVE_NJS)
        ret = nxt_js_call(task, query->state->jcf, &query->cache->js,
                          tstr->u.js, val, query->ctx);

        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }
#endif
    }

    if (tstr->flags & NXT_TSTR_STRZ) {
        val->length--;
    }

#if (NXT_DEBUG)
    nxt_str_t str;

    nxt_tstr_str(tstr, &str);

    nxt_debug(task, "tstr query: \"%V\", result: \"%V\"", &str, val);
#endif

    return NXT_OK;
}

void
nxt_tstr_query_release(nxt_tstr_query_t *query)
{
#if (NXT_HAVE_NJS)
    nxt_js_release(&query->cache->js);
#endif
}

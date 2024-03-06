
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


struct nxt_var_s {
    size_t              length;
    nxt_uint_t          vars;
    u_char              data[];

/*
    nxt_var_sub_t       subs[vars];
    u_char              raw[length];
*/
};


typedef struct {
    uint32_t            index;
    uint32_t            length;
    uint32_t            position;
} nxt_var_sub_t;


struct nxt_var_query_s {
    nxt_mp_t            *pool;

    nxt_var_cache_t     cache;

    nxt_uint_t          waiting;
    nxt_uint_t          failed;   /* 1 bit */

    void                *ctx;
    void                *data;

    nxt_work_handler_t  ready;
    nxt_work_handler_t  error;
};


#define nxt_var_subs(var)  ((nxt_var_sub_t *) (var)->data)

#define nxt_var_raw_start(var)                                                \
    ((var)->data + (var)->vars * sizeof(nxt_var_sub_t))


static nxt_int_t nxt_var_hash_test(nxt_lvlhsh_query_t *lhq, void *data);
static nxt_var_decl_t *nxt_var_hash_find(nxt_str_t *name);

static nxt_var_ref_t *nxt_var_ref_get(nxt_tstr_state_t *state, nxt_str_t *name,
    nxt_mp_t *mp);

static nxt_int_t nxt_var_cache_test(nxt_lvlhsh_query_t *lhq, void *data);
static nxt_str_t *nxt_var_cache_value(nxt_task_t *task, nxt_tstr_state_t *state,
    nxt_var_cache_t *cache, nxt_var_ref_t *ref, void *ctx);

static u_char *nxt_var_next_part(u_char *start, u_char *end, nxt_str_t *part);


static const nxt_lvlhsh_proto_t  nxt_var_hash_proto  nxt_aligned(64) = {
    NXT_LVLHSH_DEFAULT,
    nxt_var_hash_test,
    nxt_lvlhsh_alloc,
    nxt_lvlhsh_free,
};

static const nxt_lvlhsh_proto_t  nxt_var_cache_proto  nxt_aligned(64) = {
    NXT_LVLHSH_DEFAULT,
    nxt_var_cache_test,
    nxt_mp_lvlhsh_alloc,
    nxt_mp_lvlhsh_free,
};


static nxt_lvlhsh_t       nxt_var_hash;
static uint32_t           nxt_var_count;

static nxt_var_decl_t     **nxt_vars;


static nxt_int_t
nxt_var_hash_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_var_decl_t  *decl;

    decl = data;

    return nxt_strstr_eq(&lhq->key, &decl->name) ? NXT_OK : NXT_DECLINED;
}


static nxt_var_decl_t *
nxt_var_hash_find(nxt_str_t *name)
{
    nxt_lvlhsh_query_t  lhq;

    lhq.key_hash = nxt_djb_hash(name->start, name->length);
    lhq.key = *name;
    lhq.proto = &nxt_var_hash_proto;

    if (nxt_lvlhsh_find(&nxt_var_hash, &lhq) != NXT_OK) {
        return NULL;
    }

    return lhq.value;
}


static nxt_var_ref_t *
nxt_var_ref_get(nxt_tstr_state_t *state, nxt_str_t *name, nxt_mp_t *mp)
{
    nxt_int_t       ret;
    nxt_uint_t      i;
    nxt_var_ref_t   *ref;
    nxt_var_decl_t  *decl;

    ref = state->var_refs->elts;

    for (i = 0; i < state->var_refs->nelts; i++) {

        if (nxt_strstr_eq(ref[i].name, name)) {
            return &ref[i];
        }
    }

    if (mp != NULL) {
        ref = nxt_mp_alloc(mp, sizeof(nxt_var_ref_t));
        if (nxt_slow_path(ref == NULL)) {
            return NULL;
        }

    } else {
        ref = nxt_array_add(state->var_refs);
        if (nxt_slow_path(ref == NULL)) {
            return NULL;
        }

        ref->index = state->var_refs->nelts - 1;

        mp = state->pool;
    }

    decl = nxt_var_hash_find(name);

    if (decl != NULL) {
        ref->handler = decl->handler;
        ref->cacheable = (mp == state->pool) ? decl->cacheable : 0;

        goto done;
    }

    ret = nxt_http_unknown_var_ref(mp, ref, name);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NULL;
    }

done:

    ref->name = nxt_str_dup(mp, NULL, name);
    if (nxt_slow_path(ref->name == NULL)) {
        return NULL;
    }

    return ref;
}


nxt_var_field_t *
nxt_var_field_new(nxt_mp_t *mp, nxt_str_t *name, uint32_t hash)
{
    nxt_str_t        *str;
    nxt_var_field_t  *field;

    field = nxt_mp_alloc(mp, sizeof(nxt_var_field_t));
    if (nxt_slow_path(field == NULL)) {
        return NULL;
    }

    str = nxt_str_dup(mp, &field->name, name);
    if (nxt_slow_path(str == NULL)) {
        return NULL;
    }

    field->hash = hash;

    return field;
}


nxt_var_field_t *
nxt_var_field_get(nxt_array_t *fields, uint16_t index)
{
    nxt_uint_t       nfields;
    nxt_var_field_t  *field;

    field = fields->elts;
    nfields = fields->nelts;

    if (nfields > 0 && index <= nfields) {
        return &field[index];
    }

    return NULL;
}


static nxt_int_t
nxt_var_cache_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    return NXT_OK;
}


static nxt_str_t *
nxt_var_cache_value(nxt_task_t *task, nxt_tstr_state_t *state,
    nxt_var_cache_t *cache, nxt_var_ref_t *ref, void *ctx)
{
    nxt_int_t           ret;
    nxt_str_t           *value;
    nxt_lvlhsh_query_t  lhq;

    value = cache->spare;

    if (value == NULL) {
        value = nxt_mp_zget(cache->pool, sizeof(nxt_str_t));
        if (nxt_slow_path(value == NULL)) {
            return NULL;
        }

        cache->spare = value;
    }

    if (!ref->cacheable) {
        goto not_cached;
    }

    lhq.key_hash = nxt_murmur_hash2_uint32(&ref->index);
    lhq.replace = 0;
    lhq.key.length = sizeof(uint32_t);
    lhq.key.start = (u_char *) &ref->index;
    lhq.value = value;
    lhq.proto = &nxt_var_cache_proto;
    lhq.pool = cache->pool;

    ret = nxt_lvlhsh_insert(&cache->hash, &lhq);
    if (nxt_slow_path(ret == NXT_ERROR)) {
        return NULL;
    }

    if (ret == NXT_DECLINED) {
        return lhq.value;
    }

not_cached:

    ret = ref->handler(task, value, ctx, ref->data);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NULL;
    }

    cache->spare = NULL;

    return value;
}


nxt_int_t
nxt_var_register(nxt_var_decl_t *decl, size_t n)
{
    nxt_uint_t          i;
    nxt_lvlhsh_query_t  lhq;

    lhq.replace = 0;
    lhq.proto = &nxt_var_hash_proto;

    for (i = 0; i < n; i++) {
        lhq.key = decl[i].name;
        lhq.key_hash = nxt_djb_hash(lhq.key.start, lhq.key.length);
        lhq.value = &decl[i];

        if (nxt_slow_path(nxt_lvlhsh_insert(&nxt_var_hash, &lhq) != NXT_OK)) {
            return NXT_ERROR;
        }
    }

    nxt_var_count += n;

    return NXT_OK;
}


nxt_int_t
nxt_var_index_init(void)
{
    nxt_uint_t         i;
    nxt_var_decl_t     *decl, **vars;
    nxt_lvlhsh_each_t  lhe;

    vars = nxt_memalign(64, nxt_var_count * sizeof(nxt_var_decl_t *));
    if (vars == NULL) {
        return NXT_ERROR;
    }

    nxt_lvlhsh_each_init(&lhe, &nxt_var_hash_proto);

    for (i = 0; i < nxt_var_count; i++) {
        decl = nxt_lvlhsh_each(&nxt_var_hash, &lhe);
        vars[i] = decl;
    }

    nxt_vars = vars;

    return NXT_OK;
}


nxt_var_t *
nxt_var_compile(nxt_tstr_state_t *state, nxt_str_t *str)
{
    u_char         *p, *end, *next, *src;
    size_t         size;
    nxt_var_t      *var;
    nxt_str_t      part;
    nxt_uint_t     n;
    nxt_var_sub_t  *subs;
    nxt_var_ref_t  *ref;

    n = 0;

    p = str->start;
    end = p + str->length;

    while (p < end) {
        p = nxt_var_next_part(p, end, &part);
        if (nxt_slow_path(p == NULL)) {
            return NULL;
        }

        if (part.start != NULL) {
            n++;
        }
    }

    size = sizeof(nxt_var_t) + n * sizeof(nxt_var_sub_t) + str->length;

    var = nxt_mp_get(state->pool, size);
    if (nxt_slow_path(var == NULL)) {
        return NULL;
    }

    var->length = str->length;
    var->vars = n;

    subs = nxt_var_subs(var);
    src = nxt_var_raw_start(var);

    nxt_memcpy(src, str->start, str->length);

    n = 0;
    p = str->start;

    while (p < end) {
        next = nxt_var_next_part(p, end, &part);

        if (part.start != NULL) {
            ref = nxt_var_ref_get(state, &part, NULL);
            if (nxt_slow_path(ref == NULL)) {
                return NULL;
            }

            subs[n].index = ref->index;
            subs[n].length = next - p;
            subs[n].position = p - str->start;

            n++;
        }

        p = next;
    }

    return var;
}


nxt_int_t
nxt_var_test(nxt_tstr_state_t *state, nxt_str_t *str, u_char *error)
{
    u_char         *p, *end, *next;
    nxt_str_t      part;
    nxt_var_ref_t  *ref;

    p = str->start;
    end = p + str->length;

    while (p < end) {
        next = nxt_var_next_part(p, end, &part);

        if (next == NULL) {
            nxt_sprintf(error, error + NXT_MAX_ERROR_STR,
                        "Invalid variable at position %uz%Z", p - str->start);

            return NXT_ERROR;
        }

        if (part.start != NULL) {
            ref = nxt_var_ref_get(state, &part, NULL);

            if (ref == NULL) {
                nxt_sprintf(error, error + NXT_MAX_ERROR_STR,
                            "Unknown variable \"%V\"%Z", &part);

                return NXT_ERROR;
            }
        }

        p = next;
    }

    return NXT_OK;
}


static u_char *
nxt_var_next_part(u_char *start, u_char *end, nxt_str_t *part)
{
    size_t      length;
    u_char      *p, ch, c;
    nxt_bool_t  bracket;

    p = memchr(start, '$', end - start);

    if (p == start) {
        p++;

        if (p == end) {
            return NULL;
        }

        if (*p == '{') {
            bracket = 1;

            if (end - p < 2) {
                return NULL;
            }

            p++;

        } else {
            bracket = 0;
        }

        length = 0;
        start = p;

        while (p < end) {
            ch = *p;

            c = (u_char) (ch | 0x20);

            if ((c >= 'a' && c <= 'z') || ch == '_') {
                p++;
                length++;
                continue;
            }

            if (bracket && ch == '}') {
                p++;
                bracket = 0;
            }

            break;
        }

        if (bracket || length == 0) {
            return NULL;
        }

        part->length = length;
        part->start = start;

    } else {
        if (p == NULL) {
            p = end;
        }

        nxt_str_null(part);
    }

    return p;
}


nxt_int_t
nxt_var_interpreter(nxt_task_t *task, nxt_tstr_state_t *state,
    nxt_var_cache_t *cache, nxt_var_t *var, nxt_str_t *str, void *ctx,
    nxt_bool_t logging)
{
    u_char         *p, *src;
    size_t         length, last, next;
    uint32_t       index;
    nxt_str_t      *value, **part;
    nxt_uint_t     i;
    nxt_array_t    parts;
    nxt_var_ref_t  *ref;
    nxt_var_sub_t  *subs;

    nxt_memzero(&parts, sizeof(nxt_array_t));
    nxt_array_init(&parts, cache->pool, sizeof(nxt_str_t *));

    ref = state->var_refs->elts;
    subs = nxt_var_subs(var);

    length = var->length;

    for (i = 0; i < var->vars; i++) {
        index = subs[i].index;
        value = nxt_var_cache_value(task, state, cache, &ref[index], ctx);
        if (nxt_slow_path(value == NULL)) {
            return NXT_ERROR;
        }

        part = nxt_array_add(&parts);
        if (nxt_slow_path(part == NULL)) {
            return NXT_ERROR;
        }

        *part = value;

        length += value->length - subs[i].length;

        if (logging && value->start == NULL) {
            length += 1;
        }
    }

    p = nxt_mp_nget(cache->pool, length);
    if (nxt_slow_path(p == NULL)) {
        return NXT_ERROR;
    }

    str->length = length;
    str->start = p;

    part = parts.elts;
    src = nxt_var_raw_start(var);

    last = 0;

    for (i = 0; i < var->vars; i++) {
        next = subs[i].position;

        if (next != last) {
            p = nxt_cpymem(p, &src[last], next - last);
        }

        p = nxt_cpymem(p, part[i]->start, part[i]->length);

        if (logging && part[i]->start == NULL) {
            *p++ = '-';
        }

        last = next + subs[i].length;
    }

    if (last != var->length) {
        nxt_cpymem(p, &src[last], var->length - last);
    }

    return NXT_OK;
}


nxt_str_t *
nxt_var_get(nxt_task_t *task, nxt_tstr_state_t *state, nxt_var_cache_t *cache,
    nxt_str_t *name, void *ctx)
{
    nxt_var_ref_t  *ref;

    ref = nxt_var_ref_get(state, name, cache->pool);
    if (nxt_slow_path(ref == NULL)) {
        return NULL;
    }

    return nxt_var_cache_value(task, state, cache, ref, ctx);
}

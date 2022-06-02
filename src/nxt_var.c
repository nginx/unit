
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


struct nxt_var_s {
    size_t              length;
    nxt_uint_t          vars;
    nxt_var_flags_t     flags;
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

    nxt_lvlhsh_t        cache;
    nxt_str_t           *spare;

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

static nxt_var_decl_t *nxt_var_decl_get(nxt_str_t *name, nxt_array_t *fields,
    uint32_t *index);
static nxt_var_field_t *nxt_var_field_add(nxt_array_t *fields, nxt_str_t *name,
    uint32_t hash);

static nxt_int_t nxt_var_cache_test(nxt_lvlhsh_query_t *lhq, void *data);
static nxt_str_t *nxt_var_cache_value(nxt_task_t *task, nxt_var_query_t *query,
    uint32_t index);

static u_char *nxt_var_next_part(u_char *start, size_t length, nxt_str_t *part,
    nxt_bool_t *is_var);


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

static nxt_var_handler_t  *nxt_var_index;


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


static nxt_var_decl_t *
nxt_var_decl_get(nxt_str_t *name, nxt_array_t *fields, uint32_t *index)
{
    u_char           *p, *end;
    int64_t          hash;
    uint16_t         field;
    nxt_str_t        str;
    nxt_var_decl_t   *decl;
    nxt_var_field_t  *f;

    f = NULL;
    field = 0;
    decl = nxt_var_hash_find(name);

    if (decl == NULL) {
        p = name->start;
        end = p + name->length;

        while (p < end) {
            if (*p++ == '_') {
                break;
            }
        }

        if (p == end) {
            return NULL;
        }

        str.start = name->start;
        str.length = p - 1 - name->start;

        decl = nxt_var_hash_find(&str);

        if (decl != NULL) {
            str.start = p;
            str.length = end - p;

            hash = decl->field_hash(fields->mem_pool, &str);
            if (nxt_slow_path(hash == -1)) {
                return NULL;
            }

            f = nxt_var_field_add(fields, &str, (uint32_t) hash);
            if (nxt_slow_path(f == NULL)) {
                return NULL;
            }

            field = f->index;
        }
    }

    if (decl != NULL) {
        if (decl->field_hash != NULL && f == NULL) {
            return NULL;
        }

        if (index != NULL) {
            *index = (decl->index << 16) | field;
        }
    }

    return decl;
}


static nxt_var_field_t *
nxt_var_field_add(nxt_array_t *fields, nxt_str_t *name, uint32_t hash)
{
    nxt_uint_t       i;
    nxt_var_field_t  *field;

    field = fields->elts;

    for (i = 0; i < fields->nelts; i++) {
        if (field[i].hash == hash
            && nxt_strstr_eq(&field[i].name, name))
        {
            return field;
        }
    }

    field = nxt_array_add(fields);
    if (nxt_slow_path(field == NULL)) {
        return NULL;
    }

    field->name = *name;
    field->hash = hash;
    field->index = fields->nelts - 1;

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
nxt_var_cache_value(nxt_task_t *task, nxt_var_query_t *query, uint32_t index)
{
    nxt_int_t           ret;
    nxt_str_t           *value;
    nxt_lvlhsh_query_t  lhq;

    value = query->spare;

    if (value == NULL) {
        value = nxt_mp_zget(query->pool, sizeof(nxt_str_t));
        if (nxt_slow_path(value == NULL)) {
            return NULL;
        }

        query->spare = value;
    }

    lhq.key_hash = nxt_murmur_hash2_uint32(&index);
    lhq.replace = 0;
    lhq.key.length = sizeof(uint32_t);
    lhq.key.start = (u_char *) &index;
    lhq.value = value;
    lhq.proto = &nxt_var_cache_proto;
    lhq.pool = query->pool;

    ret = nxt_lvlhsh_insert(&query->cache, &lhq);
    if (nxt_slow_path(ret == NXT_ERROR)) {
        return NULL;
    }

    if (ret == NXT_OK) {
        ret = nxt_var_index[index >> 16](task, value, query->ctx,
                                         index & 0xffff);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NULL;
        }

        query->spare = NULL;
    }

    return lhq.value;
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
    nxt_var_decl_t     *decl;
    nxt_var_handler_t  *index;
    nxt_lvlhsh_each_t  lhe;

    index = nxt_memalign(64, nxt_var_count * sizeof(nxt_var_handler_t));
    if (index == NULL) {
        return NXT_ERROR;
    }

    nxt_lvlhsh_each_init(&lhe, &nxt_var_hash_proto);

    for (i = 0; i < nxt_var_count; i++) {
        decl = nxt_lvlhsh_each(&nxt_var_hash, &lhe);
        decl->index = i;
        index[i] = decl->handler;
    }

    nxt_var_index = index;

    return NXT_OK;
}


nxt_var_t *
nxt_var_compile(nxt_str_t *str, nxt_mp_t *mp, nxt_array_t *fields,
    nxt_var_flags_t flags)
{
    u_char          *p, *end, *next, *src;
    size_t          size;
    uint32_t        index;
    nxt_bool_t      strz;
    nxt_var_t       *var;
    nxt_str_t       part;
    nxt_uint_t      n;
    nxt_bool_t      is_var;
    nxt_var_sub_t   *subs;
    nxt_var_decl_t  *decl;

    strz = (flags & NXT_VAR_STRZ) != 0;

    n = 0;

    p = str->start;
    end = p + str->length;

    while (p < end) {
        p = nxt_var_next_part(p, end - p, &part, &is_var);
        if (nxt_slow_path(p == NULL)) {
            return NULL;
        }

        if (is_var) {
            n++;
        }
    }

    size = sizeof(nxt_var_t) + n * sizeof(nxt_var_sub_t) + str->length;

    var = nxt_mp_get(mp, size + strz);
    if (nxt_slow_path(var == NULL)) {
        return NULL;
    }

    var->length = str->length;
    var->vars = n;
    var->flags = flags;

    subs = nxt_var_subs(var);
    src = nxt_var_raw_start(var);

    nxt_memcpy(src, str->start, str->length);

    if (strz) {
        src[str->length] = '\0';
    }

    n = 0;
    p = str->start;

    while (p < end) {
        next = nxt_var_next_part(p, end - p, &part, &is_var);

        if (is_var) {
            decl = nxt_var_decl_get(&part, fields, &index);
            if (nxt_slow_path(decl == NULL)) {
                return NULL;
            }

            subs[n].index = index;
            subs[n].length = next - p;
            subs[n].position = p - str->start;

            n++;
        }

        p = next;
    }

    return var;
}


nxt_int_t
nxt_var_test(nxt_str_t *str, nxt_array_t *fields, u_char *error)
{
    u_char          *p, *end, *next;
    nxt_str_t       part;
    nxt_bool_t      is_var;
    nxt_var_decl_t  *decl;

    p = str->start;
    end = p + str->length;

    while (p < end) {
        next = nxt_var_next_part(p, end - p, &part, &is_var);

        if (next == NULL) {
            nxt_sprintf(error, error + NXT_MAX_ERROR_STR,
                        "Invalid variable at position %uz%Z", p - str->start);

            return NXT_ERROR;
        }

        if (is_var) {
            decl = nxt_var_decl_get(&part, fields, NULL);

            if (decl == NULL) {
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
nxt_var_next_part(u_char *start, size_t length, nxt_str_t *part,
    nxt_bool_t *is_var)
{
    u_char      *p, *end, ch, c;
    nxt_bool_t  bracket;

    end = start + length;

    p = nxt_memchr(start, '$', length);

    if (p == start) {
        *is_var = 1;

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

        start = p;

        for ( ;; ) {
            ch = *p;

            c = (u_char) (ch | 0x20);
            if ((c < 'a' || c > 'z') && ch != '_') {

                if (bracket && ch != '}') {
                    return NULL;
                }

                break;
            }

            p++;

            if (p == end) {
                if (bracket) {
                    return NULL;
                }

                break;
            }
        }

        length = p - start;
        end = p + bracket;

    } else {
        *is_var = 0;

        if (p != NULL) {
            length = p - start;
            end = p;
        }
    }

    part->length = length;
    part->start = start;

    return end;
}


void
nxt_var_raw(nxt_var_t *var, nxt_str_t *str)
{
    str->length = var->length;
    str->start = nxt_var_raw_start(var);
}


nxt_bool_t
nxt_var_is_const(nxt_var_t *var)
{
    return (var->vars == 0);
}


nxt_int_t
nxt_var_query_init(nxt_var_query_t **query_p, void *ctx, nxt_mp_t *mp)
{
    nxt_var_query_t  *query;

    query = *query_p;

    if (*query_p == NULL) {
        query = nxt_mp_zget(mp, sizeof(nxt_var_query_t));
        if (nxt_slow_path(query == NULL)) {
            return NXT_ERROR;
        }
    }

    query->pool = mp;
    query->ctx = ctx;

    *query_p = query;

    return NXT_OK;
}


void
nxt_var_query(nxt_task_t *task, nxt_var_query_t *query, nxt_var_t *var,
    nxt_str_t *str)
{
    u_char         *p, *src;
    size_t         length, last, next;
    nxt_str_t      *value, **part;
    nxt_uint_t     i;
    nxt_bool_t     strz, logging;
    nxt_array_t    parts;
    nxt_var_sub_t  *subs;

    if (var->vars == 0) {
        nxt_var_raw(var, str);
        return;
    }

    if (nxt_slow_path(query->failed)) {
        return;
    }

    nxt_memzero(&parts, sizeof(nxt_array_t));
    nxt_array_init(&parts, query->pool, sizeof(nxt_str_t *));

    strz = (var->flags & NXT_VAR_STRZ) != 0;
    logging = (var->flags & NXT_VAR_LOGGING) != 0;

    subs = nxt_var_subs(var);

    length = var->length;

    for (i = 0; i < var->vars; i++) {
        value = nxt_var_cache_value(task, query, subs[i].index);
        if (nxt_slow_path(value == NULL)) {
            goto fail;
        }

        part = nxt_array_add(&parts);
        if (nxt_slow_path(part == NULL)) {
            goto fail;
        }

        *part = value;

        length += value->length - subs[i].length;

        if (logging && value->start == NULL) {
            length += 1;
        }
    }

    p = nxt_mp_nget(query->pool, length + strz);
    if (nxt_slow_path(p == NULL)) {
        goto fail;
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
        p = nxt_cpymem(p, &src[last], var->length - last);
    }

    if (strz) {
        *p = '\0';
    }

    nxt_debug(task, "var: \"%*s\" -> \"%V\"", length, src, str);

    return;

fail:

    query->failed = 1;
}


void
nxt_var_query_resolve(nxt_task_t *task, nxt_var_query_t *query, void *data,
    nxt_work_handler_t ready, nxt_work_handler_t error)
{
    query->data = data;
    query->ready = ready;
    query->error = error;

    if (query->waiting == 0) {
        nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                           query->failed ? query->error : query->ready,
                           task, query->ctx, query->data);
    }
}


void
nxt_var_query_handle(nxt_task_t *task, nxt_var_query_t *query,
    nxt_bool_t failed)
{
    query->failed |= failed;

    if (--query->waiting == 0) {
        nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                           query->failed ? query->error : query->ready,
                           task, query->ctx, query->data);
    }
}

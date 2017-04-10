
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_conf.h>
#if 0
#include <math.h>
#include <float.h>
#endif


typedef enum {
    NXT_CONF_JSON_NULL = 0,
    NXT_CONF_JSON_BOOLEAN,
    NXT_CONF_JSON_INTEGER,
    NXT_CONF_JSON_NUMBER,
    NXT_CONF_JSON_SHORT_STRING,
    NXT_CONF_JSON_STRING,
    NXT_CONF_JSON_ARRAY,
    NXT_CONF_JSON_OBJECT,
} nxt_conf_json_type_t;


struct nxt_conf_json_value_s {
    union {
        uint32_t          boolean;  /* 1 bit. */
        int64_t           integer;
     /* double            number; */
        u_char            str[15];
        nxt_str_t         *string;
        nxt_lvlhsh_t      *object;
        nxt_array_t       *array;
    } u;

    nxt_conf_json_type_t  type:8;   /* 3 bits. */
};


typedef struct {
    nxt_conf_json_value_t  name;
    nxt_conf_json_value_t  value;
} nxt_conf_json_obj_member_t;


static nxt_int_t nxt_conf_json_object_hash_test(nxt_lvlhsh_query_t *lhq,
    void *data);
static nxt_int_t nxt_conf_json_object_member_add(nxt_lvlhsh_t *lvlhsh,
    nxt_conf_json_obj_member_t *member, nxt_mem_pool_t *pool);
#if 0
static nxt_conf_json_value_t *nxt_conf_json_object_member_get(
    nxt_lvlhsh_t *lvlhsh, u_char *name, size_t length);
#endif


static u_char *nxt_conf_json_skip_space(u_char *pos, u_char *end);
static u_char *nxt_conf_json_parse_value(u_char *pos, u_char *end,
    nxt_conf_json_value_t *value, nxt_mem_pool_t *pool);
static u_char *nxt_conf_json_parse_object(u_char *pos, u_char *end,
    nxt_conf_json_value_t *value, nxt_mem_pool_t *pool);
static u_char *nxt_conf_json_parse_array(u_char *pos, u_char *end,
    nxt_conf_json_value_t *value, nxt_mem_pool_t *pool);
static u_char *nxt_conf_json_parse_string(u_char *pos, u_char *end,
    nxt_conf_json_value_t *value, nxt_mem_pool_t *pool);
static u_char *nxt_conf_json_parse_number(u_char *pos, u_char *end,
    nxt_conf_json_value_t *value, nxt_mem_pool_t *pool);


static uintptr_t nxt_conf_json_print_value(u_char *pos,
    nxt_conf_json_value_t *value);
static uintptr_t nxt_conf_json_print_integer(u_char *pos,
    nxt_conf_json_value_t *value);
static uintptr_t nxt_conf_json_print_string(u_char *pos,
    nxt_conf_json_value_t *value);
static uintptr_t nxt_conf_json_print_array(u_char *pos,
    nxt_conf_json_value_t *value);
static uintptr_t nxt_conf_json_print_object(u_char *pos,
    nxt_conf_json_value_t *value);

static uintptr_t nxt_conf_json_escape(u_char *dst, u_char *src, size_t size);


static const nxt_lvlhsh_proto_t nxt_conf_json_object_hash_proto
    nxt_aligned(64) =
{
    NXT_LVLHSH_DEFAULT,
    0,
    nxt_conf_json_object_hash_test,
    nxt_lvlhsh_pool_alloc,
    nxt_lvlhsh_pool_free,
};


static nxt_int_t
nxt_conf_json_object_hash_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_conf_json_value_t  *name;

    name = &((nxt_conf_json_obj_member_t *) data)->name;

    if (name->type == NXT_CONF_JSON_SHORT_STRING) {

        if (nxt_str_eq(&lhq->key, &name->u.str[1], name->u.str[0])) {
            return NXT_OK;
        }

    } else {

        if (nxt_strstr_eq(&lhq->key, name->u.string)) {
            return NXT_OK;
        }
    }

    return NXT_DECLINED;
}


static nxt_int_t
nxt_conf_json_object_member_add(nxt_lvlhsh_t *lvlhsh,
    nxt_conf_json_obj_member_t *member, nxt_mem_pool_t *pool)
{
    nxt_lvlhsh_query_t     lhq;
    nxt_conf_json_value_t  *name;

    name = &member->name;

    if (name->type == NXT_CONF_JSON_SHORT_STRING) {
        lhq.key.length = name->u.str[0];
        lhq.key.start = &name->u.str[1];

    } else {
        lhq.key = *name->u.string;
    }

    lhq.key_hash = nxt_djb_hash(lhq.key.start, lhq.key.length);
    lhq.replace = 0;
    lhq.value = member;
    lhq.proto = &nxt_conf_json_object_hash_proto;
    lhq.pool = pool;

    return nxt_lvlhsh_insert(lvlhsh, &lhq);
}


#if 0
static nxt_conf_json_value_t *
nxt_conf_json_object_member_get(nxt_lvlhsh_t *lvlhsh, u_char *name,
    size_t length)
{
    nxt_lvlhsh_query_t          lhq;
    nxt_conf_json_obj_member_t  *member;

    lhq.key_hash = nxt_djb_hash(name, length);
    lhq.key.length = length;
    lhq.key.start = name;
    lhq.proto = &nxt_conf_json_object_hash_proto;

    if (nxt_fast_path(nxt_lvlhsh_find(lvlhsh, &lhq) == NXT_OK)) {
        member = lhq.value;
        return &member->value;
    }

    return NULL;
}
#endif


nxt_conf_json_value_t *
nxt_conf_json_parse(nxt_buf_mem_t *b, nxt_mem_pool_t *pool)
{
    u_char                 *pos, *end;
    nxt_conf_json_value_t  *value;

    value = nxt_mem_alloc(pool, sizeof(nxt_conf_json_value_t));
    if (nxt_slow_path(value == NULL)) {
        return NULL;
    }

    pos = b->pos;
    end = b->free;

    pos = nxt_conf_json_skip_space(pos, end);

    if (nxt_slow_path(pos == end)) {
        return NULL;
    }

    pos = nxt_conf_json_parse_value(pos, end, value, pool);

    if (nxt_slow_path(pos == NULL)) {
        return NULL;
    }

    pos = nxt_conf_json_skip_space(pos, end);

    if (nxt_slow_path(pos != end)) {
        return NULL;
    }

    return value;
}


static u_char *
nxt_conf_json_skip_space(u_char *pos, u_char *end)
{
    for ( /* void */ ; nxt_fast_path(pos != end); pos++) {

        switch (*pos) {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
            continue;
        }

        break;
    }

    return pos;
}


static u_char *
nxt_conf_json_parse_value(u_char *pos, u_char *end,
    nxt_conf_json_value_t *value, nxt_mem_pool_t *pool)
{
    u_char  ch;

    ch = *pos;

    switch (ch) {
    case '{':
        return nxt_conf_json_parse_object(pos, end, value, pool);

    case '[':
        return nxt_conf_json_parse_array(pos, end, value, pool);

    case '"':
        return nxt_conf_json_parse_string(pos, end, value, pool);

    case 't':
        if (nxt_fast_path(end - pos >= 4
                          || nxt_memcmp(pos, (u_char *) "true", 4) == 0))
        {
            value->u.boolean = 1;
            value->type = NXT_CONF_JSON_BOOLEAN;

            return pos + 4;
        }

        return NULL;

    case 'f':
        if (nxt_fast_path(end - pos >= 5
                          || nxt_memcmp(pos, (u_char *) "false", 5) == 0))
        {
            value->u.boolean = 0;
            value->type = NXT_CONF_JSON_BOOLEAN;

            return pos + 5;
        }

        return NULL;

    case 'n':
        if (nxt_fast_path(end - pos >= 4
                          || nxt_memcmp(pos, (u_char *) "null", 4) == 0))
        {
            value->type = NXT_CONF_JSON_NULL;
            return pos + 4;
        }

        return NULL;
    }

    if (nxt_fast_path(ch == '-' || (ch - '0') <= 9)) {
        return nxt_conf_json_parse_number(pos, end, value, pool);
    }

    return NULL;
}


static u_char *
nxt_conf_json_parse_object(u_char *pos, u_char *end,
    nxt_conf_json_value_t *value, nxt_mem_pool_t *pool)
{
    nxt_int_t                   rc;
    nxt_lvlhsh_t                *object;
    nxt_conf_json_obj_member_t  *member;

    object = nxt_mem_alloc(pool, sizeof(nxt_lvlhsh_t));
    if (nxt_slow_path(object == NULL)) {
        return NULL;
    }

    nxt_lvlhsh_init(object);

    value->type = NXT_CONF_JSON_OBJECT;
    value->u.object = object;

    pos = nxt_conf_json_skip_space(pos + 1, end);

    if (nxt_slow_path(pos == end)) {
        return NULL;
    }

    if (*pos != '}') {

        for ( ;; ) {
            if (*pos != '"') {
                return NULL;
            }

            member = nxt_mem_alloc(pool, sizeof(nxt_conf_json_obj_member_t));
            if (nxt_slow_path(member == NULL)) {
                return NULL;
            }

            pos = nxt_conf_json_parse_string(pos, end, &member->name, pool);

            if (nxt_slow_path(pos == NULL)) {
                return NULL;
            }

            pos = nxt_conf_json_skip_space(pos, end);

            if (nxt_slow_path(pos == end || *pos != ':')) {
                return NULL;
            }

            pos = nxt_conf_json_skip_space(pos + 1, end);

            if (nxt_slow_path(pos == end)) {
                return NULL;
            }

            pos = nxt_conf_json_parse_value(pos, end, &member->value, pool);

            if (nxt_slow_path(pos == NULL)) {
                return NULL;
            }

            rc = nxt_conf_json_object_member_add(object, member, pool);

            if (nxt_slow_path(rc != NXT_OK)) {
                return NULL;
            }

            pos = nxt_conf_json_skip_space(pos, end);

            if (nxt_slow_path(pos == end)) {
                return NULL;
            }

            if (*pos == '}') {
                break;
            }

            if (nxt_slow_path(*pos != ',')) {
                return NULL;
            }

            pos = nxt_conf_json_skip_space(pos + 1, end);

            if (nxt_slow_path(pos == end)) {
                return NULL;
            }
        }
    }

    return pos + 1;
}


static u_char *
nxt_conf_json_parse_array(u_char *pos, u_char *end,
    nxt_conf_json_value_t *value, nxt_mem_pool_t *pool)
{
    nxt_array_t  *array;

    array = nxt_array_create(pool, 8, sizeof(nxt_conf_json_value_t));
    if (nxt_slow_path(array == NULL)) {
        return NULL;
    }

    value->type = NXT_CONF_JSON_ARRAY;
    value->u.array = array;

    pos = nxt_conf_json_skip_space(pos + 1, end);

    if (nxt_slow_path(pos == end)) {
        return NULL;
    }

    if (*pos != ']') {

        for ( ;; ) {
            value = nxt_array_add(array);
            if (nxt_slow_path(value == NULL)) {
                return NULL;
            }

            pos = nxt_conf_json_parse_value(pos, end, value, pool);

            if (nxt_slow_path(pos == NULL)) {
                return NULL;
            }

            pos = nxt_conf_json_skip_space(pos, end);

            if (nxt_slow_path(pos == end)) {
                return NULL;
            }

            if (*pos == ']') {
                break;
            }

            if (nxt_slow_path(*pos != ',')) {
                return NULL;
            }

            pos = nxt_conf_json_skip_space(pos + 1, end);

            if (nxt_slow_path(pos == end)) {
                return NULL;
            }
        }
    }

    return pos + 1;
}


static u_char *
nxt_conf_json_parse_string(u_char *pos, u_char *end,
    nxt_conf_json_value_t *value, nxt_mem_pool_t *pool)
{
    u_char      ch, *last, *s;
    size_t      size, surplus;
    uint32_t    utf, utf_high;
    nxt_uint_t  i;
    enum {
        sw_usual = 0,
        sw_escape,
        sw_encoded1,
        sw_encoded2,
        sw_encoded3,
        sw_encoded4,
    } state;

    pos++;

    state = 0;
    surplus = 0;

    for (last = pos; last != end; last++) {
        ch = *last;

        switch (state) {

        case sw_usual:

            if (ch == '"') {
                break;
            }

            if (ch == '\\') {
                state = sw_escape;
                continue;
            }

            if (nxt_fast_path(ch >= ' ')) {
                continue;
            }

            return NULL;

        case sw_escape:

            switch (ch) {
            case '"':
            case '\\':
            case '/':
            case 'n':
            case 'r':
            case 't':
            case 'b':
            case 'f':
                surplus++;
                state = sw_usual;
                continue;

            case 'u':
                /*
                 * Basic unicode 6 bytes "\uXXXX" in JSON
                 * and up to 3 bytes in UTF-8.
                 *
                 * Surrogate pair: 12 bytes "\uXXXX\uXXXX" in JSON
                 * and 3 or 4 bytes in UTF-8.
                 */
                surplus += 3;
                state = sw_encoded1;
                continue;
            }

            return NULL;

        case sw_encoded1:
        case sw_encoded2:
        case sw_encoded3:
        case sw_encoded4:

            if (nxt_fast_path((ch >= '0' && ch <= '9')
                              || (ch >= 'A' && ch <= 'F')))
            {
                state = (state == sw_encoded4) ? sw_usual : state + 1;
                continue;
            }

            return NULL;
        }

        break;
    }

    if (nxt_slow_path(last == end)) {
        return NULL;
    }

    size = last - pos - surplus;

    if (size > 14) {
        value->type = NXT_CONF_JSON_STRING;
        value->u.string = nxt_str_alloc(pool, size);

        if (nxt_slow_path(value->u.string == NULL)) {
            return NULL;
        }

        s = value->u.string->start;

    } else {
        value->type = NXT_CONF_JSON_SHORT_STRING;
        value->u.str[0] = size;

        s = &value->u.str[1];
    }

    if (surplus == 0) {
        nxt_memcpy(s, pos, size);
        return last + 1;
    }

    state = 0;

    do {
        ch = *pos++;

        if (ch != '\\') {
            *s++ = ch;
            continue;
        }

        ch = *pos++;

        switch (ch) {
        case '"':
        case '\\':
        case '/':
            *s++ = ch;
            continue;

        case 'n':
            *s++ = '\n';
            continue;

        case 'r':
            *s++ = '\r';
            continue;

        case 't':
            *s++ = '\t';
            continue;

        case 'b':
            *s++ = '\b';
            continue;

        case 'f':
            *s++ = '\f';
            continue;
        }

        utf = 0;
        utf_high = 0;

        for ( ;; ) {
            for (i = 0; i < 4; i++) {
                utf = (utf << 4) + (pos[i] - (pos[i] >= 'A' ? 'A' : '0'));
            }

            pos += 4;

            if (utf < 0xd800 || utf > 0xdbff || utf_high) {
                break;
            }

            utf_high = utf;
            utf = 0;

            if (pos[0] != '\\' || pos[1] != 'u') {
                break;
            }

            pos += 2;
        }

        if (utf_high != 0) {
            if (nxt_slow_path(utf_high < 0xd800
                              || utf_high > 0xdbff
                              || utf < 0xdc00
                              || utf > 0xdfff))
            {
                /* invalid surrogate pair */
                return NULL;
            }

            utf = ((utf_high - 0xd800) << 10) + (utf - 0xdc00);
        }

        s = nxt_utf8_encode(s, utf);

    } while (pos != last);

    if (size > 14) {
        value->u.string->length = s - value->u.string->start;

    } else {
        value->u.str[0] = s - &value->u.str[1];
    }

    return pos + 1;
}


static u_char *
nxt_conf_json_parse_number(u_char *pos, u_char *end,
    nxt_conf_json_value_t *value, nxt_mem_pool_t *pool)
{
    u_char     ch, *p;
    uint64_t   integer;
    nxt_int_t  sign;
#if 0
    uint64_t   frac, power
    nxt_int_t  e, negative;
#endif

    static const uint64_t cutoff = NXT_INT64_T_MAX / 10;
    static const uint64_t cutlim = NXT_INT64_T_MAX % 10;

    ch = *pos;

    if (ch == '-') {
        sign = -1;
        pos++;

    } else {
        sign = 1;
    }

    integer = 0;

    for (p = pos; nxt_fast_path(p != end); p++) {
        ch = *p;

        /* Values below '0' become >= 208. */
        ch = ch - '0';

        if (ch > 9) {
            break;
        }

        if (nxt_slow_path(integer >= cutoff
                          && (integer > cutoff || ch > cutlim)))
        {
             return NULL;
        }

        integer = integer * 10 + ch;
    }

    if (nxt_slow_path(p == pos || (p > pos + 1 && *pos == '0'))) {
        return NULL;
    }

    if (ch != '.') {
        value->type = NXT_CONF_JSON_INTEGER;
        value->u.integer = sign * integer;
        return p;
    }

#if 0
    pos = p + 1;

    frac = 0;
    power = 1;

    for (p = pos; nxt_fast_path(p != end); p++) {
        ch = *p;

        /* Values below '0' become >= 208. */
        ch = ch - '0';

        if (ch > 9) {
            break;
        }

        if (nxt_slow_path((frac >= cutoff && (frac > cutoff || ch > cutlim))
                          || power > cutoff))
        {
             return NULL;
        }

        frac = frac * 10 + ch;
        power *= 10;
    }

    if (nxt_slow_path(p == pos)) {
        return NULL;
    }

    value->type = NXT_CONF_JSON_NUMBER;
    value->u.number = integer + (double) frac / power;

    value->u.number = copysign(value->u.number, sign);

    if (ch == 'e' || ch == 'E') {
        pos = p + 1;

        ch = *pos;

        if (ch == '-' || ch == '+') {
            pos++;
        }

        negative = (ch == '-') ? 1 : 0;
        e = 0;

        for (p = pos; nxt_fast_path(p != end); p++) {
            ch = *p;

            /* Values below '0' become >= 208. */
            ch = ch - '0';

            if (ch > 9) {
                break;
            }

            e = e * 10 + ch;

            if (nxt_slow_path(e > DBL_MAX_10_EXP)) {
                return NULL;
            }
        }

        if (nxt_slow_path(p == pos)) {
            return NULL;
        }

        if (negative) {
            value->u.number /= exp10(e);

        } else {
            value->u.number *= exp10(e);
        }
    }

    if (nxt_fast_path(isfinite(value->u.number))) {
        return p;
    }
#endif

    return NULL;
}


nxt_buf_t *
nxt_conf_json_print(nxt_conf_json_value_t *value, nxt_mem_pool_t *pool)
{
    size_t     size;
    nxt_buf_t  *b;

    size = nxt_conf_json_print_value(NULL, value);

    b = nxt_buf_mem_alloc(pool, size, 0);
    if (nxt_slow_path(b == NULL)) {
        return NULL;
    }

    b->mem.free = (u_char *) nxt_conf_json_print_value(b->mem.free, value);

    return b;
}


static uintptr_t
nxt_conf_json_print_value(u_char *pos, nxt_conf_json_value_t *value)
{
    static const u_char null[4] = "null";
    static const u_char true[4] = "true";
    static const u_char false[5] = "false";

    switch (value->type) {

    case NXT_CONF_JSON_NULL:

        if (pos == NULL) {
            return sizeof(null);
        }

        return (uintptr_t) nxt_cpymem(pos, null, sizeof(null));

    case NXT_CONF_JSON_BOOLEAN:

        if (pos == NULL) {
            return value->u.boolean ? 4 : 5;
        }

        if (value->u.boolean) {
            return (uintptr_t) nxt_cpymem(pos, true, sizeof(true));
        }

        return (uintptr_t) nxt_cpymem(pos, false, sizeof(false));

    case NXT_CONF_JSON_INTEGER:
        return nxt_conf_json_print_integer(pos, value);

    case NXT_CONF_JSON_NUMBER:
        /* TODO */
        return (pos == NULL) ? 0 : (uintptr_t) pos;

    case NXT_CONF_JSON_SHORT_STRING:
    case NXT_CONF_JSON_STRING:
        return nxt_conf_json_print_string(pos, value);

    case NXT_CONF_JSON_ARRAY:
        return nxt_conf_json_print_array(pos, value);

    case NXT_CONF_JSON_OBJECT:
        return nxt_conf_json_print_object(pos, value);
    }

    nxt_unreachable();

    return (pos == NULL) ? 0 : (uintptr_t) pos;
}


static uintptr_t
nxt_conf_json_print_integer(u_char *pos, nxt_conf_json_value_t *value)
{
    int64_t  num;

    num = value->u.integer;

    if (pos == NULL) {
        num = llabs(num);

        if (num <= 9999) {
            return sizeof("-9999") - 1;
        }

        if (num <= 99999999999) {
            return sizeof("-99999999999") - 1;
        }

        return NXT_INT64_T_LEN;
    }

    return (uintptr_t) nxt_sprintf(pos, pos + NXT_INT64_T_LEN, "%L", num);
}


static uintptr_t
nxt_conf_json_print_string(u_char *pos, nxt_conf_json_value_t *value)
{
    size_t  len;
    u_char  *s;

    if (value->type == NXT_CONF_JSON_SHORT_STRING) {
        len = value->u.str[0];
        s = &value->u.str[1];

    } else {
        len = value->u.string->length;
        s = value->u.string->start;
    }

    if (pos == NULL) {
        return 2 + len + nxt_conf_json_escape(NULL, s, len);
    }

    *pos++ = '"';

    pos = (u_char *) nxt_conf_json_escape(pos, s, len);

    *pos++ = '"';

    return (uintptr_t) pos;
}


static uintptr_t
nxt_conf_json_print_array(u_char *pos, nxt_conf_json_value_t *value)
{
    size_t       len;
    uint32_t     n;
    nxt_array_t  *array;

    array = value->u.array;

    if (pos == NULL) {
        len = 2;

        value = array->elts;

        for (n = 0; n < array->nelts; n++) {
            len += nxt_conf_json_print_value(NULL, &value[n]);
        }

        return n + len;
    }

    *pos++ = '[';

    if (array->nelts != 0) {
        value = array->elts;

        pos = (u_char *) nxt_conf_json_print_value(pos, &value[0]);

        for (n = 1; n < array->nelts; n++) {
            *pos++ = ',';
            pos = (u_char *) nxt_conf_json_print_value(pos, &value[n]);
        }
    }

    *pos++ = ']';

    return (uintptr_t) pos;
}


static uintptr_t
nxt_conf_json_print_object(u_char *pos, nxt_conf_json_value_t *value)
{
    size_t                      len;
    nxt_lvlhsh_t                *object;
    nxt_lvlhsh_each_t           lhe;
    nxt_conf_json_obj_member_t  *member;

    nxt_memzero(&lhe, sizeof(nxt_lvlhsh_each_t));

    lhe.proto = &nxt_conf_json_object_hash_proto;

    object = value->u.object;

    if (pos == NULL) {
        len = 2;

        for ( ;; ) {
            member = nxt_lvlhsh_each(object, &lhe);

            if (member == NULL) {
                break;
            }

            len += nxt_conf_json_print_string(NULL, &member->name) + 1
                   + nxt_conf_json_print_value(NULL, &member->value) + 1;
        }

        return len;
    }

    *pos++ = '{';

    member = nxt_lvlhsh_each(object, &lhe);

    if (member != NULL) {

        for ( ;; ) {
            pos = (u_char *) nxt_conf_json_print_string(pos, &member->name);

            *pos++ = ':';

            pos = (u_char *) nxt_conf_json_print_value(pos, &member->value);

            member = nxt_lvlhsh_each(object, &lhe);

            if (member == NULL) {
                break;
            }

            *pos++ = ',';
        }
    }

    *pos++ = '}';

    return (uintptr_t) pos;
}


static uintptr_t
nxt_conf_json_escape(u_char *dst, u_char *src, size_t size)
{
    u_char  ch;
    size_t  len;

    if (dst == NULL) {
        len = 0;

        while (size) {
            ch = *src++;

            if (ch == '\\' || ch == '"') {
                len++;

            } else if (ch <= 0x1f) {

                switch (ch) {
                case '\n':
                case '\r':
                case '\t':
                case '\b':
                case '\f':
                    len++;
                    break;

                default:
                    len += sizeof("\\u001F") - 2;
                }
            }

            size--;
        }

        return len;
    }

    while (size) {
        ch = *src++;

        if (ch > 0x1f) {

            if (ch == '\\' || ch == '"') {
                *dst++ = '\\';
            }

            *dst++ = ch;

        } else {
            *dst++ = '\\';

            switch (ch) {
            case '\n':
                *dst++ = 'n';
                break;

            case '\r':
                *dst++ = 'r';
                break;

            case '\t':
                *dst++ = 't';
                break;

            case '\b':
                *dst++ = 'b';
                break;

            case '\f':
                *dst++ = 'f';
                break;

            default:
                *dst++ = 'u'; *dst++ = '0'; *dst++ = '0';
                *dst++ = '0' + (ch >> 4);

                ch &= 0xf;

                *dst++ = (ch < 10) ? ('0' + ch) : ('A' + ch - 10);
            }
        }

        size--;
    }

    return (uintptr_t) dst;
}

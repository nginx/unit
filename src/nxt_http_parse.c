
/*
 * Copyright (C) NGINX, Inc.
 * Copyright (C) Valentin V. Bartenev
 */

#include <nxt_main.h>


typedef struct {
    nxt_http_field_handler_t    handler;
    uintptr_t                   data;

    union {
        uint8_t                 str[8];
        uint64_t                ui64;
    } key[];
} nxt_http_fields_hash_elt_t;


struct nxt_http_fields_hash_s {
    size_t                      min_length;
    size_t                      max_length;
    void                        *long_fields;
    nxt_http_fields_hash_elt_t  *elts[];
};


#define nxt_http_fields_hash_next_elt(elt, n)                                 \
    ((nxt_http_fields_hash_elt_t *) ((u_char *) (elt)                         \
                                     + sizeof(nxt_http_fields_hash_elt_t)     \
                                     + n * 8))


static nxt_int_t nxt_http_parse_unusual_target(nxt_http_request_parse_t *rp,
    u_char **pos, u_char *end);
static nxt_int_t nxt_http_parse_request_line(nxt_http_request_parse_t *rp,
    u_char **pos, u_char *end);
static nxt_int_t nxt_http_parse_field_name(nxt_http_request_parse_t *rp,
    u_char **pos, u_char *end);
static nxt_int_t nxt_http_parse_field_value(nxt_http_request_parse_t *rp,
    u_char **pos, u_char *end);
static u_char *nxt_http_lookup_field_end(u_char *p, u_char *end);
static nxt_int_t nxt_http_parse_field_end(nxt_http_request_parse_t *rp,
    u_char **pos, u_char *end);

static void nxt_http_fields_hash_lookup(nxt_http_fields_hash_t *hash,
    uint64_t key[4], nxt_http_field_t *field);
static void nxt_http_fields_hash_lookup_long(nxt_http_fields_hash_t *hash,
    nxt_http_field_t *field);

static nxt_int_t nxt_http_parse_complex_target(nxt_http_request_parse_t *rp);


typedef enum {
    NXT_HTTP_TARGET_SPACE = 1,   /* \s  */
    NXT_HTTP_TARGET_HASH,        /*  #  */
    NXT_HTTP_TARGET_AGAIN,
    NXT_HTTP_TARGET_BAD,         /* \0\r\n */

    /* traps below are used for extended check only */

    NXT_HTTP_TARGET_SLASH = 5,   /*  /  */
    NXT_HTTP_TARGET_DOT,         /*  .  */
    NXT_HTTP_TARGET_ARGS_MARK,   /*  ?  */
    NXT_HTTP_TARGET_QUOTE_MARK,  /*  %  */
    NXT_HTTP_TARGET_PLUS,        /*  +  */
} nxt_http_target_traps_e;


static const uint8_t  nxt_http_target_chars[256] nxt_aligned(64) = {
    /* \0                               \n        \r       */
        4, 0, 0, 0,  0, 0, 0, 0,   0, 0, 4, 0,  0, 4, 0, 0,
        0, 0, 0, 0,  0, 0, 0, 0,   0, 0, 0, 0,  0, 0, 0, 0,

    /* \s  !  "  #   $  %  &  '    (  )  *  +   ,  -  .  / */
        1, 0, 0, 2,  0, 8, 0, 0,   0, 0, 0, 9,  0, 0, 6, 5,

    /*  0  1  2  3   4  5  6  7    8  9  :  ;   <  =  >  ? */
        0, 0, 0, 0,  0, 0, 0, 0,   0, 0, 0, 0,  0, 0, 0, 7,
};


nxt_inline nxt_http_target_traps_e
nxt_http_parse_target(u_char **pos, u_char *end)
{
    u_char      *p;
    nxt_uint_t  trap;

    p = *pos;

    while (nxt_fast_path(end - p >= 10)) {

#define nxt_target_test_char(ch)                                              \
                                                                              \
        trap = nxt_http_target_chars[ch];                                     \
                                                                              \
        if (nxt_slow_path(trap != 0)) {                                       \
            *pos = &(ch);                                                     \
            return trap;                                                      \
        }

/* enddef */

        nxt_target_test_char(p[0]);
        nxt_target_test_char(p[1]);
        nxt_target_test_char(p[2]);
        nxt_target_test_char(p[3]);

        nxt_target_test_char(p[4]);
        nxt_target_test_char(p[5]);
        nxt_target_test_char(p[6]);
        nxt_target_test_char(p[7]);

        nxt_target_test_char(p[8]);
        nxt_target_test_char(p[9]);

        p += 10;
    }

    return NXT_HTTP_TARGET_AGAIN;
}


nxt_int_t
nxt_http_parse_request(nxt_http_request_parse_t *rp, nxt_buf_mem_t *b)
{
    nxt_int_t  rc;

    if (rp->handler == NULL) {
        rp->handler = &nxt_http_parse_request_line;
    }

    do {
        rc = rp->handler(rp, &b->pos, b->free);
    } while (rc == NXT_OK);

    return rc;
}


static nxt_int_t
nxt_http_parse_request_line(nxt_http_request_parse_t *rp, u_char **pos,
    u_char *end)
{
    u_char                   *p, ch, *after_slash;
    nxt_int_t                rc;
    nxt_http_ver_t           version;
    nxt_http_target_traps_e  trap;

    static const nxt_http_ver_t  http11 = { "HTTP/1.1" };
    static const nxt_http_ver_t  http10 = { "HTTP/1.0" };

    p = *pos;

    rp->method.start = p;

    for ( ;; ) {

        while (nxt_fast_path(end - p >= 8)) {

#define nxt_method_test_char(ch)                                              \
                                                                              \
            if (nxt_slow_path((ch) < 'A' || (ch) > 'Z')) {                    \
                p = &(ch);                                                    \
                goto method_unusual_char;                                     \
            }

/* enddef */

            nxt_method_test_char(p[0]);
            nxt_method_test_char(p[1]);
            nxt_method_test_char(p[2]);
            nxt_method_test_char(p[3]);

            nxt_method_test_char(p[4]);
            nxt_method_test_char(p[5]);
            nxt_method_test_char(p[6]);
            nxt_method_test_char(p[7]);

            p += 8;
        }

        return NXT_AGAIN;

    method_unusual_char:

        ch = *p;

        if (nxt_fast_path(ch == ' ')) {
            rp->method.length = p - rp->method.start;
            break;
        }

        if (ch == '_' || ch == '-') {
            p++;
            continue;
        }

        if (rp->method.start == p && (ch == NXT_CR || ch == NXT_LF)) {
            rp->method.start++;
            p++;
            continue;
        }

        return NXT_ERROR;
    }

    p++;

    if (nxt_slow_path(p == end)) {
        return NXT_AGAIN;
    }

    /* target */

    ch = *p;

    if (nxt_slow_path(ch != '/')) {
        rc = nxt_http_parse_unusual_target(rp, &p, end);

        if (nxt_slow_path(rc != NXT_OK)) {
            return rc;
        }
    }

    rp->target_start = p;

    after_slash = p + 1;

    for ( ;; ) {
        p++;

        trap = nxt_http_parse_target(&p, end);

        switch (trap) {
        case NXT_HTTP_TARGET_SLASH:
            if (nxt_slow_path(after_slash == p)) {
                rp->complex_target = 1;
                goto rest_of_target;
            }

            after_slash = p + 1;

            rp->exten_start = NULL;
            continue;

        case NXT_HTTP_TARGET_DOT:
            if (nxt_slow_path(after_slash == p)) {
                rp->complex_target = 1;
                goto rest_of_target;
            }

            rp->exten_start = p + 1;
            continue;

        case NXT_HTTP_TARGET_ARGS_MARK:
            rp->args_start = p + 1;
            goto rest_of_target;

        case NXT_HTTP_TARGET_SPACE:
            rp->target_end = p;
            goto space_after_target;

        case NXT_HTTP_TARGET_QUOTE_MARK:
            rp->quoted_target = 1;
            goto rest_of_target;

        case NXT_HTTP_TARGET_PLUS:
            rp->plus_in_target = 1;
            continue;

        case NXT_HTTP_TARGET_HASH:
            rp->complex_target = 1;
            goto rest_of_target;

        case NXT_HTTP_TARGET_AGAIN:
            return NXT_AGAIN;

        case NXT_HTTP_TARGET_BAD:
            return NXT_ERROR;
        }

        nxt_unreachable();
    }

rest_of_target:

    for ( ;; ) {
        p++;

        trap = nxt_http_parse_target(&p, end);

        switch (trap) {
        case NXT_HTTP_TARGET_SPACE:
            rp->target_end = p;
            goto space_after_target;

        case NXT_HTTP_TARGET_HASH:
            rp->complex_target = 1;
            continue;

        case NXT_HTTP_TARGET_AGAIN:
            return NXT_AGAIN;

        case NXT_HTTP_TARGET_BAD:
            return NXT_ERROR;

        default:
            continue;
        }

        nxt_unreachable();
    }

space_after_target:

    if (nxt_slow_path(end - p < 10)) {
        return NXT_AGAIN;
    }

    /* " HTTP/1.1\r\n" or " HTTP/1.1\n" */

    nxt_memcpy(version.str, &p[1], 8);

    if (nxt_fast_path((version.ui64 == http11.ui64
                       || version.ui64 == http10.ui64
                       || (p[1] == 'H'
                           && p[2] == 'T'
                           && p[3] == 'T'
                           && p[4] == 'P'
                           && p[5] == '/'
                           && p[6] >= '0' && p[6] <= '9'
                           && p[7] == '.'
                           && p[8] >= '0' && p[8] <= '9'))
                      && (p[9] == '\r' || p[9] == '\n')))
    {
        rp->version.ui64 = version.ui64;

        if (nxt_fast_path(p[9] == '\r')) {
            p += 10;

            if (nxt_slow_path(p == end)) {
                return NXT_AGAIN;
            }

            if (nxt_slow_path(*p != '\n')) {
                return NXT_ERROR;
            }

            *pos = p + 1;

        } else {
            *pos = p + 10;
        }

        if (rp->complex_target != 0 || rp->quoted_target != 0) {
            rc = nxt_http_parse_complex_target(rp);

            if (nxt_slow_path(rc != NXT_OK)) {
                return rc;
            }

            return nxt_http_parse_field_name(rp, pos, end);
        }

        rp->path.start = rp->target_start;

        if (rp->args_start != NULL) {
            rp->path.length = rp->args_start - rp->target_start - 1;

            rp->args.start = rp->args_start;
            rp->args.length = rp->target_end - rp->args_start;

        } else {
            rp->path.length = rp->target_end - rp->target_start;
        }

        if (rp->exten_start) {
            rp->exten.length = rp->path.start + rp->path.length -
                               rp->exten_start;
            rp->exten.start = rp->exten_start;
        }

        return nxt_http_parse_field_name(rp, pos, end);
    }

    if (p[1] == ' ') {
        /* surplus space after tartet */
        p++;
        goto space_after_target;
    }

    rp->space_in_target = 1;
    goto rest_of_target;
}


static nxt_int_t
nxt_http_parse_unusual_target(nxt_http_request_parse_t *rp, u_char **pos,
    u_char *end)
{
    u_char  *p, ch;

    p = *pos;

    ch = *p;

    if (ch == ' ') {
        /* skip surplus spaces before target */

        do {
            p++;

            if (nxt_slow_path(p == end)) {
                return NXT_AGAIN;
            }

            ch = *p;

        } while (ch == ' ');

        if (ch == '/') {
            *pos = p;
            return NXT_OK;
        }
    }

    /* absolute path or '*' */

    /* TODO */

    return NXT_ERROR;
}


static nxt_int_t
nxt_http_parse_field_name(nxt_http_request_parse_t *rp, u_char **pos,
    u_char *end)
{
    u_char  *p, ch, c;
    size_t  i, size;

    static const u_char  normal[256]  nxt_aligned(64) =
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"

        /* These 64 bytes should reside in one cache line. */
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"

        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    p = *pos;

    size = end - p;
    i = rp->field_name.length;

    while (nxt_fast_path(size - i >= 8)) {

#define nxt_field_name_test_char(i)                                           \
                                                                              \
        ch = p[i];                                                            \
        c = normal[ch];                                                       \
                                                                              \
        if (nxt_slow_path(c == '\0')) {                                       \
            goto name_end;                                                    \
        }                                                                     \
                                                                              \
        rp->field_key.str[i % 32] = c;

/* enddef */

        nxt_field_name_test_char(i); i++;
        nxt_field_name_test_char(i); i++;
        nxt_field_name_test_char(i); i++;
        nxt_field_name_test_char(i); i++;

        nxt_field_name_test_char(i); i++;
        nxt_field_name_test_char(i); i++;
        nxt_field_name_test_char(i); i++;
        nxt_field_name_test_char(i); i++;
    }

    while (nxt_fast_path(i != size)) {
        nxt_field_name_test_char(i); i++;
    }

    rp->field_name.length = i;
    rp->handler = &nxt_http_parse_field_name;

    return NXT_AGAIN;

name_end:

    if (nxt_fast_path(ch == ':')) {
        if (nxt_slow_path(i == 0)) {
            return NXT_ERROR;
        }

        *pos = &p[i] + 1;

        rp->field_name.length = i;
        rp->field_name.start = p;

        return nxt_http_parse_field_value(rp, pos, end);
    }

    if (nxt_slow_path(i != 0)) {
        return NXT_ERROR;
    }

    return nxt_http_parse_field_end(rp, pos, end);
}


static nxt_int_t
nxt_http_parse_field_value(nxt_http_request_parse_t *rp, u_char **pos,
    u_char *end)
{
    u_char  *p, ch;

    p = *pos;

    for ( ;; ) {
        if (nxt_slow_path(p == end)) {
            *pos = p;
            rp->handler = &nxt_http_parse_field_value;
            return NXT_AGAIN;
        }

        if (*p != ' ') {
            break;
        }

        p++;
    }

    *pos = p;

    p += rp->field_value.length;

    for ( ;; ) {
        p = nxt_http_lookup_field_end(p, end);

        if (nxt_slow_path(p == end)) {
            rp->field_value.length = p - *pos;
            rp->handler = &nxt_http_parse_field_value;
            return NXT_AGAIN;
        }

        ch = *p;

        if (nxt_fast_path(ch == '\r' || ch == '\n')) {
            break;
        }

        if (ch == '\0') {
            return NXT_ERROR;
        }
    }

    if (nxt_fast_path(p != *pos)) {
        while (p[-1] == ' ') {
            p--;
        }
    }

    rp->field_value.length = p - *pos;
    rp->field_value.start = *pos;

    *pos = p;

    return nxt_http_parse_field_end(rp, pos, end);
}


static u_char *
nxt_http_lookup_field_end(u_char *p, u_char *end)
{
    while (nxt_fast_path(end - p >= 16)) {

#define nxt_field_end_test_char(ch)                                           \
                                                                              \
        if (nxt_slow_path((ch) < 0x10)) {                                     \
            return &(ch);                                                     \
        }

/* enddef */

        nxt_field_end_test_char(p[0]);
        nxt_field_end_test_char(p[1]);
        nxt_field_end_test_char(p[2]);
        nxt_field_end_test_char(p[3]);

        nxt_field_end_test_char(p[4]);
        nxt_field_end_test_char(p[5]);
        nxt_field_end_test_char(p[6]);
        nxt_field_end_test_char(p[7]);

        nxt_field_end_test_char(p[8]);
        nxt_field_end_test_char(p[9]);
        nxt_field_end_test_char(p[10]);
        nxt_field_end_test_char(p[11]);

        nxt_field_end_test_char(p[12]);
        nxt_field_end_test_char(p[13]);
        nxt_field_end_test_char(p[14]);
        nxt_field_end_test_char(p[15]);

        p += 16;
    }

    while (nxt_fast_path(end - p >= 4)) {

        nxt_field_end_test_char(p[0]);
        nxt_field_end_test_char(p[1]);
        nxt_field_end_test_char(p[2]);
        nxt_field_end_test_char(p[3]);

        p += 4;
    }

    switch (end - p) {
    case 3:
        nxt_field_end_test_char(*p); p++;
        /* Fall through. */
    case 2:
        nxt_field_end_test_char(*p); p++;
        /* Fall through. */
    case 1:
        nxt_field_end_test_char(*p); p++;
        /* Fall through. */
    case 0:
        break;
    default:
        nxt_unreachable();
    }

    return p;
}


static nxt_int_t
nxt_http_parse_field_end(nxt_http_request_parse_t *rp, u_char **pos,
    u_char *end)
{
    u_char            *p;
    nxt_http_field_t  *field;

    p = *pos;

    if (nxt_fast_path(*p == '\r')) {
        p++;

        if (nxt_slow_path(p == end)) {
            rp->handler = &nxt_http_parse_field_end;
            return NXT_AGAIN;
        }
    }

    if (nxt_fast_path(*p == '\n')) {
        *pos = p + 1;

        if (rp->field_name.length != 0) {
            field = nxt_list_add(rp->fields);

            if (nxt_slow_path(field == NULL)) {
                return NXT_ERROR;
            }

            field->name = rp->field_name;
            field->value = rp->field_value;

            nxt_http_fields_hash_lookup(rp->fields_hash, rp->field_key.ui64,
                                        field);

            nxt_memzero(rp->field_key.str, 32);

            rp->field_name.length = 0;
            rp->field_value.length = 0;

            rp->handler = &nxt_http_parse_field_name;
            return NXT_OK;
        }

        return NXT_DONE;
    }

    return NXT_ERROR;
}


nxt_http_fields_hash_t *
nxt_http_fields_hash_create(nxt_http_fields_hash_entry_t *entries,
    nxt_mp_t *mp)
{
    size_t                      min_length, max_length, length, size;
    nxt_uint_t                  i, j, n;
    nxt_http_fields_hash_t      *hash;
    nxt_http_fields_hash_elt_t  *elt;

    min_length = 32 + 1;
    max_length = 0;

    for (i = 0; entries[i].handler != NULL; i++) {
        length = entries[i].name.length;

        if (length > 32) {
            /* TODO */
            return NULL;
        }

        min_length = nxt_min(length, min_length);
        max_length = nxt_max(length, max_length);
    }

    size = sizeof(nxt_http_fields_hash_t);

    if (min_length <= 32) {
        size += (max_length - min_length + 1)
                * sizeof(nxt_http_fields_hash_elt_t *);
    }

    hash = nxt_mp_zget(mp, size);
    if (nxt_slow_path(hash == NULL)) {
        return NULL;
    }

    hash->min_length = min_length;
    hash->max_length = max_length;

    for (i = 0; entries[i].handler != NULL; i++) {
        length = entries[i].name.length;
        elt = hash->elts[length - min_length];

        if (elt != NULL) {
            continue;
        }

        n = 1;

        for (j = i + 1; entries[j].handler != NULL; j++) {
            if (length == entries[j].name.length) {
                n++;
            }
        }

        size = sizeof(nxt_http_fields_hash_elt_t) + nxt_align_size(length, 8);

        elt = nxt_mp_zget(mp, n * size + sizeof(nxt_http_fields_hash_elt_t));

        if (nxt_slow_path(elt == NULL)) {
            return NULL;
        }

        hash->elts[length - min_length] = elt;

        for (j = i; entries[j].handler != NULL; j++) {
            if (length != entries[j].name.length) {
                continue;
            }

            elt->handler = entries[j].handler;
            elt->data = entries[j].data;

            nxt_memcpy_lowcase(elt->key->str, entries[j].name.start, length);

            n--;

            if (n == 0) {
                break;
            }

            elt = nxt_pointer_to(elt, size);
        }
    }

    return hash;
}


static void
nxt_http_fields_hash_lookup(nxt_http_fields_hash_t *hash, uint64_t key[4],
    nxt_http_field_t *field)
{
    nxt_http_fields_hash_elt_t  *elt;

    if (hash == NULL || field->name.length < hash->min_length) {
        goto not_found;
    }

    if (field->name.length > hash->max_length) {

        if (field->name.length > 32 && hash->long_fields != NULL) {
            nxt_http_fields_hash_lookup_long(hash, field);
            return;
        }

        goto not_found;
    }

    elt = hash->elts[field->name.length - hash->min_length];

    if (elt == NULL) {
        goto not_found;
    }

    switch ((field->name.length + 7) / 8) {
    case 1:
        do {
            if (elt->key[0].ui64 == key[0]) {
                break;
            }

            elt = nxt_http_fields_hash_next_elt(elt, 1);

        } while (elt->handler != NULL);

        break;

    case 2:
        do {
            if (elt->key[0].ui64 == key[0]
                && elt->key[1].ui64 == key[1])
            {
                break;
            }

            elt = nxt_http_fields_hash_next_elt(elt, 2);

        } while (elt->handler != NULL);

        break;

    case 3:
        do {
            if (elt->key[0].ui64 == key[0]
                && elt->key[1].ui64 == key[1]
                && elt->key[2].ui64 == key[2])
            {
                break;
            }

            elt = nxt_http_fields_hash_next_elt(elt, 3);

        } while (elt->handler != NULL);

        break;

    case 4:
        do {
            if (elt->key[0].ui64 == key[0]
                && elt->key[1].ui64 == key[1]
                && elt->key[2].ui64 == key[2]
                && elt->key[3].ui64 == key[3])
            {
                break;
            }

            elt = nxt_http_fields_hash_next_elt(elt, 4);

        } while (elt->handler != NULL);

        break;

    default:
        nxt_unreachable();
    }

    field->handler = elt->handler;
    field->data = elt->data;

    return;

not_found:

    field->handler = NULL;
    field->data = 0;
}


static void
nxt_http_fields_hash_lookup_long(nxt_http_fields_hash_t *hash,
    nxt_http_field_t *field)
{
    /* TODO */

    field->handler = NULL;
    field->data = 0;
}


nxt_int_t
nxt_http_fields_process(nxt_list_t *fields, void *ctx, nxt_log_t *log)
{
    nxt_int_t         rc;
    nxt_http_field_t  *field;

    nxt_list_each(field, fields) {

        if (field->handler != NULL) {
            rc = field->handler(ctx, field, log);

            if (rc != NXT_OK) {
                return rc;
            }
        }

    } nxt_list_loop;

    return NXT_OK;
}


#define                                                                       \
nxt_http_is_normal(c)                                                         \
    (nxt_fast_path((nxt_http_normal[c / 8] & (1 << (c & 7))) != 0))


static const uint8_t  nxt_http_normal[32]  nxt_aligned(32) = {

                             /*        \0   \r  \n                         */
    0xfe, 0xdb, 0xff, 0xff,  /* 1111 1110  1101 1011  1111 1111  1111 1111 */

                             /* '&%$ #"!   /.-, |*)(  7654 3210  ?>=< ;:98 */
    0xd6, 0x37, 0xff, 0x7f,  /* 1101 0110  0011 0111  1111 1111  0111 1111 */

                             /* GFED CBA@  ONML KJIH  WVUT SRQP  _^]\ [ZYX */
    0xff, 0xff, 0xff, 0xff,  /* 1111 1111  1111 1111  1111 1111  1111 1111 */

                             /* gfed cba`  onml kjih  wvut srqp   ~}| {zyx */
    0xff, 0xff, 0xff, 0xff,  /* 1111 1111  1111 1111  1111 1111  1111 1111 */

    0xff, 0xff, 0xff, 0xff,  /* 1111 1111  1111 1111  1111 1111  1111 1111 */
    0xff, 0xff, 0xff, 0xff,  /* 1111 1111  1111 1111  1111 1111  1111 1111 */
    0xff, 0xff, 0xff, 0xff,  /* 1111 1111  1111 1111  1111 1111  1111 1111 */
    0xff, 0xff, 0xff, 0xff,  /* 1111 1111  1111 1111  1111 1111  1111 1111 */
};


static nxt_int_t
nxt_http_parse_complex_target(nxt_http_request_parse_t *rp)
{
    u_char  *p, *u, c, ch, high;
    enum {
        sw_normal = 0,
        sw_slash,
        sw_dot,
        sw_dot_dot,
        sw_quoted,
        sw_quoted_second,
    } state, saved_state;

    nxt_prefetch(nxt_http_normal);

    state = sw_normal;
    saved_state = sw_normal;
    p = rp->target_start;

    u = nxt_mp_alloc(rp->mem_pool, rp->target_end - p + 1);

    if (nxt_slow_path(u == NULL)) {
        return NXT_ERROR;
    }

    rp->path.length = 0;
    rp->path.start = u;

    high = '\0';
    rp->exten_start = NULL;
    rp->args_start = NULL;

    while (p < rp->target_end) {

        ch = *p++;

    again:

        switch (state) {

        case sw_normal:

            if (nxt_http_is_normal(ch)) {
                *u++ = ch;
                continue;
            }

            switch (ch) {
            case '/':
                rp->exten_start = NULL;
                state = sw_slash;
                *u++ = ch;
                continue;
            case '%':
                saved_state = state;
                state = sw_quoted;
                continue;
            case '?':
                rp->args_start = p;
                goto args;
            case '#':
                goto done;
            case '.':
                rp->exten_start = u + 1;
                *u++ = ch;
                continue;
            case '+':
                rp->plus_in_target = 1;
                /* Fall through. */
            default:
                *u++ = ch;
                continue;
            }

            break;

        case sw_slash:

            if (nxt_http_is_normal(ch)) {
                state = sw_normal;
                *u++ = ch;
                continue;
            }

            switch (ch) {
            case '/':
                continue;
            case '.':
                state = sw_dot;
                *u++ = ch;
                continue;
            case '%':
                saved_state = state;
                state = sw_quoted;
                continue;
            case '?':
                rp->args_start = p;
                goto args;
            case '#':
                goto done;
            case '+':
                rp->plus_in_target = 1;
                /* Fall through. */
            default:
                state = sw_normal;
                *u++ = ch;
                continue;
            }

            break;

        case sw_dot:

            if (nxt_http_is_normal(ch)) {
                state = sw_normal;
                *u++ = ch;
                continue;
            }

            switch (ch) {
            case '/':
                state = sw_slash;
                u--;
                continue;
            case '.':
                state = sw_dot_dot;
                *u++ = ch;
                continue;
            case '%':
                saved_state = state;
                state = sw_quoted;
                continue;
            case '?':
                rp->args_start = p;
                goto args;
            case '#':
                goto done;
            case '+':
                rp->plus_in_target = 1;
                /* Fall through. */
            default:
                state = sw_normal;
                *u++ = ch;
                continue;
            }

            break;

        case sw_dot_dot:

            if (nxt_http_is_normal(ch)) {
                state = sw_normal;
                *u++ = ch;
                continue;
            }

            switch (ch) {
            case '/':
                state = sw_slash;
                u -= 5;
                for ( ;; ) {
                    if (u < rp->path.start) {
                        return NXT_ERROR;
                    }
                    if (*u == '/') {
                        u++;
                        break;
                    }
                    u--;
                }
                break;

            case '%':
                saved_state = state;
                state = sw_quoted;
                continue;
            case '?':
                rp->args_start = p;
                goto args;
            case '#':
                goto done;
            case '+':
                rp->plus_in_target = 1;
                /* Fall through. */
            default:
                state = sw_normal;
                *u++ = ch;
                continue;
            }

            break;

        case sw_quoted:
            rp->quoted_target = 1;

            if (ch >= '0' && ch <= '9') {
                high = (u_char) (ch - '0');
                state = sw_quoted_second;
                continue;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                high = (u_char) (c - 'a' + 10);
                state = sw_quoted_second;
                continue;
            }

            return NXT_ERROR;

        case sw_quoted_second:
            if (ch >= '0' && ch <= '9') {
                ch = (u_char) ((high << 4) + ch - '0');

                if (ch == '%' || ch == '#') {
                    state = sw_normal;
                    *u++ = ch;
                    continue;

                } else if (ch == '\0') {
                    return NXT_ERROR;
                }

                state = saved_state;
                goto again;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                ch = (u_char) ((high << 4) + c - 'a' + 10);

                if (ch == '?') {
                    state = sw_normal;
                    *u++ = ch;
                    continue;

                } else if (ch == '+') {
                    rp->plus_in_target = 1;
                }

                state = saved_state;
                goto again;
            }

            return NXT_ERROR;
        }
    }

    if (state >= sw_quoted) {
        return NXT_ERROR;
    }

args:

    for (/* void */; p < rp->target_end; p++) {
        if (*p == '#') {
            break;
        }
    }

    if (rp->args_start != NULL) {
        rp->args.length = p - rp->args_start;
        rp->args.start = rp->args_start;
    }

done:

    rp->path.length = u - rp->path.start;

    if (rp->exten_start) {
        rp->exten.length = u - rp->exten_start;
        rp->exten.start = rp->exten_start;
    }

    return NXT_OK;
}


/*
 * Copyright (C) NGINX, Inc.
 * Copyright (C) Valentin V. Bartenev
 */

#include <nxt_main.h>


static nxt_int_t nxt_http_parse_unusual_target(nxt_http_request_parse_t *rp,
    u_char **pos, const u_char *end);
static nxt_int_t nxt_http_parse_request_line(nxt_http_request_parse_t *rp,
    u_char **pos, const u_char *end);
static nxt_int_t nxt_http_parse_field_name(nxt_http_request_parse_t *rp,
    u_char **pos, const u_char *end);
static nxt_int_t nxt_http_parse_field_value(nxt_http_request_parse_t *rp,
    u_char **pos, const u_char *end);
static u_char *nxt_http_lookup_field_end(u_char *p, const u_char *end);
static nxt_int_t nxt_http_parse_field_end(nxt_http_request_parse_t *rp,
    u_char **pos, const u_char *end);

static nxt_int_t nxt_http_field_hash_test(nxt_lvlhsh_query_t *lhq, void *data);

static nxt_int_t nxt_http_field_hash_collision(nxt_lvlhsh_query_t *lhq,
    void *data);


#define NXT_HTTP_MAX_FIELD_NAME         0xFF
#define NXT_HTTP_MAX_FIELD_VALUE        NXT_INT32_T_MAX

#define NXT_HTTP_FIELD_LVLHSH_SHIFT     5


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
} nxt_http_target_traps_e;


static const uint8_t  nxt_http_target_chars[256] nxt_aligned(64) = {
    /* \0                               \n        \r       */
        4, 0, 0, 0,  0, 0, 0, 0,   0, 0, 4, 0,  0, 4, 0, 0,
        0, 0, 0, 0,  0, 0, 0, 0,   0, 0, 0, 0,  0, 0, 0, 0,

    /* \s  !  "  #   $  %  &  '    (  )  *  +   ,  -  .  / */
        1, 0, 0, 2,  0, 8, 0, 0,   0, 0, 0, 0,  0, 0, 6, 5,

    /*  0  1  2  3   4  5  6  7    8  9  :  ;   <  =  >  ? */
        0, 0, 0, 0,  0, 0, 0, 0,   0, 0, 0, 0,  0, 0, 0, 7,
};


nxt_inline nxt_http_target_traps_e
nxt_http_parse_target(u_char **pos, const u_char *end)
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

    while (p != end) {
        nxt_target_test_char(*p); p++;
    }

    return NXT_HTTP_TARGET_AGAIN;
}


nxt_int_t
nxt_http_parse_request_init(nxt_http_request_parse_t *rp, nxt_mp_t *mp)
{
    rp->mem_pool = mp;

    rp->fields = nxt_list_create(mp, 8, sizeof(nxt_http_field_t));
    if (nxt_slow_path(rp->fields == NULL)) {
        return NXT_ERROR;
    }

    rp->field_hash = NXT_HTTP_FIELD_HASH_INIT;

    return NXT_OK;
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


nxt_int_t
nxt_http_parse_fields(nxt_http_request_parse_t *rp, nxt_buf_mem_t *b)
{
    nxt_int_t  rc;

    if (rp->handler == NULL) {
        rp->handler = &nxt_http_parse_field_name;
    }

    do {
        rc = rp->handler(rp, &b->pos, b->free);
    } while (rc == NXT_OK);

    return rc;
}


static nxt_int_t
nxt_http_parse_request_line(nxt_http_request_parse_t *rp, u_char **pos,
    const u_char *end)
{
    u_char                   *p, ch, *after_slash, *args;
    nxt_int_t                rc;
    nxt_bool_t               rest;
    nxt_http_ver_t           ver;
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

        while (p != end) {
            nxt_method_test_char(*p); p++;
        }

        rp->method.length = p - rp->method.start;

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

        if (rp->method.start == p && (ch == '\r' || ch == '\n')) {
            rp->method.start++;
            p++;
            continue;
        }

        rp->method.length = p - rp->method.start;

        return NXT_HTTP_PARSE_INVALID;
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
    args = NULL;
    rest = 0;

continue_target:

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
            continue;

        case NXT_HTTP_TARGET_DOT:
            if (nxt_slow_path(after_slash == p)) {
                rp->complex_target = 1;
                goto rest_of_target;
            }

            continue;

        case NXT_HTTP_TARGET_ARGS_MARK:
            args = p + 1;
            goto rest_of_target;

        case NXT_HTTP_TARGET_SPACE:
            rp->target_end = p;
            goto space_after_target;

        case NXT_HTTP_TARGET_QUOTE_MARK:
            rp->quoted_target = 1;
            goto rest_of_target;

        case NXT_HTTP_TARGET_HASH:
            rp->complex_target = 1;
            goto rest_of_target;

        case NXT_HTTP_TARGET_AGAIN:
            rp->target_end = p;
            return NXT_AGAIN;

        case NXT_HTTP_TARGET_BAD:
            rp->target_end = p;
            return NXT_HTTP_PARSE_INVALID;
        }

        nxt_unreachable();
    }

rest_of_target:

    rest = 1;

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
            rp->target_end = p;
            return NXT_AGAIN;

        case NXT_HTTP_TARGET_BAD:
            rp->target_end = p;
            return NXT_HTTP_PARSE_INVALID;

        default:
            continue;
        }

        nxt_unreachable();
    }

space_after_target:

    if (nxt_slow_path(end - p < 10)) {

        do {
            p++;

            if (p == end) {
                return NXT_AGAIN;
            }

        } while (*p == ' ');

        if (memcmp(p, "HTTP/", nxt_min(end - p, 5)) == 0) {

            switch (end - p) {
            case 8:
                if (p[7] < '0' || p[7] > '9') {
                    break;
                }
                /* Fall through. */
            case 7:
                if (p[6] != '.') {
                    break;
                }
                /* Fall through. */
            case 6:
                if (p[5] < '0' || p[5] > '9') {
                    break;
                }
                /* Fall through. */
            default:
                return NXT_AGAIN;
            }
        }

        //rp->space_in_target = 1;

        if (rest) {
            goto rest_of_target;
        }

        goto continue_target;
    }

    /* " HTTP/1.1\r\n" or " HTTP/1.1\n" */

    if (nxt_slow_path(p[9] != '\r' && p[9] != '\n')) {

        if (p[1] == ' ') {
            /* surplus space after tartet */
            p++;
            goto space_after_target;
        }

        //rp->space_in_target = 1;

        if (rest) {
            goto rest_of_target;
        }

        goto continue_target;
    }

    nxt_memcpy(ver.str, &p[1], 8);

    if (nxt_fast_path(ver.ui64 == http11.ui64
                      || ver.ui64 == http10.ui64
                      || (memcmp(ver.str, "HTTP/1.", 7) == 0
                          && ver.s.minor >= '0' && ver.s.minor <= '9')))
    {
        rp->version.ui64 = ver.ui64;

        p += 9;
        if (nxt_fast_path(*p == '\r')) {

            if (nxt_slow_path(p + 1 == end)) {
                return NXT_AGAIN;
            }

            if (nxt_slow_path(p[1] != '\n')) {
                return NXT_HTTP_PARSE_INVALID;
            }

            *pos = p + 2;

        } else {
            *pos = p + 1;
        }

        rp->request_line_end = p;

        if (rp->complex_target || rp->quoted_target) {
            rc = nxt_http_parse_complex_target(rp);

            if (nxt_slow_path(rc != NXT_OK)) {
                return rc;
            }

            return nxt_http_parse_field_name(rp, pos, end);
        }

        rp->path.start = rp->target_start;

        if (args != NULL) {
            rp->path.length = args - rp->target_start - 1;

            rp->args.length = rp->target_end - args;
            rp->args.start = args;

        } else {
            rp->path.length = rp->target_end - rp->target_start;
        }

        return nxt_http_parse_field_name(rp, pos, end);
    }

    if (memcmp(ver.s.prefix, "HTTP/", 5) == 0
        && ver.s.major >= '0' && ver.s.major <= '9'
        && ver.s.point == '.'
        && ver.s.minor >= '0' && ver.s.minor <= '9')
    {
        rp->version.ui64 = ver.ui64;
        return NXT_HTTP_PARSE_UNSUPPORTED_VERSION;
    }

    return NXT_HTTP_PARSE_INVALID;
}


static nxt_int_t
nxt_http_parse_unusual_target(nxt_http_request_parse_t *rp, u_char **pos,
    const u_char *end)
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

    return NXT_HTTP_PARSE_INVALID;
}


static nxt_int_t
nxt_http_parse_field_name(nxt_http_request_parse_t *rp, u_char **pos,
    const u_char *end)
{
    u_char    *p, c;
    size_t    len;
    uint32_t  hash;

    static const u_char  normal[256]  NXT_NONSTRING nxt_aligned(64) =
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    /*   \s ! " # $ % & ' ( ) * + ,        . /                 : ; < = > ?   */
        "\0\1\0\1\1\1\1\1\0\0\1\1\0" "-" "\1\0" "0123456789" "\0\0\0\0\0\0"

    /*    @                                 [ \ ] ^ _                        */
        "\0" "abcdefghijklmnopqrstuvwxyz" "\0\0\0\1\1"
    /*    `                                 { | } ~                          */
        "\1" "abcdefghijklmnopqrstuvwxyz" "\0\1\0\1\0"

        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    p = *pos + rp->field_name.length;
    hash = rp->field_hash;

    while (nxt_fast_path(end - p >= 8)) {

#define nxt_field_name_test_char(ch)                                          \
                                                                              \
        c = normal[ch];                                                       \
                                                                              \
        if (nxt_slow_path(c <= '\1')) {                                       \
            if (c == '\0') {                                                  \
                p = &(ch);                                                    \
                goto name_end;                                                \
            }                                                                 \
                                                                              \
            rp->skip_field = rp->discard_unsafe_fields;                       \
            c = ch;                                                           \
        }                                                                     \
                                                                              \
        hash = nxt_http_field_hash_char(hash, c);

/* enddef */

        nxt_field_name_test_char(p[0]);
        nxt_field_name_test_char(p[1]);
        nxt_field_name_test_char(p[2]);
        nxt_field_name_test_char(p[3]);

        nxt_field_name_test_char(p[4]);
        nxt_field_name_test_char(p[5]);
        nxt_field_name_test_char(p[6]);
        nxt_field_name_test_char(p[7]);

        p += 8;
    }

    while (nxt_fast_path(p != end)) {
        nxt_field_name_test_char(*p); p++;
    }

    len = p - *pos;

    if (nxt_slow_path(len > NXT_HTTP_MAX_FIELD_NAME)) {
        return NXT_HTTP_PARSE_TOO_LARGE_FIELD;
    }

    rp->field_hash = hash;
    rp->field_name.length = len;

    rp->handler = &nxt_http_parse_field_name;

    return NXT_AGAIN;

name_end:

    if (nxt_fast_path(*p == ':')) {
        if (nxt_slow_path(p == *pos)) {
            return NXT_HTTP_PARSE_INVALID;
        }

        len = p - *pos;

        if (nxt_slow_path(len > NXT_HTTP_MAX_FIELD_NAME)) {
            return NXT_HTTP_PARSE_TOO_LARGE_FIELD;
        }

        rp->field_hash = hash;

        rp->field_name.length = len;
        rp->field_name.start = *pos;

        *pos = p + 1;

        return nxt_http_parse_field_value(rp, pos, end);
    }

    if (nxt_slow_path(p != *pos)) {
        return NXT_HTTP_PARSE_INVALID;
    }

    return nxt_http_parse_field_end(rp, pos, end);
}


static nxt_int_t
nxt_http_parse_field_value(nxt_http_request_parse_t *rp, u_char **pos,
    const u_char *end)
{
    u_char  *p, *start, ch;
    size_t  len;

    p = *pos;

    for ( ;; ) {
        if (nxt_slow_path(p == end)) {
            *pos = p;
            rp->handler = &nxt_http_parse_field_value;
            return NXT_AGAIN;
        }

        ch = *p;

        if (ch != ' ' && ch != '\t') {
            break;
        }

        p++;
    }

    start = p;

    p += rp->field_value.length;

    for ( ;; ) {
        p = nxt_http_lookup_field_end(p, end);

        if (nxt_slow_path(p == end)) {
            *pos = start;

            len = p - start;

            if (nxt_slow_path(len > NXT_HTTP_MAX_FIELD_VALUE)) {
                return NXT_HTTP_PARSE_TOO_LARGE_FIELD;
            }

            rp->field_value.length = len;
            rp->handler = &nxt_http_parse_field_value;
            return NXT_AGAIN;
        }

        ch = *p;

        if (nxt_fast_path(ch == '\r' || ch == '\n')) {
            break;
        }

        if (ch != '\t') {
            return NXT_HTTP_PARSE_INVALID;
        }

        p++;
    }

    *pos = p;

    if (nxt_fast_path(p != start)) {

        while (p[-1] == ' ' || p[-1] == '\t') {
            p--;
        }
    }

    len = p - start;

    if (nxt_slow_path(len > NXT_HTTP_MAX_FIELD_VALUE)) {
        return NXT_HTTP_PARSE_TOO_LARGE_FIELD;
    }

    rp->field_value.length = len;
    rp->field_value.start = start;

    return nxt_http_parse_field_end(rp, pos, end);
}


static u_char *
nxt_http_lookup_field_end(u_char *p, const u_char *end)
{
    while (nxt_fast_path(end - p >= 16)) {

#define nxt_field_end_test_char(ch)                                           \
                                                                              \
        if (nxt_slow_path((ch) < 0x20)) {                                     \
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
    const u_char *end)
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
            if (rp->skip_field) {
                rp->skip_field = 0;

            } else {
                field = nxt_list_add(rp->fields);

                if (nxt_slow_path(field == NULL)) {
                    return NXT_ERROR;
                }

                field->hash = nxt_http_field_hash_end(rp->field_hash);
                field->skip = 0;
                field->hopbyhop = 0;

                field->name_length = rp->field_name.length;
                field->value_length = rp->field_value.length;
                field->name = rp->field_name.start;
                field->value = rp->field_value.start;
            }

            rp->field_hash = NXT_HTTP_FIELD_HASH_INIT;

            rp->field_name.length = 0;
            rp->field_value.length = 0;

            rp->handler = &nxt_http_parse_field_name;
            return NXT_OK;
        }

        return NXT_DONE;
    }

    return NXT_HTTP_PARSE_INVALID;
}


#define nxt_http_is_normal(c)                                                 \
    (nxt_fast_path((nxt_http_normal[c / 8] & (1 << (c & 7))) != 0))


static const uint8_t  nxt_http_normal[32]  nxt_aligned(32) = {

                             /*        \0   \r  \n                         */
    0xFE, 0xDB, 0xFF, 0xFF,  /* 1111 1110  1101 1011  1111 1111  1111 1111 */

                             /* '&%$ #"!   /.-, |*)(  7654 3210  ?>=< ;:98 */
    0xD6, 0x37, 0xFF, 0x7F,  /* 1101 0110  0011 0111  1111 1111  0111 1111 */

                             /* GFED CBA@  ONML KJIH  WVUT SRQP  _^]\ [ZYX */
    0xFF, 0xFF, 0xFF, 0xFF,  /* 1111 1111  1111 1111  1111 1111  1111 1111 */

                             /* gfed cba`  onml kjih  wvut srqp   ~}| {zyx */
    0xFF, 0xFF, 0xFF, 0xFF,  /* 1111 1111  1111 1111  1111 1111  1111 1111 */

    0xFF, 0xFF, 0xFF, 0xFF,  /* 1111 1111  1111 1111  1111 1111  1111 1111 */
    0xFF, 0xFF, 0xFF, 0xFF,  /* 1111 1111  1111 1111  1111 1111  1111 1111 */
    0xFF, 0xFF, 0xFF, 0xFF,  /* 1111 1111  1111 1111  1111 1111  1111 1111 */
    0xFF, 0xFF, 0xFF, 0xFF,  /* 1111 1111  1111 1111  1111 1111  1111 1111 */
};


nxt_int_t
nxt_http_parse_complex_target(nxt_http_request_parse_t *rp)
{
    u_char  *p, *u, c, ch, high, *args;

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
    args = NULL;

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
                state = sw_slash;
                *u++ = ch;
                continue;
            case '%':
                saved_state = state;
                state = sw_quoted;
                continue;
            case '?':
                args = p;
                goto args;
            case '#':
                goto done;
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
                args = p;
                goto args;
            case '#':
                goto done;
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
                u--;
                args = p;
                goto args;
            case '#':
                u--;
                goto done;
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
            case '?':
            case '#':
                u -= 5;

                for ( ;; ) {
                    if (u < rp->path.start) {
                        return NXT_HTTP_PARSE_INVALID;
                    }

                    if (*u == '/') {
                        u++;
                        break;
                    }

                    u--;
                }

                if (ch == '?') {
                    args = p;
                    goto args;
                }

                if (ch == '#') {
                    goto done;
                }

                state = sw_slash;
                break;

            case '%':
                saved_state = state;
                state = sw_quoted;
                continue;

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

            return NXT_HTTP_PARSE_INVALID;

        case sw_quoted_second:
            if (ch >= '0' && ch <= '9') {
                ch = (u_char) ((high << 4) + ch - '0');

                if (ch == '%') {
                    state = sw_normal;
                    *u++ = '%';

                    if (rp->encoded_slashes) {
                        *u++ = '2';
                        *u++ = '5';
                    }

                    continue;
                }

                if (ch == '#') {
                    state = sw_normal;
                    *u++ = '#';
                    continue;
                }

                if (ch == '\0') {
                    return NXT_HTTP_PARSE_INVALID;
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
                }

                if (ch == '/' && rp->encoded_slashes) {
                    state = sw_normal;
                    *u++ = '%';
                    *u++ = '2';
                    *u++ = p[-1];  /* 'f' or 'F' */
                    continue;
                }

                state = saved_state;
                goto again;
            }

            return NXT_HTTP_PARSE_INVALID;
        }
    }

    if (state >= sw_dot) {
        if (state >= sw_quoted) {
            return NXT_HTTP_PARSE_INVALID;
        }

        /* "/." and "/.." must be normalized similar to "/./" and "/../". */
        ch = '/';
        goto again;
    }

args:

    for (/* void */; p < rp->target_end; p++) {
        if (*p == '#') {
            break;
        }
    }

    if (args != NULL) {
        rp->args.length = p - args;
        rp->args.start = args;
    }

done:

    rp->path.length = u - rp->path.start;

    return NXT_OK;
}


const nxt_lvlhsh_proto_t  nxt_http_fields_hash_proto  nxt_aligned(64) = {
    NXT_LVLHSH_BUCKET_SIZE(64),
    { NXT_HTTP_FIELD_LVLHSH_SHIFT, 0, 0, 0, 0, 0, 0, 0 },
    nxt_http_field_hash_test,
    nxt_lvlhsh_alloc,
    nxt_lvlhsh_free,
};


static nxt_int_t
nxt_http_field_hash_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_http_field_proc_t  *field;

    field = data;

    if (nxt_strcasestr_eq(&lhq->key, &field->name)) {
        return NXT_OK;
    }

    return NXT_DECLINED;
}


static nxt_int_t
nxt_http_field_hash_collision(nxt_lvlhsh_query_t *lhq, void *data)
{
    return NXT_OK;
}


nxt_int_t
nxt_http_fields_hash(nxt_lvlhsh_t *hash,
    nxt_http_field_proc_t items[], nxt_uint_t count)
{
    u_char              ch;
    uint32_t            key;
    nxt_str_t           *name;
    nxt_int_t           ret;
    nxt_uint_t          i, j;
    nxt_lvlhsh_query_t  lhq;

    lhq.replace = 0;
    lhq.proto = &nxt_http_fields_hash_proto;
    lhq.pool = NULL;

    for (i = 0; i < count; i++) {
        key = NXT_HTTP_FIELD_HASH_INIT;
        name = &items[i].name;

        for (j = 0; j < name->length; j++) {
            ch = nxt_lowcase(name->start[j]);
            key = nxt_http_field_hash_char(key, ch);
        }

        lhq.key_hash = nxt_http_field_hash_end(key) & 0xFFFF;
        lhq.key = *name;
        lhq.value = &items[i];

        ret = nxt_lvlhsh_insert(hash, &lhq);

        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


nxt_uint_t
nxt_http_fields_hash_collisions(nxt_lvlhsh_t *hash,
    nxt_http_field_proc_t items[], nxt_uint_t count, nxt_bool_t level)
{
    u_char              ch;
    uint32_t            key, mask;
    nxt_str_t           *name;
    nxt_uint_t          colls, i, j;
    nxt_lvlhsh_proto_t  proto;
    nxt_lvlhsh_query_t  lhq;

    proto = nxt_http_fields_hash_proto;
    proto.test = nxt_http_field_hash_collision;

    lhq.replace = 0;
    lhq.proto = &proto;

    mask = level ? (1 << NXT_HTTP_FIELD_LVLHSH_SHIFT) - 1 : 0xFFFF;

    colls = 0;

    for (i = 0; i < count; i++) {
        key = NXT_HTTP_FIELD_HASH_INIT;
        name = &items[i].name;

        for (j = 0; j < name->length; j++) {
            ch = nxt_lowcase(name->start[j]);
            key = nxt_http_field_hash_char(key, ch);
        }

        lhq.key_hash = nxt_http_field_hash_end(key) & mask;
        lhq.value = &items[i];

        if (nxt_lvlhsh_insert(hash, &lhq) == NXT_DECLINED) {
            colls++;
        }
    }

    return colls;
}


nxt_int_t
nxt_http_fields_process(nxt_list_t *fields, nxt_lvlhsh_t *hash, void *ctx)
{
    nxt_int_t         ret;
    nxt_http_field_t  *field;

    nxt_list_each(field, fields) {

        ret = nxt_http_field_process(field, hash, ctx);
        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }

    } nxt_list_loop;

    return NXT_OK;
}

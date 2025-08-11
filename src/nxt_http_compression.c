/*
 * Copyright (C) Andrew Clayton
 * Copyright (C) F5, Inc.
 */

#include <nxt_auto_config.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <nxt_router.h>
#include <nxt_http.h>
#include <nxt_tstr.h>
#include <nxt_conf.h>
#include <nxt_http_compression.h>


#define NXT_COMP_LEVEL_UNSET               INT8_MIN


typedef enum nxt_http_comp_scheme_e        nxt_http_comp_scheme_t;
typedef struct nxt_http_comp_type_s        nxt_http_comp_type_t;
typedef struct nxt_http_comp_opts_s        nxt_http_comp_opts_t;
typedef struct nxt_http_comp_compressor_s  nxt_http_comp_compressor_t;
typedef struct nxt_http_comp_ctx_s         nxt_http_comp_ctx_t;

enum nxt_http_comp_scheme_e {
    NXT_HTTP_COMP_SCHEME_IDENTITY = 0,
#if NXT_HAVE_ZLIB
    NXT_HTTP_COMP_SCHEME_DEFLATE,
    NXT_HTTP_COMP_SCHEME_GZIP,
#endif
#if NXT_HAVE_ZSTD
    NXT_HTTP_COMP_SCHEME_ZSTD,
#endif
#if NXT_HAVE_BROTLI
    NXT_HTTP_COMP_SCHEME_BROTLI,
#endif

    /* keep last */
    NXT_HTTP_COMP_SCHEME_UNKNOWN
};
#define NXT_NR_COMPRESSORS  NXT_HTTP_COMP_SCHEME_UNKNOWN

struct nxt_http_comp_type_s {
    nxt_str_t                         token;
    nxt_http_comp_scheme_t            scheme;
    int8_t                            def_compr;
    int8_t                            comp_min;
    int8_t                            comp_max;

    const nxt_http_comp_operations_t  *cops;
};

struct nxt_http_comp_opts_s {
    int8_t                      level;
    nxt_off_t                   min_len;
};

struct nxt_http_comp_compressor_s {
    const nxt_http_comp_type_t  *type;
    nxt_http_comp_opts_t        opts;
};

struct nxt_http_comp_ctx_s {
    nxt_uint_t                      idx;

    nxt_off_t                       resp_clen;
    nxt_off_t                       clen_sent;

    nxt_http_comp_compressor_ctx_t  ctx;
};


static nxt_tstr_t                  *nxt_http_comp_accept_encoding_query;
static nxt_http_route_rule_t       *nxt_http_comp_mime_types_rule;
static nxt_http_comp_compressor_t  *nxt_http_comp_enabled_compressors;
static nxt_uint_t                  nxt_http_comp_nr_enabled_compressors;

static nxt_thread_declare_data(nxt_http_comp_ctx_t,
                               nxt_http_comp_compressor_ctx);

#define nxt_http_comp_ctx()  nxt_thread_get_data(nxt_http_comp_compressor_ctx)

static const nxt_conf_map_t  nxt_http_comp_compressors_opts_map[] = {
    {
        nxt_string("level"),
        NXT_CONF_MAP_INT,
        offsetof(nxt_http_comp_opts_t, level),
    }, {
        nxt_string("min_length"),
        NXT_CONF_MAP_SIZE,
        offsetof(nxt_http_comp_opts_t, min_len),
    },
};

static const nxt_http_comp_type_t  nxt_http_comp_compressors[] = {
    /* Keep this first */
    {
        .token      = nxt_string("identity"),
        .scheme     = NXT_HTTP_COMP_SCHEME_IDENTITY,
#if NXT_HAVE_ZLIB
    }, {
        .token      = nxt_string("deflate"),
        .scheme     = NXT_HTTP_COMP_SCHEME_DEFLATE,
        .def_compr  = NXT_HTTP_COMP_ZLIB_DEFAULT_LEVEL,
        .comp_min   = NXT_HTTP_COMP_ZLIB_COMP_MIN,
        .comp_max   = NXT_HTTP_COMP_ZLIB_COMP_MAX,
        .cops       = &nxt_http_comp_deflate_ops,
    }, {
        .token      = nxt_string("gzip"),
        .scheme     = NXT_HTTP_COMP_SCHEME_GZIP,
        .def_compr  = NXT_HTTP_COMP_ZLIB_DEFAULT_LEVEL,
        .comp_min   = NXT_HTTP_COMP_ZLIB_COMP_MIN,
        .comp_max   = NXT_HTTP_COMP_ZLIB_COMP_MAX,
        .cops       = &nxt_http_comp_gzip_ops,
#endif
#if NXT_HAVE_ZSTD
    }, {
        .token      = nxt_string("zstd"),
        .scheme     = NXT_HTTP_COMP_SCHEME_ZSTD,
        .def_compr  = NXT_HTTP_COMP_ZSTD_DEFAULT_LEVEL,
        .comp_min   = NXT_HTTP_COMP_ZSTD_COMP_MIN,
        .comp_max   = NXT_HTTP_COMP_ZSTD_COMP_MAX,
        .cops       = &nxt_http_comp_zstd_ops,
#endif
#if NXT_HAVE_BROTLI
    }, {
        .token      = nxt_string("br"),
        .scheme     = NXT_HTTP_COMP_SCHEME_BROTLI,
        .def_compr  = NXT_HTTP_COMP_BROTLI_DEFAULT_LEVEL,
        .comp_min   = NXT_HTTP_COMP_BROTLI_COMP_MIN,
        .comp_max   = NXT_HTTP_COMP_BROTLI_COMP_MAX,
        .cops       = &nxt_http_comp_brotli_ops,
#endif
    },
};


static ssize_t
nxt_http_comp_compress(uint8_t *dst, size_t dst_size, const uint8_t *src,
                       size_t src_size, bool last)
{
    nxt_http_comp_ctx_t               *ctx = nxt_http_comp_ctx();
    nxt_http_comp_compressor_t        *compressor;
    const nxt_http_comp_operations_t  *cops;

    compressor = &nxt_http_comp_enabled_compressors[ctx->idx];
    cops = compressor->type->cops;

    return cops->deflate(&ctx->ctx, src, src_size, dst, dst_size, last);
}


static size_t
nxt_http_comp_bound(size_t size)
{
    nxt_http_comp_ctx_t               *ctx = nxt_http_comp_ctx();
    nxt_http_comp_compressor_t        *compressor;
    const nxt_http_comp_operations_t  *cops;

    compressor = &nxt_http_comp_enabled_compressors[ctx->idx];
    cops = compressor->type->cops;

    return cops->bound(&ctx->ctx, size);
}


nxt_int_t
nxt_http_comp_compress_app_response(nxt_task_t *task, nxt_http_request_t *r,
                                    nxt_buf_t **b)
{
    bool                 last;
    size_t               buf_len;
    ssize_t              cbytes;
    nxt_buf_t            *buf;
    nxt_off_t            in_len;
    nxt_http_comp_ctx_t  *ctx = nxt_http_comp_ctx();

    if (ctx->idx == NXT_HTTP_COMP_SCHEME_IDENTITY) {
        return NXT_OK;
    }

    if (!nxt_buf_is_port_mmap(*b)) {
        return NXT_OK;
    }

    in_len = (*b)->mem.free - (*b)->mem.pos;
    buf_len = nxt_http_comp_bound(in_len);

    buf = nxt_buf_mem_ts_alloc(task, (*b)->data, buf_len);
    if (nxt_slow_path(buf == NULL)) {
        return NXT_ERROR;
    }

    buf->data = (*b)->data;
    buf->parent = (*b)->parent;

    last = ctx->clen_sent + in_len == ctx->resp_clen;

    cbytes = nxt_http_comp_compress(buf->mem.start, buf_len,
                                    (*b)->mem.pos, in_len, last);
    if (cbytes == -1) {
        nxt_buf_free(buf->data, buf);
        return NXT_ERROR;
    }

    buf->mem.free += cbytes;

    ctx->clen_sent += in_len;

#define nxt_swap_buf(db, sb)                                                  \
    do {                                                                      \
        nxt_buf_t  **db_ = (db);                                              \
        nxt_buf_t  **sb_ = (sb);                                              \
        nxt_buf_t  *tmp_;                                                     \
                                                                              \
        tmp_ = *db_;                                                          \
        *db_ = *sb_;                                                          \
        *sb_ = tmp_;                                                          \
    } while (0)

    nxt_swap_buf(b, &buf);

#undef nxt_swap_buf

    nxt_buf_free(buf->data, buf);

    return NXT_OK;
}


nxt_int_t
nxt_http_comp_compress_static_response(nxt_task_t *task, nxt_http_request_t *r,
                                       nxt_file_t **f, nxt_file_info_t *fi,
                                       size_t static_buf_len, size_t *out_total)
{
    size_t         in_size, out_size, rest;
    char           *tmp_path, *p;
    uint8_t        *in, *out;
    nxt_int_t      ret;
    nxt_file_t     tfile;
    nxt_runtime_t  *rt = task->thread->runtime;

    static const char  *template = "unit-compr-XXXXXX";

    *out_total = 0;

    tmp_path = nxt_mp_nget(r->mem_pool,
                           strlen(rt->tmp) + 1 + strlen(template) + 1);
    if (nxt_slow_path(tmp_path == NULL)) {
        return NXT_ERROR;
    }

    p = tmp_path;
    p = nxt_cpymem(p, rt->tmp, strlen(rt->tmp));
    *p++ = '/';
    p = nxt_cpymem(p, template, strlen(template));
    *p = '\0';

    tfile.fd = mkstemp(tmp_path);
    if (nxt_slow_path(tfile.fd == -1)) {
        nxt_alert(task, "mkstemp(%s) failed %E", tmp_path, nxt_errno);
        return NXT_ERROR;
    }
    unlink(tmp_path);
    tfile.name = (nxt_file_name_t *)tmp_path;

    in_size = nxt_file_size(fi);
    out_size = nxt_http_comp_bound(in_size);

    ret = ftruncate(tfile.fd, out_size);
    if (nxt_slow_path(ret == -1)) {
        nxt_alert(task, "ftruncate(%d<%s>, %uz) failed %E",
                  tfile.fd, tmp_path, out_size, nxt_errno);
        nxt_file_close(task, &tfile);
        return NXT_ERROR;
    }

    in = nxt_mem_mmap(NULL, in_size, PROT_READ, MAP_SHARED, (*f)->fd, 0);
    if (nxt_slow_path(in == MAP_FAILED)) {
        nxt_file_close(task, &tfile);
        return NXT_ERROR;
    }

    out = nxt_mem_mmap(NULL, out_size, PROT_READ|PROT_WRITE, MAP_SHARED,
                       tfile.fd, 0);
    if (nxt_slow_path(out == MAP_FAILED)) {
        nxt_mem_munmap(in, in_size);
        nxt_file_close(task, &tfile);
        return NXT_ERROR;
    }

    rest = in_size;

    do {
        bool     last;
        size_t   n;
        ssize_t  cbytes;

        n = nxt_min(rest, static_buf_len);

        last = n == rest;

        cbytes = nxt_http_comp_compress(out + *out_total, out_size - *out_total,
                                        in + in_size - rest, n, last);
        if (cbytes == -1) {
            nxt_file_close(task, &tfile);
            nxt_mem_munmap(in, in_size);
            nxt_mem_munmap(out, out_size);
            return NXT_ERROR;
        }

        *out_total += cbytes;
        rest -= n;
    } while (rest > 0);

    nxt_mem_munmap(in, in_size);
    msync(out, out_size, MS_ASYNC);
    nxt_mem_munmap(out, out_size);

    ret = ftruncate(tfile.fd, *out_total);
    if (nxt_slow_path(ret == -1)) {
        nxt_alert(task, "ftruncate(%d<%s>, %uz) failed %E",
                  tfile.fd, tmp_path, *out_total, nxt_errno);
        nxt_file_close(task, &tfile);
        return NXT_ERROR;
    }

    nxt_file_close(task, *f);

    **f = tfile;

    return NXT_OK;
}


bool
nxt_http_comp_wants_compression(void)
{
    nxt_http_comp_ctx_t  *ctx = nxt_http_comp_ctx();

    return ctx->idx;
}


static nxt_uint_t
nxt_http_comp_compressor_lookup_enabled(const nxt_str_t *token)
{
    if (token->start[0] == '*') {
        return NXT_HTTP_COMP_SCHEME_IDENTITY;
    }

    for (nxt_uint_t i = 0; i < nxt_http_comp_nr_enabled_compressors; i++) {
        if (nxt_strstr_eq(token,
                          &nxt_http_comp_enabled_compressors[i].type->token))
        {
            return i;
        }
    }

    return NXT_HTTP_COMP_SCHEME_UNKNOWN;
}


/*
 * We need to parse the 'Accept-Encoding` header as described by
 * <https://www.rfc-editor.org/rfc/rfc9110.html#field.accept-encoding>
 * which can take forms such as
 *
 *  Accept-Encoding: compress, gzip
 *  Accept-Encoding:
 *  Accept-Encoding: *
 *  Accept-Encoding: compress;q=0.5, gzip;q=1.0
 *  Accept-Encoding: gzip;q=1.0, identity;q=0.5, *;q=0
 *
 *  '*:q=0' means if the content being served has no 'Content-Coding'
 *  matching an 'Accept-Encoding' entry then don't send any response.
 *
 * 'identity;q=0' seems to basically mean the same thing...
 */
static nxt_int_t
nxt_http_comp_select_compressor(nxt_http_request_t *r, const nxt_str_t *token)
{
    bool       identity_allowed = true;
    char       *str, *tkn, *tail, *cur;
    double     weight = 0.0;
    nxt_int_t  idx = NXT_HTTP_COMP_SCHEME_IDENTITY;

    str = nxt_str_cstrz(r->mem_pool, token);
    if (str == NULL) {
        return NXT_HTTP_COMP_SCHEME_IDENTITY;
    }

    cur = tail = str;
    /*
     * To ease parsing the Accept-Encoding header, remove all spaces,
     * which hold no semantic meaning.
     */
    for (; *cur != '\0'; cur++) {
        if (*cur == ' ') {
            continue;
        }

        *tail++ = *cur;
    }
    *tail = '\0';

    while ((tkn = strsep(&str, ","))) {
        char                    *qptr;
        double                  qval = 1.0;
        nxt_str_t               enc;
        nxt_uint_t              ecidx;
        nxt_http_comp_scheme_t  scheme;

        qptr = strstr(tkn, ";q=");
        if (qptr != NULL) {
            nxt_errno = 0;

            qval = strtod(qptr + 3, NULL);

            if (nxt_errno == ERANGE || qval < 0.0 || qval > 1.0) {
                continue;
            }
        }

        enc.start = (u_char *)tkn;
        enc.length = qptr != NULL ? (size_t)(qptr - tkn) : strlen(tkn);

        ecidx = nxt_http_comp_compressor_lookup_enabled(&enc);
        if (ecidx == NXT_HTTP_COMP_SCHEME_UNKNOWN) {
            continue;
        }

        scheme = nxt_http_comp_enabled_compressors[ecidx].type->scheme;

        if (qval == 0.0 && scheme == NXT_HTTP_COMP_SCHEME_IDENTITY) {
            identity_allowed = false;
        }

        if (qval == 0.0 || qval < weight) {
            continue;
        }

        idx = ecidx;
        weight = qval;
    }

    if (idx == NXT_HTTP_COMP_SCHEME_IDENTITY && !identity_allowed) {
        return -1;
    }

    return idx;
}


static nxt_int_t
nxt_http_comp_set_header(nxt_http_request_t *r, nxt_uint_t comp_idx)
{
    const nxt_str_t   *token;
    nxt_http_field_t  *f;

    static const nxt_str_t  content_encoding_str =
                                    nxt_string("Content-Encoding");

    f = nxt_list_add(r->resp.fields);
    if (nxt_slow_path(f == NULL)) {
        return NXT_ERROR;
    }

    token = &nxt_http_comp_enabled_compressors[comp_idx].type->token;

    *f = (nxt_http_field_t){};

    f->name = content_encoding_str.start;
    f->name_length = content_encoding_str.length;
    f->value = token->start;
    f->value_length = token->length;

    r->resp.content_length = NULL;
    r->resp.content_length_n = -1;

    if (r->resp.mime_type == NULL) {
        nxt_http_field_t *f;

        /*
         * As per RFC 2616 section 4.4 item 3, you should not send
         * Content-Length when a Transfer-Encoding header is present.
         */
        nxt_list_each(f, r->resp.fields) {
            if (nxt_strcasecmp(f->name,
                               (const u_char *)"Content-Length") == 0)
            {
                f->skip = true;
                break;
            }
        } nxt_list_loop;
    }

    return NXT_OK;
}


static bool
nxt_http_comp_is_resp_content_encoded(const nxt_http_request_t *r)
{
    nxt_http_field_t  *f;

    nxt_list_each(f, r->resp.fields) {
        if (nxt_strcasecmp(f->name, (const u_char *)"Content-Encoding") == 0) {
            return true;
        }
    } nxt_list_loop;

    return false;
}


nxt_int_t
nxt_http_comp_check_compression(nxt_task_t *task, nxt_http_request_t *r)
{
    int                         err;
    nxt_int_t                   ret, idx;
    nxt_off_t                   min_len;
    nxt_str_t                   accept_encoding, mime_type = {};
    nxt_router_conf_t           *rtcf;
    nxt_http_comp_ctx_t         *ctx = nxt_http_comp_ctx();
    nxt_http_comp_compressor_t  *compressor;

    *ctx = (nxt_http_comp_ctx_t){ .resp_clen = -1 };

    if (nxt_http_comp_nr_enabled_compressors == 0) {
        return NXT_OK;
    }

    if (r->resp.content_length == NULL && r->resp.content_length_n == -1) {
        return NXT_OK;
    }

    if (r->resp.content_length_n == 0) {
        return NXT_OK;
    }

    if (r->resp.mime_type != NULL) {
        mime_type = *r->resp.mime_type;
    } else if (r->resp.content_type != NULL) {
        mime_type.start = r->resp.content_type->value;
        mime_type.length = r->resp.content_type->value_length;
    }

    if (mime_type.start == NULL) {
        return NXT_OK;
    }

    if (nxt_http_comp_mime_types_rule != NULL) {
        ret = nxt_http_route_test_rule(r, nxt_http_comp_mime_types_rule,
                                       mime_type.start,
                                       mime_type.length);
        if (ret == 0) {
            return NXT_OK;
        }
    }

    rtcf = r->conf->socket_conf->router_conf;

    if (nxt_http_comp_is_resp_content_encoded(r)) {
        return NXT_OK;
    }

    ret = nxt_tstr_query_init(&r->tstr_query, rtcf->tstr_state, &r->tstr_cache,
                              r, r->mem_pool);
    if (nxt_slow_path(ret == NXT_ERROR)) {
        return NXT_ERROR;
    }

    ret = nxt_tstr_query(task, r->tstr_query,
                         nxt_http_comp_accept_encoding_query, &accept_encoding);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    idx = nxt_http_comp_select_compressor(r, &accept_encoding);
    if (idx == -1) {
        return NXT_HTTP_NOT_ACCEPTABLE;
    }

    if (idx == NXT_HTTP_COMP_SCHEME_IDENTITY) {
        return NXT_OK;
    }

    compressor = &nxt_http_comp_enabled_compressors[idx];

    if (r->resp.content_length_n > -1) {
        ctx->resp_clen = r->resp.content_length_n;
    } else if (r->resp.content_length != NULL) {
        ctx->resp_clen =
                strtol((char *)r->resp.content_length->value, NULL, 10);
    }

    min_len = compressor->opts.min_len;

    if (ctx->resp_clen > -1 && ctx->resp_clen < min_len) {
        return NXT_OK;
    }

    nxt_http_comp_set_header(r, idx);

    ctx->idx = idx;
    ctx->ctx.level = nxt_http_comp_enabled_compressors[idx].opts.level;

    err = compressor->type->cops->init(&ctx->ctx);
    if (nxt_slow_path(err)) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_uint_t
nxt_http_comp_compressor_token2idx(const nxt_str_t *token)
{
    for (nxt_uint_t i = 0; i < nxt_nitems(nxt_http_comp_compressors); i++) {
        if (nxt_strstr_eq(token, &nxt_http_comp_compressors[i].token)) {
            return i;
        }
    }

    return NXT_HTTP_COMP_SCHEME_UNKNOWN;
}


bool
nxt_http_comp_compressor_is_valid(const nxt_str_t *token)
{
    nxt_uint_t  idx;

    idx = nxt_http_comp_compressor_token2idx(token);
    if (idx != NXT_HTTP_COMP_SCHEME_UNKNOWN) {
        return true;
    }

    return false;
}


static nxt_int_t
nxt_http_comp_set_compressor(nxt_task_t *task, nxt_router_conf_t *rtcf,
                             const nxt_conf_value_t *comp, nxt_uint_t index)
{
    nxt_int_t                   ret;
    nxt_str_t                   token;
    nxt_uint_t                  cidx;
    nxt_conf_value_t            *obj;
    nxt_http_comp_compressor_t  *compr;

    static const nxt_str_t  token_str = nxt_string("encoding");

    obj = nxt_conf_get_object_member(comp, &token_str, NULL);
    if (obj == NULL) {
        return NXT_ERROR;
    }

    nxt_conf_get_string(obj, &token);
    cidx = nxt_http_comp_compressor_token2idx(&token);

    compr = &nxt_http_comp_enabled_compressors[index];

    compr->type = &nxt_http_comp_compressors[cidx];
    compr->opts.level = compr->type->def_compr;
    compr->opts.min_len = -1;

    ret = nxt_conf_map_object(rtcf->mem_pool, comp,
                              nxt_http_comp_compressors_opts_map,
                              nxt_nitems(nxt_http_comp_compressors_opts_map),
                              &compr->opts);
    if (nxt_slow_path(ret == NXT_ERROR)) {
        return NXT_ERROR;
    }

    if (compr->opts.level < compr->type->comp_min
        || compr->opts.level > compr->type->comp_max)
    {
        nxt_log(task, NXT_LOG_NOTICE,
                "Overriding invalid compression level for [%V] [%d] -> [%d]",
                &compr->type->token, compr->opts.level,
                compr->type->def_compr);
        compr->opts.level = compr->type->def_compr;
    }

    return NXT_OK;
}


nxt_int_t
nxt_http_comp_compression_init(nxt_task_t *task, nxt_router_conf_t *rtcf,
                               const nxt_conf_value_t *comp_conf)
{
    nxt_int_t         ret;
    nxt_uint_t        n = 1;  /* 'identity' */
    nxt_conf_value_t  *comps, *mimes;

    static const nxt_str_t  accept_enc_str =
                                    nxt_string("$header_accept_encoding");
    static const nxt_str_t  comps_str = nxt_string("compressors");
    static const nxt_str_t  mimes_str = nxt_string("types");

    mimes = nxt_conf_get_object_member(comp_conf, &mimes_str, NULL);
    if (mimes != NULL) {
        nxt_http_comp_mime_types_rule =
                        nxt_http_route_types_rule_create(task,
                                                         rtcf->mem_pool, mimes);
        if (nxt_slow_path(nxt_http_comp_mime_types_rule == NULL)) {
            return NXT_ERROR;
        }
    }

    nxt_http_comp_accept_encoding_query =
                            nxt_tstr_compile(rtcf->tstr_state, &accept_enc_str,
                                             NXT_TSTR_STRZ);
    if (nxt_slow_path(nxt_http_comp_accept_encoding_query == NULL)) {
        return NXT_ERROR;
    }

    comps = nxt_conf_get_object_member(comp_conf, &comps_str, NULL);
    if (nxt_slow_path(comps == NULL)) {
        return NXT_ERROR;
    }

    if (nxt_conf_type(comps) == NXT_CONF_OBJECT) {
        n++;
    } else {
        n += nxt_conf_object_members_count(comps);
    }
    nxt_http_comp_nr_enabled_compressors = n;

    nxt_http_comp_enabled_compressors =
                        nxt_mp_zalloc(rtcf->mem_pool,
                                      sizeof(nxt_http_comp_compressor_t) * n);

    nxt_http_comp_enabled_compressors[0] =
        (nxt_http_comp_compressor_t){ .type = &nxt_http_comp_compressors[0],
                                      .opts.level = NXT_COMP_LEVEL_UNSET,
                                      .opts.min_len = -1 };

    if (nxt_conf_type(comps) == NXT_CONF_OBJECT) {
        return nxt_http_comp_set_compressor(task, rtcf, comps, 1);
    }

    for (nxt_uint_t i = 1; i < nxt_http_comp_nr_enabled_compressors; i++) {
        nxt_conf_value_t  *obj;

        obj = nxt_conf_get_array_element(comps, i - 1);
        ret = nxt_http_comp_set_compressor(task, rtcf, obj, i);
        if (ret == NXT_ERROR) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}

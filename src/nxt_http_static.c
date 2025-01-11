
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


typedef struct {
    nxt_tstr_t                  *tstr;
#if (NXT_HAVE_OPENAT2)
    u_char                      *fname;
#endif
    uint8_t                     is_const;  /* 1 bit */
} nxt_http_static_share_t;


typedef struct {
    nxt_uint_t                  nshares;
    nxt_http_static_share_t     *shares;
    nxt_str_t                   index;
#if (NXT_HAVE_OPENAT2)
    nxt_tstr_t                  *chroot;
    nxt_uint_t                  resolve;
#endif
    nxt_http_route_rule_t       *types;
} nxt_http_static_conf_t;


typedef struct {
    nxt_http_action_t           *action;
    nxt_str_t                   share;
#if (NXT_HAVE_OPENAT2)
    nxt_str_t                   chroot;
#endif
    uint32_t                    share_idx;
    uint8_t                     need_body;  /* 1 bit */
} nxt_http_static_ctx_t;


#define NXT_HTTP_STATIC_BUF_COUNT  2
#define NXT_HTTP_STATIC_BUF_SIZE   (128 * 1024)


static nxt_http_action_t *nxt_http_static(nxt_task_t *task,
    nxt_http_request_t *r, nxt_http_action_t *action);
static void nxt_http_static_iterate(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_static_ctx_t *ctx);
static void nxt_http_static_send(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_static_ctx_t *ctx);
static void nxt_http_static_next(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_static_ctx_t *ctx, nxt_http_status_t status);
#if (NXT_HAVE_OPENAT2)
static u_char *nxt_http_static_chroot_match(u_char *chr, u_char *shr);
#endif
static void nxt_http_static_extract_extension(nxt_str_t *path,
    nxt_str_t *exten);
static void nxt_http_static_body_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_http_static_buf_completion(nxt_task_t *task, void *obj,
    void *data);

static nxt_int_t nxt_http_static_mtypes_hash_test(nxt_lvlhsh_query_t *lhq,
    void *data);
static void *nxt_http_static_mtypes_hash_alloc(void *data, size_t size);
static void nxt_http_static_mtypes_hash_free(void *data, void *p);


static const nxt_http_request_state_t  nxt_http_static_send_state;


nxt_int_t
nxt_http_static_init(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_http_action_t *action, nxt_http_action_conf_t *acf)
{
    uint32_t                i;
    nxt_mp_t                *mp;
    nxt_str_t               str, *ret;
    nxt_tstr_t              *tstr;
    nxt_conf_value_t        *cv;
    nxt_router_conf_t       *rtcf;
    nxt_http_static_conf_t  *conf;

    rtcf = tmcf->router_conf;
    mp = rtcf->mem_pool;

    conf = nxt_mp_zget(mp, sizeof(nxt_http_static_conf_t));
    if (nxt_slow_path(conf == NULL)) {
        return NXT_ERROR;
    }

    action->handler = nxt_http_static;
    action->u.conf = conf;

    conf->nshares = nxt_conf_array_elements_count_or_1(acf->share);
    conf->shares = nxt_mp_zget(mp, sizeof(nxt_http_static_share_t)
                                   * conf->nshares);
    if (nxt_slow_path(conf->shares == NULL)) {
        return NXT_ERROR;
    }

    for (i = 0; i < conf->nshares; i++) {
        cv = nxt_conf_get_array_element_or_itself(acf->share, i);
        nxt_conf_get_string(cv, &str);

        tstr = nxt_tstr_compile(rtcf->tstr_state, &str, NXT_TSTR_STRZ);
        if (nxt_slow_path(tstr == NULL)) {
            return NXT_ERROR;
        }

        conf->shares[i].tstr = tstr;
        conf->shares[i].is_const = nxt_tstr_is_const(tstr);
    }

    if (acf->index == NULL) {
        nxt_str_set(&conf->index, "index.html");

    } else {
        ret = nxt_conf_get_string_dup(acf->index, mp, &conf->index);
        if (nxt_slow_path(ret == NULL)) {
            return NXT_ERROR;
        }
    }

#if (NXT_HAVE_OPENAT2)
    if (acf->chroot.length > 0) {
        nxt_str_t   chr, shr;
        nxt_bool_t  is_const;

        conf->chroot = nxt_tstr_compile(rtcf->tstr_state, &acf->chroot,
                                        NXT_TSTR_STRZ);
        if (nxt_slow_path(conf->chroot == NULL)) {
            return NXT_ERROR;
        }

        is_const = nxt_tstr_is_const(conf->chroot);

        for (i = 0; i < conf->nshares; i++) {
            conf->shares[i].is_const &= is_const;

            if (conf->shares[i].is_const) {
                nxt_tstr_str(conf->chroot, &chr);
                nxt_tstr_str(conf->shares[i].tstr, &shr);

                conf->shares[i].fname = nxt_http_static_chroot_match(chr.start,
                                                                     shr.start);
            }
        }
    }

    if (acf->follow_symlinks != NULL
        && !nxt_conf_get_boolean(acf->follow_symlinks))
    {
        conf->resolve |= RESOLVE_NO_SYMLINKS;
    }

    if (acf->traverse_mounts != NULL
        && !nxt_conf_get_boolean(acf->traverse_mounts))
    {
        conf->resolve |= RESOLVE_NO_XDEV;
    }
#endif

    if (acf->types != NULL) {
        conf->types = nxt_http_route_types_rule_create(task, mp, acf->types);
        if (nxt_slow_path(conf->types == NULL)) {
            return NXT_ERROR;
        }
    }

    if (acf->fallback != NULL) {
        action->fallback = nxt_mp_alloc(mp, sizeof(nxt_http_action_t));
        if (nxt_slow_path(action->fallback == NULL)) {
            return NXT_ERROR;
        }

        return nxt_http_action_init(task, tmcf, acf->fallback,
                                    action->fallback);
    }

    return NXT_OK;
}


static nxt_http_action_t *
nxt_http_static(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_action_t *action)
{
    nxt_bool_t             need_body;
    nxt_http_static_ctx_t  *ctx;

    if (nxt_slow_path(!nxt_str_eq(r->method, "GET", 3))) {

        if (!nxt_str_eq(r->method, "HEAD", 4)) {
            if (action->fallback != NULL) {
                if (nxt_slow_path(r->log_route)) {
                    nxt_log(task, NXT_LOG_NOTICE, "\"fallback\" taken");
                }
                return action->fallback;
            }

            nxt_http_request_error(task, r, NXT_HTTP_METHOD_NOT_ALLOWED);
            return NULL;
        }

        need_body = 0;

    } else {
        need_body = 1;
    }

    ctx = nxt_mp_zget(r->mem_pool, sizeof(nxt_http_static_ctx_t));
    if (nxt_slow_path(ctx == NULL)) {
        nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    ctx->action = action;
    ctx->need_body = need_body;

    nxt_http_static_iterate(task, r, ctx);

    return NULL;
}


static void
nxt_http_static_iterate(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_static_ctx_t *ctx)
{
    nxt_int_t                ret;
    nxt_router_conf_t        *rtcf;
    nxt_http_static_conf_t   *conf;
    nxt_http_static_share_t  *share;

    conf = ctx->action->u.conf;

    share = &conf->shares[ctx->share_idx];

#if (NXT_DEBUG)
    nxt_str_t  shr;
    nxt_str_t  idx;

    nxt_tstr_str(share->tstr, &shr);
    idx = conf->index;

#if (NXT_HAVE_OPENAT2)
    nxt_str_t  chr;

    if (conf->chroot != NULL) {
        nxt_tstr_str(conf->chroot, &chr);

    } else {
        nxt_str_set(&chr, "");
    }

    nxt_debug(task, "http static: \"%V\", index: \"%V\" (chroot: \"%V\")",
              &shr, &idx, &chr);
#else
    nxt_debug(task, "http static: \"%V\", index: \"%V\"", &shr, &idx);
#endif
#endif /* NXT_DEBUG */

    if (share->is_const) {
        nxt_tstr_str(share->tstr, &ctx->share);

#if (NXT_HAVE_OPENAT2)
        if (conf->chroot != NULL && ctx->share_idx == 0) {
            nxt_tstr_str(conf->chroot, &ctx->chroot);
        }
#endif

    } else {
        rtcf = r->conf->socket_conf->router_conf;

        ret = nxt_tstr_query_init(&r->tstr_query, rtcf->tstr_state,
                                  &r->tstr_cache, r, r->mem_pool);
        if (nxt_slow_path(ret != NXT_OK)) {
            goto fail;
        }

        ret = nxt_tstr_query(task, r->tstr_query, share->tstr, &ctx->share);
        if (nxt_slow_path(ret != NXT_OK)) {
            goto fail;
        }

#if (NXT_HAVE_OPENAT2)
        if (conf->chroot != NULL && ctx->share_idx == 0) {
            ret = nxt_tstr_query(task, r->tstr_query, conf->chroot,
                                 &ctx->chroot);
            if (nxt_slow_path(ret != NXT_OK)) {
                goto fail;
            }
        }
#endif
    }

    nxt_http_static_send(task, r, ctx);

    return;

fail:

    nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
}


static void
nxt_http_static_send(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_static_ctx_t *ctx)
{
    size_t                  length, encode;
    u_char                  *p, *fname;
    struct tm               tm;
    nxt_buf_t               *fb;
    nxt_int_t               ret;
    nxt_str_t               *shr, *index, exten, *mtype;
    nxt_uint_t              level;
    nxt_file_t              *f, file;
    nxt_file_info_t         fi;
    nxt_http_field_t        *field;
    nxt_http_status_t       status;
    nxt_router_conf_t       *rtcf;
    nxt_http_action_t       *action;
    nxt_work_handler_t      body_handler;
    nxt_http_static_conf_t  *conf;

    action = ctx->action;
    conf = action->u.conf;
    rtcf = r->conf->socket_conf->router_conf;

    f = NULL;
    mtype = NULL;

    shr = &ctx->share;
    index = &conf->index;

    if (shr->start[shr->length - 1] == '/') {
        nxt_http_static_extract_extension(index, &exten);

        length = shr->length + index->length;

        fname = nxt_mp_nget(r->mem_pool, length + 1);
        if (nxt_slow_path(fname == NULL)) {
            goto fail;
        }

        p = fname;
        p = nxt_cpymem(p, shr->start, shr->length);
        p = nxt_cpymem(p, index->start, index->length);
        *p = '\0';

    } else {
        if (conf->types == NULL) {
            nxt_str_null(&exten);

        } else {
            nxt_http_static_extract_extension(shr, &exten);
            mtype = nxt_http_static_mtype_get(&rtcf->mtypes_hash, &exten);

            ret = nxt_http_route_test_rule(r, conf->types, mtype->start,
                                           mtype->length);
            if (nxt_slow_path(ret == NXT_ERROR)) {
                goto fail;
            }

            if (ret == 0) {
                nxt_http_static_next(task, r, ctx, NXT_HTTP_FORBIDDEN);
                return;
            }
        }

        fname = ctx->share.start;
    }

    nxt_memzero(&file, sizeof(nxt_file_t));

    file.name = fname;

#if (NXT_HAVE_OPENAT2)
    if (conf->resolve != 0 || ctx->chroot.length > 0) {
        nxt_str_t                *chr;
        nxt_uint_t               resolve;
        nxt_http_static_share_t  *share;

        share = &conf->shares[ctx->share_idx];

        resolve = conf->resolve;
        chr = &ctx->chroot;

        if (chr->length > 0) {
            resolve |= RESOLVE_IN_ROOT;

            fname = share->is_const
                    ? share->fname
                    : nxt_http_static_chroot_match(chr->start, file.name);

            if (fname != NULL) {
                file.name = chr->start;
                ret = nxt_file_open(task, &file, NXT_FILE_SEARCH, NXT_FILE_OPEN,
                                    0);

            } else {
                file.error = NXT_EACCES;
                ret = NXT_ERROR;
            }

        } else if (fname[0] == '/') {
            file.name = (u_char *) "/";
            ret = nxt_file_open(task, &file, NXT_FILE_SEARCH, NXT_FILE_OPEN, 0);

        } else {
            file.name = (u_char *) ".";
            file.fd = AT_FDCWD;
            ret = NXT_OK;
        }

        if (nxt_fast_path(ret == NXT_OK)) {
            nxt_file_t  af;

            af = file;
            nxt_memzero(&file, sizeof(nxt_file_t));
            file.name = fname;

            ret = nxt_file_openat2(task, &file, NXT_FILE_RDONLY,
                                   NXT_FILE_OPEN, 0, af.fd, resolve);

            if (af.fd != AT_FDCWD) {
                nxt_file_close(task, &af);
            }
        }

    } else {
        ret = nxt_file_open(task, &file, NXT_FILE_RDONLY, NXT_FILE_OPEN, 0);
    }

#else
    ret = nxt_file_open(task, &file, NXT_FILE_RDONLY, NXT_FILE_OPEN, 0);
#endif

    if (nxt_slow_path(ret != NXT_OK)) {

        switch (file.error) {

        /*
         * For Unix domain sockets "errno" is set to:
         *  - ENXIO on Linux;
         *  - EOPNOTSUPP on *BSD, MacOSX, and Solaris.
         */

        case NXT_ENOENT:
        case NXT_ENOTDIR:
        case NXT_ENAMETOOLONG:
#if (NXT_LINUX)
        case NXT_ENXIO:
#else
        case NXT_EOPNOTSUPP:
#endif
            level = NXT_LOG_ERR;
            status = NXT_HTTP_NOT_FOUND;
            break;

        case NXT_EACCES:
#if (NXT_HAVE_OPENAT2)
        case NXT_ELOOP:
        case NXT_EXDEV:
#endif
            level = NXT_LOG_ERR;
            status = NXT_HTTP_FORBIDDEN;
            break;

        default:
            level = NXT_LOG_ALERT;
            status = NXT_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (status != NXT_HTTP_NOT_FOUND) {
#if (NXT_HAVE_OPENAT2)
            nxt_str_t  *chr = &ctx->chroot;

            if (chr->length > 0) {
                nxt_log(task, level, "opening \"%s\" at \"%V\" failed %E",
                        fname, chr, file.error);

            } else {
                nxt_log(task, level, "opening \"%s\" failed %E",
                        fname, file.error);
            }

#else
            nxt_log(task, level, "opening \"%s\" failed %E", fname, file.error);
#endif
        }

        if (level == NXT_LOG_ERR) {
            nxt_http_static_next(task, r, ctx, status);
            return;
        }

        goto fail;
    }

    f = nxt_mp_get(r->mem_pool, sizeof(nxt_file_t));
    if (nxt_slow_path(f == NULL)) {
        nxt_file_close(task, &file);
        goto fail;
    }

    *f = file;

    ret = nxt_file_info(f, &fi);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    if (nxt_fast_path(nxt_is_file(&fi))) {
        r->status = NXT_HTTP_OK;
        r->resp.content_length_n = nxt_file_size(&fi);

        field = nxt_list_zero_add(r->resp.fields);
        if (nxt_slow_path(field == NULL)) {
            goto fail;
        }

        nxt_http_field_name_set(field, "Last-Modified");

        p = nxt_mp_nget(r->mem_pool, NXT_HTTP_DATE_LEN);
        if (nxt_slow_path(p == NULL)) {
            goto fail;
        }

        nxt_localtime(nxt_file_mtime(&fi), &tm);

        field->value = p;
        field->value_length = nxt_http_date(p, &tm) - p;

        field = nxt_list_zero_add(r->resp.fields);
        if (nxt_slow_path(field == NULL)) {
            goto fail;
        }

        nxt_http_field_name_set(field, "ETag");

        length = NXT_TIME_T_HEXLEN + NXT_OFF_T_HEXLEN + 3;

        p = nxt_mp_nget(r->mem_pool, length);
        if (nxt_slow_path(p == NULL)) {
            goto fail;
        }

        field->value = p;
        field->value_length = nxt_sprintf(p, p + length, "\"%xT-%xO\"",
                                          nxt_file_mtime(&fi),
                                          nxt_file_size(&fi))
                              - p;

        if (exten.start == NULL) {
            nxt_http_static_extract_extension(shr, &exten);
        }

        if (mtype == NULL) {
            mtype = nxt_http_static_mtype_get(&rtcf->mtypes_hash, &exten);
        }

        if (mtype->length != 0) {
            field = nxt_list_zero_add(r->resp.fields);
            if (nxt_slow_path(field == NULL)) {
                goto fail;
            }

            nxt_http_field_name_set(field, "Content-Type");

            field->value = mtype->start;
            field->value_length = mtype->length;
        }

        if (ctx->need_body && nxt_file_size(&fi) > 0) {
            fb = nxt_mp_zget(r->mem_pool, NXT_BUF_FILE_SIZE);
            if (nxt_slow_path(fb == NULL)) {
                goto fail;
            }

            fb->file = f;
            fb->file_end = nxt_file_size(&fi);

            r->out = fb;

            body_handler = &nxt_http_static_body_handler;

        } else {
            nxt_file_close(task, f);
            body_handler = NULL;
        }

    } else {
        /* Not a file. */
        nxt_file_close(task, f);

        if (nxt_slow_path(!nxt_is_dir(&fi)
                          || shr->start[shr->length - 1] == '/'))
        {
            nxt_log(task, NXT_LOG_ERR, "\"%FN\" is not a regular file",
                    f->name);

            nxt_http_static_next(task, r, ctx, NXT_HTTP_NOT_FOUND);
            return;
        }

        f = NULL;

        r->status = NXT_HTTP_MOVED_PERMANENTLY;
        r->resp.content_length_n = 0;

        field = nxt_list_zero_add(r->resp.fields);
        if (nxt_slow_path(field == NULL)) {
            goto fail;
        }

        nxt_http_field_name_set(field, "Location");

        encode = nxt_encode_uri(NULL, r->path->start, r->path->length);
        length = r->path->length + encode * 2 + 1;

        if (r->args->length > 0) {
            length += 1 + r->args->length;
        }

        p = nxt_mp_nget(r->mem_pool, length);
        if (nxt_slow_path(p == NULL)) {
            goto fail;
        }

        field->value = p;
        field->value_length = length;

        if (encode > 0) {
            p = (u_char *) nxt_encode_uri(p, r->path->start, r->path->length);

        } else {
            p = nxt_cpymem(p, r->path->start, r->path->length);
        }

        *p++ = '/';

        if (r->args->length > 0) {
            *p++ = '?';
            nxt_memcpy(p, r->args->start, r->args->length);
        }

        body_handler = NULL;
    }

    nxt_http_request_header_send(task, r, body_handler, NULL);

    r->state = &nxt_http_static_send_state;
    return;

fail:

    if (f != NULL) {
        nxt_file_close(task, f);
    }

    nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
}


static void
nxt_http_static_next(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_static_ctx_t *ctx, nxt_http_status_t status)
{
    nxt_http_action_t       *action;
    nxt_http_static_conf_t  *conf;

    action = ctx->action;
    conf = action->u.conf;

    ctx->share_idx++;

    if (ctx->share_idx < conf->nshares) {
        nxt_http_static_iterate(task, r, ctx);
        return;
    }

    if (action->fallback != NULL) {
        if (nxt_slow_path(r->log_route)) {
            nxt_log(task, NXT_LOG_NOTICE, "\"fallback\" taken");
        }

        r->action = action->fallback;
        nxt_http_request_action(task, r, action->fallback);
        return;
    }

    nxt_http_request_error(task, r, status);
}


#if (NXT_HAVE_OPENAT2)

static u_char *
nxt_http_static_chroot_match(u_char *chr, u_char *shr)
{
    if (*chr != *shr) {
        return NULL;
    }

    chr++;
    shr++;

    for ( ;; ) {
        if (*shr == '\0') {
            return NULL;
        }

        if (*chr == *shr) {
            chr++;
            shr++;
            continue;
        }

        if (*chr == '\0') {
            break;
        }

        if (*chr == '/') {
            if (chr[-1] == '/') {
                chr++;
                continue;
            }

        } else if (*shr == '/') {
            if (shr[-1] == '/') {
                shr++;
                continue;
            }
        }

        return NULL;
    }

    if (shr[-1] != '/' && *shr != '/') {
        return NULL;
    }

    while (*shr == '/') {
        shr++;
    }

    return (*shr != '\0') ? shr : NULL;
}

#endif


static void
nxt_http_static_extract_extension(nxt_str_t *path, nxt_str_t *exten)
{
    u_char  ch, *p, *end;

    end = path->start + path->length;
    p = end;

    while (p > path->start) {
        p--;
        ch = *p;

        switch (ch) {
        case '/':
            p++;
            /* Fall through. */
        case '.':
            goto extension;
        }
    }

extension:

    exten->length = end - p;
    exten->start = p;
}


static void
nxt_http_static_body_handler(nxt_task_t *task, void *obj, void *data)
{
    size_t              alloc;
    nxt_buf_t           *fb, *b, **next, *out;
    nxt_off_t           rest;
    nxt_int_t           n;
    nxt_work_queue_t    *wq;
    nxt_http_request_t  *r;

    r = obj;
    fb = r->out;

    rest = fb->file_end - fb->file_pos;
    out = NULL;
    next = &out;
    n = 0;

    do {
        alloc = nxt_min(rest, NXT_HTTP_STATIC_BUF_SIZE);

        b = nxt_buf_mem_alloc(r->mem_pool, alloc, 0);
        if (nxt_slow_path(b == NULL)) {
            goto fail;
        }

        b->completion_handler = nxt_http_static_buf_completion;
        b->parent = r;

        nxt_mp_retain(r->mem_pool);

        *next = b;
        next = &b->next;

        rest -= alloc;

    } while (rest > 0 && ++n < NXT_HTTP_STATIC_BUF_COUNT);

    wq = &task->thread->engine->fast_work_queue;

    nxt_sendbuf_drain(task, wq, out);
    return;

fail:

    while (out != NULL) {
        b = out;
        out = b->next;

        nxt_mp_free(r->mem_pool, b);
        nxt_mp_release(r->mem_pool);
    }
}


static const nxt_http_request_state_t  nxt_http_static_send_state
    nxt_aligned(64) =
{
    .error_handler = nxt_http_request_error_handler,
};


static void
nxt_http_static_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    ssize_t             n, size;
    nxt_buf_t           *b, *fb, *next;
    nxt_off_t           rest;
    nxt_http_request_t  *r;

    b = obj;
    r = data;

complete_buf:

    fb = r->out;

    if (nxt_slow_path(fb == NULL || r->error)) {
        goto clean;
    }

    rest = fb->file_end - fb->file_pos;
    size = nxt_buf_mem_size(&b->mem);

    size = nxt_min(rest, (nxt_off_t) size);

    n = nxt_file_read(fb->file, b->mem.start, size, fb->file_pos);

    if (nxt_slow_path(n == NXT_ERROR)) {
        nxt_http_request_error_handler(task, r, r->proto.any);
        goto clean;
    }

    next = b->next;

    if (n == rest) {
        nxt_file_close(task, fb->file);
        r->out = NULL;

        b->next = nxt_http_buf_last(r);

    } else {
        fb->file_pos += n;
        b->next = NULL;
    }

    b->mem.pos = b->mem.start;
    b->mem.free = b->mem.pos + n;

    nxt_http_request_send(task, r, b);

    if (next != NULL) {
        b = next;
        goto complete_buf;
    }

    return;

clean:

    do {
        next = b->next;

        nxt_mp_free(r->mem_pool, b);
        nxt_mp_release(r->mem_pool);

        b = next;
    } while (b != NULL);

    if (fb != NULL) {
        nxt_file_close(task, fb->file);
        r->out = NULL;
    }
}


nxt_int_t
nxt_http_static_mtypes_init(nxt_mp_t *mp, nxt_lvlhsh_t *hash)
{
    nxt_str_t   *type, exten;
    nxt_int_t   ret;
    nxt_uint_t  i;

    static const struct {
        nxt_str_t   type;
        const char  *exten;
    } default_types[] = {

        { nxt_string("text/html"),      ".html"  },
        { nxt_string("text/html"),      ".htm"   },
        { nxt_string("text/css"),       ".css"   },

        { nxt_string("image/svg+xml"),  ".svg"   },
        { nxt_string("image/webp"),     ".webp"  },
        { nxt_string("image/png"),      ".png"   },
        { nxt_string("image/apng"),     ".apng"  },
        { nxt_string("image/jpeg"),     ".jpeg"  },
        { nxt_string("image/jpeg"),     ".jpg"   },
        { nxt_string("image/gif"),      ".gif"   },
        { nxt_string("image/x-icon"),   ".ico"   },

        { nxt_string("image/avif"),           ".avif"  },
        { nxt_string("image/avif-sequence"),  ".avifs" },

        { nxt_string("font/woff"),      ".woff"  },
        { nxt_string("font/woff2"),     ".woff2" },
        { nxt_string("font/otf"),       ".otf"   },
        { nxt_string("font/ttf"),       ".ttf"   },

        { nxt_string("text/plain"),     ".txt"   },
        { nxt_string("text/markdown"),  ".md"    },
        { nxt_string("text/x-rst"),     ".rst"   },

        { nxt_string("application/javascript"),  ".js"   },
        { nxt_string("application/javascript"),  ".mjs"  },
        { nxt_string("application/json"),        ".json" },
        { nxt_string("application/xml"),         ".xml"  },
        { nxt_string("application/rss+xml"),     ".rss"  },
        { nxt_string("application/atom+xml"),    ".atom" },
        { nxt_string("application/pdf"),         ".pdf"  },

        { nxt_string("application/zip"),         ".zip"  },

        { nxt_string("audio/mpeg"),       ".mp3"  },
        { nxt_string("audio/ogg"),        ".ogg"  },
        { nxt_string("audio/midi"),       ".midi" },
        { nxt_string("audio/midi"),       ".mid"  },
        { nxt_string("audio/flac"),       ".flac" },
        { nxt_string("audio/aac"),        ".aac"  },
        { nxt_string("audio/wav"),        ".wav"  },

        { nxt_string("video/mpeg"),       ".mpeg" },
        { nxt_string("video/mpeg"),       ".mpg"  },
        { nxt_string("video/mp4"),        ".mp4"  },
        { nxt_string("video/webm"),       ".webm" },
        { nxt_string("video/x-msvideo"),  ".avi"  },

        { nxt_string("application/octet-stream"),  ".exe" },
        { nxt_string("application/octet-stream"),  ".bin" },
        { nxt_string("application/octet-stream"),  ".dll" },
        { nxt_string("application/octet-stream"),  ".iso" },
        { nxt_string("application/octet-stream"),  ".img" },
        { nxt_string("application/octet-stream"),  ".msi" },

        { nxt_string("application/octet-stream"),  ".deb" },
        { nxt_string("application/octet-stream"),  ".rpm" },

        { nxt_string("application/x-httpd-php"),   ".php" },
    };

    for (i = 0; i < nxt_nitems(default_types); i++) {
        type = (nxt_str_t *) &default_types[i].type;

        exten.start = (u_char *) default_types[i].exten;
        exten.length = nxt_strlen(exten.start);

        ret = nxt_http_static_mtypes_hash_add(mp, hash, &exten, type);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


static const nxt_lvlhsh_proto_t  nxt_http_static_mtypes_hash_proto
    nxt_aligned(64) =
{
    NXT_LVLHSH_DEFAULT,
    nxt_http_static_mtypes_hash_test,
    nxt_http_static_mtypes_hash_alloc,
    nxt_http_static_mtypes_hash_free,
};


typedef struct {
    nxt_str_t  exten;
    nxt_str_t  *type;
} nxt_http_static_mtype_t;


nxt_int_t
nxt_http_static_mtypes_hash_add(nxt_mp_t *mp, nxt_lvlhsh_t *hash,
    const nxt_str_t *exten, nxt_str_t *type)
{
    nxt_lvlhsh_query_t       lhq;
    nxt_http_static_mtype_t  *mtype;

    mtype = nxt_mp_get(mp, sizeof(nxt_http_static_mtype_t));
    if (nxt_slow_path(mtype == NULL)) {
        return NXT_ERROR;
    }

    mtype->exten = *exten;
    mtype->type = type;

    lhq.key = *exten;
    lhq.key_hash = nxt_djb_hash_lowcase(lhq.key.start, lhq.key.length);
    lhq.replace = 1;
    lhq.value = mtype;
    lhq.proto = &nxt_http_static_mtypes_hash_proto;
    lhq.pool = mp;

    return nxt_lvlhsh_insert(hash, &lhq);
}


nxt_str_t *
nxt_http_static_mtype_get(nxt_lvlhsh_t *hash, const nxt_str_t *exten)
{
    nxt_lvlhsh_query_t       lhq;
    nxt_http_static_mtype_t  *mtype;

    static nxt_str_t  empty = nxt_string("");

    lhq.key = *exten;
    lhq.key_hash = nxt_djb_hash_lowcase(lhq.key.start, lhq.key.length);
    lhq.proto = &nxt_http_static_mtypes_hash_proto;

    if (nxt_lvlhsh_find(hash, &lhq) == NXT_OK) {
        mtype = lhq.value;
        return mtype->type;
    }

    return &empty;
}


static nxt_int_t
nxt_http_static_mtypes_hash_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_http_static_mtype_t  *mtype;

    mtype = data;

    return nxt_strcasestr_eq(&lhq->key, &mtype->exten) ? NXT_OK : NXT_DECLINED;
}


static void *
nxt_http_static_mtypes_hash_alloc(void *data, size_t size)
{
    return nxt_mp_align(data, size, size);
}


static void
nxt_http_static_mtypes_hash_free(void *data, void *p)
{
    nxt_mp_free(data, p);
}

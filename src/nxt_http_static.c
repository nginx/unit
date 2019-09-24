
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


#define NXT_HTTP_STATIC_BUF_COUNT  2
#define NXT_HTTP_STATIC_BUF_SIZE   (128 * 1024)


static void nxt_http_static_extract_extension(nxt_str_t *path,
    nxt_str_t *extension);
static void nxt_http_static_body_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_http_static_buf_completion(nxt_task_t *task, void *obj,
    void *data);

static nxt_int_t nxt_http_static_mtypes_hash_test(nxt_lvlhsh_query_t *lhq,
    void *data);
static void *nxt_http_static_mtypes_hash_alloc(void *data, size_t size);
static void nxt_http_static_mtypes_hash_free(void *data, void *p);


static const nxt_http_request_state_t  nxt_http_static_send_state;


nxt_http_pass_t *
nxt_http_static_handler(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_pass_t *pass)
{
    size_t              alloc, encode;
    u_char              *p;
    struct tm           tm;
    nxt_buf_t           *fb;
    nxt_int_t           ret;
    nxt_str_t           index, extension, *mtype;
    nxt_uint_t          level;
    nxt_bool_t          need_body;
    nxt_file_t          *f;
    nxt_file_info_t     fi;
    nxt_http_field_t    *field;
    nxt_http_status_t   status;
    nxt_router_conf_t   *rtcf;
    nxt_work_handler_t  body_handler;

    if (nxt_slow_path(!nxt_str_eq(r->method, "GET", 3))) {

        if (!nxt_str_eq(r->method, "HEAD", 4)) {
            nxt_http_request_error(task, r, NXT_HTTP_METHOD_NOT_ALLOWED);
            return NULL;
        }

        need_body = 0;

    } else {
        need_body = 1;
    }

    f = nxt_mp_zget(r->mem_pool, sizeof(nxt_file_t));
    if (nxt_slow_path(f == NULL)) {
        goto fail;
    }

    f->fd = NXT_FILE_INVALID;

    if (r->path->start[r->path->length - 1] == '/') {
        /* TODO: dynamic index setting. */
        nxt_str_set(&index, "index.html");
        nxt_str_set(&extension, ".html");

    } else {
        nxt_str_null(&index);
        nxt_str_null(&extension);
    }

    alloc = pass->name.length + r->path->length + index.length + 1;

    f->name = nxt_mp_nget(r->mem_pool, alloc);
    if (nxt_slow_path(f->name == NULL)) {
        goto fail;
    }

    p = f->name;
    p = nxt_cpymem(p, pass->name.start, pass->name.length);
    p = nxt_cpymem(p, r->path->start, r->path->length);
    p = nxt_cpymem(p, index.start, index.length);
    *p = '\0';

    ret = nxt_file_open(task, f, NXT_FILE_RDONLY, NXT_FILE_OPEN, 0);

    if (nxt_slow_path(ret != NXT_OK)) {
        switch (f->error) {

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
            level = NXT_LOG_ERR;
            status = NXT_HTTP_FORBIDDEN;
            break;

        default:
            level = NXT_LOG_ALERT;
            status = NXT_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (status != NXT_HTTP_NOT_FOUND) {
            nxt_log(task, level, "open(\"%FN\") failed %E", f->name, f->error);
        }

        nxt_http_request_error(task, r, status);
        return NULL;
    }

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

        alloc = NXT_TIME_T_HEXLEN + NXT_OFF_T_HEXLEN + 3;

        p = nxt_mp_nget(r->mem_pool, alloc);
        if (nxt_slow_path(p == NULL)) {
            goto fail;
        }

        field->value = p;
        field->value_length = nxt_sprintf(p, p + alloc, "\"%xT-%xO\"",
                                          nxt_file_mtime(&fi),
                                          nxt_file_size(&fi))
                              - p;

        if (extension.start == NULL) {
            nxt_http_static_extract_extension(r->path, &extension);
        }

        rtcf = r->conf->socket_conf->router_conf;

        mtype = nxt_http_static_mtypes_hash_find(&rtcf->mtypes_hash,
                                                 &extension);

        if (mtype != NULL) {
            field = nxt_list_zero_add(r->resp.fields);
            if (nxt_slow_path(field == NULL)) {
                goto fail;
            }

            nxt_http_field_name_set(field, "Content-Type");

            field->value = mtype->start;
            field->value_length = mtype->length;
        }

        if (need_body && nxt_file_size(&fi) > 0) {
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

        if (nxt_slow_path(!nxt_is_dir(&fi))) {
            nxt_log(task, NXT_LOG_ERR, "\"%FN\" is not a regular file",
                    f->name);
            nxt_http_request_error(task, r, NXT_HTTP_NOT_FOUND);
            return NULL;
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
        alloc = r->path->length + encode * 2 + 1;

        if (r->args->length > 0) {
            alloc += 1 + r->args->length;
        }

        p = nxt_mp_nget(r->mem_pool, alloc);
        if (nxt_slow_path(p == NULL)) {
            goto fail;
        }

        field->value = p;
        field->value_length = alloc;

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

    nxt_http_request_header_send(task, r, body_handler);

    r->state = &nxt_http_static_send_state;
    return NULL;

fail:

    nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);

    if (f != NULL && f->fd != NXT_FILE_INVALID) {
        nxt_file_close(task, f);
    }

    return NULL;
}


static void
nxt_http_static_extract_extension(nxt_str_t *path, nxt_str_t *extension)
{
    u_char  ch, *p, *end;

    end = path->start + path->length;
    p = end;

    for ( ;; ) {
        /* There's always '/' in the beginning of the request path. */

        p--;
        ch = *p;

        switch (ch) {
        case '/':
            p++;
            /* Fall through. */
        case '.':
            extension->length = end - p;
            extension->start = p;
            return;
        }
    }
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
    nxt_buf_t           *b, *fb;
    nxt_off_t           rest;
    nxt_http_request_t  *r;

    b = obj;
    r = data;
    fb = r->out;

    if (nxt_slow_path(fb == NULL || r->error)) {
        goto clean;
    }

    rest = fb->file_end - fb->file_pos;
    size = nxt_buf_mem_size(&b->mem);

    size = nxt_min(rest, (nxt_off_t) size);

    n = nxt_file_read(fb->file, b->mem.start, size, fb->file_pos);

    if (n != size) {
        if (n >= 0) {
            nxt_log(task, NXT_LOG_ERR, "file \"%FN\" has changed "
                    "while sending response to a client", fb->file->name);
        }

        nxt_http_request_error_handler(task, r, r->proto.any);
        goto clean;
    }

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
    return;

clean:

    nxt_mp_free(r->mem_pool, b);
    nxt_mp_release(r->mem_pool);

    if (fb != NULL) {
        nxt_file_close(task, fb->file);
        r->out = NULL;
    }
}


nxt_int_t
nxt_http_static_mtypes_init(nxt_mp_t *mp, nxt_lvlhsh_t *hash)
{
    nxt_str_t   *type, extension;
    nxt_int_t   ret;
    nxt_uint_t  i;

    static const struct {
        nxt_str_t   type;
        const char  *extension;
    } default_types[] = {

        { nxt_string("text/html"),      ".html"  },
        { nxt_string("text/html"),      ".htm"   },
        { nxt_string("text/css"),       ".css"   },

        { nxt_string("image/svg+xml"),  ".svg"   },
        { nxt_string("image/svg+xml"),  ".svg"   },
        { nxt_string("image/webp"),     ".webp"  },
        { nxt_string("image/png"),      ".png"   },
        { nxt_string("image/jpeg"),     ".jpeg"  },
        { nxt_string("image/jpeg"),     ".jpg"   },
        { nxt_string("image/gif"),      ".gif"   },
        { nxt_string("image/x-icon"),   ".ico"   },

        { nxt_string("font/woff"),      ".woff"  },
        { nxt_string("font/woff2"),     ".woff2" },
        { nxt_string("font/otf"),       ".otf"   },
        { nxt_string("font/ttf"),       ".ttf"   },

        { nxt_string("text/plain"),     ".txt"   },
        { nxt_string("text/markdown"),  ".md"    },
        { nxt_string("text/x-rst"),     ".rst"   },

        { nxt_string("application/javascript"),  ".js"   },
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
    };

    for (i = 0; i < nxt_nitems(default_types); i++) {
        type = (nxt_str_t *) &default_types[i].type;

        extension.start = (u_char *) default_types[i].extension;
        extension.length = nxt_strlen(extension.start);

        ret = nxt_http_static_mtypes_hash_add(mp, hash, &extension, type);
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
    nxt_str_t  extension;
    nxt_str_t  *type;
} nxt_http_static_mtype_t;


nxt_int_t
nxt_http_static_mtypes_hash_add(nxt_mp_t *mp, nxt_lvlhsh_t *hash,
    nxt_str_t *extension, nxt_str_t *type)
{
    nxt_lvlhsh_query_t       lhq;
    nxt_http_static_mtype_t  *mtype;

    mtype = nxt_mp_get(mp, sizeof(nxt_http_static_mtype_t));
    if (nxt_slow_path(mtype == NULL)) {
        return NXT_ERROR;
    }

    mtype->extension = *extension;
    mtype->type = type;

    lhq.key = *extension;
    lhq.key_hash = nxt_djb_hash_lowcase(lhq.key.start, lhq.key.length);
    lhq.replace = 1;
    lhq.value = mtype;
    lhq.proto = &nxt_http_static_mtypes_hash_proto;
    lhq.pool = mp;

    return nxt_lvlhsh_insert(hash, &lhq);
}


nxt_str_t *
nxt_http_static_mtypes_hash_find(nxt_lvlhsh_t *hash, nxt_str_t *extension)
{
    nxt_lvlhsh_query_t       lhq;
    nxt_http_static_mtype_t  *mtype;

    lhq.key = *extension;
    lhq.key_hash = nxt_djb_hash_lowcase(lhq.key.start, lhq.key.length);
    lhq.proto = &nxt_http_static_mtypes_hash_proto;

    if (nxt_lvlhsh_find(hash, &lhq) == NXT_OK) {
        mtype = lhq.value;
        return mtype->type;
    }

    return NULL;
}


static nxt_int_t
nxt_http_static_mtypes_hash_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_http_static_mtype_t  *mtype;

    mtype = data;

    return nxt_strcasestr_eq(&lhq->key, &mtype->extension) ? NXT_OK
                                                           : NXT_DECLINED;
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

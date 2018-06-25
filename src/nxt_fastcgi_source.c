
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


#define NXT_FASTCGI_RESPONDER  1
#define NXT_FASTCGI_KEEP_CONN  1


typedef struct {
    u_char    *buf;
    uint32_t  len;
    u_char    length[4];
} nxt_fastcgi_param_t;


#define                                                                       \
nxt_fastcgi_set_record_length(p, length)                                      \
    do {                                                                      \
        uint32_t  len = length;                                               \
                                                                              \
        p[1] = (u_char) len;  len >>= 8;                                      \
        p[0] = (u_char) len;                                                  \
    } while (0)


nxt_inline size_t
nxt_fastcgi_param_length(u_char *p, uint32_t length)
{
    if (nxt_fast_path(length < 128)) {
        *p = (u_char) length;
        return 1;
    }

    p[3] = (u_char) length;  length >>= 8;
    p[2] = (u_char) length;  length >>= 8;
    p[1] = (u_char) length;  length >>= 8;
    p[0] = (u_char) (length | 0x80);

    return 4;
}


static nxt_buf_t *nxt_fastcgi_request_create(nxt_fastcgi_source_t *fs);
static nxt_int_t nxt_fastcgi_next_param(nxt_fastcgi_source_t *fs,
    nxt_fastcgi_param_t *param);

static void nxt_fastcgi_source_record_filter(nxt_task_t *task, void *obj,
    void *data);
static void nxt_fastcgi_source_record_error(nxt_task_t *task, void *obj,
    void *data);
static void nxt_fastcgi_source_header_filter(nxt_task_t *task, void *obj,
    void *data);
static void nxt_fastcgi_source_sync_buffer(nxt_task_t *task,
    nxt_fastcgi_source_t *fs, nxt_buf_t *b);

static nxt_int_t nxt_fastcgi_source_header_process(nxt_task_t *task,
    nxt_fastcgi_source_t *fs);
static nxt_int_t nxt_fastcgi_source_status(nxt_upstream_source_t *us,
    nxt_name_value_t *nv);
static nxt_int_t nxt_fastcgi_source_content_length(nxt_upstream_source_t *us,
    nxt_name_value_t *nv);

static void nxt_fastcgi_source_header_ready(nxt_fastcgi_source_t *fs,
    nxt_buf_t *b);
static void nxt_fastcgi_source_body_filter(nxt_task_t *task, void *obj,
    void *data);
static nxt_buf_t *nxt_fastcgi_source_last_buf(nxt_fastcgi_parse_t *fp);
static void nxt_fastcgi_source_error(nxt_task_t *task,
    nxt_stream_source_t *stream);
static void nxt_fastcgi_source_fail(nxt_task_t *task, nxt_fastcgi_source_t *fs);


/*
 * A FastCGI request:
 *   FCGI_BEGIN_REQUEST record;
 *   Several FCGI_PARAMS records, the last FCGI_PARAMS record must have
 *   zero content length,
 *   Several FCGI_STDIN records, the last FCGI_STDIN record must have
 *   zero content length.
 */

static const uint8_t  nxt_fastcgi_begin_request[] = {
    1,                                 /* FastCGI version.                   */
    NXT_FASTCGI_BEGIN_REQUEST,         /* The BEGIN_REQUEST record type.     */
    0, 1,                              /* Request ID.                        */
    0, 8,                              /* Content length of the Role record. */
    0,                                 /* Padding length.                    */
    0,                                 /* Reserved.                          */

    0, NXT_FASTCGI_RESPONDER,          /* The Responder Role.                */
    0,                                 /* Flags.                             */
    0, 0, 0, 0, 0,                     /* Reserved.                          */
};


static const uint8_t  nxt_fastcgi_params_record[] = {
    1,                                 /* FastCGI version.                   */
    NXT_FASTCGI_PARAMS,                /* The PARAMS record type.            */
    0, 1,                              /* Request ID.                        */
    0, 0,                              /* Content length.                    */
    0,                                 /* Padding length.                    */
    0,                                 /* Reserved.                          */
};


static const uint8_t  nxt_fastcgi_stdin_record[] = {
    1,                                 /* FastCGI version.                   */
    NXT_FASTCGI_STDIN,                 /* The STDIN record type.             */
    0, 1,                              /* Request ID.                        */
    0, 0,                              /* Content length.                    */
    0,                                 /* Padding length.                    */
    0,                                 /* Reserved.                          */
};


void
nxt_fastcgi_source_handler(nxt_task_t *task, nxt_upstream_source_t *us,
    nxt_fastcgi_source_request_create_t request_create)
{
    nxt_stream_source_t   *stream;
    nxt_fastcgi_source_t  *fs;

    fs = nxt_mp_zget(us->buffers.mem_pool, sizeof(nxt_fastcgi_source_t));
    if (nxt_slow_path(fs == NULL)) {
        goto fail;
    }

    us->protocol_source = fs;

    fs->header_in.list = nxt_list_create(us->buffers.mem_pool, 8,
                                         sizeof(nxt_name_value_t));
    if (nxt_slow_path(fs->header_in.list == NULL)) {
        goto fail;
    }

    fs->header_in.hash = us->header_hash;
    fs->upstream = us;
    fs->request_create = request_create;

    stream = us->stream;

    if (stream == NULL) {
        stream = nxt_mp_zget(us->buffers.mem_pool, sizeof(nxt_stream_source_t));
        if (nxt_slow_path(stream == NULL)) {
            goto fail;
        }

        us->stream = stream;
        stream->upstream = us;

    } else {
        nxt_memzero(stream, sizeof(nxt_stream_source_t));
    }

    /*
     * Create the FastCGI source filter chain:
     *   stream source | FastCGI record filter | FastCGI HTTP header filter
     */
    stream->next = &fs->query;
    stream->error_handler = nxt_fastcgi_source_error;

    fs->record.next.context = fs;
    fs->record.next.filter = nxt_fastcgi_source_header_filter;

    fs->record.parse.last_buf = nxt_fastcgi_source_last_buf;
    fs->record.parse.data = fs;
    fs->record.parse.mem_pool = us->buffers.mem_pool;

    fs->query.context = &fs->record.parse;
    fs->query.filter = nxt_fastcgi_source_record_filter;

    fs->header_in.content_length = -1;

    stream->out = nxt_fastcgi_request_create(fs);

    if (nxt_fast_path(stream->out != NULL)) {
        nxt_memzero(&fs->u.header, sizeof(nxt_http_split_header_parse_t));
        fs->u.header.mem_pool = fs->upstream->buffers.mem_pool;

        nxt_stream_source_connect(task, stream);
        return;
    }

fail:

    nxt_fastcgi_source_fail(task, fs);
}


static nxt_buf_t *
nxt_fastcgi_request_create(nxt_fastcgi_source_t *fs)
{
    u_char               *p, *record_length;
    size_t               len, size, max_record_size;
    nxt_int_t            ret;
    nxt_buf_t            *b, *req, **prev;
    nxt_bool_t           begin_request;
    nxt_fastcgi_param_t  param;

    nxt_thread_log_debug("fastcgi request");

    begin_request = 1;
    param.len = 0;
    prev = &req;

new_buffer:

    ret = nxt_buf_pool_mem_alloc(&fs->upstream->buffers, 0);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NULL;
    }

    b = fs->upstream->buffers.current;
    fs->upstream->buffers.current = NULL;

    *prev = b;
    prev = &b->next;

new_record:

    size = b->mem.end - b->mem.free;
    size = nxt_align_size(size, 8) - 8;
    /* The maximal FastCGI record content size is 65535.  65528 is 64K - 8. */
    max_record_size = nxt_min(65528, size);

    p = b->mem.free;

    if (begin_request) {
        /* TODO: fastcgi keep conn in flags. */
        p = nxt_cpymem(p, nxt_fastcgi_begin_request, 16);
        max_record_size -= 16;
        begin_request = 0;
    }

    b->mem.free = nxt_cpymem(p, nxt_fastcgi_params_record, 8);
    record_length = &p[4];
    size = 0;

    for ( ;; ) {
        if (param.len == 0) {
            ret = nxt_fastcgi_next_param(fs, &param);

            if (nxt_slow_path(ret != NXT_OK)) {

                if (nxt_slow_path(ret == NXT_ERROR)) {
                    return NULL;
                }

                /* ret == NXT_DONE */
                break;
            }
        }

        len = max_record_size;

        if (nxt_fast_path(len >= param.len)) {
            len = param.len;
            param.len = 0;

        } else {
            param.len -= len;
        }

        nxt_thread_log_debug("fastcgi copy len:%uz", len);

        b->mem.free = nxt_cpymem(b->mem.free, param.buf, len);

        size += len;
        max_record_size -= len;

        if (nxt_slow_path(param.len != 0)) {
            /* The record is full. */

            param.buf += len;

            nxt_thread_log_debug("fastcgi content size:%uz", size);

            nxt_fastcgi_set_record_length(record_length, size);

            /* The minimal size of aligned record with content is 16 bytes. */
            if (b->mem.end - b->mem.free >= 16) {
                goto new_record;
            }

            nxt_thread_log_debug("\"%*s\"", b->mem.free - b->mem.pos,
                                 b->mem.pos);
            goto new_buffer;
        }
    }

    nxt_thread_log_debug("fastcgi content size:%uz", size);

    nxt_fastcgi_set_record_length(record_length, size);

    /* A padding length. */
    size = 8 - size % 8;
    record_length[2] = (u_char) size;
    nxt_memzero(b->mem.free, size);
    b->mem.free += size;

    nxt_thread_log_debug("fastcgi padding:%uz", size);

    if (b->mem.end - b->mem.free < 16) {
        nxt_thread_log_debug("\"%*s\"", b->mem.free - b->mem.pos, b->mem.pos);

        b = nxt_buf_mem_alloc(fs->upstream->buffers.mem_pool, 16, 0);
        if (nxt_slow_path(b == NULL)) {
            return NULL;
        }

        *prev = b;
        prev = &b->next;
    }

    /* The end of FastCGI params. */
    p = nxt_cpymem(b->mem.free, nxt_fastcgi_params_record, 8);

    /* The end of FastCGI stdin. */
    b->mem.free = nxt_cpymem(p, nxt_fastcgi_stdin_record, 8);

    nxt_thread_log_debug("\"%*s\"", b->mem.free - b->mem.pos, b->mem.pos);

    return req;
}


static nxt_int_t
nxt_fastcgi_next_param(nxt_fastcgi_source_t *fs, nxt_fastcgi_param_t *param)
{
    nxt_int_t  ret;

    enum {
        sw_name_length = 0,
        sw_value_length,
        sw_name,
        sw_value,
    };

    switch (fs->state) {

    case sw_name_length:
        ret = fs->request_create(fs);

        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }

        nxt_thread_log_debug("fastcgi param \"%V: %V\"",
                             &fs->u.request.name, &fs->u.request.value);

        fs->state = sw_value_length;
        param->buf = param->length;
        param->len = nxt_fastcgi_param_length(param->length,
                                              fs->u.request.name.len);
        break;

    case sw_value_length:
        fs->state = sw_name;
        param->buf = param->length;
        param->len = nxt_fastcgi_param_length(param->length,
                                              fs->u.request.value.len);
        break;

    case sw_name:
        fs->state = sw_value;
        param->buf = fs->u.request.name.data;
        param->len = fs->u.request.name.len;
        break;

    case sw_value:
        fs->state = sw_name_length;
        param->buf = fs->u.request.value.data;
        param->len = fs->u.request.value.len;
        break;
    }

    return NXT_OK;
}


static void
nxt_fastcgi_source_record_filter(nxt_task_t *task, void *obj, void *data)
{
    size_t                       size;
    u_char                       *p;
    nxt_buf_t                    *b, *in;
    nxt_fastcgi_source_t         *fs;
    nxt_fastcgi_source_record_t  *fsr;

    fsr = obj;
    in = data;

    nxt_debug(task, "fastcgi source record filter");

    if (nxt_slow_path(fsr->parse.done)) {
        return;
    }

    nxt_fastcgi_record_parse(task, &fsr->parse, in);

    fs = nxt_container_of(fsr, nxt_fastcgi_source_t, record);

    if (fsr->parse.error) {
        nxt_fastcgi_source_fail(task, fs);
        return;
    }

    if (fsr->parse.fastcgi_error) {
        /*
         * Output all parsed before a FastCGI record error and close upstream.
         */
        nxt_thread_current_work_queue_add(task->thread,
                                          nxt_fastcgi_source_record_error,
                                          task, fs, NULL);
    }

    /* Log FastCGI stderr output. */

    for (b = fsr->parse.out[1]; b != NULL; b = b->next) {

        for (p = b->mem.free - 1; p >= b->mem.pos; p--) {
            if (*p != '\r' && *p != '\n') {
                break;
            }
        }

        size = (p + 1) - b->mem.pos;

        if (size != 0) {
            nxt_log(task, NXT_LOG_ERR,
                    "upstream sent in FastCGI stderr: \"%*s\"",
                    size, b->mem.pos);
        }

        b->completion_handler(task, b, b->parent);
    }

    /* Process FastCGI stdout output. */

    if (fsr->parse.out[0] != NULL) {
        nxt_source_filter(task->thread, fs->upstream->work_queue, task,
                          &fsr->next, fsr->parse.out[0]);
    }
}


static void
nxt_fastcgi_source_record_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_fastcgi_source_t  *fs;

    fs = obj;

    nxt_fastcgi_source_fail(task, fs);
}


static void
nxt_fastcgi_source_header_filter(nxt_task_t *task, void *obj, void *data)
{
    nxt_int_t             ret;
    nxt_buf_t             *b;
    nxt_fastcgi_source_t  *fs;

    fs = obj;
    b = data;

    do {
        nxt_debug(task, "fastcgi source header filter");

        if (nxt_slow_path(nxt_buf_is_sync(b))) {
            nxt_fastcgi_source_sync_buffer(task, fs, b);
            return;
        }

        for ( ;; ) {
            ret = nxt_http_split_header_parse(&fs->u.header, &b->mem);

            if (nxt_slow_path(ret != NXT_OK)) {
                break;
            }

            ret = nxt_fastcgi_source_header_process(task, fs);

            if (nxt_slow_path(ret != NXT_OK)) {
                break;
            }
        }

        if (nxt_fast_path(ret == NXT_DONE)) {
            nxt_debug(task, "fastcgi source header done");
            nxt_fastcgi_source_header_ready(fs, b);
            return;
        }

        if (nxt_fast_path(ret != NXT_AGAIN)) {

            if (ret != NXT_ERROR) {
                /* n == NXT_DECLINED: "\r" is not followed by "\n" */
                nxt_log(task, NXT_LOG_ERR,
                        "upstream sent invalid header line: \"%*s\\r...\"",
                        fs->u.header.parse.header_end
                            - fs->u.header.parse.header_name_start,
                        fs->u.header.parse.header_name_start);
            }

            /* ret == NXT_ERROR */

            nxt_fastcgi_source_fail(task, fs);
            return;
        }

        b = b->next;

    } while (b != NULL);
}


static void
nxt_fastcgi_source_sync_buffer(nxt_task_t *task, nxt_fastcgi_source_t *fs,
    nxt_buf_t *b)
{
    if (nxt_buf_is_last(b)) {
        nxt_log(task, NXT_LOG_ERR, "upstream closed prematurely connection");

    } else {
        nxt_log(task, NXT_LOG_ERR, "%ui buffers %uz each are not "
                "enough to process upstream response header",
                fs->upstream->buffers.max, fs->upstream->buffers.size);
    }

    /* The stream source sends only the last and the nobuf sync buffer. */

    nxt_fastcgi_source_fail(task, fs);
}


static nxt_int_t
nxt_fastcgi_source_header_process(nxt_task_t *task, nxt_fastcgi_source_t *fs)
{
    size_t                     len;
    nxt_name_value_t           *nv;
    nxt_lvlhsh_query_t         lhq;
    nxt_http_header_parse_t    *hp;
    nxt_upstream_name_value_t  *unv;

    hp = &fs->u.header.parse;

    len = hp->header_name_end - hp->header_name_start;

    if (len > 255) {
        nxt_log(task, NXT_LOG_INFO,
                "upstream sent too long header field name: \"%*s\"",
                len, hp->header_name_start);
        return NXT_ERROR;
    }

    nv = nxt_list_add(fs->header_in.list);
    if (nxt_slow_path(nv == NULL)) {
        return NXT_ERROR;
    }

    nv->hash = hp->header_hash;
    nv->skip = 0;
    nv->name_len = len;
    nv->name_start = hp->header_name_start;
    nv->value_len = hp->header_end - hp->header_start;
    nv->value_start = hp->header_start;

    nxt_debug(task, "http header: \"%*s: %*s\"",
              nv->name_len, nv->name_start, nv->value_len, nv->value_start);

    lhq.key_hash = nv->hash;
    lhq.key.len = nv->name_len;
    lhq.key.data = nv->name_start;
    lhq.proto = &nxt_upstream_header_hash_proto;

    if (nxt_lvlhsh_find(&fs->header_in.hash, &lhq) == NXT_OK) {
        unv = lhq.value;

        if (unv->handler(fs->upstream, nv) == NXT_OK) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


static const nxt_upstream_name_value_t  nxt_fastcgi_source_headers[]
    nxt_aligned(32) =
{
    { nxt_fastcgi_source_status,
      nxt_upstream_name_value("status") },

    { nxt_fastcgi_source_content_length,
      nxt_upstream_name_value("content-length") },
};


nxt_int_t
nxt_fastcgi_source_hash_create(nxt_mp_t *mp, nxt_lvlhsh_t *lh)
{
    return nxt_upstream_header_hash_add(mp, lh, nxt_fastcgi_source_headers,
                                        nxt_nitems(nxt_fastcgi_source_headers));
}


static nxt_int_t
nxt_fastcgi_source_status(nxt_upstream_source_t *us, nxt_name_value_t *nv)
{
    nxt_int_t             n;
    nxt_str_t             s;
    nxt_fastcgi_source_t  *fs;

    s.len = nv->value_len;
    s.data = nv->value_start;

    n = nxt_str_int_parse(&s);

    if (nxt_fast_path(n > 0)) {
        fs = us->protocol_source;
        fs->header_in.status = n;
        return NXT_OK;
    }

    return NXT_ERROR;
}


static nxt_int_t
nxt_fastcgi_source_content_length(nxt_upstream_source_t *us,
    nxt_name_value_t *nv)
{
    nxt_off_t             length;
    nxt_fastcgi_source_t  *fs;

    length = nxt_off_t_parse(nv->value_start, nv->value_len);

    if (nxt_fast_path(length > 0)) {
        fs = us->protocol_source;
        fs->header_in.content_length = length;
        return NXT_OK;
    }

    return NXT_ERROR;
}


static void
nxt_fastcgi_source_header_ready(nxt_fastcgi_source_t *fs, nxt_buf_t *b)
{
    /*
     * Change the FastCGI source filter chain:
     *   stream source | FastCGI record filter | FastCGI body filter
     */
    fs->record.next.filter = nxt_fastcgi_source_body_filter;

    if (nxt_buf_mem_used_size(&b->mem) != 0) {
        fs->rest = b;
    }

    if (fs->header_in.status == 0) {
        /* The "200 OK" status by default. */
        fs->header_in.status = 200;
    }

    fs->upstream->state->ready_handler(fs);
}


/*
 * The FastCGI source body filter accumulates first body buffers before the next
 * filter will be established and sets completion handler for the last buffer.
 */

static void
nxt_fastcgi_source_body_filter(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t             *b, *in;
    nxt_fastcgi_source_t  *fs;

    fs = obj;
    in = data;

    nxt_debug(task, "fastcgi source body filter");

    for (b = in; b != NULL; b = b->next) {

        if (nxt_buf_is_last(b)) {
            b->data = fs->upstream->data;
            b->completion_handler = fs->upstream->state->completion_handler;
        }
    }

    if (fs->next != NULL) {
        nxt_source_filter(task->thread, fs->upstream->work_queue, task,
                          fs->next, in);
        return;
    }

    nxt_buf_chain_add(&fs->rest, in);
}


static nxt_buf_t *
nxt_fastcgi_source_last_buf(nxt_fastcgi_parse_t *fp)
{
    nxt_buf_t             *b;
    nxt_fastcgi_source_t  *fs;

    fs = fp->data;

    b = nxt_buf_sync_alloc(fp->mem_pool, NXT_BUF_SYNC_LAST);

    if (nxt_fast_path(b != NULL)) {
        b->data = fs->upstream->data;
        b->completion_handler = fs->upstream->state->completion_handler;
    }

    return b;
}


static void
nxt_fastcgi_source_error(nxt_task_t *task, nxt_stream_source_t *stream)
{
    nxt_fastcgi_source_t  *fs;

    nxt_thread_log_debug("fastcgi source error");

    fs = stream->upstream->protocol_source;

    nxt_fastcgi_source_fail(task, fs);
}


static void
nxt_fastcgi_source_fail(nxt_task_t *task, nxt_fastcgi_source_t *fs)
{
    nxt_debug(task, "fastcgi source fail");

    /* TODO: fail, next upstream, or bad gateway */

    fs->upstream->state->error_handler(task, fs, NULL);
}

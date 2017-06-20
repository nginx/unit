
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


typedef struct {
    nxt_http_chunk_parse_t  parse;
    nxt_source_hook_t       next;
} nxt_http_source_chunk_t;


static nxt_buf_t *nxt_http_source_request_create(nxt_http_source_t *hs);

static void nxt_http_source_status_filter(nxt_task_t *task, void *obj,
    void *data);
static void nxt_http_source_header_filter(nxt_task_t *task, void *obj,
    void *data);

static nxt_int_t nxt_http_source_header_line_process(nxt_http_source_t *hs);
static nxt_int_t nxt_http_source_content_length(nxt_upstream_source_t *us,
    nxt_name_value_t *nv);
static nxt_int_t nxt_http_source_transfer_encoding(nxt_upstream_source_t *us,
    nxt_name_value_t *nv);

static void nxt_http_source_header_ready(nxt_task_t *task,
    nxt_http_source_t *hs, nxt_buf_t *rest);
static void nxt_http_source_chunk_filter(nxt_task_t *task, void *obj,
    void *data);
static void nxt_http_source_chunk_error(nxt_task_t *task, void *obj,
    void *data);
static void nxt_http_source_body_filter(nxt_task_t *task, void *obj,
    void *data);

static void nxt_http_source_sync_buffer(nxt_task_t *task, nxt_http_source_t *hs,
    nxt_buf_t *b);
static void nxt_http_source_error(nxt_task_t *task,
    nxt_stream_source_t *stream);
static void nxt_http_source_fail(nxt_task_t *task, nxt_http_source_t *hs);
static void nxt_http_source_message(const char *msg, size_t len, u_char *p);


void
nxt_http_source_handler(nxt_task_t *task, nxt_upstream_source_t *us,
    nxt_http_source_request_create_t request_create)
{
    nxt_http_source_t    *hs;
    nxt_stream_source_t  *stream;

    hs = nxt_mp_zget(us->buffers.mem_pool, sizeof(nxt_http_source_t));
    if (nxt_slow_path(hs == NULL)) {
        goto fail;
    }

    us->protocol_source = hs;

    hs->header_in.list = nxt_list_create(us->buffers.mem_pool, 8,
                                         sizeof(nxt_name_value_t));
    if (nxt_slow_path(hs->header_in.list == NULL)) {
        goto fail;
    }

    hs->header_in.hash = us->header_hash;
    hs->upstream = us;
    hs->request_create = request_create;

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
     * Create the HTTP source filter chain:
     *   stream source | HTTP status line filter
     */
    stream->next = &hs->query;
    stream->error_handler = nxt_http_source_error;

    hs->query.context = hs;
    hs->query.filter = nxt_http_source_status_filter;

    hs->header_in.content_length = -1;

    stream->out = nxt_http_source_request_create(hs);

    if (nxt_fast_path(stream->out != NULL)) {
        nxt_memzero(&hs->u.status_parse, sizeof(nxt_http_status_parse_t));

        nxt_stream_source_connect(task, stream);
        return;
    }

fail:

    nxt_http_source_fail(task, hs);
}


nxt_inline u_char *
nxt_http_source_copy(u_char *p, nxt_str_t *src, size_t len)
{
    u_char  *s;

    if (nxt_fast_path(len >= src->len)) {
        len = src->len;
        src->len = 0;

    } else {
        src->len -= len;
    }

    s = src->data;
    src->data += len;

    return nxt_cpymem(p, s, len);
}


static nxt_buf_t *
nxt_http_source_request_create(nxt_http_source_t *hs)
{
    nxt_int_t  ret;
    nxt_buf_t  *b, *req, **prev;

    nxt_thread_log_debug("http source create request");

    prev = &req;

new_buffer:

    ret = nxt_buf_pool_mem_alloc(&hs->upstream->buffers, 0);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NULL;
    }

    b = hs->upstream->buffers.current;
    hs->upstream->buffers.current = NULL;

    *prev = b;
    prev = &b->next;

    for ( ;; ) {
        ret = hs->request_create(hs);

        if (nxt_fast_path(ret == NXT_OK)) {
            b->mem.free = nxt_http_source_copy(b->mem.free, &hs->u.request.copy,
                                               b->mem.end - b->mem.free);

            if (nxt_fast_path(hs->u.request.copy.len == 0)) {
                continue;
            }

            nxt_thread_log_debug("\"%*s\"", b->mem.free - b->mem.pos,
                                 b->mem.pos);

            goto new_buffer;
        }

        if (nxt_slow_path(ret == NXT_ERROR)) {
            return NULL;
        }

        /* ret == NXT_DONE */
        break;
    }

    nxt_thread_log_debug("\"%*s\"", b->mem.free - b->mem.pos, b->mem.pos);

    return req;
}


static void
nxt_http_source_status_filter(nxt_task_t *task, void *obj, void *data)
{
    nxt_int_t          ret;
    nxt_buf_t          *b;
    nxt_http_source_t  *hs;

    hs = obj;
    b = data;

    /*
     * No cycle over buffer chain is required since at
     * start the stream source passes buffers one at a time.
     */

    nxt_debug(task, "http source status filter");

    if (nxt_slow_path(nxt_buf_is_sync(b))) {
        nxt_http_source_sync_buffer(task, hs, b);
        return;
    }

    ret = nxt_http_status_parse(&hs->u.status_parse, &b->mem);

    if (nxt_fast_path(ret == NXT_OK)) {
        /*
         * Change the HTTP source filter chain:
         *    stream source | HTTP header filter
         */
        hs->query.filter = nxt_http_source_header_filter;

        nxt_debug(task, "upstream status: \"%*s\"",
                  hs->u.status_parse.end - b->mem.start, b->mem.start);

        hs->header_in.status = hs->u.status_parse.code;

        nxt_debug(task, "upstream version:%d status:%uD \"%*s\"",
                  hs->u.status_parse.http_version,
                  hs->u.status_parse.code,
                  hs->u.status_parse.end - hs->u.status_parse.start,
                  hs->u.status_parse.start);

        nxt_memzero(&hs->u.header, sizeof(nxt_http_split_header_parse_t));
        hs->u.header.mem_pool = hs->upstream->buffers.mem_pool;

        nxt_http_source_header_filter(task, hs, b);
        return;
    }

    if (nxt_slow_path(ret == NXT_ERROR)) {
        /* HTTP/0.9 response. */
        hs->header_in.status = 200;
        nxt_http_source_header_ready(task, hs, b);
        return;
    }

    /* ret == NXT_AGAIN */

    /*
     * b->mem.pos is always equal to b->mem.end because b is a buffer
     * which points to a response part read by the stream source.
     * However, since the stream source is an immediate source of the
     * status filter, b->parent is a buffer the stream source reads in.
     */
    if (b->parent->mem.pos == b->parent->mem.end) {
        nxt_http_source_message("upstream sent too long status line: \"%*s\"",
                                b->mem.pos - b->mem.start, b->mem.start);

        nxt_http_source_fail(task, hs);
    }
}


static void
nxt_http_source_header_filter(nxt_task_t *task, void *obj, void *data)
{
    nxt_int_t          ret;
    nxt_buf_t          *b;
    nxt_http_source_t  *hs;

    hs = obj;
    b = data;

    /*
     * No cycle over buffer chain is required since at
     * start the stream source passes buffers one at a time.
     */

    nxt_debug(task, "http source header filter");

    if (nxt_slow_path(nxt_buf_is_sync(b))) {
        nxt_http_source_sync_buffer(task, hs, b);
        return;
    }

    for ( ;; ) {
        ret = nxt_http_split_header_parse(&hs->u.header, &b->mem);

        if (nxt_slow_path(ret != NXT_OK)) {
            break;
        }

        ret = nxt_http_source_header_line_process(hs);

        if (nxt_slow_path(ret != NXT_OK)) {
            break;
        }
    }

    if (nxt_fast_path(ret == NXT_DONE)) {
        nxt_debug(task, "http source header done");
        nxt_http_source_header_ready(task, hs, b);
        return;
    }

    if (nxt_fast_path(ret == NXT_AGAIN)) {
        return;
    }

    if (ret != NXT_ERROR) {
        /* ret == NXT_DECLINED: "\r" is not followed by "\n" */
        nxt_log(task, NXT_LOG_ERR,
                "upstream sent invalid header line: \"%*s\\r...\"",
                hs->u.header.parse.header_end
                    - hs->u.header.parse.header_name_start,
                hs->u.header.parse.header_name_start);
    }

    /* ret == NXT_ERROR */

    nxt_http_source_fail(task, hs);
}


static nxt_int_t
nxt_http_source_header_line_process(nxt_http_source_t *hs)
{
    size_t                     name_len;
    nxt_name_value_t           *nv;
    nxt_lvlhsh_query_t         lhq;
    nxt_http_header_parse_t    *hp;
    nxt_upstream_name_value_t  *unv;

    hp = &hs->u.header.parse;

    name_len = hp->header_name_end - hp->header_name_start;

    if (name_len > 255) {
        nxt_http_source_message("upstream sent too long header field name: "
                                "\"%*s\"", name_len, hp->header_name_start);
        return NXT_ERROR;
    }

    nv = nxt_list_add(hs->header_in.list);
    if (nxt_slow_path(nv == NULL)) {
        return NXT_ERROR;
    }

    nv->hash = hp->header_hash;
    nv->skip = 0;
    nv->name_len = name_len;
    nv->name_start = hp->header_name_start;
    nv->value_len = hp->header_end - hp->header_start;
    nv->value_start = hp->header_start;

    nxt_thread_log_debug("upstream header: \"%*s: %*s\"",
                         nv->name_len, nv->name_start,
                         nv->value_len, nv->value_start);

    lhq.key_hash = nv->hash;
    lhq.key.len = nv->name_len;
    lhq.key.data = nv->name_start;
    lhq.proto = &nxt_upstream_header_hash_proto;

    if (nxt_lvlhsh_find(&hs->header_in.hash, &lhq) == NXT_OK) {
        unv = lhq.value;

        if (unv->handler(hs->upstream, nv) != NXT_OK) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


static const nxt_upstream_name_value_t  nxt_http_source_headers[]
    nxt_aligned(32) =
{
    { nxt_http_source_content_length,
      nxt_upstream_name_value("content-length") },

    { nxt_http_source_transfer_encoding,
      nxt_upstream_name_value("transfer-encoding") },
};


nxt_int_t
nxt_http_source_hash_create(nxt_mp_t *mp, nxt_lvlhsh_t *lh)
{
    return nxt_upstream_header_hash_add(mp, lh, nxt_http_source_headers,
                                        nxt_nitems(nxt_http_source_headers));
}


static nxt_int_t
nxt_http_source_content_length(nxt_upstream_source_t *us, nxt_name_value_t *nv)
{
    nxt_off_t          length;
    nxt_http_source_t  *hs;

    length = nxt_off_t_parse(nv->value_start, nv->value_len);

    if (nxt_fast_path(length > 0)) {
        hs = us->protocol_source;
        hs->header_in.content_length = length;
        return NXT_OK;
    }

    return NXT_ERROR;
}


static nxt_int_t
nxt_http_source_transfer_encoding(nxt_upstream_source_t *us,
    nxt_name_value_t *nv)
{
    u_char             *end;
    nxt_http_source_t  *hs;

    end = nv->value_start + nv->value_len;

    if (nxt_memcasestrn(nv->value_start, end, "chunked", 7) != NULL) {
        hs = us->protocol_source;
        hs->chunked = 1;
    }

    return NXT_OK;
}


static void
nxt_http_source_header_ready(nxt_task_t *task, nxt_http_source_t *hs,
    nxt_buf_t *rest)
{
    nxt_buf_t                *b;
    nxt_upstream_source_t    *us;
    nxt_http_source_chunk_t  *hsc;

    us = hs->upstream;

    /* Free buffers used for request header. */

    for (b = us->stream->out; b != NULL; b = b->next) {
        nxt_buf_pool_free(&us->buffers, b);
    }

    if (nxt_fast_path(nxt_buf_pool_available(&us->buffers))) {

        if (hs->chunked) {
            hsc = nxt_mp_zalloc(hs->upstream->buffers.mem_pool,
                                sizeof(nxt_http_source_chunk_t));
            if (nxt_slow_path(hsc == NULL)) {
                goto fail;
            }

            /*
             * Change the HTTP source filter chain:
             *    stream source | chunk filter | HTTP body filter
             */
            hs->query.context = hsc;
            hs->query.filter = nxt_http_source_chunk_filter;

            hsc->next.context = hs;
            hsc->next.filter = nxt_http_source_body_filter;

            hsc->parse.mem_pool = hs->upstream->buffers.mem_pool;

            if (nxt_buf_mem_used_size(&rest->mem) != 0) {
                hs->rest = nxt_http_chunk_parse(task, &hsc->parse, rest);

                if (nxt_slow_path(hs->rest == NULL)) {
                    goto fail;
                }
            }

        } else {
            /*
             * Change the HTTP source filter chain:
             *    stream source | HTTP body filter
             */
            hs->query.filter = nxt_http_source_body_filter;

            if (nxt_buf_mem_used_size(&rest->mem) != 0) {
                hs->rest = rest;
            }
        }

        hs->upstream->state->ready_handler(hs);
        return;
    }

    nxt_thread_log_error(NXT_LOG_ERR, "%d buffers %uDK each "
                         "are not enough to read upstream response",
                         us->buffers.max, us->buffers.size / 1024);
fail:

    nxt_http_source_fail(task, hs);
}


static void
nxt_http_source_chunk_filter(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t                *b;
    nxt_http_source_t        *hs;
    nxt_http_source_chunk_t  *hsc;

    hsc = obj;
    b = data;

    nxt_debug(task, "http source chunk filter");

    b = nxt_http_chunk_parse(task, &hsc->parse, b);

    hs = hsc->next.context;

    if (hsc->parse.error) {
        nxt_http_source_fail(task, hs);
        return;
    }

    if (hsc->parse.chunk_error) {
        /* Output all parsed before a chunk error and close upstream. */
        nxt_thread_current_work_queue_add(task->thread,
                                          nxt_http_source_chunk_error,
                                          task, hs, NULL);
    }

    if (b != NULL) {
        nxt_source_filter(task->thread, hs->upstream->work_queue, task,
                          &hsc->next, b);
    }
}


static void
nxt_http_source_chunk_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_source_t  *hs;

    hs = obj;

    nxt_http_source_fail(task, hs);
}


/*
 * The HTTP source body filter accumulates first body buffers before the next
 * filter will be established and sets completion handler for the last buffer.
 */

static void
nxt_http_source_body_filter(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t          *b, *in;
    nxt_http_source_t  *hs;

    hs = obj;
    in = data;

    nxt_debug(task, "http source body filter");

    for (b = in; b != NULL; b = b->next) {

        if (nxt_buf_is_last(b)) {
            b->data = hs->upstream->data;
            b->completion_handler = hs->upstream->state->completion_handler;
        }
    }

    if (hs->next != NULL) {
        nxt_source_filter(task->thread, hs->upstream->work_queue, task,
                          hs->next, in);
        return;
    }

    nxt_buf_chain_add(&hs->rest, in);
}


static void
nxt_http_source_sync_buffer(nxt_task_t *task, nxt_http_source_t *hs,
    nxt_buf_t *b)
{
    if (nxt_buf_is_last(b)) {
        nxt_log(task, NXT_LOG_ERR,
                "upstream closed prematurely connection");

    } else {
        nxt_log(task, NXT_LOG_ERR,"%ui buffers %uz each are not "
                "enough to process upstream response header",
                hs->upstream->buffers.max, hs->upstream->buffers.size);
    }

    /* The stream source sends only the last and the nobuf sync buffer. */

    nxt_http_source_fail(task, hs);
}


static void
nxt_http_source_error(nxt_task_t *task, nxt_stream_source_t *stream)
{
    nxt_http_source_t  *hs;

    nxt_thread_log_debug("http source error");

    hs = stream->next->context;
    nxt_http_source_fail(task, hs);
}


static void
nxt_http_source_fail(nxt_task_t *task, nxt_http_source_t *hs)
{
    nxt_debug(task, "http source fail");

    /* TODO: fail, next upstream, or bad gateway */

    hs->upstream->state->error_handler(task, hs, NULL);
}


static void
nxt_http_source_message(const char *msg, size_t len, u_char *p)
{
    if (len > NXT_MAX_ERROR_STR - 300) {
        len = NXT_MAX_ERROR_STR - 300;
        p[len++] = '.'; p[len++] = '.'; p[len++] = '.';
    }

    nxt_thread_log_error(NXT_LOG_ERR, msg, len, p);
}

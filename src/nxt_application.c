
/*
 * Copyright (C) Max Romanov
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_application.h>
#include <nxt_master_process.h>


nxt_application_module_t         *nxt_app_modules[NXT_APP_MAX];

static nxt_thread_mutex_t        nxt_app_mutex;
static nxt_thread_cond_t         nxt_app_cond;

static nxt_http_fields_hash_entry_t  nxt_app_request_fields[];
static nxt_http_fields_hash_t        *nxt_app_request_fields_hash;

static nxt_application_module_t      *nxt_app;

nxt_int_t
nxt_app_start(nxt_task_t *task, void *data)
{
    nxt_int_t             ret;
    nxt_common_app_conf_t *app_conf;

    app_conf = data;

    if (nxt_slow_path(nxt_thread_mutex_create(&nxt_app_mutex) != NXT_OK)) {
        return NXT_ERROR;
    }

    if (nxt_slow_path(nxt_thread_cond_create(&nxt_app_cond) != NXT_OK)) {
        return NXT_ERROR;
    }

    nxt_app = nxt_app_modules[app_conf->type_id];

    ret = nxt_app->init(task, data);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_debug(task, "application init failed");

    } else {
        nxt_debug(task, "application init done");
    }

    return ret;
}


nxt_int_t
nxt_app_http_init(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_http_fields_hash_t  *hash;

    hash = nxt_http_fields_hash_create(nxt_app_request_fields, rt->mem_pool);
    if (nxt_slow_path(hash == NULL)) {
        return NXT_ERROR;
    }

    nxt_app_request_fields_hash = hash;

    return NXT_OK;
}


void
nxt_port_app_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    size_t          dump_size;
    nxt_buf_t       *b;
    nxt_port_t      *port;
    nxt_app_rmsg_t  rmsg = { msg->buf };
    nxt_app_wmsg_t  wmsg;

    b = msg->buf;
    dump_size = b->mem.free - b->mem.pos;

    if (dump_size > 300) {
        dump_size = 300;
    }

    nxt_debug(task, "app data: %*s ...", dump_size, b->mem.pos);

    port = nxt_runtime_port_find(task->thread->runtime, msg->port_msg.pid,
                                 msg->port_msg.reply_port);
    if (nxt_slow_path(port == NULL)) {
        //
    }

    wmsg.port = port;
    wmsg.write = NULL;
    wmsg.buf = &wmsg.write;
    wmsg.stream = msg->port_msg.stream;

    nxt_app->run(task, &rmsg, &wmsg);
}


nxt_inline nxt_port_t *
nxt_app_msg_get_port(nxt_task_t *task, nxt_app_wmsg_t *msg)
{
    return msg->port;
}


u_char *
nxt_app_msg_write_get_buf(nxt_task_t *task, nxt_app_wmsg_t *msg, size_t size)
{
    size_t      free_size;
    u_char      *res;
    nxt_buf_t   *b;
    nxt_port_t  *port;

    res = NULL;

    do {
        b = *msg->buf;

        if (b == NULL) {
            port = nxt_app_msg_get_port(task, msg);
            if (nxt_slow_path(port == NULL)) {
                return NULL;
            }

            b = nxt_port_mmap_get_buf(task, port, size);
            if (nxt_slow_path(b == NULL)) {
                return NULL;
            }

            *msg->buf = b;

            free_size = nxt_buf_mem_free_size(&b->mem);

            if (nxt_slow_path(free_size < size)) {
                nxt_debug(task, "requested buffer too big (%z < %z)",
                          free_size, size);
                return NULL;
            }

        }

        free_size = nxt_buf_mem_free_size(&b->mem);

        if (free_size >= size) {
            res = b->mem.free;
            b->mem.free += size;

            return res;
        }

        if (nxt_port_mmap_increase_buf(task, b, size) == NXT_OK) {
            res = b->mem.free;
            b->mem.free += size;

            return res;
        }

        msg->buf = &b->next;
    } while(1);
}


nxt_int_t
nxt_app_msg_write(nxt_task_t *task, nxt_app_wmsg_t *msg, u_char *c, size_t size)
{
    u_char  *dst;
    size_t  dst_length;

    if (c != NULL) {
        dst_length = size + (size < 128 ? 1 : 4) + 1;

        dst = nxt_app_msg_write_get_buf(task, msg, dst_length);
        if (nxt_slow_path(dst == NULL)) {
            nxt_debug(task, "nxt_app_msg_write: get_buf(%uz) failed",
                      dst_length);
            return NXT_ERROR;
        }

        dst = nxt_app_msg_write_length(dst, size + 1); /* +1 for trailing 0 */

        nxt_memcpy(dst, c, size);
        dst[size] = 0;

        nxt_debug(task, "nxt_app_msg_write: %uz %*s", size, (int)size, c);
    } else {
        dst_length = 1;

        dst = nxt_app_msg_write_get_buf(task, msg, dst_length);
        if (nxt_slow_path(dst == NULL)) {
            nxt_debug(task, "nxt_app_msg_write: get_buf(%uz) failed",
                      dst_length);
            return NXT_ERROR;
        }

        dst = nxt_app_msg_write_length(dst, 0);

        nxt_debug(task, "nxt_app_msg_write: NULL");
    }

    return NXT_OK;
}


nxt_int_t
nxt_app_msg_write_prefixed_upcase(nxt_task_t *task, nxt_app_wmsg_t *msg,
    const nxt_str_t *prefix, const nxt_str_t *v)
{
    u_char  *dst, *src;
    size_t  i, length, dst_length;

    length = prefix->length + v->length;

    dst_length = length + (length < 128 ? 1 : 4) + 1;

    dst = nxt_app_msg_write_get_buf(task, msg, dst_length);
    if (nxt_slow_path(dst == NULL)) {
        return NXT_ERROR;
    }

    dst = nxt_app_msg_write_length(dst, length + 1); /* +1 for trailing 0 */

    nxt_memcpy(dst, prefix->start, prefix->length);
    dst += prefix->length;

    src = v->start;
    for (i = 0; i < v->length; i++, dst++, src++) {

        if (*src >= 'a' && *src <= 'z') {
            *dst = *src & ~0x20;
            continue;
        }

        if (*src == '-') {
            *dst = '_';
            continue;
        }

        *dst = *src;
    }

    *dst = 0;

    return NXT_OK;
}


nxt_int_t
nxt_app_msg_read_str(nxt_task_t *task, nxt_app_rmsg_t *msg, nxt_str_t *str)
{
    size_t     length;
    nxt_buf_t  *buf;

    do {
        buf = msg->buf;

        if (nxt_slow_path(buf == NULL)) {
            return NXT_DONE;
        }

        if (nxt_slow_path(nxt_buf_mem_used_size(&buf->mem) < 1)) {
            if (nxt_fast_path(nxt_buf_mem_used_size(&buf->mem) == 0)) {
                msg->buf = buf->next;
                continue;
            }
            return NXT_ERROR;
        }

        if (buf->mem.pos[0] >= 128) {
            if (nxt_slow_path(nxt_buf_mem_used_size(&buf->mem) < 4)) {
                return NXT_ERROR;
            }
        }

        break;
    } while (1);

    buf->mem.pos = nxt_app_msg_read_length(buf->mem.pos, &length);

    if (nxt_slow_path(nxt_buf_mem_used_size(&buf->mem) < (intptr_t)length))
    {
        return NXT_ERROR;
    }

    if (length > 0) {
        str->start = buf->mem.pos;
        str->length = length - 1;

        buf->mem.pos += length;

        nxt_debug(task, "nxt_read_str: %d %*s", (int)length - 1,
                        (int)length - 1, str->start);
    } else {
        str->start = NULL;
        str->length = 0;

        nxt_debug(task, "nxt_read_str: NULL");
    }

    return NXT_OK;
}


nxt_int_t
nxt_app_msg_read_nvp(nxt_task_t *task, nxt_app_rmsg_t *rmsg, nxt_str_t *n,
    nxt_str_t *v)
{
    nxt_int_t rc;

    rc = nxt_app_msg_read_str(task, rmsg, n);
    if (nxt_slow_path(rc != NXT_OK)) {
        return rc;
    }

    rc = nxt_app_msg_read_str(task, rmsg, v);
    if (nxt_slow_path(rc != NXT_OK)) {
        return rc;
    }

    return rc;
}


nxt_int_t
nxt_app_msg_read_size(nxt_task_t *task, nxt_app_rmsg_t *msg, size_t *size)
{
    nxt_buf_t  *buf;

    do {
        buf = msg->buf;

        if (nxt_slow_path(buf == NULL)) {
            return NXT_DONE;
        }

        if (nxt_slow_path(nxt_buf_mem_used_size(&buf->mem) < 1)) {
            if (nxt_fast_path(nxt_buf_mem_used_size(&buf->mem) == 0)) {
                msg->buf = buf->next;
                continue;
            }
            return NXT_ERROR;
        }

        if (buf->mem.pos[0] >= 128) {
            if (nxt_slow_path(nxt_buf_mem_used_size(&buf->mem) < 4)) {
                return NXT_ERROR;
            }
        }

        break;
    } while (1);

    buf->mem.pos = nxt_app_msg_read_length(buf->mem.pos, size);

    nxt_debug(task, "nxt_read_size: %d", (int)*size);

    return NXT_OK;
}


static nxt_int_t
nxt_app_request_content_length(void *ctx, nxt_http_field_t *field,
    nxt_log_t *log)
{
    nxt_str_t                 *v;
    nxt_app_parse_ctx_t       *c;
    nxt_app_request_header_t  *h;

    c = ctx;
    h = &c->r.header;
    v = &field->value;

    h->content_length = *v;
    h->parsed_content_length = nxt_off_t_parse(v->start, v->length);

    return NXT_OK;
}


static nxt_int_t
nxt_app_request_content_type(void *ctx, nxt_http_field_t *field,
    nxt_log_t *log)
{
    nxt_app_parse_ctx_t       *c;
    nxt_app_request_header_t  *h;

    c = ctx;
    h = &c->r.header;

    h->content_type = field->value;

    return NXT_OK;
}


static nxt_int_t
nxt_app_request_cookie(void *ctx, nxt_http_field_t *field,
    nxt_log_t *log)
{
    nxt_app_parse_ctx_t       *c;
    nxt_app_request_header_t  *h;

    c = ctx;
    h = &c->r.header;

    h->cookie = field->value;

    return NXT_OK;
}


static nxt_int_t
nxt_app_request_host(void *ctx, nxt_http_field_t *field,
    nxt_log_t *log)
{
    nxt_app_parse_ctx_t       *c;
    nxt_app_request_header_t  *h;

    c = ctx;
    h = &c->r.header;

    h->host = field->value;

    return NXT_OK;
}


static nxt_http_fields_hash_entry_t  nxt_app_request_fields[] = {
    { nxt_string("Content-Length"), &nxt_app_request_content_length, 0 },
    { nxt_string("Content-Type"), &nxt_app_request_content_type, 0 },
    { nxt_string("Cookie"), &nxt_app_request_cookie, 0 },
    { nxt_string("Host"), &nxt_app_request_host, 0 },

    { nxt_null_string, NULL, 0 }
};


nxt_int_t
nxt_app_http_req_init(nxt_task_t *task, nxt_app_parse_ctx_t *ctx)
{
    nxt_int_t  rc;

    ctx->mem_pool = nxt_mp_create(1024, 128, 256, 32);

    rc = nxt_http_parse_request_init(&ctx->parser, ctx->mem_pool);
    if (nxt_slow_path(rc != NXT_OK)) {
        return rc;
    }

    ctx->parser.fields_hash = nxt_app_request_fields_hash;

    return NXT_OK;
}


nxt_int_t
nxt_app_http_req_parse(nxt_task_t *task, nxt_app_parse_ctx_t *ctx,
    nxt_buf_t *buf)
{
    nxt_int_t                 rc;
    nxt_app_request_body_t    *b;
    nxt_http_request_parse_t  *p;
    nxt_app_request_header_t  *h;

    p = &ctx->parser;
    b = &ctx->r.body;
    h = &ctx->r.header;

    if (h->done == 0) {
        rc = nxt_http_parse_request(p, &buf->mem);

        if (nxt_slow_path(rc != NXT_DONE)) {
            return rc;
        }

        rc = nxt_http_fields_process(p->fields, ctx, task->log);

        if (nxt_slow_path(rc != NXT_OK)) {
            return rc;
        }

        h->fields = p->fields;
        h->done = 1;

        h->version.start = p->version.str;
        h->version.length = nxt_strlen(p->version.str);

        h->method = p->method;

        h->target.start = p->target_start;
        h->target.length = p->target_end - p->target_start;

        h->path = p->path;
        h->query = p->args;

        if (h->parsed_content_length == 0) {
            b->done = 1;
        }
    }

    if (b->done == 0) {
        b->preread.length = buf->mem.free - buf->mem.pos;
        b->preread.start = buf->mem.pos;

        b->done = b->preread.length >= (size_t) h->parsed_content_length;
    }

    if (h->done == 1 && b->done == 1) {
        return NXT_DONE;
    }

    return NXT_AGAIN;
}


nxt_int_t
nxt_app_http_req_done(nxt_task_t *task, nxt_app_parse_ctx_t *ctx)
{
    nxt_mp_destroy(ctx->mem_pool);

    return NXT_OK;
}


nxt_int_t
nxt_app_msg_flush(nxt_task_t *task, nxt_app_wmsg_t *msg, nxt_bool_t last)
{
    nxt_int_t   rc;
    nxt_buf_t   *b;
    nxt_port_t  *port;

    rc = NXT_OK;

    port = nxt_app_msg_get_port(task, msg);
    if (nxt_slow_path(port == NULL)) {
        return NXT_ERROR;
    }

    if (nxt_slow_path(last == 1)) {
        do {
            b = *msg->buf;

            if (b == NULL) {
                b = nxt_buf_sync_alloc(port->mem_pool, NXT_BUF_SYNC_LAST);
                *msg->buf = b;
                break;
            }

            msg->buf = &b->next;
        } while(1);
    }

    if (nxt_slow_path(msg->write != NULL)) {
        rc = nxt_port_socket_write(task, port, NXT_PORT_MSG_DATA,
                                   -1, msg->stream, 0, msg->write);

        msg->write = NULL;
        msg->buf = &msg->write;
    }

    return rc;
}


nxt_int_t
nxt_app_msg_write_raw(nxt_task_t *task, nxt_app_wmsg_t *msg, const u_char *c,
    size_t size)
{
    u_char  *dst;

    dst = nxt_app_msg_write_get_buf(task, msg, size);
    if (nxt_slow_path(dst == NULL)) {
        return NXT_ERROR;
    }

    nxt_memcpy(dst, c, size);

    nxt_debug(task, "nxt_app_msg_write_raw: %d %*s", (int)size,
              (int)size, c);

    return NXT_OK;
}


nxt_app_type_t
nxt_app_parse_type(nxt_str_t *str)
{
    if (nxt_str_eq(str, "python", 6)) {
        return NXT_APP_PYTHON;

    } else if (nxt_str_eq(str, "python2", 7)) {
        return NXT_APP_PYTHON2;

    } else if (nxt_str_eq(str, "python3", 7)) {
        return NXT_APP_PYTHON3;

    } else if (nxt_str_eq(str, "php", 3)) {
        return NXT_APP_PHP;

    } else if (nxt_str_eq(str, "php5", 4)) {
        return NXT_APP_PHP5;

    } else if (nxt_str_eq(str, "php7", 4)) {
        return NXT_APP_PHP7;

    } else if (nxt_str_eq(str, "ruby", 4)) {
        return NXT_APP_RUBY;

    } else if (nxt_str_eq(str, "go", 2)) {
        return NXT_APP_GO;

    }

    return NXT_APP_UNKNOWN;
}

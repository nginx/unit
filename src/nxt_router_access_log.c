
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_conf.h>
#include <nxt_http.h>


typedef struct {
    nxt_str_t                       path;
    nxt_conf_value_t                *format;
    nxt_conf_value_t                *expr;
} nxt_router_access_log_conf_t;


typedef struct {
    nxt_str_t                       text;
    nxt_router_access_log_t         *access_log;
} nxt_router_access_log_ctx_t;


typedef struct {
    nxt_str_t                       name;
    nxt_tstr_t                      *tstr;
} nxt_router_access_log_member_t;


struct nxt_router_access_log_format_s {
    nxt_tstr_t                      *tstr;
    nxt_uint_t                      nmembers;
    nxt_router_access_log_member_t  *member;
};


static nxt_router_access_log_format_t *nxt_router_access_log_format_create(
    nxt_task_t *task, nxt_router_conf_t *rtcf, nxt_conf_value_t *value);
static void nxt_router_access_log_writer(nxt_task_t *task,
    nxt_http_request_t *r, nxt_router_access_log_t *access_log,
    nxt_router_access_log_format_t *format);
static nxt_int_t nxt_router_access_log_text(nxt_task_t *task,
    nxt_http_request_t *r, nxt_router_access_log_ctx_t *ctx, nxt_tstr_t *tstr);
static nxt_int_t nxt_router_access_log_json(nxt_task_t *task,
    nxt_http_request_t *r, nxt_router_access_log_ctx_t *ctx,
    nxt_router_access_log_format_t *format);
static void nxt_router_access_log_write(nxt_task_t *task, nxt_http_request_t *r,
    nxt_router_access_log_ctx_t *ctx);
static void nxt_router_access_log_ready(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static void nxt_router_access_log_error(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static void nxt_router_access_log_reopen_completion(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_access_log_reopen_ready(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static void nxt_router_access_log_reopen_error(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);


static nxt_conf_map_t  nxt_router_access_log_conf[] = {
    {
        nxt_string("path"),
        NXT_CONF_MAP_STR,
        offsetof(nxt_router_access_log_conf_t, path),
    },

    {
        nxt_string("format"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_router_access_log_conf_t, format),
    },

    {
        nxt_string("if"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_router_access_log_conf_t, expr),
    },
};


nxt_int_t
nxt_router_access_log_create(nxt_task_t *task, nxt_router_conf_t *rtcf,
    nxt_conf_value_t *value)
{
    nxt_int_t                     ret;
    nxt_str_t                     str;
    nxt_router_t                  *router;
    nxt_router_access_log_t       *access_log;
    nxt_router_access_log_conf_t  alcf;

    nxt_memzero(&alcf, sizeof(nxt_router_access_log_conf_t));

    if (nxt_conf_type(value) == NXT_CONF_STRING) {
        nxt_conf_get_string(value, &alcf.path);

    } else {
        ret = nxt_conf_map_object(rtcf->mem_pool, value,
                                  nxt_router_access_log_conf,
                                  nxt_nitems(nxt_router_access_log_conf),
                                  &alcf);
        if (ret != NXT_OK) {
            nxt_alert(task, "access log map error");
            return NXT_ERROR;
        }
    }

    router = nxt_router;

    access_log = router->access_log;

    if (access_log != NULL && nxt_strstr_eq(&alcf.path, &access_log->path)) {
        nxt_router_access_log_use(&router->lock, access_log);

    } else {
        access_log = nxt_malloc(sizeof(nxt_router_access_log_t)
                                + alcf.path.length);
        if (access_log == NULL) {
            nxt_alert(task, "failed to allocate access log structure");
            return NXT_ERROR;
        }

        access_log->fd = -1;
        access_log->handler = &nxt_router_access_log_writer;
        access_log->count = 1;

        access_log->path.length = alcf.path.length;
        access_log->path.start = (u_char *) access_log
                                 + sizeof(nxt_router_access_log_t);

        nxt_memcpy(access_log->path.start, alcf.path.start, alcf.path.length);
    }

    rtcf->access_log = access_log;

    rtcf->log_format = nxt_router_access_log_format_create(task, rtcf,
                                                           alcf.format);
    if (nxt_slow_path(rtcf->log_format == NULL)) {
        return NXT_ERROR;
    }

    if (alcf.expr != NULL) {
        nxt_conf_get_string(alcf.expr, &str);

        ret = nxt_tstr_cond_compile(rtcf->tstr_state, &str, &rtcf->log_cond);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


static nxt_router_access_log_format_t *
nxt_router_access_log_format_create(nxt_task_t *task, nxt_router_conf_t *rtcf,
    nxt_conf_value_t *value)
{
    size_t                          size;
    uint32_t                        i, n, next;
    nxt_str_t                       name, str, *dst;
    nxt_bool_t                      has_js;
    nxt_conf_value_t                *cv;
    nxt_router_access_log_member_t  *member;
    nxt_router_access_log_format_t  *format;

    static const nxt_str_t  default_format = nxt_string("$remote_addr - - "
        "[$time_local] \"$request_line\" $status $body_bytes_sent "
        "\"$header_referer\" \"$header_user_agent\"");

    format = nxt_mp_zalloc(rtcf->mem_pool,
                           sizeof(nxt_router_access_log_format_t));
    if (nxt_slow_path(format == NULL)) {
        return NULL;
    }

    if (value != NULL) {

        if (nxt_conf_type(value) == NXT_CONF_OBJECT) {
            next = 0;
            has_js = 0;

            n = nxt_conf_object_members_count(value);

            for ( ;; ) {
                cv = nxt_conf_next_object_member(value, &name, &next);
                if (cv == NULL) {
                    break;
                }

                nxt_conf_get_string(cv, &str);

                if (nxt_tstr_is_js(&str)) {
                    has_js = 1;
                }
            }

            if (has_js) {
                member = nxt_mp_alloc(rtcf->mem_pool,
                                    n * sizeof(nxt_router_access_log_member_t));
                if (nxt_slow_path(member == NULL)) {
                    return NULL;
                }

                next = 0;

                for (i = 0; i < n; i++) {
                    cv = nxt_conf_next_object_member(value, &name, &next);
                    if (cv == NULL) {
                        break;
                    }

                    dst = nxt_str_dup(rtcf->mem_pool, &member[i].name, &name);
                    if (nxt_slow_path(dst == NULL)) {
                        return NULL;
                    }

                    nxt_conf_get_string(cv, &str);

                    member[i].tstr = nxt_tstr_compile(rtcf->tstr_state, &str,
                                                      NXT_TSTR_LOGGING);
                    if (nxt_slow_path(member[i].tstr == NULL)) {
                        return NULL;
                    }
                }

                format->nmembers = n;
                format->member = member;

                return format;
            }

            size = nxt_conf_json_length(value, NULL);

            str.start = nxt_mp_nget(rtcf->mem_pool, size);
            if (nxt_slow_path(str.start == NULL)) {
                return NULL;
            }

            str.length = nxt_conf_json_print(str.start, value, NULL)
                         - str.start;

        } else {
            nxt_conf_get_string(value, &str);
        }

    } else {
        str = default_format;
    }

    format->tstr = nxt_tstr_compile(rtcf->tstr_state, &str,
                                    NXT_TSTR_LOGGING | NXT_TSTR_NEWLINE);
    if (nxt_slow_path(format->tstr == NULL)) {
        return NULL;
    }

    return format;
}


static void
nxt_router_access_log_writer(nxt_task_t *task, nxt_http_request_t *r,
    nxt_router_access_log_t *access_log, nxt_router_access_log_format_t *format)
{
    nxt_int_t                    ret;
    nxt_router_access_log_ctx_t  *ctx;

    ctx = nxt_mp_get(r->mem_pool, sizeof(nxt_router_access_log_ctx_t));
    if (nxt_slow_path(ctx == NULL)) {
        return;
    }

    ctx->access_log = access_log;

    if (format->tstr != NULL) {
        ret = nxt_router_access_log_text(task, r, ctx, format->tstr);

    } else {
        ret = nxt_router_access_log_json(task, r, ctx, format);
    }

    if (ret == NXT_OK) {
        nxt_router_access_log_write(task, r, ctx);
    }
}


static nxt_int_t
nxt_router_access_log_text(nxt_task_t *task, nxt_http_request_t *r,
    nxt_router_access_log_ctx_t *ctx, nxt_tstr_t *tstr)
{
    nxt_int_t          ret;
    nxt_router_conf_t  *rtcf;

    if (nxt_tstr_is_const(tstr)) {
        nxt_tstr_str(tstr, &ctx->text);

    } else {
        rtcf = r->conf->socket_conf->router_conf;

        ret = nxt_tstr_query_init(&r->tstr_query, rtcf->tstr_state,
                                  &r->tstr_cache, r, r->mem_pool);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }

        ret = nxt_tstr_query(task, r->tstr_query, tstr, &ctx->text);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_router_access_log_json(nxt_task_t *task, nxt_http_request_t *r,
    nxt_router_access_log_ctx_t *ctx, nxt_router_access_log_format_t *format)
{
    u_char                          *p;
    size_t                          size;
    nxt_int_t                       ret;
    nxt_str_t                       str;
    nxt_uint_t                      i;
    nxt_conf_value_t                *value;
    nxt_router_conf_t               *rtcf;
    nxt_router_access_log_member_t  *member;

    rtcf = r->conf->socket_conf->router_conf;

    value = nxt_conf_create_object(r->mem_pool, format->nmembers);
    if (nxt_slow_path(value == NULL)) {
        return NXT_ERROR;
    }

    for (i = 0; i < format->nmembers; i++) {
        member = &format->member[i];

        if (nxt_tstr_is_const(member->tstr)) {
            nxt_tstr_str(member->tstr, &str);

        } else {
            ret = nxt_tstr_query_init(&r->tstr_query, rtcf->tstr_state,
                                      &r->tstr_cache, r, r->mem_pool);
            if (nxt_slow_path(ret != NXT_OK)) {
                return NXT_ERROR;
            }

            ret = nxt_tstr_query(task, r->tstr_query, member->tstr, &str);
            if (nxt_slow_path(ret != NXT_OK)) {
                return NXT_ERROR;
            }
        }

        nxt_conf_set_member_string(value, &member->name, &str, i);
    }

    size = nxt_conf_json_length(value, NULL) + 1;

    p = nxt_mp_nget(r->mem_pool, size);
    if (nxt_slow_path(p == NULL)) {
        return NXT_ERROR;
    }

    ctx->text.start = p;

    p = nxt_conf_json_print(p, value, NULL);
    *p++ = '\n';

    ctx->text.length = p - ctx->text.start;

    return NXT_OK;
}


static void
nxt_router_access_log_write(nxt_task_t *task, nxt_http_request_t *r,
    nxt_router_access_log_ctx_t *ctx)
{
    nxt_fd_write(ctx->access_log->fd, ctx->text.start, ctx->text.length);

    nxt_http_request_close_handler(task, r, r->proto.any);
}


void
nxt_router_access_log_open(nxt_task_t *task, nxt_router_temp_conf_t *tmcf)
{
    uint32_t                 stream;
    nxt_int_t                ret;
    nxt_buf_t                *b;
    nxt_port_t               *main_port, *router_port;
    nxt_runtime_t            *rt;
    nxt_router_access_log_t  *access_log;

    access_log = tmcf->router_conf->access_log;

    b = nxt_buf_mem_alloc(tmcf->mem_pool, access_log->path.length + 1, 0);
    if (nxt_slow_path(b == NULL)) {
        goto fail;
    }

    b->completion_handler = nxt_buf_dummy_completion;

    nxt_buf_cpystr(b, &access_log->path);
    *b->mem.free++ = '\0';

    rt = task->thread->runtime;
    main_port = rt->port_by_type[NXT_PROCESS_MAIN];
    router_port = rt->port_by_type[NXT_PROCESS_ROUTER];

    stream = nxt_port_rpc_register_handler(task, router_port,
                                           nxt_router_access_log_ready,
                                           nxt_router_access_log_error,
                                           -1, tmcf);
    if (nxt_slow_path(stream == 0)) {
        goto fail;
    }

    ret = nxt_port_socket_write(task, main_port, NXT_PORT_MSG_ACCESS_LOG, -1,
                                stream, router_port->id, b);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_port_rpc_cancel(task, router_port, stream);
        goto fail;
    }

    return;

fail:

    nxt_router_conf_error(task, tmcf);
}


static void
nxt_router_access_log_ready(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_router_temp_conf_t   *tmcf;
    nxt_router_access_log_t  *access_log;

    tmcf = data;

    access_log = tmcf->router_conf->access_log;

    access_log->fd = msg->fd[0];

    nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                       nxt_router_conf_apply, task, tmcf, NULL);
}


static void
nxt_router_access_log_error(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_router_temp_conf_t  *tmcf;

    tmcf = data;

    nxt_router_conf_error(task, tmcf);
}


void
nxt_router_access_log_use(nxt_thread_spinlock_t *lock,
    nxt_router_access_log_t *access_log)
{
    if (access_log == NULL) {
        return;
    }

    nxt_thread_spin_lock(lock);

    access_log->count++;

    nxt_thread_spin_unlock(lock);
}


void
nxt_router_access_log_release(nxt_task_t *task, nxt_thread_spinlock_t *lock,
    nxt_router_access_log_t *access_log)
{
    if (access_log == NULL) {
        return;
    }

    nxt_thread_spin_lock(lock);

    if (--access_log->count != 0) {
        access_log = NULL;
    }

    nxt_thread_spin_unlock(lock);

    if (access_log != NULL) {

        if (access_log->fd != -1) {
            nxt_fd_close(access_log->fd);
        }

        nxt_free(access_log);
    }
}


typedef struct {
    nxt_mp_t                 *mem_pool;
    nxt_router_access_log_t  *access_log;
} nxt_router_access_log_reopen_t;


void
nxt_router_access_log_reopen_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_mp_t                        *mp;
    uint32_t                        stream;
    nxt_int_t                       ret;
    nxt_buf_t                       *b;
    nxt_port_t                      *main_port, *router_port;
    nxt_runtime_t                   *rt;
    nxt_router_access_log_t         *access_log;
    nxt_router_access_log_reopen_t  *reopen;

    access_log = nxt_router->access_log;

    if (access_log == NULL) {
        return;
    }

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (nxt_slow_path(mp == NULL)) {
        return;
    }

    reopen = nxt_mp_get(mp, sizeof(nxt_router_access_log_reopen_t));
    if (nxt_slow_path(reopen == NULL)) {
        goto fail;
    }

    reopen->mem_pool = mp;
    reopen->access_log = access_log;

    b = nxt_buf_mem_alloc(mp, access_log->path.length + 1, 0);
    if (nxt_slow_path(b == NULL)) {
        goto fail;
    }

    b->completion_handler = nxt_router_access_log_reopen_completion;

    nxt_buf_cpystr(b, &access_log->path);
    *b->mem.free++ = '\0';

    rt = task->thread->runtime;
    main_port = rt->port_by_type[NXT_PROCESS_MAIN];
    router_port = rt->port_by_type[NXT_PROCESS_ROUTER];

    stream = nxt_port_rpc_register_handler(task, router_port,
                                           nxt_router_access_log_reopen_ready,
                                           nxt_router_access_log_reopen_error,
                                           -1, reopen);
    if (nxt_slow_path(stream == 0)) {
        goto fail;
    }

    ret = nxt_port_socket_write(task, main_port, NXT_PORT_MSG_ACCESS_LOG, -1,
                                stream, router_port->id, b);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_port_rpc_cancel(task, router_port, stream);
        goto fail;
    }

    nxt_mp_retain(mp);

    return;

fail:

    nxt_mp_destroy(mp);
}


static void
nxt_router_access_log_reopen_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_mp_t   *mp;
    nxt_buf_t  *b;

    b = obj;
    mp = b->data;

    nxt_mp_release(mp);
}


static void
nxt_router_access_log_reopen_ready(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_router_access_log_t         *access_log;
    nxt_router_access_log_reopen_t  *reopen;

    reopen = data;

    access_log = reopen->access_log;

    if (access_log == nxt_router->access_log) {

        if (nxt_slow_path(dup2(msg->fd[0], access_log->fd) == -1)) {
            nxt_alert(task, "dup2(%FD, %FD) failed %E",
                      msg->fd[0], access_log->fd, nxt_errno);
        }
    }

    nxt_fd_close(msg->fd[0]);
    nxt_mp_release(reopen->mem_pool);
}


static void
nxt_router_access_log_reopen_error(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_router_access_log_reopen_t  *reopen;

    reopen = data;

    nxt_mp_release(reopen->mem_pool);
}

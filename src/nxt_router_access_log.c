
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_conf.h>
#include <nxt_http.h>


typedef struct {
    nxt_str_t                 path;
    nxt_str_t                 format;
    nxt_conf_value_t          *expr;
} nxt_router_access_log_conf_t;


typedef struct {
    nxt_str_t                 text;
    nxt_router_access_log_t   *access_log;
} nxt_router_access_log_ctx_t;


static void nxt_router_access_log_writer(nxt_task_t *task,
    nxt_http_request_t *r, nxt_router_access_log_t *access_log,
    nxt_tstr_t *format);
static void nxt_router_access_log_write_ready(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_access_log_write_error(nxt_task_t *task, void *obj,
    void *data);
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
        NXT_CONF_MAP_STR,
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
    u_char                        *p;
    nxt_int_t                     ret;
    nxt_str_t                     str;
    nxt_tstr_t                    *format;
    nxt_router_t                  *router;
    nxt_router_access_log_t       *access_log;
    nxt_router_access_log_conf_t  alcf;

    static const nxt_str_t  log_format_str = nxt_string("$remote_addr - - "
        "[$time_local] \"$request_line\" $status $body_bytes_sent "
        "\"$header_referer\" \"$header_user_agent\"");

    nxt_memzero(&alcf, sizeof(nxt_router_access_log_conf_t));

    alcf.format = log_format_str;

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

    str.length = alcf.format.length + 1;

    str.start = nxt_malloc(str.length);
    if (str.start == NULL) {
        nxt_alert(task, "failed to allocate log format structure");
        return NXT_ERROR;
    }

    p = nxt_cpymem(str.start, alcf.format.start, alcf.format.length);
    *p = '\n';

    format = nxt_tstr_compile(rtcf->tstr_state, &str, NXT_TSTR_LOGGING);
    if (nxt_slow_path(format == NULL)) {
        return NXT_ERROR;
    }

    rtcf->access_log = access_log;
    rtcf->log_format = format;

    if (alcf.expr != NULL) {
        nxt_conf_get_string(alcf.expr, &str);

        if (str.length > 0 && str.start[0] == '!') {
            rtcf->log_negate = 1;

            str.start++;
            str.length--;
        }

        rtcf->log_expr = nxt_tstr_compile(rtcf->tstr_state, &str, 0);
        if (nxt_slow_path(rtcf->log_expr == NULL)) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


static void
nxt_router_access_log_writer(nxt_task_t *task, nxt_http_request_t *r,
    nxt_router_access_log_t *access_log, nxt_tstr_t *format)
{
    nxt_int_t                    ret;
    nxt_router_conf_t            *rtcf;
    nxt_router_access_log_ctx_t  *ctx;

    ctx = nxt_mp_get(r->mem_pool, sizeof(nxt_router_access_log_ctx_t));
    if (nxt_slow_path(ctx == NULL)) {
        return;
    }

    ctx->access_log = access_log;

    if (nxt_tstr_is_const(format)) {
        nxt_tstr_str(format, &ctx->text);

        nxt_router_access_log_write_ready(task, r, ctx);

    } else {
        rtcf = r->conf->socket_conf->router_conf;

        ret = nxt_tstr_query_init(&r->tstr_query, rtcf->tstr_state,
                                  &r->tstr_cache, r, r->mem_pool);
        if (nxt_slow_path(ret != NXT_OK)) {
            return;
        }

        nxt_tstr_query(task, r->tstr_query, format, &ctx->text);
        nxt_tstr_query_resolve(task, r->tstr_query, ctx,
                               nxt_router_access_log_write_ready,
                               nxt_router_access_log_write_error);
     }
}


static void
nxt_router_access_log_write_ready(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_request_t           *r;
    nxt_router_access_log_ctx_t  *ctx;

    r = obj;
    ctx = data;

    nxt_fd_write(ctx->access_log->fd, ctx->text.start, ctx->text.length);

    nxt_http_request_close_handler(task, r, r->proto.any);
}


static void
nxt_router_access_log_write_error(nxt_task_t *task, void *obj, void *data)
{

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
